"""ForenZX MCP Hub v5: OpenID Connect (OIDC) & JWKS token verification."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

import jwt
from jwt import PyJWKClient, PyJWKClientError

from core.acl import TokenUser
from core.config import config
from core.utils.logger import get_logger

logger = get_logger("forenzx.auth.oidc")


class OIDCValidator:
    """Verifies incoming Bearer JWTs against an OIDC JWKS endpoint (e.g. Authentik)."""

    def __init__(self) -> None:
        self._jwks_client: Optional[PyJWKClient] = None
        self._configured_jwks_url: Optional[str] = None
        self._lock = threading.Lock()

    def _get_client(self) -> Optional[PyJWKClient]:
        jwks_url = config.oidc_jwks_url.strip() if config.oidc_jwks_url else ""
        if not jwks_url:
            return None

        with self._lock:
            if self._jwks_client is None or self._configured_jwks_url != jwks_url:
                try:
                    self._jwks_client = PyJWKClient(
                        jwks_url,
                        cache_jwk_set=True,
                        lifespan=3600,
                        timeout=5,
                    )
                    self._configured_jwks_url = jwks_url
                    logger.info(f"OIDC JWKS client initialized for: {jwks_url}")
                except Exception as exc:
                    logger.error(f"Failed to initialize PyJWKClient for {jwks_url}: {exc}")
                    return None
            return self._jwks_client

    def verify_token(self, token: str) -> Optional[TokenUser]:
        """Verify an RS256/ES256 OIDC token against Authentik JWKS."""
        if not config.oidc_enabled:
            return None

        client = self._get_client()
        if not client:
            return None

        try:
            unverified_header = jwt.get_unverified_header(token)
            alg = unverified_header.get("alg", "")
            if alg.startswith("HS"):
                # Symmetric tokens are verified by local secret, not JWKS.
                return None

            signing_key = client.get_signing_key_from_jwt(token)

            decode_options: Dict[str, Any] = {
                "verify_signature": True,
                "verify_exp": True,
                "require": ["exp"],
            }

            decode_kwargs: Dict[str, Any] = {
                "algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                "options": decode_options,
            }

            if config.oidc_issuer_url:
                decode_kwargs["issuer"] = config.oidc_issuer_url.strip()
                decode_options["verify_iss"] = True

            if config.oidc_audience:
                decode_kwargs["audience"] = config.oidc_audience.strip()
                decode_options["verify_aud"] = True
            else:
                decode_options["verify_aud"] = False

            payload = jwt.decode(token, signing_key.key, **decode_kwargs)

            user_id = (
                payload.get("sub")
                or payload.get("preferred_username")
                or payload.get("email")
                or payload.get("user_id")
            )
            if not user_id:
                logger.warning("OIDC token missing subject identifier")
                return None

            roles = self._extract_roles(payload)
            organization = str(
                payload.get("organization")
                or payload.get("org")
                or payload.get("org_id")
                or "default_org"
            )

            return TokenUser(
                user_id=str(user_id),
                roles=roles,
                organization=organization,
            )

        except PyJWKClientError as exc:
            logger.warning(f"OIDC JWKS key retrieval failed: {exc}")
            return None
        except jwt.PyJWTError as exc:
            logger.warning(f"OIDC JWT verification failed: {exc}")
            return None
        except Exception as exc:
            logger.error(f"Unexpected error validating OIDC token: {exc}")
            return None

    @staticmethod
    def _extract_roles(payload: Dict[str, Any]) -> List[str]:
        raw_roles: List[str] = []

        # Check standard claims
        if "roles" in payload:
            val = payload["roles"]
            raw_roles.extend(val if isinstance(val, list) else [val])

        if "groups" in payload:
            val = payload["groups"]
            raw_roles.extend(val if isinstance(val, list) else [val])

        # Keycloak / standard realm_access
        realm_access = payload.get("realm_access")
        if isinstance(realm_access, dict) and "roles" in realm_access:
            r_roles = realm_access["roles"]
            raw_roles.extend(r_roles if isinstance(r_roles, list) else [r_roles])

        normalized_roles: set[str] = set()
        for r in raw_roles:
            r_lower = str(r).lower()
            if r_lower in {"admin", "admins", "forenzx_admin", "forenzx_admins", "authentik admins"}:
                normalized_roles.add("admin")
                normalized_roles.add("analyst")
            elif r_lower in {"analyst", "analysts", "forenzx_analyst", "forenzx_analysts"}:
                normalized_roles.add("analyst")
            elif r_lower in {"auditor", "auditors", "forenzx_auditor", "forenzx_auditors"}:
                normalized_roles.add("auditor")
            else:
                normalized_roles.add(str(r))

        if not normalized_roles:
            normalized_roles.add("analyst")

        return sorted(list(normalized_roles))


oidc_validator = OIDCValidator()
