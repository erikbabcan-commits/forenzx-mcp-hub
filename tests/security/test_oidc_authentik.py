"""Unit and security tests for Authentik / OIDC JWKS token verification."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from core.acl import TokenUser
from core.auth_oidc import OIDCValidator
from core.config import config


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate ephemeral RSA keypair for testing RS256 JWTs."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()
    return private_key, public_key


def test_oidc_disabled_by_default():
    validator = OIDCValidator()
    # When disabled, always returns None
    assert validator.verify_token("some.dummy.token") is None


def test_oidc_rs256_token_verification(rsa_keypair):
    private_key, public_key = rsa_keypair
    validator = OIDCValidator()

    now = int(time.time())
    payload = {
        "sub": "auth0_user_12345",
        "preferred_username": "jan.novak",
        "email": "jan.novak@corp.local",
        "groups": ["forenzx_admins"],
        "organization": "cyber_defense_unit",
        "iss": "http://authentik:9000/application/o/forenzx-mcp-hub/",
        "aud": "forenzx-mcp-hub",
        "exp": now + 3600,
        "iat": now,
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key

    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_signing_key

    with patch.object(config, "oidc_enabled", True), \
         patch.object(config, "oidc_jwks_url", "http://authentik:9000/application/o/forenzx-mcp-hub/jwks/"), \
         patch.object(config, "oidc_issuer_url", "http://authentik:9000/application/o/forenzx-mcp-hub/"), \
         patch.object(config, "oidc_audience", "forenzx-mcp-hub"), \
         patch.object(validator, "_get_client", return_value=mock_client):

        user = validator.verify_token(token)

        assert isinstance(user, TokenUser)
        assert user.user_id == "auth0_user_12345"
        assert "admin" in user.roles
        assert "analyst" in user.roles
        assert user.organization == "cyber_defense_unit"


def test_oidc_expired_token_rejected(rsa_keypair):
    private_key, public_key = rsa_keypair
    validator = OIDCValidator()

    now = int(time.time())
    payload = {
        "sub": "expired_user",
        "groups": ["forenzx_analysts"],
        "exp": now - 3600,  # Expired
        "iat": now - 7200,
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key-1"})

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key

    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = mock_signing_key

    with patch.object(config, "oidc_enabled", True), \
         patch.object(config, "oidc_jwks_url", "http://authentik:9000/application/o/forenzx-mcp-hub/jwks/"), \
         patch.object(validator, "_get_client", return_value=mock_client):

        user = validator.verify_token(token)
        assert user is None


def test_oidc_role_mapping():
    assert "admin" in OIDCValidator._extract_roles({"groups": ["forenzx_admins"]})
    assert "analyst" in OIDCValidator._extract_roles({"groups": ["forenzx_analysts"]})
    assert "auditor" in OIDCValidator._extract_roles({"groups": ["forenzx_auditors"]})
    # Default fallback
    assert OIDCValidator._extract_roles({}) == ["analyst"]
