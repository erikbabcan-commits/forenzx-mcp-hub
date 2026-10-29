"""
Threat Intel Vault: Správa a verifikácia pinovaných STIX2 IoC balíkov.
Fail-closed design - missing or corrupt bundles BLOCK execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from pydantic import BaseModel

from core.config import config
from core.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatIntelError(Exception):
    """Raised when threat intelligence validation fails."""

    pass


class IOCBundleInfo(BaseModel):
    """Information about a loaded IOC bundle."""

    bundle_name: str
    version: str
    sha256: str
    source: str
    loaded_at: str


class ThreatIntelVault:
    """Threat intelligence vault with fail-closed semantics."""

    _loaded_bundles: dict[str, IOCBundleInfo] = {}

    @classmethod
    def get_pinned_stix_bundle(cls, bundle_name: str = "pegasus_predator.stix2") -> Tuple[Path, str, str]:
        """
        Load and verify a STIX2 IoC bundle.

        All environments:
        - Missing bundle: raises ThreatIntelError (FAIL CLOSED)
        - Corrupt bundle: raises ThreatIntelError (FAIL CLOSED)
        - Missing/malformed trust configuration: raises ThreatIntelError
        - Digest not in FORENZX_TRUSTED_STIX_DIGESTS: raises ThreatIntelError
        - Every call re-reads bytes and checks current trust (no cache bypass)

        Development/test behavior:
        - Creates a missing sample ONLY if ENVIRONMENT is development/test
        - Samples still require an explicitly approved digest
        """
        ioc_dir = config.threat_intel_dir.resolve()
        bundle_path = (ioc_dir / bundle_name).resolve()

        # Trust is explicit in every environment, including generated samples.
        env = config.environment.lower()
        if bundle_path.parent != ioc_dir:
            raise ThreatIntelError("THREAT INTEL FAIL CLOSED: bundle must be inside THREAT_INTEL_DIR.")

        # Verify the bundle exists
        if not bundle_path.is_file():
            if env in ["development", "test"]:
                # ONLY in dev/test, create a sample bundle
                ioc_dir.mkdir(parents=True, exist_ok=True)
                sample_bundle = {
                    "type": "bundle",
                    "id": "bundle--forenzx-sample-ioc-v4",
                    "objects": [
                        {
                            "type": "indicator",
                            "id": "indicator--sample-pegasus-trace",
                            "name": "SAMPLE - Pegasus Spyware Domain",
                            "pattern": "[domain-name:value = 'sample-malicious-infrastructure.test']",
                            "pattern_type": "stix",
                            "valid_from": "2024-01-01T00:00:00Z",
                            "labels": ["malicious-activity", "spyware"],
                        }
                    ],
                }
                with open(bundle_path, "w", encoding="utf-8") as f:
                    json.dump(sample_bundle, f, indent=2)
                logger.warning(f"Created SAMPLE IOC bundle in {env} mode: {bundle_name}")
            else:
                raise ThreatIntelError(
                    f"THREAT INTEL FAIL CLOSED: IOC bundle '{bundle_name}' not found. "
                    "Analysis blocked. Please ensure threat intelligence bundles are properly installed."
                )

        # Verify bundle is valid JSON
        try:
            with open(bundle_path, "rb") as f:
                bundle_content = f.read()
            json.loads(bundle_content)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ThreatIntelError(
                f"THREAT INTEL FAIL CLOSED: IOC bundle '{bundle_name}' is corrupt. Error: {e}. Analysis blocked."
            )

        # Compute hash
        hasher = hashlib.sha256()
        hasher.update(bundle_content)
        bundle_sha256 = hasher.hexdigest().lower()

        # Do not trust cached metadata: files and allowlists may change between jobs.
        raw_allowlist = config.forenzx_trusted_stix_digests
        trusted_digests = {item.strip().lower() for item in raw_allowlist.split(",") if item.strip()}
        if not trusted_digests or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in trusted_digests):
            raise ThreatIntelError(
                "THREAT INTEL FAIL CLOSED: FORENZX_TRUSTED_STIX_DIGESTS must contain approved SHA-256 digests."
            )
        if bundle_sha256 not in trusted_digests:
            raise ThreatIntelError("THREAT INTEL FAIL CLOSED: IOC bundle digest is not trusted. Analysis blocked.")
        version = "2026.09.29-STIX2-ENTERPRISE"

        # Store bundle info
        bundle_info = IOCBundleInfo(
            bundle_name=bundle_name,
            version=version,
            sha256=bundle_sha256,
            source=str(bundle_path),
            loaded_at=datetime.now(timezone.utc).isoformat(),
        )
        cls._loaded_bundles[bundle_name] = bundle_info

        logger.info(f"Loaded STIX2 IoC Bundle: {bundle_name} | SHA256: {bundle_sha256[:16]}... | Ver: {version}")
        return bundle_path, bundle_sha256, version

    @classmethod
    def verify_bundle_hash(cls, bundle_path: Path, expected_sha256: str) -> bool:
        """Verify a bundle's SHA-256 hash matches expected value."""
        hasher = hashlib.sha256()
        try:
            with open(bundle_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            actual_hash = hasher.hexdigest().lower()
            return actual_hash == expected_sha256.lower()
        except Exception:
            return False

    @classmethod
    def reset(cls) -> None:
        """Reset loaded bundles (for testing)."""
        cls._loaded_bundles = {}
