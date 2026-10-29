"""
Threat Intel tests - Verify fail-closed IOC bundle loading.
"""

import hashlib
import json

import pytest

from core.config import AppConfig, config
from core.threat_intel import IOCBundleInfo, ThreatIntelError, ThreatIntelVault


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Setup test environment."""
    monkeypatch.setattr(config, "environment", "test")
    monkeypatch.setattr(config, "forenzx_trusted_stix_digests", "")
    ThreatIntelVault.reset()
    yield
    ThreatIntelVault.reset()


@pytest.fixture
def temp_threat_intel_dir(tmp_path):
    """Create a temporary threat intel directory."""
    intel_dir = tmp_path / "threat_intel"
    intel_dir.mkdir()
    return intel_dir


class TestThreatIntelVault:
    """Test threat intelligence vault."""

    def test_runtime_reads_canonical_allowlist_environment(self, monkeypatch):
        digest = hashlib.sha256(b"approved-test-bundle").hexdigest()
        monkeypatch.setenv("FORENZX_TRUSTED_STIX_DIGESTS", digest)
        assert AppConfig(_env_file=None).forenzx_trusted_stix_digests == digest

    def test_missing_ioc_bundle_in_production_fails(self, monkeypatch, tmp_path):
        """Production: missing IOC bundle must FAIL CLOSED."""
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        with pytest.raises(ThreatIntelError) as exc_info:
            ThreatIntelVault.get_pinned_stix_bundle("test_bundle.stix2")

        assert "FAIL CLOSED" in str(exc_info.value)

    def test_corrupt_ioc_bundle_fails(self, monkeypatch, tmp_path):
        """Corrupt IOC bundle must FAIL CLOSED."""
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Create a corrupt file (not valid JSON)
        bundle_path = tmp_path / "test_bundle.stix2"
        bundle_path.write_text("NOT VALID JSON {{")

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        with pytest.raises(ThreatIntelError) as exc_info:
            ThreatIntelVault.get_pinned_stix_bundle("test_bundle.stix2")

        assert "FAIL CLOSED" in str(exc_info.value)
        assert "corrupt" in str(exc_info.value).lower()

    def test_valid_ioc_bundle_succeeds(self, monkeypatch, tmp_path):
        """Valid IOC bundle must be loaded successfully."""
        monkeypatch.setattr(config, "environment", "test")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Create a valid STIX2 bundle
        bundle_path = tmp_path / "valid_bundle.stix2"
        valid_bundle = {
            "type": "bundle",
            "id": "bundle--test-valid",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--test-1",
                    "name": "Test IOC",
                    "pattern": "[domain-name:value = 'test.example.com']",
                    "pattern_type": "stix",
                }
            ],
        }

        import json

        with open(bundle_path, "w") as f:
            json.dump(valid_bundle, f)

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        monkeypatch.setattr(
            config, "forenzx_trusted_stix_digests", hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        )
        path, sha256, version = ThreatIntelVault.get_pinned_stix_bundle("valid_bundle.stix2")

        assert path.exists()
        assert len(sha256) == 64  # SHA-256 hex digest
        assert version is not None

    def test_sample_bundle_in_dev(self, monkeypatch, tmp_path):
        """Dev mode: sample bundle created automatically."""
        monkeypatch.setattr(config, "environment", "development")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        # Generated development samples do not establish trust automatically.
        with pytest.raises(ThreatIntelError, match="FORENZX_TRUSTED_STIX_DIGESTS"):
            ThreatIntelVault.get_pinned_stix_bundle("sample.stix2")
        sample_path = tmp_path / "sample.stix2"
        monkeypatch.setattr(
            config, "forenzx_trusted_stix_digests", hashlib.sha256(sample_path.read_bytes()).hexdigest()
        )
        path, sha256, version = ThreatIntelVault.get_pinned_stix_bundle("sample.stix2")

        assert path.exists()

        # Read the file to verify it's STIX2
        import json

        with open(path, "r") as f:
            bundle = json.load(f)

        assert bundle["type"] == "bundle"

    def test_bundle_caching(self, monkeypatch, tmp_path):
        """Bundles are cached after loading."""
        monkeypatch.setattr(config, "environment", "test")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Create a bundle
        bundle_path = tmp_path / "cached_bundle.stix2"
        import json

        with open(bundle_path, "w") as f:
            json.dump({"type": "bundle", "id": "bundle--cache-test", "objects": []}, f)
        monkeypatch.setattr(
            config, "forenzx_trusted_stix_digests", hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        )

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        # Load once
        path1, sha1, ver1 = ThreatIntelVault.get_pinned_stix_bundle("cached_bundle.stix2")

        # Load again - same bytes and allowlist give the same digest.
        path2, sha2, ver2 = ThreatIntelVault.get_pinned_stix_bundle("cached_bundle.stix2")

        assert sha1 == sha2
        assert ver1 == ver2

    def test_bundle_info_stored(self, monkeypatch, tmp_path):
        """Bundle info is stored with metadata."""
        monkeypatch.setattr(config, "environment", "test")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)

        # Create a bundle
        bundle_path = tmp_path / "info_bundle.stix2"
        import json

        with open(bundle_path, "w") as f:
            json.dump({"type": "bundle", "id": "bundle--info-test", "objects": []}, f)
        monkeypatch.setattr(
            config, "forenzx_trusted_stix_digests", hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        )

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        path, sha256, version = ThreatIntelVault.get_pinned_stix_bundle("info_bundle.stix2")

        # Check bundle info is stored
        assert "info_bundle.stix2" in ThreatIntelVault._loaded_bundles

        info = ThreatIntelVault._loaded_bundles["info_bundle.stix2"]
        assert info.bundle_name == "info_bundle.stix2"
        assert info.sha256 == sha256
        assert info.version == version
        assert info.source == str(bundle_path)

    @pytest.mark.parametrize("environment", ["production", "staging", "development", "test"])
    @pytest.mark.parametrize("allowlist", ["", " ", "bad-digest", "a" * 64, "a" * 64 + ",malformed"])
    def test_missing_malformed_or_wrong_pin_blocks_every_environment(
        self, monkeypatch, tmp_path, environment, allowlist
    ):
        monkeypatch.setattr(config, "environment", environment)
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)
        monkeypatch.setattr(config, "forenzx_trusted_stix_digests", allowlist)
        (tmp_path / "bundle.stix2").write_text(json.dumps({"type": "bundle", "objects": []}))
        with pytest.raises(ThreatIntelError, match="FAIL CLOSED"):
            ThreatIntelVault.get_pinned_stix_bundle("bundle.stix2")
        assert not ThreatIntelVault._loaded_bundles

    def test_correct_pin_matches_exact_file_bytes(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)
        bundle_path = tmp_path / "bundle.stix2"
        bundle_path.write_bytes(b'{"type":"bundle","objects":[]}\n')
        digest = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        monkeypatch.setattr(config, "forenzx_trusted_stix_digests", "a" * 64 + ", " + digest.upper())
        path, actual_digest, _ = ThreatIntelVault.get_pinned_stix_bundle("bundle.stix2")
        assert path == bundle_path
        assert actual_digest == digest
        # Semantically identical JSON with different bytes is not pinned.
        bundle_path.write_bytes(b'{"type":"bundle","objects":[]}')
        with pytest.raises(ThreatIntelError, match="digest is not trusted"):
            ThreatIntelVault.get_pinned_stix_bundle("bundle.stix2")

    def test_revoking_cached_pin_blocks_next_load(self, monkeypatch, tmp_path):
        monkeypatch.setattr(config, "threat_intel_dir", tmp_path)
        bundle_path = tmp_path / "bundle.stix2"
        bundle_path.write_bytes(b'{"type":"bundle","objects":[]}')
        monkeypatch.setattr(
            config, "forenzx_trusted_stix_digests", hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        )
        ThreatIntelVault.get_pinned_stix_bundle("bundle.stix2")
        monkeypatch.setattr(config, "forenzx_trusted_stix_digests", "")
        with pytest.raises(ThreatIntelError, match="FORENZX_TRUSTED_STIX_DIGESTS"):
            ThreatIntelVault.get_pinned_stix_bundle("bundle.stix2")

    def test_path_escape_blocks_even_trusted_digest(self, monkeypatch, tmp_path):
        ioc_dir = tmp_path / "ioc"
        ioc_dir.mkdir()
        outside = tmp_path / "outside.stix2"
        outside.write_bytes(b'{"type":"bundle","objects":[]}')
        monkeypatch.setattr(config, "threat_intel_dir", ioc_dir)
        monkeypatch.setattr(config, "forenzx_trusted_stix_digests", hashlib.sha256(outside.read_bytes()).hexdigest())
        with pytest.raises(ThreatIntelError, match="inside THREAT_INTEL_DIR"):
            ThreatIntelVault.get_pinned_stix_bundle("../outside.stix2")


class TestIOCBundleInfo:
    """Test IOCBundleInfo model."""

    def test_bundle_info_creation(self):
        """IOCBundleInfo can be created."""
        info = IOCBundleInfo(
            bundle_name="test_bundle",
            version="1.0.0",
            sha256="a" * 64,
            source="/path/to/bundle",
            loaded_at="2024-01-01T00:00:00Z",
        )

        assert info.bundle_name == "test_bundle"
        assert info.version == "1.0.0"
