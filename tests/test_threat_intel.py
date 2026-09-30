"""
Threat Intel tests - Verify fail-closed IOC bundle loading.
"""
import pytest

from core.config import config
from core.threat_intel import IOCBundleInfo, ThreatIntelError, ThreatIntelVault


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


@pytest.fixture
def temp_threat_intel_dir(tmp_path):
    """Create a temporary threat intel directory."""
    intel_dir = tmp_path / "threat_intel"
    intel_dir.mkdir()
    return intel_dir


class TestThreatIntelVault:
    """Test threat intelligence vault."""

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
                    "pattern_type": "stix"
                }
            ]
        }

        import json
        with open(bundle_path, "w") as f:
            json.dump(valid_bundle, f)

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        # Should succeed in test mode
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

        # Should create sample bundle
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

        # Reset loaded bundles
        ThreatIntelVault._loaded_bundles = {}

        # Load once
        path1, sha1, ver1 = ThreatIntelVault.get_pinned_stix_bundle("cached_bundle.stix2")

        # Load again - should use cache
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


class TestIOCBundleInfo:
    """Test IOCBundleInfo model."""

    def test_bundle_info_creation(self):
        """IOCBundleInfo can be created."""
        info = IOCBundleInfo(
            bundle_name="test_bundle",
            version="1.0.0",
            sha256="a" * 64,
            source="/path/to/bundle",
            loaded_at="2024-01-01T00:00:00Z"
        )

        assert info.bundle_name == "test_bundle"
        assert info.version == "1.0.0"
