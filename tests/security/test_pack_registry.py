"""
Pack Registry tests - Verify fail-closed pack loading.
"""
import json

import pytest

from core.config import config
from core.models.forensic import PackManifest
from core.pack_registry import PackRegistry, PackRegistryError, pack_registry


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


@pytest.fixture
def temp_packs_dir(tmp_path):
    """Create a temporary packs directory."""
    packs_dir = tmp_path / "packs"
    packs_dir.mkdir()

    # Create a test pack
    test_pack_dir = packs_dir / "test_pack"
    test_pack_dir.mkdir()

    manifest = {
        "id": "test_pack",
        "name": "Test Pack",
        "version": "1.0.0",
        "description": "Test pack for validation",
        "license": "MIT",
        "author": "Test Author",
        "supported_platforms": ["linux"],
        "supported_inputs": ["test_input"],
        "capabilities": ["test_capability"],
        "container_image": "test-image",
        "pinned_image_digest": "sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
        "enabled": True
    }

    with open(test_pack_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)

    # Create adapter
    with open(test_pack_dir / "adapter.py", "w") as f:
        f.write("""
from packs.base import ForensicPackAdapter

class TestPackAdapter(ForensicPackAdapter):
    def get_execution_command(self, spec, params):
        return ["test", "command"]

    async def validate_input(self, spec):
        return True

    async def parse_output_artifacts(self, output_dir):
        return ("NO_KNOWN_IOC", [], [], [])
""")

    return packs_dir


class TestPackRegistry:
    """Test pack registry functionality."""

    def test_mobile_compromise_pack_loads(self):
        """Mobile compromise pack must load successfully."""
        packs = pack_registry.list_packs()

        pack_ids = [p.id for p in packs]
        assert "mobile_compromise" in pack_ids

    def test_pack_manifest_validation(self, temp_packs_dir):
        """Pack manifests must be validated by Pydantic."""
        registry = PackRegistry()
        registry.packs_dir = temp_packs_dir

        # Should not raise
        registry.load_packs()

        packs = registry.list_packs()
        assert len(packs) == 1
        assert packs[0].id == "test_pack"

    def test_invalid_manifest_fails(self, tmp_path):
        """Invalid manifest must cause server startup fail."""
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()

        invalid_pack_dir = packs_dir / "invalid_pack"
        invalid_pack_dir.mkdir()

        # Create invalid manifest (missing required fields)
        manifest = {
            "id": "invalid_pack",
            # Missing name, version, etc.
        }

        with open(invalid_pack_dir / "manifest.json", "w") as f:
            json.dump(manifest, f)

        registry = PackRegistry()
        registry._load_pack(invalid_pack_dir / "manifest.json")
        assert "invalid_pack" in registry.errors()

    def test_disabled_pack_denied(self, temp_packs_dir, monkeypatch):
        """Disabled pack must be DENIED."""
        # Create a disabled pack
        disabled_pack_dir = temp_packs_dir / "disabled_pack"
        disabled_pack_dir.mkdir()

        manifest = {
            "id": "disabled_pack",
            "name": "Disabled Pack",
            "version": "1.0.0",
            "description": "Disabled pack",
            "license": "MIT",
            "author": "Test",
            "supported_platforms": ["linux"],
            "supported_inputs": ["test"],
            "capabilities": ["test"],
            "container_image": "test",
            "pinned_image_digest": "sha256:123",
            "enabled": False  # Disabled
        }

        with open(disabled_pack_dir / "manifest.json", "w") as f:
            json.dump(manifest, f)

        registry = PackRegistry()
        registry.packs_dir = temp_packs_dir
        registry.load_packs()

        # Should return None for disabled pack
        assert registry.get_pack("disabled_pack") is None

    def test_unknown_pack_denied(self, temp_packs_dir):
        """Unknown pack must be DENIED."""
        registry = PackRegistry()
        registry.packs_dir = temp_packs_dir
        registry.load_packs()

        # Unknown pack
        assert registry.get_pack("nonexistent_pack") is None

    def test_placeholder_digest_disables_mobile_pack(self):
        """The shipped placeholder digest must be visible but disabled until pinned."""
        record = next(x for x in pack_registry.describe() if x["id"] == "mobile_compromise")
        assert record["enabled"] is False
        assert record["registry_error"]

    def test_pack_adapter_unknown(self):
        """Unknown pack adapter must return None."""
        adapter = pack_registry.get_adapter("nonexistent")

        assert adapter is None

    def test_supported_inputs_visible_for_disabled_pack(self):
        record = next(x for x in pack_registry.describe() if x["id"] == "mobile_compromise")
        assert "ios_backup" in record["supported_inputs"]
        assert "android_backup" in record["supported_inputs"]


class TestPackManifest:
    """Test PackManifest Pydantic model."""

    def test_valid_manifest(self):
        """Valid manifest must pass validation."""
        manifest_data = {
            "id": "test_pack",
            "name": "Test Pack",
            "version": "1.0.0",
            "description": "Test",
            "license": "MIT",
            "author": "Test",
            "supported_platforms": ["linux"],
            "supported_inputs": ["test"],
            "capabilities": ["test"],
            "container_image": "test",
            "pinned_image_digest": "sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
        }

        manifest = PackManifest(**manifest_data)
        assert manifest.id == "test_pack"

    def test_invalid_id_fails(self):
        """Invalid pack ID must fail validation."""
        manifest_data = {
            "id": "INVALID ID WITH SPACES!",  # Invalid
            "name": "Test",
            "version": "1.0.0",
            "description": "Test",
            "license": "MIT",
            "author": "Test",
            "supported_platforms": ["linux"],
            "supported_inputs": ["test"],
            "capabilities": ["test"],
            "container_image": "test",
            "pinned_image_digest": "sha256:123",
        }

        with pytest.raises(Exception):
            PackManifest(**manifest_data)

    def test_invalid_version_fails(self):
        """Invalid version must fail validation."""
        manifest_data = {
            "id": "test_pack",
            "name": "Test",
            "version": "invalid",  # Invalid
            "description": "Test",
            "license": "MIT",
            "author": "Test",
            "supported_platforms": ["linux"],
            "supported_inputs": ["test"],
            "capabilities": ["test"],
            "container_image": "test",
            "pinned_image_digest": "sha256:123",
        }

        with pytest.raises(Exception):
            PackManifest(**manifest_data)
