"""
Docker tests - Verify image digest verification and sandbox security.
"""
from unittest.mock import MagicMock, patch

import pytest

from core.config import config
from workers.isolation import DockerDigestVerificationError, SandboxSecurityManager


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


class TestDockerDigestVerification:
    """Test canonical RepoDigest verification without requiring a Docker daemon."""

    def test_matching_digest_passes(self):
        client = MagicMock()
        image = MagicMock()
        digest = "sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a"
        image.attrs = {"RepoDigests": [f"ghcr.io/test/image@{digest}"]}
        client.images.get.return_value = image
        assert SandboxSecurityManager.verify_image_digest("test-image", digest, client=client) == digest

    def test_mismatching_digest_fails(self):
        client = MagicMock()
        image = MagicMock()
        image.attrs = {"RepoDigests": ["ghcr.io/test/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}
        client.images.get.return_value = image
        with pytest.raises(DockerDigestVerificationError, match="IMAGE_DIGEST_MISMATCH"):
            SandboxSecurityManager.verify_image_digest(
                "test-image",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                client=client,
            )

    def test_missing_repo_digest_fails(self):
        client = MagicMock()
        image = MagicMock()
        image.attrs = {"RepoDigests": []}
        client.images.get.return_value = image
        with pytest.raises(DockerDigestVerificationError, match="no trustworthy RepoDigests"):
            SandboxSecurityManager.verify_image_digest(
                "test-image",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                client=client,
            )


class TestSandboxSecurityConfig:
    """Test sandbox security configuration."""

    @pytest.fixture(autouse=True)
    def mock_digest(self, monkeypatch):
        monkeypatch.setattr(
            SandboxSecurityManager,
            "verify_image_digest",
            lambda image, pinned_digest, client=None: "sha256:123"
        )

    def test_read_only_filesystem(self):
        """Root filesystem must be read-only."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert config["read_only"] is True

    def test_no_network_by_default(self):
        """Network must be disabled by default."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert config["network_mode"] == "none"

    def test_network_bridge_when_required(self):
        """Network can be enabled when required by manifest."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=True,
            pinned_digest="sha256:123"
        )

        assert config["network_mode"] == "bridge"

    def test_capabilities_dropped(self):
        """All capabilities must be dropped."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert config["cap_drop"] == ["ALL"]

    def test_no_new_privileges(self):
        """No new privileges must be enabled."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert "no-new-privileges:true" in config["security_opt"]

    def test_memory_limits_applied(self):
        """Memory limits must be applied."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=4096,
            cpu_cores=2.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert config["mem_limit"] == "4096m"
        assert config["memswap_limit"] == "4096m"

    def test_cpu_limits_applied(self):
        """CPU limits must be applied."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=2.5,
            net=False,
            pinned_digest="sha256:123"
        )

        # cpu_period is 100000, cpu_quota is cpu_cores * 100000
        assert config["cpu_period"] == 100000
        assert config["cpu_quota"] == 250000

    def test_mounts_read_only(self):
        """Mounts must be read-only by default."""
        mounts = [
            {"host_path": "/host/path", "container_path": "/container/path"}
        ]

        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=mounts,
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert "/host/path" in config["volumes"]
        assert config["volumes"]["/host/path"]["mode"] == "ro"

    def test_tmpfs_secure(self):
        """Tmpfs must have secure mount options."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert "/tmp" in config["tmpfs"]
        tmpfs_opts = config["tmpfs"]["/tmp"]
        assert "noexec" in tmpfs_opts
        assert "nosuid" in tmpfs_opts
        assert "nodev" in tmpfs_opts


class TestPIDLimits:
    """Test process limits."""

    @pytest.fixture(autouse=True)
    def mock_digest(self, monkeypatch):
        monkeypatch.setattr(
            SandboxSecurityManager,
            "verify_image_digest",
            lambda image, pinned_digest, client=None: "sha256:123"
        )

    def test_pids_limit_applied(self):
        """PIDs limit must be applied."""
        config = SandboxSecurityManager.get_config(
            image="test",
            mounts=[],
            cmd=["test"],
            mem_mb=1024,
            cpu_cores=1.0,
            net=False,
            pinned_digest="sha256:123"
        )

        assert config["pids_limit"] == 128
