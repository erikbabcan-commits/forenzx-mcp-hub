"""
Vault tests - Verify path traversal and symlink protection.
"""

from pathlib import Path

import pytest

from core.config import config
from core.vault import EvidenceVault, SecurityPathError


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"
    config.vault_base_dir = Path("/tmp/forenzx_vault_test")
    config.scratch_base_dir = Path("/tmp/forenzx_scratch_test")


@pytest.fixture
def temp_vault(tmp_path):
    """Create a temporary vault structure."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()

    # Create a test case directory
    case_dir = vault_dir / "test_case"
    case_dir.mkdir()

    # Create evidence directory
    evidence_dir = case_dir / "test_evidence"
    evidence_dir.mkdir()

    # Create a test file
    test_file = evidence_dir / "test_file.txt"
    test_file.write_text("test evidence content")

    return vault_dir


class TestPathSanitization:
    """Test path sanitization."""

    def test_valid_id_passes(self):
        """Valid alphanumeric IDs must pass."""
        result = EvidenceVault.sanitize_id("valid_case_123", "case_id")
        assert result == "valid_case_123"

    def test_empty_id_fails(self):
        """Empty ID must fail."""
        with pytest.raises(SecurityPathError):
            EvidenceVault.sanitize_id("", "case_id")

    def test_id_with_special_chars_fails(self):
        """ID with special characters must fail."""
        invalid_ids = [
            "../case",
            "/case",
            "case/../",
            "case with spaces",
            "case\twith\ttabs",
            "case\nwith\nnewlines",
            "case;rm -rf",
            "case|cat /etc/passwd",
        ]

        for invalid_id in invalid_ids:
            with pytest.raises(SecurityPathError):
                EvidenceVault.sanitize_id(invalid_id, "case_id")

    def test_long_id_fails(self):
        """ID longer than 256 chars must fail."""
        long_id = "a" * 257
        with pytest.raises(SecurityPathError):
            EvidenceVault.sanitize_id(long_id, "case_id")


class TestPathResolution:
    """Test path resolution security."""

    def test_path_traversal_blocked(self, temp_vault, monkeypatch):
        """Path traversal attempts must be BLOCKED."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("../etc/passwd", "evidence")

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("test_case/../etc/passwd", "evidence")

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("test_case/../../etc/passwd", "evidence")

    def test_absolute_path_blocked(self, temp_vault, monkeypatch):
        """Absolute path injection must be BLOCKED."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("/etc/passwd", "evidence")

    def test_valid_path_resolves(self, temp_vault, monkeypatch):
        """Valid paths must resolve correctly."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        result = EvidenceVault.resolve_path("test_case", "test_evidence")

        assert result.exists()
        assert result == temp_vault / "test_case" / "test_evidence"

    def test_nonexistent_evidence_fails(self, temp_vault, monkeypatch):
        """Nonexistent evidence must raise FileNotFoundError."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        with pytest.raises(FileNotFoundError):
            EvidenceVault.resolve_path("nonexistent_case", "nonexistent_evidence")


class TestSymlinkProtection:
    """Test symlink detection."""

    def test_symlink_in_path_blocked(self, temp_vault, monkeypatch):
        """Symlinks in path must be BLOCKED."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        # Create a symlink in the vault
        case_dir = temp_vault / "symlink_case"
        case_dir.mkdir()

        # Create a real evidence directory
        real_evidence = temp_vault / "real_evidence"
        real_evidence.mkdir()

        # Create symlink to real evidence
        symlink_evidence = case_dir / "evidence_link"
        try:
            symlink_evidence.symlink_to(real_evidence)
        except OSError as e:
            pytest.skip(f"Symlink creation not permitted by OS: {e}")

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("symlink_case", "evidence_link")

    def test_symlink_escape_blocked(self, temp_vault, monkeypatch, tmp_path):
        """Symlinks escaping vault must be BLOCKED."""
        monkeypatch.setattr(config, "vault_base_dir", temp_vault)

        # Create a case directory
        case_dir = temp_vault / "escape_case"
        case_dir.mkdir()

        # Create a symlink that points outside vault
        outside_file = tmp_path / "outside_file.txt"
        outside_file.write_text("outside")

        symlink_evidence = case_dir / "escape_link"
        try:
            symlink_evidence.symlink_to(outside_file)
        except OSError as e:
            pytest.skip(f"Symlink creation not permitted by OS: {e}")

        with pytest.raises(SecurityPathError):
            EvidenceVault.resolve_path("escape_case", "escape_link")


class TestIntegrityHashing:
    """Test integrity hashing."""

    def test_file_sha256(self, temp_vault):
        """File SHA-256 must be computed correctly."""
        test_file = temp_vault / "test_file.txt"
        test_file.write_text("test content")

        hash1, size1 = EvidenceVault.compute_file_sha256(test_file)
        hash2, size2 = EvidenceVault.compute_file_sha256(test_file)

        assert hash1 == hash2
        assert size1 == size2
        assert len(hash1) == 64  # SHA-256 hex digest

    def test_directory_merkle_hash(self, temp_vault):
        """Directory Merkle hash must be computed correctly."""
        test_dir = temp_vault / "test_dir"
        test_dir.mkdir()

        # Create test files
        (test_dir / "file1.txt").write_text("content1")
        (test_dir / "file2.txt").write_text("content2")

        hash1, size1, manifest1 = EvidenceVault.compute_directory_merkle_hash(test_dir)
        hash2, size2, manifest2 = EvidenceVault.compute_directory_merkle_hash(test_dir)

        assert hash1 == hash2
        assert size1 == size2
        assert manifest1 == manifest2

    def test_calculate_integrity_file(self, temp_vault):
        """Calculate integrity for file."""
        test_file = temp_vault / "test_integrity.txt"
        test_file.write_text("test")

        hash_val, size, meta = EvidenceVault.calculate_integrity(test_file)

        assert meta["type"] == "file"
        assert "sha256" in meta

    def test_calculate_integrity_directory(self, temp_vault):
        """Calculate integrity for directory."""
        test_dir = temp_vault / "test_integrity_dir"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("test")

        hash_val, size, meta = EvidenceVault.calculate_integrity(test_dir)

        assert meta["type"] == "directory_merkle"
        assert "sha256" in meta


class TestScratchCleanup:
    """Test scratch directory cleanup."""

    def test_cleanup_scratch(self, tmp_path, monkeypatch):
        """Scratch cleanup must work."""
        monkeypatch.setattr(config, "scratch_base_dir", tmp_path)

        scratch_dir = tmp_path / "scratch_123"
        scratch_dir.mkdir()

        EvidenceVault.cleanup_scratch(scratch_dir)

        assert not scratch_dir.exists()

    def test_cleanup_nonexistent_scratch(self, tmp_path, monkeypatch):
        """Cleanup of nonexistent scratch must not fail."""
        monkeypatch.setattr(config, "scratch_base_dir", tmp_path)

        scratch_dir = tmp_path / "nonexistent_scratch"

        # Should not raise
        EvidenceVault.cleanup_scratch(scratch_dir)

    def test_cleanup_outside_scratch_base(self, tmp_path, monkeypatch):
        """Cleanup of path outside scratch base must be BLOCKED."""
        monkeypatch.setattr(config, "scratch_base_dir", tmp_path)

        # Try to cleanup a path outside scratch base
        outside_dir = tmp_path.parent / "outside_scratch"
        outside_dir.mkdir()

        # Should not delete outside_dir
        EvidenceVault.cleanup_scratch(outside_dir)

        assert outside_dir.exists()
