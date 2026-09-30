"""
MVT tests - Verify command safety and parsing.
"""
import json
from pathlib import Path

import pytest

from core.models.forensic import EvidenceInputSpec
from packs.base import ForensicPackAdapter
from packs.mobile_compromise.adapter import MobileCompromiseAdapter


@pytest.fixture
def adapter():
    """Create an MVT adapter for testing."""
    manifest_data = {
        "id": "mobile_compromise",
        "name": "Mobile Forensic Analysis",
        "version": "2.3.2",
        "description": "MVT adapter",
        "license": "MIT",
        "author": "ForenZX",
        "supported_platforms": ["ios", "android"],
        "supported_inputs": ["ios_backup", "android_backup"],
        "capabilities": ["ioc_matching"],
        "container_image": "ghcr.io/mvt-project/mvt",
        "pinned_image_digest": "sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
    }

    from core.models.forensic import PackManifest
    manifest = PackManifest(**manifest_data)

    return MobileCompromiseAdapter(manifest, Path("/tmp"))


class TestMVTCommand:
    """Test MVT command generation."""

    def test_ios_command_is_argv_list(self, adapter):
        """iOS command must be exact argv list, not shell string."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="ios_backup"
        )

        cmd = adapter.get_execution_command(spec, {})

        # Must be a list
        assert isinstance(cmd, list)

        # Must not contain shell operators
        cmd_str = " ".join(cmd)
        assert "|" not in cmd_str
        assert ";" not in cmd_str
        assert "&" not in cmd_str
        assert "$" not in cmd_str
        assert "`" not in cmd_str

        # Must have expected tokens
        assert "mvt-ios" in cmd
        assert "check-backup" in cmd
        assert "--iocs" in cmd
        assert "/evidence/ioc/bundle.stix2" in cmd
        assert "--output" in cmd
        assert "/evidence/output" in cmd
        assert "/evidence/input" in cmd

    def test_android_command_is_argv_list(self, adapter):
        """Android command must be exact argv list."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="android_backup"
        )

        cmd = adapter.get_execution_command(spec, {})

        assert isinstance(cmd, list)
        assert "mvt-android" in cmd
        assert "check-backup" in cmd
        assert "--iocs" in cmd

    def test_unsupported_input_type_fails(self, adapter):
        """Unsupported input type must raise ValueError."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="disk_raw"
        )

        with pytest.raises(ValueError):
            adapter.get_execution_command(spec, {})

    def test_no_string_interpolation(self, adapter):
        """Command must not use string interpolation."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="ios_backup"
        )

        cmd = adapter.get_execution_command(spec, {})

        # All elements must be strings (not formatted strings)
        for arg in cmd:
            assert isinstance(arg, str)

        # No formatted strings in the command
        for arg in cmd:
            assert "%s" not in arg
            assert "%d" not in arg
            assert "{}" not in arg


class TestInputValidation:
    """Test input validation."""

    async def test_validate_ios_input(self, adapter):
        """iOS input must be validated."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="ios_backup"
        )

        result = await adapter.validate_input(spec)
        assert result is True

    async def test_validate_android_input(self, adapter):
        """Android input must be validated."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="android_backup"
        )

        result = await adapter.validate_input(spec)
        assert result is True

    async def test_validate_unsupported_input(self, adapter):
        """Unsupported input must be rejected."""
        spec = EvidenceInputSpec(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            input_type="disk_raw"
        )

        result = await adapter.validate_input(spec)
        assert result is False


class TestOutputParsing:
    """Test output artifact parsing."""

    async def test_parse_empty_directory(self, adapter, tmp_path):
        """Empty output directory must return NO_KNOWN_IOC."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        classification, findings, timeline, warnings = await adapter.parse_output_artifacts(output_dir)

        assert classification == "NO_KNOWN_IOC"
        assert findings == []
        assert timeline == []
        assert len(warnings) > 0

    async def test_parse_nonexistent_directory(self, adapter, tmp_path):
        """Nonexistent output directory must return ERROR."""
        output_dir = tmp_path / "nonexistent"

        classification, findings, timeline, warnings = await adapter.parse_output_artifacts(output_dir)

        assert classification == "ERROR"
        assert findings == []
        assert len(warnings) > 0

    async def test_parse_detected_ioc(self, adapter, tmp_path):
        """Detected IOC must return HIT classification."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create a detected JSON file
        detected_file = output_dir / "module1_detected.json"
        detected_data = [
            {
                "file_path": "/path/to/malicious",
                "matched_indicator": {
                    "name": "Pegasus IOC",
                    "value": "malicious.example.com",
                    "sha256": "abc123"
                }
            }
        ]

        with open(detected_file, "w") as f:
            json.dump(detected_data, f)

        classification, findings, timeline, warnings = await adapter.parse_output_artifacts(output_dir)

        assert classification == "HIT"
        assert len(findings) == 1
        assert findings[0].classification == "HIT"
        assert findings[0].ioc_name == "Pegasus IOC"

    async def test_parse_suspicious(self, adapter, tmp_path):
        """Suspicious findings must return SUSPICIOUS classification."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create a suspicious JSON file
        suspicious_file = output_dir / "module2_suspicious.json"
        suspicious_data = [
            {
                "file_path": "/path/to/suspicious",
                "description": "Heuristic anomaly detected"
            }
        ]

        with open(suspicious_file, "w") as f:
            json.dump(suspicious_data, f)

        classification, findings, timeline, warnings = await adapter.parse_output_artifacts(output_dir)

        assert classification == "SUSPICIOUS"
        assert len(findings) == 1
        assert findings[0].classification == "SUSPICIOUS"

    async def test_parse_hit_and_suspicious(self, adapter, tmp_path):
        """Both HIT and SUSPICIOUS must prioritize HIT."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create both detected and suspicious files
        detected_file = output_dir / "module1_detected.json"
        with open(detected_file, "w") as f:
            json.dump([{"matched_indicator": {"name": "IOC"}}], f)

        suspicious_file = output_dir / "module2_suspicious.json"
        with open(suspicious_file, "w") as f:
            json.dump([{"description": "suspicious"}], f)

        classification, findings, timeline, warnings = await adapter.parse_output_artifacts(output_dir)

        assert classification == "HIT"
        assert len(findings) == 2


class TestAdapterInheritance:
    """Test adapter inheritance."""

    def test_is_forensic_pack_adapter(self, adapter):
        """MobileCompromiseAdapter must be a ForensicPackAdapter."""
        assert isinstance(adapter, ForensicPackAdapter)

    def test_has_required_methods(self, adapter):
        """Adapter must have all required methods."""
        assert hasattr(adapter, "get_execution_command")
        assert hasattr(adapter, "validate_input")
        assert hasattr(adapter, "parse_output_artifacts")
