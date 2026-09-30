"""
Execution Record tests - Verify all required fields are present and signed.
"""
import hashlib
import hmac
import json

import pytest

from core.config import config
from core.models.forensic import (
    AnalysisResult,
    AnalysisState,
    ChainOfCustodyEntry,
    DetectionClassification,
    ExecutionRecord,
)


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"
    config.server_hmac_signing_key = "test-signing-key-1234567890abcdef"


class TestExecutionRecord:
    """Test execution record signing and fields."""

    def test_record_signing(self):
        """Execution record must be signable."""
        rec = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test", "command"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )

        # Before signing
        assert rec.manifest_canonical_sha256 == ""
        assert rec.server_hmac_signature == ""

        # Sign
        rec.sign_record(config.server_hmac_signing_key)

        # After signing
        assert rec.manifest_canonical_sha256 != ""
        assert len(rec.manifest_canonical_sha256) == 64
        assert rec.server_hmac_signature != ""
        assert len(rec.server_hmac_signature) == 64

    def test_record_canonical_hash(self):
        """Canonical hash must be deterministic."""
        rec1 = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test", "command"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )

        rec2 = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test", "command"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )

        rec1.sign_record("test-key")
        rec2.sign_record("test-key")

        assert rec1.manifest_canonical_sha256 == rec2.manifest_canonical_sha256

    def test_record_hmac_verification(self):
        """HMAC signature must be verifiable."""
        key = "test-secret-key"
        rec = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test", "command"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )

        rec.sign_record(key)

        # Verify the HMAC
        data = {
            "case_id": rec.case_id,
            "evidence_id": rec.evidence_id,
            "pack_id": rec.pack_id,
            "pack_version": rec.pack_version,
            "container_digest": rec.container_digest,
            "input_root_sha256": rec.input_root_sha256,
            "ioc_bundle_sha256": rec.ioc_bundle_sha256,
            "ioc_bundle_version": rec.ioc_bundle_version,
            "tool_command": rec.tool_command,
            "exit_code": rec.exit_code,
            "started_at": rec.started_at,
            "completed_at": rec.completed_at,
        }
        canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"))
        canonical_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        expected_hmac = hmac.new(
            key.encode("utf-8"),
            canonical_hash.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        assert rec.server_hmac_signature == expected_hmac


class TestAnalysisResult:
    """Test analysis result with execution record."""

    def test_analysis_result_required_fields(self):
        """AnalysisResult must have all required fields."""
        rec = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )
        rec.sign_record("test-key")

        result = AnalysisResult(
            job_id="job-123",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z",
            duration_seconds=3600.0,
            status=AnalysisState.COMPLETED,
            summary_classification=DetectionClassification.NO_KNOWN_IOC,
            input_integrity={"root_sha256": "a" * 64},
            findings=[],
            timeline=[],
            warnings=[],
            limitations=["Absence of known IOC matches does not prove absence of compromise."],
            chain_of_custody=[],
            execution_record=rec
        )

        # Verify all required fields
        assert result.job_id == "job-123"
        assert result.case_id == "CASE-001"
        assert result.evidence_id == "EVIDENCE-001"
        assert result.pack_id == "mobile_compromise"
        assert result.pack_version == "2.3.2"
        assert result.execution_record.container_digest == "sha256:abc123"
        assert result.execution_record.input_root_sha256 == "a" * 64
        assert result.execution_record.ioc_bundle_sha256 == "b" * 64
        assert result.execution_record.ioc_bundle_version == "1.0.0"
        assert result.execution_record.tool_command == ["test"]
        assert result.execution_record.exit_code == 0
        assert result.execution_record.started_at == "2024-01-01T00:00:00Z"
        assert result.execution_record.completed_at == "2024-01-01T01:00:00Z"
        assert result.execution_record.manifest_canonical_sha256 != ""
        assert result.execution_record.server_hmac_signature != ""

    def test_failed_analysis_has_error_classification(self):
        """FAILED analysis must have ERROR classification."""
        rec = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test"],
            exit_code=-1,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T00:01:00Z"
        )

        # This should raise due to invariant violation if we try ERROR classification
        # But let's test the invariant
        with pytest.raises(ValueError) as exc_info:
            AnalysisResult(
                job_id="job-123",
                pack_id="mobile_compromise",
                pack_version="2.3.2",
                case_id="CASE-001",
                evidence_id="EVIDENCE-001",
                started_at="2024-01-01T00:00:00Z",
                completed_at="2024-01-01T00:01:00Z",
                duration_seconds=60.0,
                status=AnalysisState.FAILED,
                summary_classification=DetectionClassification.HIT,  # Wrong!
                input_integrity={},
                findings=[],
                timeline=[],
                warnings=[],
                limitations=[],
                chain_of_custody=[],
                execution_record=rec
            )

        assert "INVARIANT VIOLATION" in str(exc_info.value)

    def test_no_known_ioc_has_limitation(self):
        """NO_KNOWN_IOC must have standard limitation."""
        rec = ExecutionRecord(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            container_digest="sha256:abc123",
            input_root_sha256="a" * 64,
            ioc_bundle_sha256="b" * 64,
            ioc_bundle_version="1.0.0",
            tool_command=["test"],
            exit_code=0,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z"
        )
        rec.sign_record("test-key")

        result = AnalysisResult(
            job_id="job-123",
            pack_id="mobile_compromise",
            pack_version="2.3.2",
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T01:00:00Z",
            duration_seconds=3600.0,
            status=AnalysisState.COMPLETED,
            summary_classification=DetectionClassification.NO_KNOWN_IOC,
            input_integrity={},
            findings=[],
            timeline=[],
            warnings=[],
            limitations=["Absence of known IOC matches does not prove absence of compromise."],
            chain_of_custody=[],
            execution_record=rec
        )

        assert "Absence of known IOC matches does not prove absence of compromise." in result.limitations


class TestChainOfCustody:
    """Test chain of custody."""

    def test_chain_of_custody_entry_validation(self):
        """Chain of custody entry must validate hash immutability."""
        with pytest.raises(ValueError):
            ChainOfCustodyEntry(
                action="TEST",
                actor="test",
                sha256_before="a" * 64,
                sha256_after="b" * 64,  # Different!
                details={}
            )

    def test_chain_of_custody_entry_valid(self):
        """Valid chain of custody entry must pass."""
        same_hash = "a" * 64
        entry = ChainOfCustodyEntry(
            action="VAULT_PRE_FLIGHT_VERIFIED",
            actor="vault_engine",
            sha256_before=same_hash,
            sha256_after=same_hash,
            details={"test": "value"}
        )

        assert entry.action == "VAULT_PRE_FLIGHT_VERIFIED"
        assert entry.actor == "vault_engine"
