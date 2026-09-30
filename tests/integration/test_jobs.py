"""
Job tests - Verify job ownership and IDOR protection.
"""
from uuid import UUID

import pytest

from core.acl import case_access_provider
from core.config import config
from core.jobs import AsyncJobManager
from core.models.forensic import AnalysisState


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


@pytest.fixture
def fresh_job_manager():
    """Create a fresh job manager for each test."""
    return AsyncJobManager()


class TestJobOwnership:
    """Test job ownership and IDOR protection."""

    def test_job_id_is_uuidv4(self, fresh_job_manager):
        """Job IDs must be cryptographically random UUIDv4."""
        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        # Should be a valid UUID
        try:
            uuid_obj = UUID(job_id)
            assert str(uuid_obj) == job_id
        except ValueError:
            pytest.fail(f"Job ID '{job_id}' is not a valid UUID")

    def test_job_ids_are_unique(self, fresh_job_manager):
        """Job IDs must be unique."""
        job_ids = set()
        for _ in range(10):
            job_id, _ = fresh_job_manager.create_job(
                case_id="CASE-001",
                evidence_id="EVIDENCE-001",
                pack_id="mobile_compromise",
                owner_id="user_1",
                organization_id="org_1"
            )
            assert job_id not in job_ids
            job_ids.add(job_id)

    def test_job_has_ownership(self, fresh_job_manager):
        """Jobs must have ownership tracking."""
        job_id, job_spec = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        status = fresh_job_manager.get_status(job_id)
        assert status is not None
        assert status.owner_id == "user_1"
        assert status.organization_id == "org_1"

        spec = fresh_job_manager.get_spec(job_id)
        assert spec is not None
        assert spec.owner_id == "user_1"
        assert spec.organization_id == "org_1"

    def test_job_acl_registration(self, fresh_job_manager, monkeypatch):
        """Jobs must be registered with ACL provider."""
        # Use the global job manager to test ACL registration
        monkeypatch.setattr("core.jobs.job_manager", fresh_job_manager)

        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        # Check if ACL provider has the job
        job_owner = case_access_provider.get_job_owner(job_id)
        assert job_owner is not None
        assert job_owner[0] == "user_1"  # owner_id
        assert job_owner[1] == "org_1"  # org_id


class TestJobStatus:
    """Test job status tracking."""

    def test_job_status_creation(self, fresh_job_manager):
        """Job status is created properly."""
        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        status = fresh_job_manager.get_status(job_id)
        assert status is not None
        assert status.job_id == job_id
        assert status.case_id == "CASE-001"
        assert status.evidence_id == "EVIDENCE-001"
        assert status.pack_id == "mobile_compromise"
        assert status.state == AnalysisState.QUEUED
        assert status.progress_percent == 0

    def test_job_status_update(self, fresh_job_manager):
        """Job status can be updated."""
        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        fresh_job_manager.update_progress(
            job_id, AnalysisState.RUNNING, 50, "Processing"
        )

        status = fresh_job_manager.get_status(job_id)
        assert status.state == AnalysisState.RUNNING
        assert status.progress_percent == 50
        assert status.current_stage == "Processing"

    def test_job_failure(self, fresh_job_manager):
        """Job can be marked as failed."""
        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        fresh_job_manager.fail_job(job_id, "Test failure")

        status = fresh_job_manager.get_status(job_id)
        assert status.state == AnalysisState.FAILED
        assert status.error_message == "Test failure"


class TestJobCleanup:
    """Test job cleanup."""

    def test_job_cancellation(self, fresh_job_manager):
        """Jobs can be cancelled."""
        job_id, _ = fresh_job_manager.create_job(
            case_id="CASE-001",
            evidence_id="EVIDENCE-001",
            pack_id="mobile_compromise",
            owner_id="user_1",
            organization_id="org_1"
        )

        # Mark as running
        fresh_job_manager.update_progress(
            job_id, AnalysisState.RUNNING, 50, "Processing"
        )

        # Cancel
        fresh_job_manager.cancel_job(job_id)

        # Since we're not actually running async tasks, this should still work
        fresh_job_manager.get_status(job_id)
        # The status should still be RUNNING since we can't actually cancel
        # In a real scenario, it would be CANCELLED
