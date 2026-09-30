"""
ACL tests - Verify fail-closed access control.
"""

import pytest
from fastapi import HTTPException, status

from core.acl import (
    CaseAccessController,
    DatabaseBackedCaseAccessProvider,
    TokenUser,
)
from core.config import config


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


@pytest.fixture
def fresh_acl():
    """Create a fresh ACL provider for each test."""
    return DatabaseBackedCaseAccessProvider()


class TestCaseAccessProvider:
    """Test case access provider interface."""

    def test_unknown_case_denies_access(self, fresh_acl):
        """Unknown case MUST DENY access."""
        user = TokenUser(user_id="test_user", roles=[], organization="test_org")

        result = fresh_acl.can_access_case(user, "UNKNOWN-CASE")
        assert result is False

    def test_unknown_job_denies_access(self, fresh_acl):
        """Unknown job MUST DENY access."""
        user = TokenUser(user_id="test_user", roles=[], organization="test_org")

        result = fresh_acl.can_access_job(user, "unknown-job-id")
        assert result is False

    def test_admin_can_access_anything(self, fresh_acl):
        """Admin can access any case."""
        # Register a case
        fresh_acl.register_case(case_id="CASE-001", owner_id="owner_1", org_id="org_1")

        admin_user = TokenUser(user_id="admin", roles=["admin"], organization="any")

        assert fresh_acl.can_access_case(admin_user, "CASE-001") is True
        assert fresh_acl.can_access_case(admin_user, "UNKNOWN-CASE") is True

    def test_owner_can_access_own_case(self, fresh_acl):
        """Case owner can access their own case."""
        fresh_acl.register_case(case_id="CASE-001", owner_id="owner_1", org_id="org_1")

        owner = TokenUser(user_id="owner_1", roles=[], organization="org_1")

        assert fresh_acl.can_access_case(owner, "CASE-001") is True

    def test_same_org_can_access_case(self, fresh_acl):
        """User in same organization can access case."""
        fresh_acl.register_case(case_id="CASE-001", owner_id="owner_1", org_id="org_1")

        colleague = TokenUser(user_id="colleague", roles=[], organization="org_1")

        assert fresh_acl.can_access_case(colleague, "CASE-001") is True

    def test_different_org_denied_access(self, fresh_acl):
        """User in different organization is DENIED."""
        fresh_acl.register_case(case_id="CASE-001", owner_id="owner_1", org_id="org_1")

        outsider = TokenUser(user_id="outsider", roles=[], organization="org_2")

        assert fresh_acl.can_access_case(outsider, "CASE-001") is False

    def test_job_owner_can_access_job(self, fresh_acl):
        """Job owner can access their own job."""
        fresh_acl.register_job(job_id="job-123", owner_id="owner_1", org_id="org_1", case_id="CASE-001")

        owner = TokenUser(user_id="owner_1", roles=[], organization="org_1")

        assert fresh_acl.can_access_job(owner, "job-123") is True

    def test_job_access_via_case(self, fresh_acl):
        """User with case access can access job."""
        fresh_acl.register_case(case_id="CASE-001", owner_id="owner_1", org_id="org_1")
        fresh_acl.register_job(job_id="job-123", owner_id="owner_1", org_id="org_1", case_id="CASE-001")

        colleague = TokenUser(user_id="colleague", roles=[], organization="org_1")

        # Should have access via case
        assert fresh_acl.can_access_job(colleague, "job-123", case_id="CASE-001") is True


class TestCaseAccessController:
    """Test case access controller enforcement."""

    def test_enforce_unknown_case_raises(self, fresh_acl, monkeypatch):
        """Enforce raises 403 for unknown case."""
        monkeypatch.setattr("core.acl.case_access_provider", fresh_acl)

        user = TokenUser(user_id="test_user", roles=[], organization="test_org")

        with pytest.raises(HTTPException) as exc_info:
            CaseAccessController.enforce(user, "UNKNOWN-CASE")

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    def test_enforce_allowed_case_passes(self, fresh_acl, monkeypatch):
        """Enforce passes for allowed case."""
        fresh_acl.register_case(case_id="CASE-001", owner_id="test_user", org_id="test_org")
        monkeypatch.setattr("core.acl.case_access_provider", fresh_acl)

        user = TokenUser(user_id="test_user", roles=[], organization="test_org")

        # Should not raise
        CaseAccessController.enforce(user, "CASE-001")

    def test_enforce_admin_passes(self, fresh_acl, monkeypatch):
        """Enforce passes for admin."""
        monkeypatch.setattr("core.acl.case_access_provider", fresh_acl)

        admin = TokenUser(user_id="admin", roles=["admin"], organization="any")

        # Should not raise for any case
        CaseAccessController.enforce(admin, "UNKNOWN-CASE")

    def test_enforce_job_access_denied(self, fresh_acl, monkeypatch):
        """Enforce job access raises 403 for unauthorized user."""
        fresh_acl.register_job(job_id="job-123", owner_id="owner_1", org_id="org_1", case_id="CASE-001")
        monkeypatch.setattr("core.acl.case_access_provider", fresh_acl)

        user = TokenUser(user_id="outsider", roles=[], organization="org_2")

        with pytest.raises(HTTPException) as exc_info:
            CaseAccessController.enforce_job_access(user, "job-123")

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
