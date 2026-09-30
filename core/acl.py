"""
Access Control Layer: Multi-tenant case ACL with fail-closed semantics.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException, status
from pydantic import BaseModel

from core.utils.logger import get_logger

logger = get_logger(__name__)


class TokenUser(BaseModel):
    user_id: str
    roles: list[str]
    organization: str | None = "default_org"


class CaseAccessProvider(ABC):
    """Abstract interface for case access control."""

    @abstractmethod
    def can_access_case(self, user: TokenUser, case_id: str) -> bool:
        """Check if user can access a case."""
        pass

    @abstractmethod
    def can_access_job(self, user: TokenUser, job_id: str, case_id: Optional[str] = None) -> bool:
        """Check if user can access a job."""
        pass

    @abstractmethod
    def get_case_owner(self, case_id: str) -> Optional[str]:
        """Get the owner of a case, or None if case doesn't exist."""
        pass

    @abstractmethod
    def get_case_organization(self, case_id: str) -> Optional[str]:
        """Get the organization of a case, or None if case doesn't exist."""
        pass

    @abstractmethod
    def get_job_owner(self, job_id: str) -> Optional[Tuple[str, str]]:
        """Get (owner_id, organization_id) for a job, or None if job doesn't exist."""
        pass

    def register_case(self, case_id: str, owner_id: str, org_id: str) -> None:
        """Register a case (for testing/dynamic creation)."""
        pass

    def register_job(self, job_id: str, owner_id: str, org_id: str, case_id: str) -> None:
        """Register a job (for testing/dynamic creation)."""
        pass


class DatabaseBackedCaseAccessProvider(CaseAccessProvider):
    """
    Production-ready case access provider.
    In this implementation, we use a configuration-based approach
    that can be backed by a real database in production.

    FAIL-CLOSED: Unknown cases/ jobs DENY access.
    """

    def __init__(self):
        # In production, this would query a database
        # For now, we use an empty dict - DENY by default
        self._case_acl: Dict[str, Dict[str, Any]] = {}
        self._job_ownership: Dict[str, Dict[str, Any]] = {}

    def can_access_case(self, user: TokenUser, case_id: str) -> bool:
        """Check if user can access a case. FAIL-CLOSED: unknown case = DENY."""
        # Admins can access anything
        if "admin" in user.roles:
            logger.info(f"Admin {user.user_id} accessing case {case_id}")
            return True

        # Check if case exists
        case_info = self._case_acl.get(case_id)
        if case_info is None:
            logger.critical(f"ACCESS DENIED: Case {case_id} not found. User {user.user_id} denied.")
            return False

        # Check if user is owner
        if case_info.get("owner_id") == user.user_id:
            return True

        # Check if user is in same organization
        if case_info.get("org_id") == user.organization:
            return True

        logger.critical(f"ACCESS DENIED: User {user.user_id} (org: {user.organization}) attempted access to Case {case_id} (owner: {case_info.get('owner_id')}, org: {case_info.get('org_id')})")
        return False

    def can_access_job(self, user: TokenUser, job_id: str, case_id: Optional[str] = None) -> bool:
        """Check if user can access a job. FAIL-CLOSED: unknown job = DENY."""
        # Admins can access anything
        if "admin" in user.roles:
            return True

        # Check if job exists
        job_info = self._job_ownership.get(job_id)
        if job_info is None:
            logger.critical(f"ACCESS DENIED: Job {job_id} not found. User {user.user_id} denied.")
            return False

        # Check ownership
        if job_info.get("owner_id") == user.user_id:
            return True

        # Check organization
        if job_info.get("org_id") == user.organization:
            return True

        # If case_id is provided, also check case access
        if case_id:
            if self.can_access_case(user, case_id):
                return True

        logger.critical(f"ACCESS DENIED: User {user.user_id} attempted access to Job {job_id} (owner: {job_info.get('owner_id')}, org: {job_info.get('org_id')})")
        return False

    def get_case_owner(self, case_id: str) -> Optional[str]:
        """Get case owner or None."""
        case_info = self._case_acl.get(case_id)
        if case_info:
            return case_info.get("owner_id")
        return None

    def get_case_organization(self, case_id: str) -> Optional[str]:
        """Get case organization or None."""
        case_info = self._case_acl.get(case_id)
        if case_info:
            return case_info.get("org_id")
        return None

    def get_job_owner(self, job_id: str) -> Optional[Tuple[str, str]]:
        """Get (owner_id, org_id) for job or None."""
        job_info = self._job_ownership.get(job_id)
        if job_info:
            owner_id = job_info.get("owner_id")
            org_id = job_info.get("org_id")
            if owner_id is not None and org_id is not None:
                return (str(owner_id), str(org_id))
        return None

    def register_case(self, case_id: str, owner_id: str, org_id: str) -> None:
        """Register a case (for testing/dynamic creation)."""
        self._case_acl[case_id] = {"owner_id": owner_id, "org_id": org_id}

    def register_job(self, job_id: str, owner_id: str, org_id: str, case_id: str) -> None:
        """Register a job (for testing/dynamic creation)."""
        self._job_ownership[job_id] = {
            "owner_id": owner_id,
            "org_id": org_id,
            "case_id": case_id
        }


# Global access provider instance
case_access_provider: DatabaseBackedCaseAccessProvider = DatabaseBackedCaseAccessProvider()


class CaseAccessController:
    """Controller that enforces case access using the configured provider."""

    @staticmethod
    def enforce(user: TokenUser, case_id: str) -> None:
        """Enforce case access. Raises HTTPException 403 on denial."""
        if not case_access_provider.can_access_case(user, case_id):
            logger.critical(f"IDOR VIOLATION: User {user.user_id} attempted access to Case {case_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Prístup odmietnutý: Nemáte oprávnenie na spis '{case_id}'."
            )

    @staticmethod
    def enforce_job_access(user: TokenUser, job_id: str, case_id: Optional[str] = None) -> None:
        """Enforce job access. Raises HTTPException 403 on denial."""
        if not case_access_provider.can_access_job(user, job_id, case_id):
            logger.critical(f"IDOR VIOLATION: User {user.user_id} attempted access to Job {job_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Prístup odmietnutý: Nemáte oprávnenie na úlohu '{job_id}'."
            )
