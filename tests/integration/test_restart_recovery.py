"""Restart persistence & recovery verification.

Invariant: job metadata survives a process restart (durable SQLite), and a job
that was RUNNING when the process died is honestly marked FAILED with
``INTERRUPTED_BY_RESTART`` — never left eternally RUNNING (audit-able).
"""

from __future__ import annotations

import pytest

from core.db import db
from core.jobs import AsyncJobManager
from core.models.forensic import AnalysisState


@pytest.fixture
def isolated_db(tmp_path):
    old = db.path
    db.path = tmp_path / "restart-test.db"
    db.init_schema()
    try:
        yield db.path
    finally:
        db.path = old


class TestRestartRecovery:
    def test_job_survives_restart_and_running_jobs_recovered_honestly(self, isolated_db):
        manager = AsyncJobManager()
        job_id, spec, created = manager.create_job_ex(
            case_id="CASE-R1",
            evidence_id="EVD-R1",
            pack_id="mobile_compromise",
            owner_id="analyst-1",
            organization_id="org-1",
        )
        assert created is True

        # Simulate an in-flight job at the moment the process dies.
        manager.update_progress(job_id, AnalysisState.RUNNING, 50, "RUNNING")
        assert manager.get_status(job_id).state is AnalysisState.RUNNING

        # Simulate a service restart: a fresh manager reloads durable state.
        restarted = AsyncJobManager()
        status = restarted.get_status(job_id)
        assert status is not None, "job must survive restart (durable persistence)"
        assert status.state is AnalysisState.FAILED
        assert "INTERRUPTED_BY_RESTART" in status.current_stage
        assert status.error_message and "restarted" in status.error_message.lower()
        assert status.owner_id == "analyst-1"
        assert status.case_id == "CASE-R1"

    def test_completed_jobs_are_not_marked_interrupted(self, isolated_db):
        manager = AsyncJobManager()
        job_id, _, _ = manager.create_job_ex(
            case_id="CASE-R2",
            evidence_id="EVD-R2",
            pack_id="p",
            owner_id="analyst-2",
            organization_id="org-2",
        )
        manager.update_progress(job_id, AnalysisState.COMPLETED, 100, "COMPLETED")
        restarted = AsyncJobManager()
        status = restarted.get_status(job_id)
        assert status.state is AnalysisState.COMPLETED

    def test_restart_recovery_is_auditable(self, isolated_db):
        from core.db import db as database

        manager = AsyncJobManager()
        manager.create_job_ex(
            case_id="CASE-R3",
            evidence_id="EVD-R3",
            pack_id="p",
            owner_id="analyst-3",
            organization_id="org-3",
        )
        AsyncJobManager()  # restart path
        rows = database.fetchall("SELECT job_id FROM jobs WHERE current_stage='INTERRUPTED_BY_RESTART'")
        row = database.fetchone("SELECT state, error_message FROM jobs WHERE case_id='CASE-R3'")
        assert row["state"] == "FAILED"
        assert row["error_message"]
