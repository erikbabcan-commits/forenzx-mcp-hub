"""Persistent async job manager backed by SQLite."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel

from core.acl import case_access_provider
from core.db import db
from core.models.forensic import AnalysisResult, AnalysisState, JobSpec
from core.utils.logger import get_logger

logger = get_logger(__name__)


class JobStatus(BaseModel):
    job_id: str
    case_id: str
    evidence_id: str
    pack_id: str
    state: AnalysisState
    progress_percent: int = 0
    current_stage: str = "QUEUED"
    started_at: str
    updated_at: str
    error_message: Optional[str] = None
    owner_id: str
    organization_id: str


class AsyncJobManager:
    """Durable metadata/results with in-memory task handles only for currently running jobs."""

    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}
        self._restore_acl_and_interruptions()

    def _restore_acl_and_interruptions(self) -> None:
        rows = db.fetchall("SELECT * FROM jobs")
        for row in rows:
            try:
                case_access_provider.register_job(
                    row["job_id"], row["owner_id"], row["organization_id"], row["case_id"]
                )
            except Exception:
                pass
        # A process restart cannot truthfully claim an in-process Docker task is still running.
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE jobs SET state='FAILED', current_stage='INTERRUPTED_BY_RESTART', error_message='Service restarted while job was active', updated_at=? WHERE state IN ('QUEUED','RUNNING','VALIDATING','PARSING','VERIFYING')",
            (now,),
        )

    def create_job_ex(
        self,
        case_id: str,
        evidence_id: str,
        pack_id: str,
        owner_id: str,
        organization_id: str,
        idempotency_key: str | None = None,
    ) -> tuple[str, JobSpec, bool]:
        def existing() -> tuple[str, JobSpec, bool] | None:
            if not idempotency_key:
                return None
            row = db.fetchone(
                "SELECT job_id FROM jobs WHERE organization_id=? AND case_id=? AND evidence_id=? AND pack_id=? AND idempotency_key=?",
                (organization_id, case_id, evidence_id, pack_id, idempotency_key),
            )
            if row:
                spec = self.get_spec(row["job_id"])
                if spec:
                    return row["job_id"], spec, False
            return None

        found = existing()
        if found:
            return found

        job_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        spec = JobSpec(
            job_id=job_id,
            case_id=case_id,
            evidence_id=evidence_id,
            pack_id=pack_id,
            owner_id=owner_id,
            organization_id=organization_id,
            created_at=now,
            status=AnalysisState.QUEUED,
        )
        try:
            db.execute(
                """INSERT INTO jobs(job_id,case_id,evidence_id,pack_id,state,progress_percent,current_stage,started_at,updated_at,error_message,owner_id,organization_id,spec_json,idempotency_key)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id,
                    case_id,
                    evidence_id,
                    pack_id,
                    AnalysisState.QUEUED.value,
                    0,
                    "QUEUED",
                    now,
                    now,
                    None,
                    owner_id,
                    organization_id,
                    spec.model_dump_json(),
                    idempotency_key,
                ),
            )
        except sqlite3.IntegrityError:
            # Handles concurrent callers racing on the unique idempotency index.
            found = existing()
            if found:
                return found
            raise

        case_access_provider.register_job(job_id, owner_id, organization_id, case_id)
        logger.info(f"Job created: {job_id} | Case: {case_id} | Evidence: {evidence_id} | Owner: {owner_id}")
        return job_id, spec, True

    def create_job(
        self,
        case_id: str,
        evidence_id: str,
        pack_id: str,
        owner_id: str,
        organization_id: str,
        idempotency_key: str | None = None,
    ) -> Tuple[str, JobSpec]:
        job_id, spec, _ = self.create_job_ex(case_id, evidence_id, pack_id, owner_id, organization_id, idempotency_key)
        return job_id, spec

    def update_progress(
        self, job_id: str, state: AnalysisState, progress: int, stage: str, error: Optional[str] = None
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE jobs SET state=?, progress_percent=?, current_stage=?, error_message=?, updated_at=? WHERE job_id=?",
            (state.value, max(0, min(100, progress)), stage, error, now, job_id),
        )

    def store_result(self, job_id: str, result: AnalysisResult) -> None:
        db.execute(
            "INSERT INTO job_results(job_id,result_json,created_at) VALUES(?,?,?) ON CONFLICT(job_id) DO UPDATE SET result_json=excluded.result_json, created_at=excluded.created_at",
            (job_id, result.model_dump_json(), datetime.now(timezone.utc).isoformat()),
        )
        final_stage = "COMPLETED" if result.status == AnalysisState.COMPLETED else result.status.value
        self.update_progress(job_id, result.status, 100, final_stage)

    def fail_job(self, job_id: str, error_message: str) -> None:
        self.update_progress(job_id, AnalysisState.FAILED, 100, "FAILED", error_message)

    def get_status(self, job_id: str) -> Optional[JobStatus]:
        row = db.fetchone("SELECT * FROM jobs WHERE job_id=?", (job_id,))
        if not row:
            return None
        return JobStatus(
            job_id=row["job_id"],
            case_id=row["case_id"],
            evidence_id=row["evidence_id"],
            pack_id=row["pack_id"],
            state=AnalysisState(row["state"]),
            progress_percent=row["progress_percent"],
            current_stage=row["current_stage"],
            started_at=row["started_at"],
            updated_at=row["updated_at"],
            error_message=row["error_message"],
            owner_id=row["owner_id"],
            organization_id=row["organization_id"],
        )

    def list_recent(self, limit: int = 50) -> list[dict]:
        return db.fetchall(
            "SELECT job_id,case_id,evidence_id,pack_id,state,progress_percent,current_stage,started_at,updated_at,error_message,owner_id,organization_id FROM jobs ORDER BY updated_at DESC LIMIT ?",
            (max(1, min(500, limit)),),
        )

    def get_result(self, job_id: str) -> Optional[AnalysisResult]:
        row = db.fetchone("SELECT result_json FROM job_results WHERE job_id=?", (job_id,))
        return AnalysisResult.model_validate_json(row["result_json"]) if row else None

    def get_spec(self, job_id: str) -> Optional[JobSpec]:
        row = db.fetchone("SELECT spec_json,state FROM jobs WHERE job_id=?", (job_id,))
        if not row:
            return None
        data = json.loads(row["spec_json"])
        data["status"] = row["state"]
        return JobSpec.model_validate(data)

    def register_task(self, job_id: str, task: asyncio.Task) -> None:
        self._tasks[job_id] = task

    def cleanup_task(self, job_id: str) -> None:
        self._tasks.pop(job_id, None)

    def cancel_job(self, job_id: str) -> bool:
        st = self.get_status(job_id)
        if not st or st.state in {AnalysisState.COMPLETED, AnalysisState.FAILED, AnalysisState.CANCELLED}:
            return False
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        self.update_progress(job_id, AnalysisState.CANCELLED, 100, "CANCELLED", "Job was cancelled by user")
        return True


job_manager = AsyncJobManager()
