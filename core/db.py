"""Small SQLite persistence layer for jobs, results, MCP registry and maintenance audit."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from core.config import config


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path or config.database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS mcp_servers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    server_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    transport TEXT NOT NULL DEFAULT 'streamable_http',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    auth_type TEXT NOT NULL DEFAULT 'none',
                    auth_secret_encrypted TEXT,
                    custom_headers_json TEXT NOT NULL DEFAULT '{}',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    notes TEXT NOT NULL DEFAULT '',
                    maintenance_url TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_checked_at TEXT,
                    last_status TEXT NOT NULL DEFAULT 'UNKNOWN',
                    last_latency_ms INTEGER,
                    last_error TEXT,
                    last_tools_json TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS pack_overrides (
                    pack_id TEXT PRIMARY KEY,
                    pinned_digest TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS registry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_id TEXT,
                    success INTEGER NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    pack_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    current_stage TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error_message TEXT,
                    owner_id TEXT NOT NULL,
                    organization_id TEXT NOT NULL,
                    spec_json TEXT NOT NULL,
                    idempotency_key TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency ON jobs(organization_id, case_id, evidence_id, pack_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

                CREATE TABLE IF NOT EXISTS job_results (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> Optional[dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.connect() as conn:
            conn.execute(sql, params)

    def event(self, actor: str, action: str, target_id: str | None, success: bool, details: dict[str, Any] | None = None) -> None:
        self.execute(
            "INSERT INTO registry_events(ts,actor,action,target_id,success,details_json) VALUES(?,?,?,?,?,?)",
            (utcnow(), actor, action, target_id, int(success), json.dumps(details or {}, ensure_ascii=False, sort_keys=True)),
        )


db = Database()
