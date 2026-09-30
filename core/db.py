"""Small SQLite persistence layer for jobs, results, MCP registry and maintenance audit.

Schema changes go through the versioned migration mechanism in
``core/migrations.py`` — never through ad-hoc DDL here. This module is the
single storage interface (ADR-0002): a future PostgreSQL backend implements
the same surface.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from core.config import config
from core.migrations import LATEST_VERSION, current_version, migrate


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path or config.database_path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Apply pending versioned migrations (see core/migrations.py)."""
        with self.connect() as conn:
            migrate(conn)

    def schema_version(self) -> int:
        with self.connect() as conn:
            return current_version(conn)

    def expected_schema_version(self) -> int:
        return LATEST_VERSION

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

    def event(
        self,
        actor: str,
        action: str,
        target_id: str | None,
        success: bool,
        details: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> None:
        """Append an audit event. Never log secrets, keys or tokens in ``details``."""
        self.execute(
            "INSERT INTO registry_events(ts,actor,action,target_id,success,details_json,trace_id) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                utcnow(),
                actor,
                action,
                target_id,
                int(success),
                json.dumps(details or {}, ensure_ascii=False, sort_keys=True),
                trace_id,
            ),
        )


db = Database()
