"""Versioned, ordered SQLite schema migrations for the ForenZX control plane.

Design rules (see docs/architecture/adr/0002-sqlite-default.md):
- The schema is NEVER modified by ad-hoc SQL scattered across the codebase.
  Every schema change must be a new entry in ``MIGRATIONS`` below.
- Each migration runs at most once, inside a transaction, and is recorded in
  ``schema_migrations``.
- Existing databases created before this mechanism are stamped as version 1
  (baseline schema) — no silent re-creation, no data loss.
- Migration versions must be contiguous and append-only once shipped.
"""

from __future__ import annotations

import sqlite3
from typing import List, Sequence, Tuple

MigrationStep = Tuple[int, str, str]

# ---------------------------------------------------------------------------
# Baseline schema (version 1) — the schema as of the v5 baseline commit.
# Kept with IF NOT EXISTS so stamping an existing database is safe.
# ---------------------------------------------------------------------------
BASELINE_SCHEMA = """
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

# ---------------------------------------------------------------------------
# Ordered migrations. Append ONLY — never edit, reorder or delete an entry
# that has shipped. Version numbers must be contiguous.
# ---------------------------------------------------------------------------
MIGRATIONS: List[MigrationStep] = [
    (1, "baseline_v5_schema", BASELINE_SCHEMA),
    (
        2,
        "mcp_trust_state_and_audit_trace",
        """
        ALTER TABLE mcp_servers ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'UNVERIFIED';
        ALTER TABLE mcp_servers ADD COLUMN tools_hash TEXT;
        ALTER TABLE registry_events ADD COLUMN trace_id TEXT;
        """,
    ),
]

LATEST_VERSION = MIGRATIONS[-1][0] if MIGRATIONS else 0


class MigrationError(RuntimeError):
    """Raised when the database schema cannot be brought to the expected version."""


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    return row is not None


def current_version(conn: sqlite3.Connection) -> int:
    """Return the recorded schema version, 0 for a fresh (or unstamped) database."""
    if not _table_exists(conn, "schema_migrations"):
        return 0
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return int(row[0] or 0) if row else 0


def _stamp(conn: sqlite3.Connection, version: int, name: str) -> None:
    conn.execute(
        "INSERT INTO schema_migrations(version, name, applied_at) VALUES(?,?," "STRFTIME('%Y-%m-%dT%H:%M:%fZ','now'))",
        (version, name),
    )


def migrate(conn: sqlite3.Connection) -> int:
    """Bring ``conn`` up to ``LATEST_VERSION``. Returns the resulting version.

    - Fresh database: applies all migrations in order.
    - Pre-migration database (schema present, no version table): stamps
      version 1 first, then applies anything newer.
    - Runs each migration in its own transaction; a failed step rolls back
      and raises ``MigrationError``.
    """
    applied = 0
    # Version bookkeeping table (kept outside MIGRATIONS so it always exists).
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    conn.commit()

    version = current_version(conn)

    # Legacy database created before the migration mechanism: the baseline
    # schema already exists. Stamp it as version 1 instead of "re-creating".
    if version == 0 and _table_exists(conn, "mcp_servers"):
        _stamp(conn, 1, "stamped_from_pre_migration_database")
        conn.commit()
        version = 1

    for step_version, name, sql in MIGRATIONS:
        if step_version <= version:
            continue
        if step_version != version + 1:
            raise MigrationError(f"Migration gap: expected version {version + 1}, found {step_version} ({name})")
        try:
            conn.execute("BEGIN")
            for stmt in sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    conn.execute(stmt)
            _stamp(conn, step_version, name)
            conn.commit()
        except Exception as exc:  # pragma: no cover - defensive path
            conn.rollback()
            raise MigrationError(f"Migration {step_version} ({name}) failed: {exc}") from exc
        version = step_version
        applied += 1

    if version != LATEST_VERSION:
        raise MigrationError(f"Schema version {version} != expected {LATEST_VERSION}")
    return version


def versions_applied(conn: sqlite3.Connection) -> Sequence[sqlite3.Row]:
    return conn.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version").fetchall()


def integrity_ok(conn: sqlite3.Connection, full: bool = False) -> Tuple[bool, str]:
    """Run PRAGMA quick_check (or integrity_check). Returns (ok, message)."""
    pragma = "integrity_check" if full else "quick_check"
    rows = conn.execute(f"PRAGMA {pragma}").fetchall()
    messages = [r[0] for r in rows]
    ok = messages == ["ok"]
    return ok, "; ".join(messages)


__all__ = [
    "MIGRATIONS",
    "LATEST_VERSION",
    "MigrationError",
    "migrate",
    "current_version",
    "versions_applied",
    "integrity_ok",
]
