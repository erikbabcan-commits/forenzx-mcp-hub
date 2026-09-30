"""Allowlisted local maintenance helpers. No browser-controlled shell execution."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.config import config
from core.db import db, utcnow
from core.pack_registry import pack_registry


def system_summary() -> dict:
    servers = db.fetchone("SELECT COUNT(*) AS c FROM mcp_servers") or {"c": 0}
    ready = db.fetchone("SELECT COUNT(*) AS c FROM mcp_servers WHERE last_status='READY'") or {"c": 0}
    jobs = db.fetchone("SELECT COUNT(*) AS c FROM jobs") or {"c": 0}
    failed = db.fetchone("SELECT COUNT(*) AS c FROM jobs WHERE state='FAILED'") or {"c": 0}
    db_size = config.database_path.stat().st_size if config.database_path.exists() else 0
    return {
        "database_bytes": db_size,
        "mcp_servers": servers["c"],
        "mcp_ready": ready["c"],
        "jobs": jobs["c"],
        "failed_jobs": failed["c"],
        "packs": len(pack_registry.list_packs()),
        "pack_errors": pack_registry.errors(),
    }


def backup_database() -> Path:
    """Create a consistent snapshot via the SQLite Online Backup API.

    WAL-safe: unlike a raw file copy, the backup takes a consistent picture of
    the database including WAL-resident pages while live writers continue.
    Writes a sidecar manifest (``<name>.manifest.json``) with SHA-256, size,
    schema version and source metadata. Raises on missing/in-memory sources.
    """
    source_path = config.database_path
    if str(source_path) == ":memory:" or str(source_path).startswith("file::memory:"):
        raise ValueError("Cannot back up an in-memory database; configure a persistent DATABASE_PATH.")
    if not Path(source_path).exists():
        raise FileNotFoundError(f"Database not found: {source_path}")

    config.backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = config.backups_dir / f"forenzx-{stamp}.db"

    src = sqlite3.connect(str(source_path))
    dst = sqlite3.connect(str(target))
    try:
        src.backup(dst)  # consistent, WAL-aware snapshot
    finally:
        dst.close()
        src.close()

    # Integrity-verified manifest with SHA-256 (see docs/operations/BACKUP_RESTORE.md)
    sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    version_row = None
    vconn = sqlite3.connect(str(target))
    try:
        version_row = vconn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    except sqlite3.OperationalError:
        version_row = None
    finally:
        vconn.close()
    manifest = {
        "file": target.name,
        "sha256": sha256,
        "size_bytes": target.stat().st_size,
        "schema_version": int(version_row[0] or 0) if version_row else 0,
        "created_at": utcnow(),
        "source_database": str(source_path),
        "tool": "sqlite3-online-backup-api",
    }
    (config.backups_dir / f"{target.name}.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return target


def read_backup_manifest(backup_path: Path) -> dict:
    """Load and check the manifest of a backup (missing manifest => error)."""
    manifest_path = Path(str(backup_path) + ".manifest.json")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Backup manifest not found: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not Path(backup_path).exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")
    actual = hashlib.sha256(Path(backup_path).read_bytes()).hexdigest()
    manifest["sha256_matches"] = actual == manifest.get("sha256")
    return manifest


def verify_backup(backup_path: Path) -> dict:
    """Open a backup read-only and run a quick integrity check on it."""
    if not Path(backup_path).exists():
        raise FileNotFoundError(f"Backup not found: {backup_path}")
    conn = sqlite3.connect(f"file:{Path(backup_path)}?mode=ro", uri=True)
    try:
        rows = conn.execute("PRAGMA quick_check").fetchall()
        ok = [r[0] for r in rows] == ["ok"]
        version_row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return {
            "ok": ok,
            "integrity": [r[0] for r in rows],
            "schema_version": int(version_row[0] or 0) if version_row else 0,
        }
    finally:
        conn.close()


def database_integrity_check(full: bool = False) -> dict:
    """Run quick_check (or full integrity_check) on the live database."""
    from core.migrations import integrity_ok

    with db.connect() as conn:
        ok, message = integrity_ok(conn, full=full)
    return {"ok": ok, "check": "integrity_check" if full else "quick_check", "result": message}


def vacuum_database() -> None:
    with db.connect() as conn:
        conn.execute("VACUUM")


def prune_events(days: int | None = None) -> int:
    keep = days if days is not None else config.maintenance_event_retention_days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, keep))).isoformat()
    before = db.fetchone("SELECT COUNT(*) AS c FROM registry_events WHERE ts < ?", (cutoff,)) or {"c": 0}
    db.execute("DELETE FROM registry_events WHERE ts < ?", (cutoff,))
    return int(before["c"])


def export_registry() -> dict:
    rows = db.fetchall(
        "SELECT id,name,server_type,url,transport,enabled,auth_type,custom_headers_json,tags_json,notes,maintenance_url,created_at,updated_at,last_status FROM mcp_servers ORDER BY name"
    )
    for row in rows:
        row["custom_headers"] = json.loads(row.pop("custom_headers_json") or "{}")
        row["tags"] = json.loads(row.pop("tags_json") or "[]")
        row["enabled"] = bool(row["enabled"])
        row["has_secret"] = row["auth_type"] != "none"
    return {
        "version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "servers": rows,
        "secrets_included": False,
    }
