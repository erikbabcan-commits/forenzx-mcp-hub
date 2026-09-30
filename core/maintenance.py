"""Allowlisted local maintenance helpers. No browser-controlled shell execution."""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.config import config
from core.db import db
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
    config.backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = config.backups_dir / f"forenzx-{stamp}.db"
    if config.database_path.exists():
        shutil.copy2(config.database_path, target)
    else:
        target.touch()
    return target


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
    rows = db.fetchall("SELECT id,name,server_type,url,transport,enabled,auth_type,custom_headers_json,tags_json,notes,maintenance_url,created_at,updated_at,last_status FROM mcp_servers ORDER BY name")
    for row in rows:
        row["custom_headers"] = json.loads(row.pop("custom_headers_json") or "{}")
        row["tags"] = json.loads(row.pop("tags_json") or "[]")
        row["enabled"] = bool(row["enabled"])
        row["has_secret"] = row["auth_type"] != "none"
    return {"version": 1, "exported_at": datetime.now(timezone.utc).isoformat(), "servers": rows, "secrets_included": False}
