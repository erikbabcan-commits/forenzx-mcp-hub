"""Enterprise baseline tests: DB bootstrap, migrations, backup/restore, production hard-rejection.

These tests protect the repository-baseline invariants:
- a clean checkout bootstraps a fully-versioned database,
- migrations are ordered, idempotent on re-run and stamp legacy databases,
- backups are consistent, restorable and pass integrity checks,
- production configuration rejects development credentials, placeholder secrets,
  memory-only persistence, and invalid forensic pack digests (fail-closed).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from core.config import AppConfig
from core.db import Database
from core.migrations import LATEST_VERSION, MIGRATIONS, MigrationError, migrate
from core.pack_registry import PackRegistry

# --------------------------------------------------------------------------- #
# 1. Clean database bootstrap
# --------------------------------------------------------------------------- #


class TestCleanBootstrap:
    def test_fresh_database_gets_full_versioned_schema(self, tmp_path):
        database = Database(path=tmp_path / "fresh.db")
        assert database.schema_version() == LATEST_VERSION
        with database.connect() as conn:
            tables = {
                r["name"]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
        for expected in ("mcp_servers", "pack_overrides", "registry_events", "jobs", "job_results", "schema_migrations"):
            assert expected in tables

    def test_connect_enables_sqlite_hardening_pragmas(self, tmp_path):
        database = Database(path=tmp_path / "pragmas.db")
        with database.connect() as conn:
            assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 10000

    def test_foreign_key_enforcement_is_real_not_decorative(self, tmp_path):
        database = Database(path=tmp_path / "fk.db")
        with pytest.raises(sqlite3.IntegrityError):
            with database.connect() as conn:
                conn.execute(
                    "INSERT INTO job_results(job_id,result_json,created_at) VALUES(?,?,?)",
                    ("nonexistent-job", "{}", "2026-01-01T00:00:00+00:00"),
                )

    def test_bootstrap_is_idempotent(self, tmp_path):
        database = Database(path=tmp_path / "idem.db")
        first = database.schema_version()
        database.init_schema()  # re-run must not duplicate or fail
        assert database.schema_version() == first == LATEST_VERSION


# --------------------------------------------------------------------------- #
# 2. Migrations
# --------------------------------------------------------------------------- #


class TestMigrations:
    def test_migrations_have_contiguous_versions(self):
        versions = [v for v, _, _ in MIGRATIONS]
        assert versions == sorted(versions)
        assert versions == list(range(1, len(versions) + 1))

    def test_migration_gap_is_rejected(self, tmp_path):
        path = tmp_path / "gap.db"
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO schema_migrations VALUES(7,'bogus','now')")
        conn.commit()
        with pytest.raises(MigrationError):
            migrate(conn)
        conn.close()

    def test_legacy_pre_migration_database_is_stamped_not_recreated(self, tmp_path):
        """A v5 database created before the migration mechanism keeps its data."""
        path = tmp_path / "legacy.db"
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        # Recreate the pre-migration world: schema without schema_migrations.
        from core.migrations import BASELINE_SCHEMA

        conn.executescript(BASELINE_SCHEMA)
        conn.execute(
            "INSERT INTO jobs(job_id,case_id,evidence_id,pack_id,state,progress_percent,current_stage,"
            "started_at,updated_at,error_message,owner_id,organization_id,spec_json,idempotency_key) "
            "VALUES('legacy-job','CASE-OLD','EVD-OLD','pack','COMPLETED',100,'COMPLETED',"
            "'2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00',NULL,'legacy','org','{}',NULL)"
        )
        conn.commit()
        migrate(conn)
        version = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
        assert version == LATEST_VERSION
        rows = conn.execute("SELECT job_id FROM jobs").fetchall()
        assert [r["job_id"] for r in rows] == ["legacy-job"]
        conn.close()

    def test_database_class_reports_version(self, tmp_path):
        database = Database(path=tmp_path / "version.db")
        assert database.schema_version() == database.expected_schema_version() == LATEST_VERSION


# --------------------------------------------------------------------------- #
# 3. Backup → restore → integrity
# --------------------------------------------------------------------------- #


class TestBackupRestoreIntegrity:
    def _seed_job(self, database: Database, job_id: str) -> None:
        with database.connect() as conn:
            conn.execute(
                "INSERT INTO jobs(job_id,case_id,evidence_id,pack_id,state,progress_percent,current_stage,"
                "started_at,updated_at,error_message,owner_id,organization_id,spec_json,idempotency_key) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (job_id, "CASE-1", "EVD-1", "mobile_compromise", "COMPLETED", 100, "COMPLETED",
                 "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", None,
                 "analyst", "org", json.dumps({"job_id": job_id}), None),
            )

    def test_backup_restore_roundtrip_preserves_data_and_integrity(self, tmp_path, monkeypatch):
        from core import maintenance

        db_path = tmp_path / "live" / "forenzx.db"
        backups_dir = tmp_path / "backups"
        database = Database(path=db_path)
        self._seed_job(database, "job-1")

        monkeypatch.setattr(maintenance.config, "backups_dir", backups_dir)
        # maintenance.backup_database prefers db.path (test-isolated) when it differs
        monkeypatch.setattr(maintenance.config, "database_path", db_path)

        backup = maintenance.backup_database()
        assert backup.exists() and backup.parent == backups_dir

        report = maintenance.verify_backup(backup)
        assert report["ok"] is True, report
        assert report["schema_version"] == LATEST_VERSION

        # Restore into a new location and verify data + integrity.
        restored = tmp_path / "restored.db"
        restored.write_bytes(backup.read_bytes())
        restored_db = Database(path=restored)
        row = restored_db.fetchone("SELECT job_id, state FROM jobs WHERE job_id=?", ("job-1",))
        assert row == {"job_id": "job-1", "state": "COMPLETED"}
        with restored_db.connect() as conn:
            result = conn.execute("PRAGMA quick_check").fetchone()[0]
        assert result == "ok"

    def test_backup_of_wal_active_database_is_consistent(self, tmp_path, monkeypatch):
        """Backup while WAL contains uncommitted-to-main-file data must still contain it."""
        from core import maintenance

        db_path = tmp_path / "wal" / "forenzx.db"
        database = Database(path=db_path)
        self._seed_job(database, "wal-job")
        # WAL checkpointing is lazy; rows above can live in the -wal file only.
        monkeypatch.setattr(maintenance.config, "backups_dir", tmp_path / "backups")
        monkeypatch.setattr(maintenance.config, "database_path", db_path)
        backup = maintenance.backup_database()
        report = maintenance.verify_backup(backup)
        assert report["ok"] is True
        conn = sqlite3.connect(str(backup))
        try:
            count = conn.execute("SELECT COUNT(*) FROM jobs WHERE job_id='wal-job'").fetchone()[0]
        finally:
            conn.close()
        assert count == 1

    def test_backup_rejects_memory_database(self, monkeypatch):
        from core import maintenance

        monkeypatch.setattr(maintenance.config, "backups_dir", Path("/tmp"))
        monkeypatch.setattr(maintenance.config, "database_path", Path(":memory:"))
        with pytest.raises(ValueError, match="memory"):
            maintenance.backup_database()

    def test_live_database_integrity_check_helper(self, tmp_path):
        from core import maintenance

        database = Database(path=tmp_path / "ic.db")
        self._seed_job(database, "ic-job")
        report = maintenance.database_integrity_check()
        assert report["ok"] is True


# --------------------------------------------------------------------------- #
# 4. Production environment hard rejection (fail-closed)
# --------------------------------------------------------------------------- #


class TestProductionRejection:
    VALID = dict(
        environment="production",
        jwt_secret_key="x" * 40,
        server_hmac_signing_key="y" * 40,
        api_keys=["prod-analyst-key-0123456789abcdef"],
        admin_api_keys=["prod-admin-key-0123456789abcdef"],
    )

    def test_production_accepts_valid_configuration(self, tmp_path):
        cfg = AppConfig(**self.VALID, database_path=tmp_path / "prod" / "forenzx.db", data_dir=tmp_path / "prod")
        assert cfg.environment == "production"

    def test_production_rejects_development_credentials(self, tmp_path):
        with pytest.raises(ValueError, match="API keys"):
            AppConfig(
                **{**self.VALID, "admin_api_keys": ["dev-admin-key"], "api_keys": ["dev-analyst-key"]},
                database_path=tmp_path / "prod" / "forenzx.db",
                data_dir=tmp_path / "prod",
            )

    def test_production_rejects_placeholder_secrets(self, tmp_path):
        with pytest.raises(ValueError, match="strong secret"):
            AppConfig(
                **{**self.VALID, "jwt_secret_key": "CHANGE_ME_WITH_AT_LEAST_32_RANDOM_CHARACTERS"},
                database_path=tmp_path / "prod" / "forenzx.db",
                data_dir=tmp_path / "prod",
            )

    def test_production_rejects_memory_only_persistence(self, tmp_path):
        with pytest.raises(ValueError, match="memory-only"):
            AppConfig(
                **self.VALID,
                database_path=":memory:",
                data_dir=tmp_path / "prod",
            )

    def test_production_rejects_placeholder_api_keys(self, tmp_path):
        with pytest.raises(ValueError, match="API keys"):
            AppConfig(
                **{**self.VALID, "admin_api_keys": ["CHANGE_ME_ADMIN_KEY"]},
                database_path=tmp_path / "prod" / "forenzx.db",
                data_dir=tmp_path / "prod",
            )


class TestFailClosedPackDigest:
    def test_production_pack_with_invalid_digest_is_disabled(self, tmp_path):
        """A placeholder/invalid pack digest must never yield an enabled pack."""
        pack_dir = tmp_path / "packs" / "bogus_pack"
        pack_dir.mkdir(parents=True)
        manifest = {
            "id": "bogus_pack",
            "name": "Bogus",
            "version": "1.0.0",
            "description": "test pack",
            "supported_inputs": ["file_generic"],
            "capabilities": [],
            "container_image": "example.invalid/img",
            "pinned_image_digest": "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "enabled": True,
        }
        (pack_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        registry = PackRegistry(packs_dir=tmp_path / "packs")
        registry.load_packs()
        assert registry.get_pack("bogus_pack") is None, "placeholder digest MUST fail closed"
        assert "bogus_pack" in registry.errors()
