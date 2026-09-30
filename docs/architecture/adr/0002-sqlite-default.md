# ADR-0002: SQLite as the default database with a versioned migration mechanism

- Status: Accepted
- Date: 2026-09-30

## Context

The deployment target is a single low-maintenance node. Job metadata, results, registry and audit events are modest in volume. Introducing a database server adds operational cost without benefit at this scale. However, the original code created its schema via ad-hoc `CREATE TABLE IF NOT EXISTS` at every startup, with no versioning — unpredictable and unmaintainable.

## Decision

1. SQLite remains the default and only shipped database (WAL mode, `foreign_keys=ON`, `busy_timeout=10000`).
2. All schema changes go through ordered, versioned migrations in `core/migrations.py`, recorded in a `schema_migrations` table. Ad-hoc DDL at startup is forbidden.
3. Pre-migration databases are stamped as version 1 (baseline) — no silent recreation.
4. All SQL lives behind `core/db.py` (single storage interface), so PostgreSQL can be added later as an alternate backend without touching callers. PostgreSQL is *not* shipped now.

## Consequences

- Backups must be WAL-aware: use the SQLite Online Backup API (`core/maintenance.backup_database`), never a raw file copy.
- Migration tests (`tests/test_database_baseline.py`) enforce contiguity, idempotency and legacy stamping.
- A PostgreSQL backend, when needed, only requires a new implementation of the `Database` interface plus a migration set.
