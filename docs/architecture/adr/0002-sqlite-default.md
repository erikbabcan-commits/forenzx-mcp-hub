# ADR-0002: SQLite as the default database

## Status
Accepted (Phase 1)

## Context
The platform targets low-maintenance single-node deployment. Job state,
registry, audit events, and metadata need durable, transactional storage
with referential integrity. Earlier revisions modified the schema with
ad-hoc DDL at startup, which made production state unpredictable.

## Decision
SQLite remains the default database, hardened with PRAGMA
foreign_keys=ON, WAL mode, and busy_timeout=10000 on every connection.
The schema is versioned via an explicit migration list
(core/migrations.py); runtime code performs no ad-hoc CREATE/ALTER.
Backups use the SQLite online backup API with SHA-256 manifests. A
storage-level abstraction keeps a future PostgreSQL backend possible
without making PostgreSQL a required dependency now.

## Consequences
- Zero database administration for single-VPS operation.
- Migration tests and a backup→restore→integrity test are mandatory gates.
- Write concurrency is bounded by a single writer; acceptable for the
  single-node target.
- PostgreSQL migration later requires moving off SQLite-specific backup
  tooling (documented in Phase 2 backlog).

## Alternatives
- PostgreSQL now: rejected — mandatory operational dependency for the whole
  user base while the workload does not need it.
- Keep ad-hoc startup DDL: rejected — unverifiable production schema.
- TinyDB/JSON files: rejected — no transactions, no referential integrity.
