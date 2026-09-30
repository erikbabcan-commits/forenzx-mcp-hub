# Changelog

All notable changes to ForenZX MCP Hub are documented here.
Format based on Keep a Changelog; project uses no version tags yet.

## [Unreleased] — Phase 1: Enterprise Foundation

### Added
- Versioned database migrations (`core/migrations.py`); schema version 2 adds
  `mcp_servers.trust_state`, `mcp_servers.tools_hash`,
  `registry_events.trace_id`. Ad-hoc startup DDL removed from runtime code.
- Migration test, database bootstrap test, backup→restore→integrity test,
  production config rejection test, restart-recovery test, MCP trust-model
  tests, invalid-digest fail-closed test.
- Backups now produce a sidecar manifest (SHA-256, size, schema version,
  timestamp, source) plus `verify_backup()` and
  `database_integrity_check()` maintenance primitives.
- Remote MCP trust model: servers default to `UNVERIFIED`; `HEALTHY != TRUSTED`;
  audited admin trust endpoint `PUT /api/v1/mcp-servers/{id}/trust`
  with `X-Trace-Id` support.
- Admin `Makefile` (`install/lint/format/typecheck/test/security/verify/...`),
  `.pre-commit-config.yaml`, `.editorconfig`, `.gitattributes`,
  `.dockerignore`, `.secrets.baseline`.
- GitHub Actions CI workflow, Dependabot, CODEOWNERS, issue templates.
- Documentation set: architecture (incl. ADRs 0001–0006), security (trust
  boundaries, threat model, AI/evidence boundary, audit model), operations
  (runbook, backup/restore), deployment, audit (baseline, Phase 2 backlog,
  Phase 1 result). Historical v4 documents moved to `docs/archive/v4/`.

### Changed
- Production configuration now rejects placeholder secrets, low-entropy
  secrets, and memory-only `DATABASE_PATH` (fail closed).
- SQLite connections now enforce `foreign_keys=ON`, WAL mode and
  `busy_timeout=10000`.
- Tests reorganized into `tests/{unit,integration,security,e2e}`.
- Repository layout normalized (`.github`, `core`, `packs`, `workers`,
  `tests`, `scripts`, `docs`).

### Fixed
- Jobs stuck in `RUNNING` after an unclean restart are now recovered as
  `FAILED` with `error_code=INTERRUPTED_BY_RESTART` (audited).
- Test fixtures replaced trivially weak secrets with high-entropy values
  now that entropy checks reject them.

### Known limitations
- See `docs/audit/PHASE1_RESULT.md` (NOT_VERIFIED items) and
  `docs/audit/PHASE2_BACKLOG.md` (open security work: SSRF, DNS rebinding,
  AEAD credential encryption, RBAC, audit hash chaining, supply-chain CI).

## Older versions

Pre-v5 history was not tracked in a changelog; see `docs/archive/v4/`.
