# Changelog

Format: Keep a Changelog. Versioning: project version stays `5.0.0` until the enterprise baseline ships a tagged release.

## [Unreleased] — Enterprise baseline (branch `hardening/enterprise-foundation`)

### Added
- Versioned SQLite migration mechanism (`core/migrations.py`, `schema_migrations` table); legacy databases are stamped, not recreated (ADR-0002).
- WAL-consistent database backups via the SQLite Online Backup API; `verify_backup()` and `database_integrity_check()` helpers (fixes unsafe raw file copy).
- Production configuration hard-rejection: development/placeholder API keys, placeholder secrets, and memory-only `DATABASE_PATH` are refused at startup.
- `tests/test_database_baseline.py`: clean bootstrap, migration ordering/stamping/idempotency, backup→restore→integrity round-trip, production-rejection and fail-closed pack digest gates.
- Repository baseline: `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE-TODO.md`, `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitattributes`, `.dockerignore`, `Makefile`, `.pre-commit-config.yaml`.
- Documentation set: three-plane architecture, components, data flow, ADRs 0001–0005, trust boundaries, threat model, AI≠EVIDENCE boundary, runbook, backup/restore, production deployment.
- CI workflow (lint + typecheck + tests, CI-equivalent of `make verify`), Dependabot config, CODEOWNERS, issue templates.

### Changed
- Repository layout normalized: historical v4 artifacts moved to `docs/archive/v4/`; docs organized into `architecture/`, `security/`, `operations/`, `deployment/`, `audit/`. README links updated.
- `core/db.py` now applies schema through migrations only; `PRAGMA busy_timeout=10000` added.

### Fixed
- Backups of a WAL-active database could be torn/miss WAL-resident data (`shutil.copy2` → Online Backup API).

### Known limitations
- `poetry.lock` not yet committed (audit DE-1): see `docs/audit/PHASE1_RESULT.md` → NOT VERIFIED.
