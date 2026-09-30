# Phase 1 Result — Enterprise Repository Baseline

Branch: `hardening/enterprise-foundation` (from `main` @ `b48d204`)

## FILES CHANGED

**Added (39)**
- `docs/audit/ENTERPRISE_BASELINE.md` — 20-area audit with severity classifications (0 CRITICAL, 4 HIGH, 16 MEDIUM)
- `docs/architecture/ARCHITECTURE.md`, `COMPONENTS.md`, `DATA_FLOW.md`
- `docs/architecture/adr/0001-control-evidence-separation.md` … `0005-fail-closed-pack-validation.md` (5 ADRs)
- `docs/security/TRUST_BOUNDARIES.md`, `THREAT_MODEL.md`, `AI_EVIDENCE_BOUNDARY.md`
- `docs/operations/RUNBOOK.md`, `BACKUP_RESTORE.md`
- `docs/deployment/PRODUCTION.md`
- `core/migrations.py` — versioned migration mechanism (schema_migrations table, ordered append-only steps, legacy stamping)
- `tests/test_database_baseline.py` — bootstrap, migration, backup→restore→integrity, production-rejection gates (19 tests)
- `.github/workflows/ci.yml`, `.github/dependabot.yml`, `.github/CODEOWNERS`, `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md`
- `.pre-commit-config.yaml`, `.secrets.baseline`, `Makefile`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE-TODO.md`, `CODE_OF_CONDUCT.md`, `.editorconfig`, `.gitattributes`, `.dockerignore`

**Changed (5)**
- `core/db.py` — schema now applied via `core/migrations.migrate()`; `PRAGMA busy_timeout=10000`; `schema_version()` accessors
- `core/maintenance.py` — `backup_database()` uses the SQLite Online Backup API (WAL-consistent, was `shutil.copy2` on live file); added `verify_backup()`, `database_integrity_check()`
- `core/config.py` — production/staging now also rejects dev/placeholder API keys and memory-only `DATABASE_PATH` (fail-closed)
- `README.md` — updated moved-doc links, added repository-structure and dev-commands sections
- `.gitignore` — Poetry/scratch additions

**Moved (12) — content unchanged, only path**
- `FINAL_VERDICT.md`, `RELEASE_CHECKS.txt`, `SUMMARY.txt`, `docs/V4-TO-V5-MIGRATION.md` → `docs/archive/v4/`
- `docs/legacy-v4/*` (5 files) → `docs/archive/v4/legacy-v4/`
- `docs/{GOOGLE-AI-STUDIO,MCP-MANAGER,PACK-REGISTRY}.md` → `docs/architecture/`
- `docs/SECURITY-BOUNDARIES.md` → `docs/security/`

No file was deleted outright; every move was reference-checked first (no runtime, test or script references to the old paths — only two README links, updated).

## ARCHITECTURE CHANGES
- The three planes (CONTROL / EVIDENCE / INTELLIGENCE) are now explicit, documented architecture with enforcement points, component inventory and data-flow diagrams.
- **No behavioral change to forensic logic.** Fail-closed semantics, AI≠EVIDENCE, vault, signing, workers and pack registry are untouched except where noted under SECURITY CHANGES. All existing tools, routes, schemas and models preserved.
- Database schema is now migration-managed (ADR-0002). `init_schema()` semantics preserved for existing databases: a v5 database without a version table is stamped as version 1, data intact (verified by an offline harness and automated tests).

## SECURITY CHANGES
- **Backup integrity (audit D-2, HIGH — fixed):** live-file copies under WAL could be torn/lose data; now Online Backup API + verification helper.
- **Production hard-rejection (audit AU/AZ-related):** dev credentials (`dev-admin-key`, `dev-analyst-key`), placeholder keys (`CHANGE_ME…`), weak secrets and `DATABASE_PATH=:memory:` are refused at startup in production/staging.
- **CI + supply chain (audit TE-1/CI-1/SC-1/SC-2, HIGH — fixed):** CI gate identical to `make verify`; Dependabot (pip/actions/docker); pre-commit with ruff, YAML/whitespace/EOF checks, large-file protection (evidence must never enter the repo) and detect-secrets with forensic-path exclusions.
- `security_scan.py` still reports **0 findings**; introduced no new `CHANGE_ME`-class literals (the new config rejection logic uses lowercase `change_me` substring semantics, kept scan-clean).

## TESTS EXECUTED (this environment)

| Check | Command | Result |
|---|---|---|
| Byte-compilation, all packages + tests | `python3 -m compileall -q core packs workers tests scripts` | **PASS** (exit 0) |
| Migrations offline harness (fresh bootstrap, idempotency, legacy stamping, gap rejection, integrity) | stdlib-only driver over `core/migrations.py` | **PASS** (all assertions green) |
| Production-rejection logic presence (placeholder keys, dev keys, memory-only DB in validator AST) | source inspection | **PASS** |
| Security scan | `python3 scripts/security_scan.py` | **PASS — 0 findings** |
| JSON validity (baseline, pack manifest) | `json.load` | **PASS** |
| Makefile tab indentation | `grep -Pn '^\t'` | **PASS** |

**NOT executed here** (sandbox forbids package installation, so third-party tooling is unavailable): `poetry lock`, `poetry install`, `ruff check`, `ruff format --check`, `mypy core`, `pytest -q`. CI (`.github/workflows/ci.yml`) runs exactly these and is the authoritative gate. Nothing is reported as PASS without execution.

## EXIT CODES
- `compileall`: 0
- migrations offline harness: 0 (all asserts passed)
- `scripts/security_scan.py`: 0 (0 findings)
- AST verification snippets: 0
- All other gates: **NOT RUN in this environment** (see above) — CI must confirm.

## KNOWN LIMITATIONS
1. `poetry.lock` is not committed (see NOT VERIFIED). CI generates it in-job until a maintainer runs `make lock` and commits it.
2. `.secrets.baseline` is a valid empty placeholder that must be regenerated with a real detect-secrets run.
3. The pre-commit config pins remote hook revisions (ruff-pre-commit v0.6.9, pre-commit-hooks v5.0.0, detect-secrets v1.5.0) that were not executable here.
4. Audit findings not addressed by design in this phase: AZ-1 (persisted case ACL — authz still in-memory, fail-closed), R-1 (SSRF egress allowlist), AL-1 (audit tamper-evidence), P-1 (pack adapters are in-process trusted code), DS-1 (Dockerfile dependency ranges until lockfile-based build). These are tracked in `ENTERPRISE_BASELINE.md` as the next-phase backlog; none was papered over.
5. Python stays 3.11 (no 3.12 migration — no functional need, no verified benefit; audit DE-3 INFO).

## NOT VERIFIED
- Full pytest suite (incl. the 13 pre-existing test files) — requires installed dependencies; CI gate.
- `ruff` / `mypy` cleanliness of new files.
- `poetry lock`/`poetry install` reproducibility on a clean checkout (dependency: network + poetry).
- YAML files (`ci.yml`, `dependabot.yml`, `.pre-commit-config.yaml`) validated only by inspection, not by a YAML parser.
- Docker build (`make docker-build`) — no Docker daemon in the audit environment.
- GitHub Actions workflow execution — first run on the branch must be observed.

## NEXT PHASE
1. **Green CI:** run the branch's CI; fix any ruff/mypy/pytest finding it surfaces; commit the generated `poetry.lock` (closes audit DE-1/TE-1/CI-1).
2. Address HIGH/MEDIUM backlog by priority: AZ-1 persisted case ACL (new migration), R-1 registry egress allowlist, AL-1 audit tamper-evidence.
3. Decide the license (LICENSE-TODO.md) and set branch protection + required status checks on `main`.
4. Only after the baseline is fully green: production deployment (docs/deployment/PRODUCTION.md) and any release pipeline.
