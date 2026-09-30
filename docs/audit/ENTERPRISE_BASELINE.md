# Enterprise Baseline Audit — ForenZX MCP Hub v5

> Audit state: baseline as imported from `forenzx-mcp-hub-v5.zip` (commit `b48d204`), branch `hardening/enterprise-foundation`.
> Scope: repository baseline quality (structure, reproducibility, security posture, documentation, CI). **No project score is given.**
> Method: full source read of all 63 files. Runtime verification was **not** possible in the audit sandbox (no package installation available) — see `PHASE1_RESULT.md` for what was actually executed vs. NOT_VERIFIED.

Classification legend: **CRITICAL** (must fix before production), **HIGH** (must fix in baseline phase), **MEDIUM** (should fix soon), **LOW** (nice to have), **INFO** (observation, no action).

---

## 1. Architecture

The codebase has a clean implicit layering: FastAPI app (`core/main.py`), MCP engine (`core/server.py`), registries (`core/mcp_registry.py`, `core/pack_registry.py`), job manager (`core/jobs.py`), vault (`core/vault.py`), and worker pool (`workers/pool.py`).

| ID | Severity | Finding |
|----|----------|---------|
| A-1 | **MEDIUM** | The three planes (CONTROL / EVIDENCE / INTELLIGENCE) exist in code but are not documented anywhere; there is no architecture document and no ADRs. New contributors cannot tell which invariants are deliberate. |
| A-2 | **INFO** | Single-process, single-node design. Fits the stated low-maintenance deployment goal; no Kubernetes introduced. |
| A-3 | **MEDIUM** | `DatabaseBackedCaseAccessProvider` (core/acl.py) is *not* database-backed — it uses in-memory dicts (see §3). The layer boundary is right, the implementation is misleading. |

## 2. Authentication

Two mechanisms: static API keys (`X-API-Key` / `Authorization: APIKey`) and JWT HS256 Bearer tokens. Production config validation rejects weak/placeholder secrets (<32 chars, `change_me`, `dev-secret`); dev defaults are auto-injected only outside production/staging. A dev bypass header (`X-Dev-Bypass: allowed`) is accepted only in `development`/`test` environments.

| ID | Severity | Finding |
|----|----------|---------|
| AU-1 | **MEDIUM** | API keys are compared with Python `in` against a list — not constant-time. Timing side channels are low practical risk here (network jitter), but `hmac.compare_digest` per-key is the correct pattern. |
| AU-2 | **MEDIUM** | JWT supports only HS256 with a single static secret; no `kid`, no rotation path, no JWKS endpoint (Ed25519 public key is published but JWTs are symmetric). |
| AU-3 | **LOW** | No rate limiting / brute-force protection on auth endpoints. |
| AU-4 | **INFO** | Dev bypass exists but is correctly environment-gated. |

## 3. Authorization

Case/job ACL with fail-closed semantics: unknown case/job ⇒ DENY; admin role bypasses; ownership or same-organization grants access. `CaseAccessController` raises 403 and logs `IDOR VIOLATION`.

| ID | Severity | Finding |
|----|----------|---------|
| AZ-1 | **HIGH** | ACL state is in-memory (`DatabaseBackedCaseAccessProvider._case_acl`). Jobs are re-registered from SQLite on restart (`AsyncJobManager._restore_acl_and_interruptions`), but **cases** are never persisted — in production only admin can access any case until a job for that case exists. Fail-closed (good) but the authz dataset is volatile and the class name is misleading. |
| AZ-2 | **MEDIUM** | No persisted case registration API exists (only dev-mode `_register_dev_cases`). |
| AZ-3 | **INFO** | Fail-closed invariant verified in code and covered by tests. |

## 4. MCP transport

Single `POST /mcp` (JSON-RPC 2.0 over HTTP), legacy `POST /mcp/jsonrpc` compatibility route with `Deprecation` header. Protocol-version header validation, method/name header-body mismatch checks, tools/list + tools/call.

| ID | Severity | Finding |
|----|----------|---------|
| T-1 | **INFO** | `initialize` is accepted for compatibility but sessions are stateless; acceptable for HTTP JSON-RPC. |
| T-2 | **LOW** | No request size limit beyond web server defaults; body parsed fully into memory. |
| T-3 | **INFO** | Errors mapped to JSON-RPC error codes; internal exceptions do not leak details (generic -32603). |

## 5. Remote MCP registry

CRUD + health probing + `tools/list` discovery + restart via maintenance URL. Custom header denylist (Host, Content-Length, …). Secrets encrypted at rest (Fernet, key derived from `SERVER_HMAC_SIGNING_KEY`) and never returned by the API (only `has_auth_secret` boolean). Registry export excludes secrets.

| ID | Severity | Finding |
|----|----------|---------|
| R-1 | **MEDIUM** | **SSRF surface**: an admin can register any URL and the hub will POST to it (probe). Private-range/internal endpoints are not blocked. Admin-only mitigates, but no egress allowlist exists. |
| R-2 | **LOW** | Fernet key is derived deterministically from the signing key (SHA-256) — acceptable, but rotating the signing key makes stored secrets undecryptable (documented in README, no automated migration). |
| R-3 | **INFO** | `follow_redirects=False` on outbound probes — good. |

## 6. Credentials management

| ID | Severity | Finding |
|----|----------|---------|
| C-1 | **INFO** | `.env.example` uses `CHANGE_ME_*` placeholders; production config validator rejects them; `scripts/first_run.sh` generates random values with `secrets` and `chmod 600`. Good baseline. |
| C-2 | **LOW** | No `.env` template validation tooling beyond startup validation. |

## 7. Database

SQLite with `foreign_keys=ON` and `journal_mode=WAL` per connection, `timeout=10` (busy timeout), FK cascade on `job_results`, unique partial index for idempotency.

| ID | Severity | Finding |
|----|----------|---------|
| D-1 | **HIGH** | **No versioned migrations.** Schema is created ad-hoc via `CREATE TABLE IF NOT EXISTS` at every startup (`Database.init_schema`). Future schema changes have no ordered, verifiable path; this violates the fail-closed/predictable baseline requirement. |
| D-2 | **HIGH** | `backup_database()` uses `shutil.copy2` on the **live** database file. Under WAL mode this can produce a backup that misses WAL-resident data or is torn. Should use the SQLite Online Backup API (`VACUUM INTO` / `sqlite3` backup). |
| D-3 | **MEDIUM** | No `PRAGMA quick_check`/`integrity_check` in maintenance/health path. |
| D-4 | **MEDIUM** | No migration/version table; two instances running different code versions can drift silently. |
| D-5 | **INFO** | Storage is isolated behind `core/db.py` (no raw sqlite3 usage elsewhere) — good precondition for a future PostgreSQL adapter. |

## 8. Job persistence

Durable job rows + results in SQLite; idempotency via unique partial index with race handling (`sqlite3.IntegrityError` retry). On restart, active jobs are honestly marked `FAILED / INTERRUPTED_BY_RESTART`. Progress updates are single-statement transactions.

| ID | Severity | Finding |
|----|----------|---------|
| J-1 | **INFO** | Honest restart semantics — no fake "still running" state. Good invariant, covered by tests. |
| J-2 | **LOW** | Each `execute()` opens a new connection per statement (`connect()` context manager per call) — acceptable at this scale, but transaction boundaries are per-statement only; multi-statement invariants (e.g. create-job + ACL registration) are not atomic. |

## 9. Forensic workers

`workers/pool.py` + `workers/isolation.py`: Docker sandbox with canonical RepoDigest verification (rejects short image IDs), `cap_drop=ALL`, `no-new-privileges`, `read_only` rootfs, `network_mode=none` default, mem/cpu/pids limits, noexec tmpfs, argv-list commands only (no shell). Pre-flight SHA-256/Merkle integrity + claimed-hash verification, post-execution re-check, chain-of-custody with breach detection, signed execution records (Ed25519).

| ID | Severity | Finding |
|----|----------|---------|
| W-1 | **MEDIUM** | Control plane and forensic execution share a host when Docker pack execution is enabled locally (docker.sock access). Compose deliberately does not mount the socket by default (good); separate worker host remains the production model. Documented, not enforced. |
| W-2 | **INFO** | Threat intel bundle loading is fail-closed in production (missing/corrupt ⇒ block), sample bundle only in dev/test. |
| W-3 | **LOW** | Container wait timeout handling cancels nothing at the Docker level on `asyncio.TimeoutError` before the generic `finally` cleanup — cleanup path exists but timeout leaves a running container until cleanup executes. |

## 10. Pack registry

Fail-closed loading: malformed manifest ⇒ pack disabled with error surfaced; placeholder digests (`1234567890abcdef…`, low-entropy) ⇒ disabled. Digest overrides persisted in SQLite; DB-backed override beats manifest edits.

| ID | Severity | Finding |
|----|----------|---------|
| P-1 | **MEDIUM** | Pack adapters are Python modules dynamically imported (`importlib`) **into the control-plane process**. A pack is therefore trusted code, not just data. The packs dir is a read-only mount, but the trust boundary should be documented and ideally adapters should eventually execute out-of-process. |
| P-2 | **INFO** | The shipped `mobile_compromise` manifest still contains the placeholder digest — intentionally, because the registry disables it at load time. This is the documented v5 behavior. |
| P-3 | **INFO** | Digest validation regex + entropy heuristic is a reasonable placeholder defense; a real RepoDigest is required to enable a pack. |

## 11. Docker security

Compose: `read_only`, `cap_drop: ALL`, `no-new-privileges`, non-root user, noexec tmpfs, no docker.sock by default, healthcheck. Dockerfile: non-root `forenzx` user, slim base, `PYTHONDONTWRITEBYTECODE`.

| ID | Severity | Finding |
|----|----------|---------|
| DS-1 | **MEDIUM** | Dockerfile installs dependencies with hand-maintained pip ranges that duplicate `pyproject.toml` — drift risk; no lockfile-based reproducible image build. |
| DS-2 | **LOW** | No resource limits (`mem_limit`, `cpus`) on the compose service itself. |
| DS-3 | **INFO** | Base image `python:3.11-slim` is a floating tag, not digest-pinned (control plane). Worker images are digest-pinned (good). |

## 12. Dashboard

Static HTML/JS/CSS served from `core/dashboard/`, strict CSP (`default-src 'self'`, no inline scripts), `X-Frame-Options: DENY`, nosniff, no-referrer, Permissions-Policy locked down, HSTS in production. All mutating APIs require admin key; dashboard never receives stored secrets.

| ID | Severity | Finding |
|----|----------|---------|
| DA-1 | **LOW** | `/dashboard` HTML itself is served without authentication (only the APIs require keys). Only operational metadata is exposed after login via API; acceptable but worth documenting. |
| DA-2 | **INFO** | No arbitrary shell console in dashboard — allowlisted maintenance actions only. Good. |

## 13. Audit logging

Structured JSON logs (`core/utils/logger.py`) with user/case/job context fields; `registry_events` table records registry changes, probes, pack and maintenance actions with actor + details. Pruning endpoint with retention (default 30 days).

| ID | Severity | Finding |
|----|----------|---------|
| AL-1 | **MEDIUM** | Audit events are prunable by the same admin role that performs the audited actions; no tamper-evidence (signing covers execution records, not audit events). |
| AL-2 | **LOW** | `registry_events` has no case/evidence correlation column for job-level forensics; job history is in `jobs` table separately. |

## 14. Signing

Persistent Ed25519 key (PEM on disk, `chmod 600`), key id derived from public key hash, signature + public key published via `/api/keys` and embedded in results.

| ID | Severity | Finding |
|----|----------|---------|
| S-1 | **MEDIUM** | Private key stored unencrypted (no passphrase, PKCS8 NoEncryption) in the data dir. Acceptable for a single-node sealed volume if documented; no HSM/KMS abstraction. |
| S-2 | **INFO** | `verify()` exists and is exercised by tests; execution records are independently verifiable. |

## 15. Tests

13 test files (~2,500 lines): auth, ACL, CORS, docker, execution records, jobs, MCP, MVT pack, pack registry, regression gates, threat intel, vault, hub. Regression gates explicitly verify invariants (fail-closed, AI≠evidence, integrity breach detection). `scripts/verify_import_matrix.py` isolates module imports.

| ID | Severity | Finding |
|----|----------|---------|
| TE-1 | **HIGH** | **No CI** — tests exist but nothing enforces them on push/PR. |
| TE-2 | **MEDIUM** | No database bootstrap/migration/backup-restore tests (the DB layer had no migration mechanism to test). |
| TE-3 | **LOW** | Docker-dependent tests require a daemon; skipping them must never be reported as pass (project already documents this rule). |
| TE-4 | **INFO** | `pytest.ini` sets `asyncio_mode = auto` and verbose output — fine for local, noisy for CI (CI may override `-p no:cacheprovider -q`). |

## 16. Dependencies

Poetry `pyproject.toml` with caret ranges; dev group with pytest/ruff/mypy; ruff + mypy configured.

| ID | Severity | Finding |
|----|----------|---------|
| DE-1 | **HIGH** | **No lockfile** (`poetry.lock` absent). Clean checkouts cannot reproduce the exact dependency set. |
| DE-2 | **MEDIUM** | Caret ranges (`^0.110.0`) allow minor-level drift even with a lockfile discipline in place; acceptable once a lockfile exists and CI enforces `poetry check --lock`. |
| DE-3 | **INFO** | Python `^3.11`; code uses no 3.12-only features. Migration to 3.12 is not required — defer until a dependency or feature demands it. |

## 17. Deployment

Single-node docker-compose (intentional, matches goal). HTTPS termination delegated to a fronting proxy (documented). `/data` named volume for persistence.

| ID | Severity | Finding |
|----|----------|---------|
| DP-1 | **LOW** | No example reverse-proxy/TLS configuration shipped. |
| DP-2 | **INFO** | `restart: unless-stopped`, healthcheck, read-only filesystem — appropriate for a single VPS. |

## 18. Documentation

README is strong (setup, endpoints, digest policy, verification gates). But: root contains one-time artifacts (`FINAL_VERDICT.md`, `RELEASE_CHECKS.txt`, `SUMMARY.txt`); docs are flat with a `legacy-v4/` subfolder; no SECURITY.md, CONTRIBUTING, CHANGELOG, LICENSE, architecture or operations docs.

| ID | Severity | Finding |
|----|----------|---------|
| DOC-1 | **MEDIUM** | No LICENSE — the project's legal status is undefined (pack manifest says MIT, but that is the pack's license, not the hub's). |
| DOC-2 | **MEDIUM** | No SECURITY.md (reporting policy), no threat model, no trust boundary documentation. |
| DOC-3 | **LOW** | Root layout cluttered with one-time release artifacts. |
| DOC-4 | **LOW** | README links to `docs/SECURITY-BOUNDARIES.md` and `docs/GOOGLE-AI-STUDIO.md` will need updating after normalization. |

## 19. CI/CD

| ID | Severity | Finding |
|----|----------|---------|
| CI-1 | **HIGH** | None. No lint, no typecheck, no tests, no secret scanning on push/PR. |
| CI-2 | **INFO** | Release/deployment automation is intentionally out of scope for this phase (per phase rules). |

## 20. Supply-chain security

| ID | Severity | Finding |
|----|----------|---------|
| SC-1 | **MEDIUM** | No Dependabot/renovate config; no automated dependency alerts. |
| SC-2 | **MEDIUM** | No secret scanning on push (GitHub secret scanning not enabled via repo config; no push protection policy documented). |
| SC-3 | **LOW** | No SBOM generation; worker images are digest-pinned (the strongest existing control). |
| SC-4 | **INFO** | `scripts/security_scan.py` is a basic regex allowlist scan — a useful tripwire, not a substitute for tooling. |

---

## Findings summary

| Severity | Count | Representative items |
|----------|-------|----------------------|
| CRITICAL | 0 | — |
| HIGH | 4 | D-1 (no migrations), D-2 (unsafe live backup), TE-1/CI-1 (no CI), DE-1 (no lockfile) |
| MEDIUM | 16 | AZ-1, AU-1/2, R-1, D-3/4, W-1, P-1, DS-1, AL-1, S-1, TE-2, DE-2, DOC-1/2, SC-1/2 |
| LOW | 9 | AU-3, T-2, R-2, J-2, W-3, DS-2, DA-1, AL-2, TE-4, DP-1, DOC-3/4 (subset) |
| INFO | — | Positive observations recorded inline |

No CRITICAL findings. The existing forensic logic, fail-closed semantics and the AI ≠ EVIDENCE invariant are sound and must be preserved unchanged by the baseline work.
