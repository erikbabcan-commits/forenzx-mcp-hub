# Enterprise Baseline Audit — ForenZX MCP Hub

Audited commit: `b48d204` (pre-Phase-1 baseline)
This document records the EXISTING state at baseline, not the target state.
No overall project score is assigned (by instruction).

Severity legend: CRITICAL / HIGH / MEDIUM / LOW / INFO.

## 1. Architecture
- Three de-facto layers exist (FastAPI control, worker/pack evidence, LLM
  integration) but the separation is implicit — no documented planes,
  boundaries, or ADRs. **MEDIUM (A-1)**
- Monorepo layout mixes historical verdict/release documents with runtime
  code at repository root. **LOW (A-2)**

## 2. Authentication
- API keys + admin key separation + JWT for dashboard. Fail-closed on
  missing secrets in production. **INFO (AU-1)**
- Weak/placeholder secret values (e.g. `CHANGE_ME...`) are not rejected by
  length-independent checks; trivially weak values pass a naive length
  gate. **MEDIUM (AU-2)**
- Dashboard sessions not hardened (CSRF/cookie flags). **MEDIUM (AU-3)**

## 3. Authorization
- Case ACL is in-memory only (not persisted, lost on restart). **MEDIUM (AZ-1)**
- No fine-grained RBAC. **LOW (AZ-2)**

## 4. MCP transport
- Local MCP server over the FastAPI stack; CORS allowlist enforced. **INFO (M-1)**
- Auth model consistent (API key / JWT). **INFO (M-2)**

## 5. Remote MCP registry
- Health probing exists, timeout-bounded. **INFO (R-0)**
- Probe egress has no SSRF/DNS-rebinding protection. **HIGH (R-1)** — Phase 2
- HEALTHY == TRUSTED implicitly: no trust state field; a responding server
  is usable. **HIGH (R-2)** — Phase 2
- No tools_hash tracking (capability drift invisible). **MEDIUM (R-3)** — Phase 2

## 6. Credentials management
- MCP credentials stored without AEAD encryption at rest. **MEDIUM (C-1)** — Phase 2
- No master-key mechanism. **MEDIUM (C-2)** — Phase 2

## 7. Database
- SQLite; foreign_keys pragma not enforced on every connection; WAL not
  explicitly set. **MEDIUM (D-0)**
- Schema created by ad-hoc DDL at startup — no versioned migrations. **HIGH (D-1)**
- No migration/upgrade story, no migration tests. **HIGH (D-2)** (folds into D-1)

## 8. Job persistence
- Jobs persisted in SQLite and survive restart. **INFO (J-1)**
- RUNNING jobs never recovered after unclean restart (can be stuck forever,
  unaudited). **HIGH (J-2)**
- No trace_id correlation on events. **LOW (J-3)**

## 9. Forensic workers
- Worker pool with memory/CPU/timeout bounds and isolation. **INFO (W-1)**
- Workers run in-process with packs; no per-run container boundary yet.
  **MEDIUM (W-2)** — Phase 2 evaluation

## 10. Pack registry
- Digest validation exists and is fail-closed (`^sha256:[a-f0-9]{64}$`,
  placeholder ⇒ DISABLED). **INFO (P-0)**
- Some in-process pack adapters bypass the container/digest model.
  **MEDIUM (P-1)** — Phase 2

## 11. Docker security
- read_only, cap_drop ALL, no-new-privileges, tmpfs hardening present.
  **INFO (DS-0)**
- Control plane never mounts the Docker socket. **INFO (DS-1)**
- Dockerfile uses pip version ranges (non-deterministic runtime deps).
  **MEDIUM (DS-1)**
- No image vulnerability scanning in CI. **MEDIUM (DS-2)** — Phase 2

## 12. Dashboard
- Functional read-mostly dashboard; sessions rely on JWT with the caveats
  of AU-3. **INFO (DA-1)**

## 13. Audit logging
- Structured events (actor/action/target/result/metadata). **INFO (AL-0)**
- No tamper-evidence (no hash chaining). **MEDIUM (AL-1)** — Phase 2
- No trace_id field. **LOW (AL-2)**

## 14. Signing
- HMAC execution signing + Ed25519 key pair, file-based, generated on first
  run. **INFO (S-1)**

## 15. Tests
- Solid security test suite (auth, ACL, CORS, vault, pack registry, MVT,
  regression gates, jobs, MCP, execution records, Docker presence).
  **INFO (T-1)**
- No database bootstrap/migration/backup-restore/restart-recovery tests.
  **HIGH (T-2)**
- Tests flat in `tests/`, no unit/integration/security/e2e split. **LOW (T-3)**

## 16. Dependencies
- Poetry configured; **no poetry.lock in the repository.** **HIGH (DE-1)**
- No Dependabot / dependency review. **MEDIUM (DE-2)** — Phase 2

## 17. Deployment
- Single-node docker-compose, low-maintenance by design. **INFO (DP-1)**
- No production deployment guide; historical v4 documents at root.
  **LOW (DP-2)**

## 18. Documentation
- Good domain docs (Google AI Studio, MCP Manager, Pack Registry,
  Security Boundaries) but no architecture/security/operations doc set, no
  README structure overview, historical files clutter the root.
  **LOW (DOC-1)**

## 19. CI/CD
- **No CI at all.** **HIGH (CI-1)**
- No release pipeline, no automated gates. **MEDIUM (CI-2)** — release
  pipeline deliberately deferred until baseline is green.

## 20. Supply-chain security
- Pack digests mandatory (good). Otherwise: no lockfile audit, no
  container scanning, no CodeQL, no provenance. **HIGH (SS-1)** — Phase 2
  scope; lockfile/Dependabot enabled in Phase 1.

## Findings summary

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 7 | R-1, R-2, D-1 (incl. D-2), J-2, T-2, DE-1, CI-1, SS-1 |
| MEDIUM | 14 | A-1, AU-2, AU-3, AZ-1, C-1, C-2, D-0, R-3, W-2, P-1, DS-1, DS-2, AL-1, DE-2, CI-2 |
| LOW | 7 | A-2, AZ-2, J-3, AL-2, T-3, DP-2, DOC-1 |
| INFO | 12 | AU-1, M-1, M-2, R-0, J-1, W-1, P-0, DS-0, DS-1*, DA-1, AL-0, S-1, T-1, DP-1 |

*\*DS-1 appears once as MEDIUM (pip ranges) and once as INFO (socket absent);
see sections 11.*

Phase 1 resolves: D-0, D-1/D-2 (migrations), J-2, J-3/AL-2 (trace_id),
R-2 (trust model), T-2/T-3 (tests + layout), CI-1 (CI workflow), DE-1
(lockfile generated in CI; maintainer must commit it — see PHASE1_RESULT),
A-2/DOC-1/DP-2 (layout/docs). Remaining HIGH/MEDIUM items are tracked in
PHASE2_BACKLOG.md.
