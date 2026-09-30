# Component Inventory

## Control plane (`core/`)

| Component | File(s) | Responsibility | Notes |
|---|---|---|---|
| HTTP API | `core/main.py` | FastAPI app, endpoints, error handling | Incl. admin trust endpoint `PUT /api/v1/mcp-servers/{id}/trust` with `X-Trace-Id` |
| MCP server | `core/server.py` | MCP protocol surface over the API tools | |
| Dashboard | `core/dashboard/` | Operator dashboard | Session hardening is Phase 2 |
| Configuration | `core/config.py` | Env-driven settings; production rejects placeholders/weak/low-entropy secrets, memory-only DB | `is_obviously_weak_secret` helper |
| Database | `core/db.py` | SQLite access; `foreign_keys=ON`, WAL, `busy_timeout=10000`; audit event writing with optional `trace_id` | |
| Migrations | `core/migrations.py` | Versioned migrations v1 (baseline) + v2 (trust_state, tools_hash, trace_id) | Ad-hoc startup DDL removed |
| Jobs | `core/jobs.py` | Job orchestration and persistence | Restart recovery: RUNNING→FAILED `INTERRUPTED_BY_RESTART` |
| MCP registry | `core/mcp_registry.py` | Remote MCP servers, health probes, trust state | TrustState: UNVERIFIED / TRUSTED / QUARANTINED / DISABLED; probes never promote trust |
| Pack registry | `core/pack_registry.py` | Local forensic pack manifests | Digest required `^sha256:[a-f0-9]{64}$`, placeholder = DISABLED (fail closed) |
| ACL / policy | `core/acl.py` | Case/action authorization | In-memory case ACL is a known Phase 2 item |
| Vault | `core/vault.py` | Evidence vault storage | |
| Threat intel | `core/threat_intel.py` | IOC handling | Deterministic hits are evidence; LLM hints are not |
| Signing | `core/signing.py` | HMAC execution signing + Ed25519 key pair (file-based) | |
| Maintenance | `core/maintenance.py` | DB backup (SQLite online backup API + SHA-256 manifest), verify_backup, integrity check, retention | |
| Workers | `workers/` | Worker pool + isolation of forensic execution | Evidence plane |
| Packs | `packs/` | Deterministic analysis packs (e.g. mobile_compromise) | Evidence plane |
| Dashboard assets | `core/dashboard/` | UI | Control plane |

## Test suites (`tests/`)

| Suite | Focus |
|---|---|
| `tests/unit` | Config hardening (entropy, placeholder rejection) |
| `tests/integration` | Jobs, restart recovery, MCP, execution records, v5 hub |
| `tests/security` | Auth, ACL, CORS, vault, threat intel, pack registry, MVT, database baseline, MCP trust, regression gates |
| `tests/e2e` | Docker/compose presence checks |

## Scripts (`scripts/`)

`first_run.sh` (bootstrap), `security_scan.py` (offline secret/pattern scan,
used by `make security`), `verify_import_matrix.py`.

## External planes

- **Intelligence plane**: Gemini (Google AI Studio) — see
  `GOOGLE-AI-STUDIO.md`. Advisory only.
- **Remote MCP servers**: registered in the registry, probed for health,
  trust managed by admins; see ADR-0006.
