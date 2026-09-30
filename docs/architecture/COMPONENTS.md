# Components

| Component | Location | Plane | Responsibility |
|---|---|---|---|
| FastAPI app | `core/main.py` | Control | HTTP surface, auth, CORS, security headers, lifespan, ops API |
| MCP engine | `core/server.py` | Control | JSON-RPC 2.0 tool dispatch (`forenzx_*` tools), legacy v4 aliases |
| Remote MCP registry | `core/mcp_registry.py` | Control | CRUD + health probes + `tools/list` discovery of external MCP servers; Fernet-encrypted secrets |
| Pack registry | `core/pack_registry.py` | Control | Fail-closed pack loading, placeholder-digest rejection, digest overrides |
| ACL | `core/acl.py` | Control | Case/job authorization, fail-closed, IDOR protection |
| Job manager | `core/jobs.py` | Control | Durable job lifecycle, idempotency, honest restart semantics |
| Database | `core/db.py` + `core/migrations.py` | Control | SQLite persistence, versioned migrations, pragmas (`foreign_keys`, WAL, `busy_timeout`) |
| Maintenance | `core/maintenance.py` | Control | Allowlisted ops: WAL-safe backup, VACUUM, audit pruning, integrity checks, registry export |
| Signing | `core/signing.py` | Evidence | Persistent Ed25519 key, execution-record signatures, public key publication |
| Evidence vault | `core/vault.py` | Evidence | Path-traversal/symlink-hardened storage, SHA-256 + Merkle integrity |
| Threat intel | `core/threat_intel.py` | Evidence | Pinned STIX2 IoC bundles, fail-closed loading |
| Worker pool | `workers/pool.py` | Evidence | Sandboxed container execution, resource limits, cleanup guarantees, chain of custody |
| Sandbox config | `workers/isolation.py` | Evidence | RepoDigest verification, hardened container profile |
| Pack base | `packs/base.py` | Evidence | Adapter contract (argv commands, deterministic parsing) |
| MVT pack | `packs/mobile_compromise/` | Evidence | iOS/Android backup analysis via MVT |
| Dashboard | `core/dashboard/` | Control | Static ops UI; never receives secrets |
| Models | `core/models/forensic.py` | Cross | Pydantic entities incl. `AIInterpretation` (marked, non-evidential) |
| Logger | `core/utils/logger.py` | Control | Structured JSON logs with audit context |
| Scripts | `scripts/` | Tooling | First-run secret generation, security scan, import matrix verification |

External actors: MCP clients (analyst/admin via API key or JWT), remote MCP servers, Docker daemon on the worker host (never mounted into the control-plane container by default), optional LLM clients in the intelligence plane.
