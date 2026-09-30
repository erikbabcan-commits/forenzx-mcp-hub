# ForenZX MCP Hub v5

A low-maintenance forensic MCP control plane built on the original ForenZX v4 core.

It combines:

- a forensic MCP endpoint at `POST /mcp`
- backward-compatible `POST /mcp/jsonrpc`
- persistent SQLite job metadata/results
- a remote MCP server registry
- encrypted remote MCP credentials
- background health checks and `tools/list` discovery
- an operations dashboard at `/dashboard`
- forensic pack registry with fail-closed digest validation
- Ed25519 execution-record signing
- safe maintenance actions (backup, VACUUM, audit pruning, pack reload)
- Docker sandbox hardening for local forensic packs

## 1. Fastest VPS start

```bash
unzip forenzx-mcp-hub-v5.zip
cd forenzx-mcp-hub-v5
./scripts/first_run.sh
nano .env                 # set ALLOWED_ORIGINS and review paths
docker compose up -d --build
```

Open:

```text
http://YOUR_SERVER:8000/dashboard
```

Use the admin key generated in `.env` under `ADMIN_API_KEYS`.

> Put the service behind HTTPS (Caddy/nginx/Traefik) before exposing it publicly.

## 2. Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
ENVIRONMENT=development python -m core.main
```

Development defaults when no `.env` exists:

- admin key: `dev-admin-key`
- analyst key: `dev-analyst-key`

These values are rejected as production credentials.

## 3. Dashboard

The dashboard has six small operational surfaces:

### Overview
Service counters, remote MCP health, packs and recent jobs.

### MCP Servers
Add/edit/delete a remote MCP server with:

- name and type
- MCP URL
- Streamable HTTP or legacy JSON-RPC transport
- bearer or `X-API-Key` authentication
- encrypted secret at rest
- tags and notes
- optional maintenance URL
- enable/disable
- health probe
- `tools/list` discovery
- optional restart request

The browser never receives stored remote MCP secrets.

### Forensic Packs
Shows image pins and pack registry errors. Placeholder image digests are disabled automatically. A verified RepoDigest can be added from the dashboard; it is stored as a SQLite override while `packs/` stays read-only.

### Jobs
Persistent analysis job history. If the process is restarted while a local async job is active, the job is marked `FAILED / INTERRUPTED_BY_RESTART` instead of pretending it is still executing.

### Maintenance
Allowlisted actions only:

- SQLite backup
- SQLite `VACUUM`
- audit event pruning
- registry JSON export without secrets

There is **no arbitrary shell console** in the dashboard.

### Audit
Tracks registry changes, probes, restarts, pack changes and maintenance actions.

## 4. MCP endpoint

New clients should use:

```text
POST /mcp
MCP-Protocol-Version: 2026-07-28
Authorization: Bearer ...
```

or:

```text
X-API-Key: ...
```

Core tools:

- `forenzx_health`
- `forenzx_capabilities`
- `forenzx_packs_list`
- `forenzx_analysis_start`
- `forenzx_analysis_status`
- `forenzx_analysis_cancel`
- `forenzx_analysis_results`

Legacy v4 tool aliases remain accepted so an older client does not break immediately.

## 5. Remote MCP registry

The hub can supervise many different MCP servers without merging their code into ForenZX.

Typical examples:

```text
ForenZX forensic MCP
filesystem MCP
GitHub MCP
database MCP
browser MCP
custom internal MCP
```

The registry stores operational metadata in SQLite. Bearer/API-key values are encrypted with a Fernet key derived from `SERVER_HMAC_SIGNING_KEY` and are never returned by the management API.

Changing `SERVER_HMAC_SIGNING_KEY` without migrating the registry will make previously stored remote credentials undecryptable. Treat that key as persistent infrastructure state.

## 6. Forensic Docker execution

For local forensic pack execution, the host needs Docker and the application needs Docker access.

The provided `docker-compose.yml` intentionally **does not mount `/var/run/docker.sock` by default**. This lets the hub/dashboard run safely even when forensic execution is hosted elsewhere or not yet enabled.

If you deliberately enable local Docker pack execution, review `docs/security/SECURITY-BOUNDARIES.md` first. A separate worker host remains the preferred production model.

## 7. MVT pack digest

The original project shipped an obvious placeholder digest for the MVT image. v5 detects it and disables that pack.

To enable the pack:

1. Pull/inspect the exact approved MVT image on your trusted worker.
2. Obtain its canonical RepoDigest: `sha256:<64 hex>`.
3. In **Dashboard → Forensic Packs**, choose **Set real digest**.
4. Re-run readiness and a controlled smoke test.

The system no longer accepts short Docker image IDs as a substitute for a RepoDigest.

## 8. Health endpoints

```text
GET /health/live
GET /health/ready
GET /api/system/capabilities
GET /api/keys
```

`/health/live` means the process answers.

`/health/ready` reports pack/signing/database readiness separately and can return `BLOCKED` in production when no usable forensic pack is enabled.

## 9. Storage

Default persistent state:

```text
/data/forenzx.db
/data/ed25519-private.pem
/data/backups/
```

Mount `/data` persistently in production.

## 10. Verification

Recommended release gate:

```bash
python -m compileall core packs workers
ruff check core packs workers tests
mypy core packs workers
pytest -q
```

Docker-dependent tests should run on a machine with the Docker SDK and a Docker daemon. Never label them PASS when they were skipped because the infrastructure was unavailable.

## 11. Google AI Studio / Gemini

See [`docs/architecture/GOOGLE-AI-STUDIO.md`](docs/architecture/GOOGLE-AI-STUDIO.md).

The normal architecture is:

```text
Gemini / AI Studio
        ↓
remote MCP over HTTPS
        ↓
ForenZX MCP Hub
        ↓
policy + registry + audit + jobs
        ↓
trusted forensic worker / Docker packs
```

Keep deterministic forensic evidence separate from model interpretation.

## 12. Repository structure

```text
core/       control plane + evidence-plane services (FastAPI app, MCP engine, registries, jobs, vault, signing, migrations)
packs/      forensic packs (adapters + manifests)
workers/    sandboxed forensic worker pool and Docker hardening
tests/      pytest suite (incl. database baseline, migrations, backup/restore, production-rejection gates)
scripts/    first-run secret generation, security scan, import matrix verification
docs/
  architecture/   ARCHITECTURE, COMPONENTS, DATA_FLOW, ADRs, AI-studio & registry docs
  security/       TRUST_BOUNDARIES, THREAT_MODEL, AI_EVIDENCE_BOUNDARY, SECURITY-BOUNDARIES
  operations/     RUNBOOK, BACKUP_RESTORE
  deployment/     PRODUCTION
  audit/          ENTERPRISE_BASELINE, PHASE1_RESULT
  archive/v4/     historical v4 documents (not part of runtime)
.github/    CI workflow, issue templates, Dependabot config, CODEOWNERS
```

## 13. Development commands

The project uses Poetry. `make verify` is the local equivalent of CI:

```bash
make install        # poetry install (requires poetry.lock — see CHANGELOG/PHASE1_RESULT)
make lint           # ruff check
make format-check   # ruff format --check
make typecheck      # mypy core
make test           # pytest -q
make security       # scripts/security_scan.py
make verify         # all of the above, CI-equivalent
make run            # local uvicorn
make docker-build   # docker compose build
make backup         # consistent SQLite snapshot into BACKUPS_DIR
make db-check       # PRAGMA quick_check on the live database
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing schema (`core/migrations.py`), packs, or anything touching evidence integrity.
