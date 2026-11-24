# ForenZX MCP Hub v5

A forensic MCP control plane built on the original ForenZX v4 core. Connect an
authorized MCP client to a ForenZX instance you control to check analysis status,
retrieve completed findings, and inspect execution records.

## Start here

| Goal | First step | Expected result |
| --- | --- | --- |
| Explore the public preview | Open [forenzx-mcp-hub.vercel.app](https://forenzx-mcp-hub.vercel.app/) | Home page loads and [preview health](https://forenzx-mcp-hub.vercel.app/health) reports `PREVIEW_ONLY`. |
| Run your own Hub (owner-authorized deployment) | Follow [VPS setup](#1-vps-start) and the [deployment guide](docs/deployment/PRODUCTION.md). | The process responds at `/health/live` and the authorized administrator can open `/dashboard`. |
| Connect an MCP client | Follow [MCP endpoint](#4-mcp-endpoint) on your persistent instance. | Initialization and tool discovery succeed; an authorized client can retrieve its completed analysis by job ID. |

External deployment and redistribution remain subject to the unresolved
[license decision](LICENSE-TODO.md).

It combines:

- a forensic MCP endpoint at `POST /mcp`
- backward-compatible `POST /mcp/jsonrpc`
- persistent SQLite job metadata/results
- a remote MCP server registry
- encrypted bearer/API-key credentials (custom header values remain plaintext in SQLite)
- background health checks and `tools/list` discovery
- an operations dashboard at `/dashboard`
- forensic pack registry with fail-closed digest validation
- Ed25519 execution-record signing
- safe maintenance actions (backup, VACUUM, audit pruning, pack reload)
- Docker sandbox hardening for local forensic packs

### Vercel preview versus persistent backend

The Vercel site for this repository is a **read-only technical preview**.
Its `api/index.py` serves an informational page, an SVG favicon, and an honest
`/health` response (`PREVIEW_ONLY`); `/health/ready` and operational API paths
return HTTP 503. The Vercel preview **does not execute MCP tools, accept forensic
evidence, or persist jobs, signing keys, tokens, and audit records**.

This separation is intentional: `core.main` initializes a writable SQLite
database and a persistent Ed25519 private key on import. Vercel Functions run
with a read-only deployment filesystem and non-durable instance state. Moving
these security-critical files to `/tmp` would make identity and evidence records
unreliable. The full MCP service must run on a persistent, separately secured
host per [production deployment guidance](docs/deployment/PRODUCTION.md).

The preview can be smoke-tested with `pytest -q tests/integration/test_vercel_preview.py`.
It is **not** proof of a production backend or a release of the forensic engine.

## 1. VPS start

On the persistent host, with Git, Python 3.11+ and Docker Compose installed,
obtain an authorized checkout. The repository currently provides source rather
than a verified downloadable release ZIP.

```bash
git clone https://github.com/erikbabcan-commits/forenzx-mcp-hub.git
cd forenzx-mcp-hub
cp -n .env.example .env
chmod 600 .env
```

Before starting, replace every `CHANGE_ME` value using independent random
secrets, review paths and set `ALLOWED_ORIGINS` to your HTTPS origin.
The first-run helper does not substitute the current JWT and HMAC placeholder
strings; complete those fields manually. Follow the deployment guide for
network isolation and TLS before exposing the service.

```bash
docker compose config --quiet
docker compose up -d --build
curl --fail http://127.0.0.1:8000/health/live
```

Open the dashboard through the configured HTTPS reverse proxy:

```text
https://YOUR_HOST/dashboard
```

Use your configured admin key from `ADMIN_API_KEYS`.

> Put the service behind HTTPS (Caddy/nginx/Traefik) before exposing it publicly.

The default Compose configuration starts the control plane and persists
SQLite and the Ed25519 key under `/data`. Actual forensic execution additionally
requires configured workers with Docker access, valid approved image digests,
and approved STIX input digests as described in the deployment guide.

## 2. Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
ENVIRONMENT=development uvicorn core.main:app --host 127.0.0.1 --port 8000
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

Configure your compatible MCP client with the HTTPS URL of your own persistent
Hub and credentials issued for your authorized scope. Example transport settings
(replace placeholders and keep credentials in the client's secret storage):

```text
POST https://YOUR_HOST/mcp
MCP-Protocol-Version: 2026-07-28
Authorization: Bearer <YOUR_AUTHORIZED_TOKEN>
```

or:

```text
X-API-Key: <YOUR_AUTHORIZED_API_KEY>
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

For an existing authorized analysis, initialize the connection, discover tools
and call `forenzx_analysis_status` with its `job_id`. Once completed, call
`forenzx_analysis_results` with the same ID. The result includes findings,
warnings, limitations and the execution record. Ed25519 signs the canonical
execution-record payload (including case/evidence IDs, input and IOC digests,
pack/container information, command, exit code and timestamps). This signature
does not cover the entire result JSON or establish the accuracy of every finding.
Production reporter credential lifecycle and restoration of case access after
restart remain open; see [reporter authorization PR #29](https://github.com/erikbabcan-commits/forenzx-mcp-hub/pull/29)
and [operational evidence PR #30](https://github.com/erikbabcan-commits/forenzx-mcp-hub/pull/30).

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
.github/        CI workflow, Dependabot, CODEOWNERS, issue templates
core/           control plane: API, MCP server, registry, ACL, jobs, audit, maintenance
packs/          deterministic forensic packs (evidence plane)
workers/        worker pool and forensic isolation (evidence plane)
tests/           unit / integration / security / e2e test suites
scripts/        first-run, security scan, import matrix verification
docs/
├── architecture/   ARCHITECTURE, COMPONENTS, DATA_FLOW, ADRs 0001–0006
├── security/       TRUST_BOUNDARIES, THREAT_MODEL, AI_EVIDENCE_BOUNDARY, AUDIT_MODEL
├── operations/     RUNBOOK, BACKUP_RESTORE
├── deployment/     PRODUCTION
├── audit/          ENTERPRISE_BASELINE, PHASE2_BACKLOG, PHASE1_RESULT
└── archive/v4/     historical v4 documents
```

Root files: `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`,
`LICENSE-TODO.md` (license unresolved — manual blocker), `Makefile`,
`.env.example`, `.pre-commit-config.yaml`, `.editorconfig`, `.gitattributes`,
`.gitignore`, `.dockerignore`, `.secrets.baseline`.

## 13. Developer commands

```bash
make install        # poetry install (run 'make lock' first to create poetry.lock)
make lint           # ruff check
make format         # ruff format
make format-check   # ruff format --check
make typecheck      # mypy core
make test           # pytest -q
make security       # repository security scan
make verify         # local CI-equivalent quality gates
make run            # start the API locally
make docker-build   # build the production image
make compose-check  # validate docker compose config
make backup         # consistent SQLite backup with SHA-256 manifest
make db-check       # database integrity + schema version check
```

`make verify` is the local equivalent of CI. If Docker is unavailable,
compose/docker checks report NOT_VERIFIED — they never silently pass.

## 14. Security & architecture docs

- Architecture & planes: [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md)
- ADRs (incl. AI-not-evidence, SQLite default, no Docker socket, MCP trust model):
  [`docs/architecture/adr/`](docs/architecture/adr/)
- Trust boundaries & threat model: [`docs/security/TRUST_BOUNDARIES.md`](docs/security/TRUST_BOUNDARIES.md)
- AI / evidence boundary: [`docs/security/AI_EVIDENCE_BOUNDARY.md`](docs/security/AI_EVIDENCE_BOUNDARY.md)
- Reporting vulnerabilities: [`SECURITY.md`](SECURITY.md)

## 15. Remote MCP trust model

Every new remote MCP server is registered as `UNVERIFIED`. Health probes
show liveness only — **HEALTHY is not TRUSTED**. Trust is granted explicitly
by an admin via `PUT /api/v1/mcp-servers/{id}/trust` (states: `UNVERIFIED`,
`TRUSTED`, `QUARANTINED`, `DISABLED`) and every transition is audited with a
trace id. See
[`docs/architecture/adr/0006-remote-mcp-trust-model.md`](docs/architecture/adr/0006-remote-mcp-trust-model.md).

## Verification and demo scope

This repository is a prototype/control-plane reference. The public
[Vercel preview](https://forenzx-mcp-hub.vercel.app/) provides project information
and stateless health only. The tests below exercise local code; live forensic
execution and operational readiness require separate verification.

Reproduce with synthetic data only:

```sh
poetry install --with dev
poetry run pytest -q tests/integration/test_mcp.py tests/security/test_acl.py
make verify
```

The protocol tests exercise initialization, tool listing/calls and negative
access behavior locally; actual forensic pack execution requires its separate
Docker/sandbox verification. Never supply real evidence to the examples.

## Registry credentials and external code reuse

Custom MCP header values are omitted from the registry API projection
and version 2 inventory export; these expose header **names** and a presence
flag only. Outbound remote MCP requests still use the configured headers.
**At-rest encryption is not provided by this change:** header values remain
in the SQLite `custom_headers_json` column. Treat database/backups as sensitive.

`LICENSE-TODO.md` records an unresolved licensing blocker. This README does
not authorize external reuse, including AI training tasks. See the
[change/evidence map](docs/ASKABLE_EVIDENCE.md) for candidate PRs, verification
commands and owner decisions still required.
