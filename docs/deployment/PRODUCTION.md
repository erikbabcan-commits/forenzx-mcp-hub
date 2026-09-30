# Production Deployment (single node / VPS)

## Requirements

- Docker + Docker Compose
- One host, TLS terminated in front (reverse proxy), persistent volume for
  `DATA_DIR`, `VAULT_BASE_DIR`, `THREAT_INTEL_DIR`, backups
- **No Docker socket mounted into the control plane** (ADR-0003)

## Steps

1. `cp .env.example .env` and fill in ALL secrets:
   `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`
   Placeholder/weak secrets abort startup (fail closed) — this is intended.
2. Validate configuration:
   ```bash
   make compose-check   # docker compose config
   ```
3. Build and start:
   ```bash
   make docker-build
   docker compose up -d
   ```
4. First run: `scripts/first_run.sh` guidance / dashboard bootstrap.
5. Verify: dashboard reachable, `make db-check` green, create a test job,
   run `make backup` and confirm the manifest.

## Container hardening (kept, do not weaken)

- `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges: true`, tmpfs for
  writable paths
- Non-root runtime user, no build tools in the runtime image,
  `.dockerignore` enforced
- SQLite lives on the persistent volume (WAL mode; memory paths rejected in
  production)

## Remote MCP servers

Register servers, verify identity out-of-band, then set trust explicitly.
Probes show health only — they never grant trust (ADR-0006). Until Phase 2
SSRF/egress protection lands, restrict outbound access at the network layer
(firewall / egress allowlist) for production.

## Monitoring

- Standard uvicorn/FastAPI logs; no secrets in logs
  (docs/security/AUDIT_MODEL.md never-log list)
- Weekly: backup manifest check, db integrity check, audit log review
- Known limitation: no alerting yet (Phase 2 backlog)

## Upgrade procedure

1. `make backup`
2. Pull new release, `make compose-check`, `make docker-build`
3. `docker compose up -d` — versioned migrations apply automatically
4. `make db-check`; verify recovery/jobs state in the dashboard
5. Rollback = restore backup per docs/operations/BACKUP_RESTORE.md
