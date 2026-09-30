# Operations Runbook

## Daily / weekly

- `make backup` — consistent DB backup with SHA-256 manifest (see
  BACKUP_RESTORE.md).
- `make db-check` — database integrity check (`PRAGMA integrity_check`) plus
  schema version report.
- Check worker health: jobs stuck in `RUNNING` older than
  `WORKER_TIMEOUT_SECONDS` indicate a stalled worker; restart the service.

## Restart / crash recovery

After an unclean shutdown:
1. Restart the service; schema migrations run automatically and are
   versioned (`core/migrations.py`).
2. Jobs left in `RUNNING` are recovered automatically to `FAILED` with
   `error_code=INTERRUPTED_BY_RESTART` and an audit event.
3. Verify via audit log / dashboard that the recovery events exist.

## Remote MCP servers

- New servers are `UNVERIFIED`. Health probes do NOT promote trust.
- To trust a server: `PUT /api/v1/mcp-servers/{id}/trust` with an admin API
  key (state: TRUSTED / QUARANTINED / DISABLED). The change is audited with
  a trace id (`X-Trace-Id`).
- Quarantine first, investigate later: set `QUARANTINED` if a server behaves
  oddly; its trust history remains in `registry_events`.

## Pack failures (fail closed)

- A pack that is DISABLED in the catalog means its manifest failed
  validation (most often: missing/placeholder image digest). Fix the
  manifest to `sha256:<64 hex>`, then restart. Never "fix" by relaxing
  validation.

## Production startup failures (fail closed, by design)

The app refuses to start in production when:
- `DATABASE_PATH` points to memory (`:memory:` or `memory:` URI)
- JWT/HMAC secrets are placeholders (`CHANGE_ME`, `changeme`,
  `dev-secret`, …) or obviously weak
- Required secrets are missing

Action: generate strong secrets (see `.env.example`), restart.

## Secrets rotation

- Rotate `JWT_SECRET_KEY` / `SERVER_HMAC_SIGNING_KEY` by setting the new
  value and restarting (invalidates sessions; API keys are list-based and
  rotate independently).
- Ed25519 keys live under `DATA_DIR`; rotate per
  docs/security/SECURITY-BOUNDARIES.md.

## Incident quick checks

1. `make security` (repository secret scan).
2. Inspect `registry_events` for unexpected `MCP_SERVER_TRUST_CHANGE`.
3. Verify latest backup manifest SHA-256 (BACKUP_RESTORE.md).
4. Confirm no Docker socket is mounted into the control plane container.
