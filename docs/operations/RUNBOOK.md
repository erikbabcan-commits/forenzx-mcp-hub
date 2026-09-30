# Operations Runbook

Single-node deployment. Assume all commands run from the repo root on the host.

## Daily/weekly
| Check | How | Expected |
|---|---|---|
| Liveness | `curl -fsS https://HOST/health/live` | `{"status":"ALIVE"...}` |
| Readiness | `curl -fsS https://HOST/health/ready` | `READY` (or `DEGRADED` with visible pack errors; `BLOCKED` 503 in production = no enabled pack) |
| Disk | `df -h` on the volume holding `DATABASE_PATH`, `VAULT_BASE_DIR`, `BACKUPS_DIR` | < 80% |
| Backups | `ls -l $BACKUPS_DIR` | recent WAL-consistent snapshots (automate: see BACKUP_RESTORE.md) |
| DB integrity | `make db-check` (`python -c "from core.maintenance import database_integrity_check; ..."` via API or shell) | `ok: true` |
| Logs | `docker compose logs -f forenzx-mcp-hub` | JSON lines, no unexpected tracebacks |

## Common incidents

### Service down / container restarting
1. `docker compose ps`, then `docker compose logs --tail 200 forenzx-mcp-hub`.
2. Config validation errors (weak secrets, dev keys, memory-only DB) are fatal by design — fix `.env`, never weaken the validator.
3. Restart: `docker compose up -d` (jobs that were active are honestly marked `FAILED / INTERRUPTED_BY_RESTART`).

### `/health/ready` returns DEGRADED
- Usually a pack registry error: `GET /api/v1/ops/packs` (admin key) shows per-pack `registry_error`.
- Placeholder digest ⇒ set a real RepoDigest: Dashboard → Forensic Packs → Set real digest (stored in `pack_overrides`, never by editing `packs/`).

### `/health/ready` returns BLOCKED (503, production)
- No enabled pack. Expected on a fresh deployment until a real RepoDigest is configured. Do not "fix" by enabling placeholder digests.

### Pack job fails with IMAGE_DIGEST_MISMATCH
- The pulled image no longer matches the pinned RepoDigest. Do NOT relax the pin. Re-verify the image source, update the digest via the API/dashboard, and record why.

### Database locked / busy
- `busy_timeout=10000` + WAL handles normal contention. Sustained `database is locked` ⇒ find long transactions, consider `POST /api/v1/ops/maintenance/vacuum` off-peak.

### Remote MCP probe shows DOWN
- `GET /api/v1/mcp-servers`, then `POST .../probe` for details (`last_error`). Check the remote service, then its credentials (rotate via update API; secrets are never displayed back).

## Maintenance actions (allowlisted, admin only)
- Backup: `POST /api/v1/ops/maintenance/backup` → WAL-consistent snapshot in `BACKUPS_DIR`.
- VACUUM: `POST /api/v1/ops/maintenance/vacuum` (off-peak).
- Audit prune: `POST /api/v1/ops/maintenance/prune` (retention default 30 days — consider legal hold requirements before pruning).
- Pack reload: `POST /api/v1/ops/packs/reload` (no shell console exists, by design).

## Upgrades
1. Snapshot first (`make backup` or the API).
2. `git pull && docker compose up -d --build`.
3. Migrations run automatically and are versioned (`schema_migrations`); verify with `SELECT * FROM schema_migrations`.
4. Watch `/health/ready` and logs for one full health interval.
