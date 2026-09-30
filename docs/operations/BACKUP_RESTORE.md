# Backup & Restore

## What to back up
| Data | Location | Method |
|---|---|---|
| Control-plane DB (jobs, results, registry, audit, pack overrides) | `DATABASE_PATH` (default `/data/forenzx.db`) | SQLite Online Backup API — **never** raw-copy the live file (WAL) |
| Signing key | `DATA_DIR/ed25519-private.pem` | file copy (0600) — losing it invalidates all future signature verification by third parties |
| Evidence vault | `VAULT_BASE_DIR` | filesystem-level (rsnapshot/restic/LVM) — evidence is immutable, backup cadence per case policy |
| Configuration | `.env` | secret manager / offline copy (never in the repository) |

## Creating a consistent backup
- API: `POST /api/v1/ops/maintenance/backup` (admin key) → `{"ok":true,"file":"forenzx-<UTC stamp>.db"}` in `BACKUPS_DIR`.
- The backup uses `sqlite3`'s Online Backup API, so it is consistent even while WAL contains uncheckpointed data and writers are active.
- Verify any backup before trusting it: `python -c "from core.maintenance import verify_backup; print(verify_backup('<path>'))"` → `ok: true` and expected `schema_version`.
- Restic/duplicity of the whole `/data` volume is fine as a second layer, but quiesce or use the API snapshot for guaranteed DB consistency.

## Restore procedure (single node)
1. Stop the service: `docker compose down`.
2. Move the current DB aside (do not delete): `mv /data/forenzx.db /data/forenzx.db.corrupt-$(date +%s)`.
3. Copy the verified backup into place: `cp $BACKUPS_DIR/forenzx-<stamp>.db /data/forenzx.db` and `chown` to the container user.
4. Start: `docker compose up -d`.
5. Verify: `/health/ready` 200; `SELECT MAX(version) FROM schema_migrations;` matches expected; run an integrity check (`database_integrity_check()`).
6. If signing key was also restored from backup, verify signature continuity: `GET /api/keys` must show the expected `kid`.

## Restore test (required after any backup tooling change)
`tests/test_database_baseline.py::TestBackupRestoreIntegrity` automates: seed → backup → verify → restore → data present → `PRAGMA quick_check` ok. Run it on a machine with the dev dependencies installed (`make test`).

## Retention
Keep at least: daily × 7, weekly × 4, monthly × 6 — or your case-law requirements, whichever is stricter. Audit events older than the retention window are pruned separately (`maintenance/prune`).
