# Backup & Restore

## Backup

```bash
make backup        # or call core.maintenance.backup_database()
```

Each backup produces:
- `<name>` — database file copied via the **SQLite online backup API**
  (consistent even while the DB is in use)
- `<name>.manifest.json` — SHA-256 of the backup, size, schema version,
  UTC timestamp, source path

Backups go to `BACKUPS_DIR`. Never copy the live SQLite file with `cp`
while writers are active — that snapshot is not guaranteed consistent.

## Verification

`verify_backup(path)` re-computes the SHA-256 against the manifest and
fails closed on mismatch. `database_integrity_check(path)` runs
`PRAGMA integrity_check`.

## Restore

1. Verify the backup manifest hash (`verify_backup`).
2. Stop the service (evidence continuity requires a maintenance window).
3. Replace the database file, start the service; migrations apply if the
   backup predates a schema version bump (only forward; SQLite migrations
   in this project are applied in order and are idempotent-checked).
4. Run `make db-check`.

## Test coverage

`tests/security/test_database_baseline.py` runs the full loop:
create data → backup → restore into temp DB → integrity check → data
comparison, plus tamper detection (modified backup fails the SHA-256
check).
