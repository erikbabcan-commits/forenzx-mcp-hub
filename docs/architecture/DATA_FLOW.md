# Data Flow

## 1. Analysis request (deterministic path — evidence)

```
Client (API key / JWT)
  → Control plane: authenticate → authorize (ACL) → create Job (persisted)
  → dispatch to Evidence plane: worker pool → isolated execution
      pack manifest checked: image digest MUST match ^sha256:[a-f0-9]{64}$
      placeholder/invalid digest ⇒ pack DISABLED (fail closed)
  → deterministic parser output → hashing (SHA-256) → vault storage
  → execution signing (HMAC + Ed25519)
  → results persisted; audit event written (actor, action, target, result,
    trace_id)
```

Everything on this path is forensic evidence: hashes, IOC hits from local
deterministic feeds, chain-of-custody events, signatures, timestamps
observed from deterministic sources.

## 2. Health probe (registry)

```
MCP registry → probe remote server (timeout-bounded HTTP)
  → store latency, tools hash (tools_hash)
  → NEVER changes trust_state (HEALTHY != TRUSTED)
```

New servers are inserted as `UNVERIFIED`. Only the audited admin trust
endpoint changes `trust_state`, recorded in `registry_events` with
`trace_id` and `X-Trace-Id` passthrough.

## 3. Intelligence path (advisory only)

```
Evidence/metadata → Intelligence plane (Gemini/Mistral)
  → interpretation drafts, correlation suggestions, report drafts
  → presented as ADVISORY output, marked as AI-generated
```

The intelligence plane can **read** evidence and metadata. It can **never
write** artifact hashes, deterministic IOC hits, chain-of-custody events,
execution signatures, or observed timestamps. See
`../security/AI_EVIDENCE_BOUNDARY.md`.

## 4. Persistence & recovery

- SQLite (WAL, foreign_keys=ON, busy_timeout=10s) is the single source of
  truth for jobs, registry, audit events, metadata.
- All schema changes go through numbered migrations (`core/migrations.py`);
  there is no ad-hoc startup DDL.
- On restart, jobs left `RUNNING` are recovered to `FAILED`
  (`error_code=INTERRUPTED_BY_RESTART`) and the recovery is audited — no job
  stays forever RUNNING.
- Backups use the SQLite online backup API and are written with a manifest
  (SHA-256, size, schema version, timestamp, source); restore is verified
  against the manifest hash before use.

## 5. Backup / restore

```
live DB --online backup API--> backup file + manifest.json (sha256)
restore: verify manifest sha256 → restore into target → integrity check
         (PRAGMA integrity_check) → data comparison
```

See `../operations/BACKUP_RESTORE.md`.
