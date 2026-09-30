# Audit Event Model

## Current fields (registry_events / audit path)

| Field | Purpose |
|---|---|
| id | Unique event id |
| timestamp (created_at) | UTC event time |
| actor | Identity performing the action |
| action | Event type (e.g. MCP_SERVER_TRUST_CHANGE) |
| target | Affected object |
| result | Outcome (success/failure/reason) |
| trace_id | Request correlation id (v2 schema; X-Trace-Id passthrough) |
| metadata | Structured event detail |

## Prepared for Phase 2

The data model is designed so hash chaining can be added without reshaping:
- `previous_hash` — hash of the prior event (tamper-evidence)
- `event_hash` — hash of this event's canonical form

Phase 2 adds these columns via a new migration, plus verification tooling.

## Never-log list

Audit events and logs must NEVER contain:

- API keys (raw or hashed-reversible)
- JWT tokens or JWT secret material
- passwords
- bearer tokens / Authorization headers
- decrypted MCP credentials

Secrets are referenced by id/name only. `scripts/security_scan.py` and the
pre-commit secret detection enforce the repository side of this rule.
