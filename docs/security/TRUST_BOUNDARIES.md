# Trust Boundaries

## Plane boundaries

| Boundary | Trust direction | Control |
|---|---|---|
| Client → Control plane | Untrusted input | API keys/JWT, CORS allowlist, ACL |
| Control plane → Evidence plane | Trusted dispatch only | Worker pool, capability-scoped packs, signed executions |
| Control plane → Remote MCP | UNVERIFIED by default | Trust states, health probes never grant trust, audited trust changes |
| Evidence plane → Vault | Append-mostly | Vault path rules, hashing |
| Any plane → Intelligence plane | Read-only input | AI output is advisory, stored separately from evidence |
| Control plane → Host | No Docker socket | ADR-0003, container hardening |

## Invariants

1. **Fail closed** — misconfiguration disables a component; it never
   downgrades security to stay up.
2. **AI != EVIDENCE** — see AI_EVIDENCE_BOUNDARY.md.
3. **HEALTHY != TRUSTED** — liveness never implies trust.
4. Evidence plane components never authenticate external users; only the
   control plane does.

## Data crossing a boundary

- Into the control plane: validated, typed, bounded; secrets never logged
  (see AUDIT_MODEL.md never-log list).
- Into the evidence plane: job payloads only; workers get no credentials.
- Out of the evidence plane: deterministic results + hashes + signatures.
- Into the intelligence plane: sanitized evidence/metadata; output returns
  labeled AI-generated.

## Known boundary weaknesses (Phase 2 backlog)

- In-memory case ACL (not persisted) — AZ-1.
- Remote MCP egress lacks SSRF/DNS-rebinding protection — R-1.
- Audit events lack tamper-evidence (hash chaining) — AL-1.
- MCP credentials are not AEAD-encrypted at rest — C-1.
- Dashboard sessions lack hardened cookie/CSRF story — D-1.
