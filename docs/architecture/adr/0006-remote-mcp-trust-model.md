# ADR-0006: Remote MCP trust model (HEALTHY != TRUSTED)

## Status
Accepted (Phase 1; enforcement extends into Phase 2)

## Context
Remote MCP servers are third-party endpoints. A server answering HTTP 200
only proves liveness, not integrity or intent. Treating health as trust
would let any attacker-controlled endpoint that responds to probes become a
trusted source of tool results inside the hub.

## Decision
Registry records carry an explicit trust_state: UNVERIFIED (default for
every new server), TRUSTED, QUARANTINED, DISABLED. Health probes update
latency, health, and tools_hash but NEVER change trust_state. Only the
audited admin endpoint PUT /api/v1/mcp-servers/{id}/trust changes trust,
recording an MCP_SERVER_TRUST_CHANGE audit event with trace_id. Phase 2
adds enforcement: UNVERIFIED/QUARANTINED servers must not be routable for
sensitive operations, plus SSRF/DNS-rebinding protection for probes.

## Consequences
- Liveness and trust are independent, auditable properties.
- New servers are inert until an admin explicitly trusts them.
- Trust transitions leave a tamper-visible audit trail (hash chaining in
  Phase 2).
- Operators must manage trust explicitly; there is no convenience
  auto-trust.

## Alternatives
- Trust on healthy probe: rejected — trivially gameable.
- Mutual TLS for everything: deferred — right tool for authenticated
  channels, but does not encode operator intent; can complement later.
- Manual allowlist without states: rejected — no quarantine lifecycle or
  audit story.
