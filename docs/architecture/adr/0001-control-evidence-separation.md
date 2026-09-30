# ADR-0001: Control / Evidence plane separation

## Status
Accepted (Phase 1)

## Context
ForenZX MCP Hub started as a single FastAPI process that dispatched forensic
work. Mixing operator-facing control logic with evidence-producing logic in
one trust domain means a compromise of the API (or of any request handler)
directly threatens evidence integrity.

## Decision
The system is explicitly divided into a CONTROL PLANE (FastAPI, MCP server,
dashboard, registries, ACL, jobs, audit, metadata, maintenance) and an
EVIDENCE PLANE (isolated forensic workers, packs, evidence vault,
deterministic parsers, hashing, signing). The control plane dispatches and
collects; only the evidence plane produces forensic evidence. An
INTELLIGENCE PLANE (LLMs) sits above both as advisory-only
(see ADR-0004).

## Consequences
- Evidence integrity can be reasoned about independently of API hardening.
- The evidence plane can be hardened/isolated without touching API code.
- Documentation and reviews must keep asking "which plane is this code in?"
- Some indirection cost in dispatch and result collection.

## Alternatives
- Single flat trust domain: rejected — no way to state evidence integrity
  guarantees if the API can mutate evidence directly.
- Full microservice split per plane: rejected — operational overhead
  unjustified for a single-VPS, low-maintenance target.
