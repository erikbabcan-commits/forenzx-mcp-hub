# ADR-0001: Control / Evidence / Intelligence plane separation

- Status: Accepted
- Date: 2026-09-30

## Context

ForenZX combines orchestration (API, registry, jobs), deterministic forensic execution (containers, hashing, signing) and LLM-assisted interpretation. Mixing them in one trust domain would let a compromised control process tamper with evidence, and would let model output blur into findings.

## Decision

The system is explicitly partitioned into three planes (see `docs/architecture/ARCHITECTURE.md`):

1. **CONTROL PLANE** — FastAPI, MCP, dashboard, registries, ACL, jobs, audit, metadata. Never modifies evidence.
2. **EVIDENCE PLANE** — isolated forensic workers, packs, vault, deterministic parsers, hashing, signing. Fully deterministic and verifiable.
3. **INTELLIGENCE PLANE** — LLM interpretation, report drafting, correlation. Consumes evidence read-only.

## Consequences

- Evidence-plane output is always a signed, deterministic artifact; the control plane only records and routes it.
- Intelligence-plane output is structurally separated (`AIInterpretation` vs `ForensicFinding`) and marked `is_ai_assisted`.
- A future split into separate control/evidence hosts is possible without redesign: the planes already communicate through explicit interfaces (job specs, execution records).
