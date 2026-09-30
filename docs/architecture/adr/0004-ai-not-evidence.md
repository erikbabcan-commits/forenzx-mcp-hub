# ADR-0004: AI is not evidence

- Status: Accepted
- Date: 2026-09-30

## Context

LLMs (Gemini, Mistral, …) are valuable for drafting reports, hypotheses and correlations. They are also non-deterministic and unreliable as sources of forensic fact. Any path that lets model output masquerade as a finding destroys the evidentiary value of the whole system.

## Decision

1. Deterministic evidence (findings, timeline, integrity hashes, classifications) is produced exclusively by the evidence plane — digest-pinned tools in isolated sandboxes.
2. Model output may only exist as `AIInterpretation` records that *reference* findings (`finding_refs`) and are marked `is_ai_assisted`. It can never be stored as, merged into, or promote/demote a `ForensicFinding`.
3. There is no code path from the intelligence plane into the vault, findings, job results or classifications. The intelligence plane has read-only access to signed results.
4. Regression tests enforce that failed/security-blocked analyses always carry classification `ERROR`, and that findings carry `is_ai_assisted: false` from evidence tools.

## Consequences

- Reports can cite AI interpretation only as clearly-marked interpretation.
- Findings remain independently verifiable via Ed25519-signed execution records regardless of any AI involvement.
