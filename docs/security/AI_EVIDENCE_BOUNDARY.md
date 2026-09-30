# The AI ≠ EVIDENCE Boundary

## Invariant
**Deterministic forensic evidence is produced exclusively by the evidence plane.** LLM output can never create, modify, enrich, or reclassify a finding. Model-generated content is interpretation, structurally separate and always marked.

## Enforcement points

| Layer | Mechanism |
|---|---|
| Data model (`core/models/forensic.py`) | `ForensicFinding.is_ai_assisted: bool` (false for evidence-plane tools); separate `AIInterpretation` class with `finding_refs`, `hypotheses`, `limitations` — it references findings, it cannot be a finding |
| Data model | `AnalysisResult` validator: FAILED/SECURITY_BLOCKED ⇒ classification must be `ERROR` (no softening) |
| MCP engine (`core/server.py`) | Tool surface offers only deterministic analysis tools; there is no tool that writes AI content into results |
| Worker pool (`workers/pool.py`) | Findings originate solely from parsing deterministic tool output artifacts (`adapter.parse_output_artifacts`) |
| Tests (`tests/test_regression_gates.py`) | Regression gates verify the invariant set |

## Rules for contributors
1. Never add a field to `ForensicFinding` populated from model output.
2. Never let an LLM choose or change `DetectionClassification` or `FindingSeverity`.
3. AI-assisted narratives live in `AIInterpretation` (or a report artifact) and always reference evidence by ID.
4. If a future feature mixes AI text into a report, it must be visually and structurally distinguishable from findings.
