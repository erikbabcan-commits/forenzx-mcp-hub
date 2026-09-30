# ADR-0004: AI output is not forensic evidence

## Status
Accepted (Phase 1)

## Context
The platform integrates LLMs (Gemini, Mistral, future providers) for
interpretation, correlation, and report drafting. LLMs are non-deterministic
and hallucination-prone. Any value they produce that enters the evidence
chain would make the whole forensic record unverifiable.

## Decision
The INTELLIGENCE PLANE is advisory only. AI must never create or modify:
artifact hashes, deterministic IOC hits, chain-of-custody events, execution
signatures, or observed timestamps not derived from a deterministic source.
AI output is always labeled as AI-generated and stored separately from
evidence. Only the deterministic evidence plane produces forensic facts.

## Consequences
- Evidence chain remains verifiable and reproducible.
- LLM outages degrade only the advisory layer.
- Report drafts need a human/analyst acceptance step before publication.
- Phase 2 must add technical enforcement (write-path restrictions), not
  just documentation.

## Alternatives
- Trust LLM output with human review: rejected — hallucinated details can
  survive review and contaminate the record.
- Fine-tuned local models with sampling disabled: rejected — still not
  provably deterministic.
