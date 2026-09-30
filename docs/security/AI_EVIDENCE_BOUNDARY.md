# AI / Evidence Boundary

## Invariant

**AI OUTPUT IS NOT FORENSIC EVIDENCE.**

The intelligence plane (Gemini, Mistral, future LLMs) provides
interpretation, correlation suggestions, and report drafting only.

## AI must never create or modify

- artifact hashes
- deterministic IOC hits
- chain-of-custody events
- execution signatures
- observed timestamps that do not originate from a deterministic source

## Rules

1. AI output is always labeled AI-generated and stored separately from
   evidence records.
2. AI may read evidence and metadata; it has no write path into the
   evidence plane.
3. Deterministic results (hashes, IOC matches from local feeds, signatures)
   are produced exclusively by the evidence plane.
4. Report drafts require explicit analyst acceptance before publication.
5. Any AI claim about a hash, hit, or timestamp must be treated as a hint
   and re-derived deterministically before it can be recorded.

## Enforcement status

Phase 1: documented invariant + code organization (advisory layer has no
evidence write path).
Phase 2 (backlog): technical write-path restrictions and tests that fail if
the intelligence layer can write evidence tables.

Related: ADR-0004, ../architecture/ARCHITECTURE.md.
