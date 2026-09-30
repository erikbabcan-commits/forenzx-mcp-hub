# ADR-0005: Fail-closed forensic pack validation

## Status
Accepted (Phase 1)

## Context
Packs reference container images. An unpinned or placeholder image reference
means the executed forensic code is whatever the registry serves at that
moment — a supply-chain hole that silently changes analysis results.

## Decision
Every pack manifest MUST carry an image digest matching
^sha256:[a-f0-9]{64}$, plus id, version, image, command, capabilities,
network policy, and resources. A missing or placeholder digest marks the
pack DISABLED — not a warning, not auto-fix. Production readiness is
BLOCKED while a required pack has no valid digest.

## Consequences
- Executed forensic code is bit-for-bit reproducible.
- Supply-chain updates require an explicit digest bump (auditable diff).
- Invalid/placeholder packs disappear from the catalog; dashboards must
  show disabled state (verified by tests/security regression gates).

## Alternatives
- Warn and run latest tag: rejected — silent analysis drift.
- Auto-resolve digest at first run: rejected — auto-fix of a security
  control is itself a vulnerability.
