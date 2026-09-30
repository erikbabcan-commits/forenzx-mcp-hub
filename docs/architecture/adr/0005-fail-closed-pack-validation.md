# ADR-0005: Fail-closed pack validation

- Status: Accepted
- Date: 2026-09-30

## Context

Forensic packs are the system's most dangerous input: they name container images and provide adapter code. The original v5 zip shipped an obvious placeholder digest (`sha256:1234...cdef`) for the MVT image. Accepting "close enough" digests or silently degrading on malformed packs would be a supply-chain hole.

## Decision

1. A pack is enabled only if its manifest is fully valid AND its `pinned_image_digest` is a canonical `sha256:<64 hex>` RepoDigest that passes placeholder/entropy heuristics. Anything else ⇒ pack disabled with a surfaced error (fail closed, never silently skipped).
2. At execution time the sandbox verifies the *actual pulled image* carries the pinned RepoDigest; short image IDs are rejected.
3. Digest overrides are persisted in SQLite (`pack_overrides`), not by editing the read-only `packs/` mount.
4. Malformed manifests, missing adapters or adapter import errors disable the pack and surface the reason — a degraded registry is visible (`/health/ready` reports `DEGRADED`).

## Consequences

- A fresh deployment starts with packs disabled until a real RepoDigest is configured — readiness correctly reports `BLOCKED` in production rather than pretending to work.
- Placeholder digests can never reach container creation.
