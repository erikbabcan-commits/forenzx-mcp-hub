# Threat Model (STRIDE, Phase 1 scope)

Assets: forensic evidence & chain of custody; registry/audit records;
credentials (API keys, JWT secret, HMAC key, Ed25519 keys); analyst time;
host integrity.

## Threats

| ID | Threat | Plane | Current mitigation | Status |
|---|---|---|---|---|
| S-1 | Spoofed analyst/admin | Control | API keys, admin key separation | KEPT; RBAC granularity Phase 2 |
| S-2 | Forged execution results | Evidence | HMAC + Ed25519 signing, digests | KEPT |
| T-1 | Tampering with evidence | Evidence | Vault, hashing, worker isolation | KEPT |
| T-2 | Tampering with audit log | Control | Append-only events | **OPEN** — hash chaining Phase 2 (AL-1) |
| T-3 | Supply-chain image swap | Evidence | Mandatory sha256 digests, fail closed | KEPT |
| R-1 | Repudiation of trust changes | Control | Audited trust endpoint w/ trace_id | KEPT; chaining Phase 2 |
| I-1 | Secret leakage via logs | Control | Never-log list, secret scanning, entropy checks | KEPT; enforcement Phase 2 |
| I-2 | Credential theft at rest | Control | File permissions | **OPEN** — AEAD encryption Phase 2 (C-1) |
| D-1 | DoS via job flooding | Control | Worker pool bounds | KEPT; rate limiting Phase 2 |
| D-2 | DoS via probe targets (SSRF) | Control | Timeout-bounded probes | **OPEN** — SSRF/DNS rebinding Phase 2 (R-1) |
| E-3 | Privilege escalation in container | Evidence | read_only, cap_drop ALL, no-new-privileges | KEPT |
| E-4 | Container escape via Docker socket | Control | Socket forbidden (ADR-0003) | KEPT |
| AI-1 | Hallucinated "evidence" | Intelligence | AI != EVIDENCE boundary | KEPT; technical enforcement Phase 2 |

## Out of scope for Phase 1

Kubernetes hardening, multi-tenant isolation, physical acquisition chain of
custody, nation-state supply-chain audits.
