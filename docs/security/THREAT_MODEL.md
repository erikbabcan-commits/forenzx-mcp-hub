# Threat Model (STRIDE)

Scope: single-node deployment, control plane exposed via reverse proxy, worker execution on a separate host (or explicitly-enabled local Docker).

## Assets
A1 Evidence (vault), A2 signed execution records / findings, A3 control-plane database (registry, jobs, audit), A4 remote MCP credentials, A5 signing key, A6 API keys/JWT secret, A7 service availability.

## Adversaries
T1 external attacker on the network; T2 authenticated analyst (insider); T3 malicious/compromised admin; T4 compromised remote MCP server; T5 malicious pack supply chain; T6 compromised LLM/intelligence layer; T7 curious host operator.

## Matrix

| Threat | Vector | Current mitigation | Residual risk & follow-up |
|---|---|---|---|
| Spoofing | Stolen API key/JWT (T1/T2) | Strong-secret enforcement, JWT exp required, 401 on invalid | No rotation/JWKS; no rate limiting (audit AU-2/AU-3) |
| Tampering | Evidence modified during analysis (T1/T7) | Read-only mount, pre/post SHA-256+Merkle, chain of custody breach detection | none known |
| Tampering | Malicious pack image (T5) | Canonical RepoDigest pinning + placeholder rejection (ADR-0005) | adapters are in-process code (audit P-1) |
| Tampering | LLM rewrites findings (T6) | No write path; `AIInterpretation` separate; `is_ai_assisted` marker (ADR-0004) | none known |
| Repudiation | Admin denies action (T3) | `registry_events` audit with actor | audit log prunable by same role (AL-1) |
| Info disclosure | Secrets via API/dashboard | Fernet at rest, never returned, `has_auth_secret` only | — |
| Info disclosure | SSRF via registry probe (T3) | Admin-only, no redirects | no private-range egress filtering (R-1) |
| Info disclosure | Dashboard HTML unauthenticated | Static metadata only; APIs require keys (DA-1) | document/proxy-level auth |
| DoS | Job floods, big bodies (T1/T2) | Worker pool semaphore, mem/cpu/pids caps, input validation | no API rate limiting |
| Elevation | Control plane → host (T3/T5) | No docker socket by default (ADR-0003), non-root, no caps, read-only fs | local-Docker mode is documented opt-in risk |

## Highest-priority follow-ups (from ENTERPRISE_BASELINE.md)
HIGH: D-1 (migrations — fixed this phase), D-2 (WAL-safe backup — fixed this phase), TE-1/CI-1 (CI — added this phase), DE-1 (lockfile — NOT_VERIFIED, see PHASE1_RESULT.md). MEDIUM backlog: AZ-1 (persisted case ACL), R-1 (egress allowlist), AL-1 (audit tamper-evidence).
