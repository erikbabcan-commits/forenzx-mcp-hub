# Phase 2 Backlog — Security Hardening (NOT implemented in Phase 1)

This is the real remaining security work, deliberately deferred from Phase 1.

## Network / MCP
- **SSRF protection** for remote MCP probes and egress (R-1): destination
  validation, private-range blocking, egress allowlist.
- **DNS rebinding** defenses: re-resolve-and-pin, TTL policy, IP pinning
  for probe connections.
- **Remote MCP trust enforcement**: UNVERIFIED/QUARANTINED servers must be
  unroutable for sensitive operations; trust transitions require approval.
- **Capability drift detection**: alert when tools_hash changes for a
  TRUSTED server (field already stored).

## Credentials / authz
- **Credential master key** mechanism for MCP credentials at rest.
- **AEAD secret encryption** (e.g. AES-GCM/XChaCha20-Poly1305) replacing
  plaintext credential storage (C-1/C-2).
- **RBAC** with roles/permissions beyond analyst/admin split.
- **Dashboard secure sessions**: hardened cookies, expiry, logout
  revocation.
- **CSRF** protection for state-changing dashboard/API routes.
- **XSS** review of dashboard rendering (CSP headers, escaping audit).

## Platform
- **Rate limiting** on API/MCP endpoints (D-1).
- **Audit hash chaining**: previous_hash/event_hash columns + verification
  tooling (AL-1); columns reserved in the model doc.
- Persisted case ACL (AZ-1).
- Worker per-run container isolation evaluation (W-2/P-1).

## CI/CD & supply chain
- **GitHub Actions** pipeline maturity beyond Phase 1 gates.
- **CodeQL** static analysis.
- **Dependabot** alert/maintenance cadence.
- **Dependency review** action on PRs.
- **Container vulnerability scanning** (Trivy/Grype) on builds.
- **Supply-chain security**: pip-audit, lockfile policy.
- **Release provenance**: signed releases, SLSA-style provenance.

## Prerequisites from Phase 1
- Merge `hardening/enterprise-foundation` to main.
- Commit a maintainer-generated `poetry.lock` (CI can generate in-job but
  the repository needs the checked-in lockfile).
- Resolve LICENSE blocker (LICENSE-TODO.md).
