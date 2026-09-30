# Security Policy

## Supported versions
Only the latest `main` / current release branch receives security fixes.

## Reporting a vulnerability
Please report privately — do not open a public issue for exploitable findings.
Contact the maintainers via GitHub security advisory ("Report a vulnerability" in the repo Security tab) or the address in `docs/deployment/PRODUCTION.md` once set (TODO: publish a permanent security contact, tracked in ENTERPRISE_BASELINE.md DOC-2).

Include: affected component, reproduction steps, impact assessment, logs (`core/utils/logger.py` emits structured JSON), and whether forensic evidence could be affected.

## Handling
- Acknowledgement: within 72 hours. Fix window depends on severity (CRITICAL: ASAP; HIGH: days).
- Security fixes are released with a CHANGELOG entry; credits given on request.

## Invariants that must survive every change
1. **Fail-closed**: unverifiable digests, missing threat intel, unknown ACL objects ⇒ refuse, never degrade.
2. **AI ≠ EVIDENCE**: model output never becomes or edits a forensic finding (docs/security/AI_EVIDENCE_BOUNDARY.md).
3. **No ad-hoc schema**: DB changes only via versioned migrations in `core/migrations.py`.
4. **No secrets in the repo**: `.env` is gitignored; production rejects placeholder/dev credentials at startup.

## Security boundaries in depth
- [Trust boundaries](docs/security/TRUST_BOUNDARIES.md)
- [Threat model](docs/security/THREAT_MODEL.md)
- [Security boundaries (detailed)](docs/security/SECURITY-BOUNDARIES.md)
- [Baseline audit](docs/audit/ENTERPRISE_BASELINE.md)
