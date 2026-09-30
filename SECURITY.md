# SECURITY POLICY — ForenZX MCP Hub

## Reporting a vulnerability

This project is maintained on GitHub. Please report security issues via
**GitHub private security advisories** on this repository
(Repo → Security → Report a vulnerability). Do not open public issues for
security problems.

We do not publish a dedicated e-mail contact; the GitHub advisory channel is
the single supported intake route.

## Non-negotiable invariants

- **Fail closed.** Invalid pack digests, weak/placeholder secrets, memory-only
  production persistence, and missing dependencies disable or abort the
  affected component — they are never silently downgraded or auto-fixed.
- **AI output is not forensic evidence.** LLM layers (Gemini/Mistral) may
  draft interpretations and summaries; they must never create artifact
  hashes, deterministic IOC hits, chain-of-custody events, execution
  signatures, or observed timestamps. See
  `docs/security/AI_EVIDENCE_BOUNDARY.md`.
- **HEALTHY is not TRUSTED.** Remote MCP servers default to `UNVERIFIED`
  trust state. See `docs/architecture/adr/0006-remote-mcp-trust-model.md`.

## Trust boundaries

The system is split into three planes:

- **Control plane** — FastAPI, MCP server, dashboard, registries, ACL,
  jobs, audit, maintenance.
- **Evidence plane** — isolated forensic workers, packs, evidence vault,
  deterministic parsers, hashing, execution signing.
- **Intelligence plane** — LLM interpretation, correlation, report drafting.

Detailed model: `docs/security/TRUST_BOUNDARIES.md` and
`docs/security/THREAT_MODEL.md`.

## Supported configuration

Single-node Docker deployment from the `main` branch. Docker socket access
is not required by the production control plane
(`docs/architecture/adr/0003-no-docker-socket-control-plane.md`).

## Secrets

- Generate secrets with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`.
- Production startup rejects placeholders (`CHANGE_ME`, `changeme`,
  `dev-secret`, …), known defaults, and low-entropy values.
- Never commit real secrets; `.pre-commit-config.yaml` includes secret
  detection with an audited baseline (`.secrets.baseline`).

## Hardening status

Phase 1 established the enterprise baseline (versioned DB migrations,
audited trust model, verified backups). Known open security work — SSRF
egress protection, DNS rebinding, AEAD credential encryption, RBAC, audit
hash chaining, and CI supply-chain scanning — is tracked in
`docs/audit/PHASE2_BACKLOG.md` and is **not yet implemented**. Do not deploy
to hostile networks until Phase 2 lands.
