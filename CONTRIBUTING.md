# Contributing

## Ground rules (non-negotiable)
1. Do not weaken fail-closed behavior to make a test or pipeline pass. If a check fails, fix the cause.
2. AI output must never become forensic evidence — see [AI ≠ EVIDENCE](docs/security/AI_EVIDENCE_BOUNDARY.md) (ADR-0004).
3. Database changes go through a new entry in `core/migrations.py` `MIGRATIONS` (append-only, contiguous versions). No ad-hoc DDL anywhere.
4. Do not commit secrets, placeholder production credentials, or forensic data. Pre-commit runs secret detection.
5. Docker image references for forensic packs require canonical RepoDigests (ADR-0005).
6. Keep the control plane free of Docker-socket dependencies (ADR-0003).

## Workflow
1. Branch from `main`: `feature/...`, `fix/...`, `hardening/...`.
2. `make install && make verify` must be green locally (it is the CI gate).
3. Add tests for behavior changes; never delete tests to make the suite pass.
4. PRs require: green CI, review, and an honest description of what was NOT verified.

## Style
- `ruff` (line length 120) and `mypy core` enforce style/types; `pre-commit install` wires up ruff, whitespace/EOF/YAML checks, large-file and secret detection.
- Evidence data is never touched by formatting tooling (excluded paths in `.pre-commit-config.yaml`).

## Commit messages
Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `security:`).
