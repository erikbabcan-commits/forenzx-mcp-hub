# Contributing to ForenZX MCP Hub

## Ground rules

1. **Never weaken security to make a build pass.** Fail-closed behavior and
   the AI ≠ evidence invariant are non-negotiable.
2. **No fake PASS.** If you cannot run a check locally, mark it
   `NOT_VERIFIED` in your PR description — do not claim it passed.
3. **Evidence data is immutable.** Never modify forensic evidence, binary
   samples, or hash-pinned test fixtures. Pre-commit hooks are configured to
   leave them alone.
4. Don't work directly on `main`. Use feature branches and PRs.

## Setup

```bash
git clone https://github.com/erikbabcan-commits/forenzx-mcp-hub.git
cd forenzx-mcp-hub
make install        # poetry install + pre-commit
cp .env.example .env  # fill in real secrets (never commit .env)
```

## Daily workflow

```bash
make verify   # local equivalent of the CI quality gates
```

`make verify` runs the same checks as CI (lint, format check, type check,
tests, docker compose config when Docker is available). Run it before every
push. If Docker is unavailable, `make compose-check` and `make docker-build`
report NOT_VERIFIED rather than silently passing.

## Commits

Use conventional commits, e.g.

```
feat(db): add versioned database migrations
fix(registry): probe no longer promotes server trust
docs(audit): publish phase 1 verification report
```

Keep commits logical and reviewable; don't mix refactors with behavior
changes.

## Code style

- `ruff` for lint and formatting (config in `pyproject.toml`).
- `mypy core` for type checking; prefer real type fixes over `# type: ignore`.
- Don't enable dozens of lint rules and then ignore them all.

## Tests

- All existing tests must keep passing; never delete tests to make a change land.
- New security-relevant behavior needs a test (see `tests/security/`).
- Test layout: `tests/unit`, `tests/integration`, `tests/security`, `tests/e2e`.

## Database changes

Schema changes go through `core/migrations.py` as a new numbered migration.
Never add ad-hoc `CREATE`/`ALTER` statements to runtime code outside the
versioned migration list. Add a migration test alongside the change.

## Reporting issues

Use the GitHub issue templates (`.github/ISSUE_TEMPLATE/`). For security
issues, see `SECURITY.md` — private advisory only, no public issues.
