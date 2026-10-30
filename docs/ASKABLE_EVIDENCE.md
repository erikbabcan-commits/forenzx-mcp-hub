# ForenZX MCP Hub — candidate change evidence

**Status: BLOCKED for external code reuse.** `LICENSE-TODO.md` explicitly
records unresolved copyright/license terms. Do not submit this code or any
derived task for third-party AI training until the rights holder decides and
the origin of the exact change is documented.

**Baseline checked:** `main` at `8b00998753a54bd3135821249a60a2fb4731ed81`
(2026-10-29). Refresh HEAD and rerun tests before any future submission.

| Git reference | Observable change | Verification |
| --- | --- | --- |
| [PR #12](https://github.com/erikbabcan-commits/forenzx-mcp-hub/pull/12), merge `28ad21e` | Security hardening, dependency review, HTTP integration tests and scan failure tests | `tests/integration/test_http_tool_smoke.py`, `tests/unit/test_security_scan_exit.py` |
| [PR #14](https://github.com/erikbabcan-commits/forenzx-mcp-hub/pull/14), merge `eecef08` | STIX/runtime digest pinning and regression cases | `tests/security/test_stix_worker.py`, `tests/security/test_threat_intel.py` |
| Baseline import `b48d204` | Imported v5 project archive | Original provenance and copyright remain to be established |

Merge attribution to `erikbabcan-commits`, and other historical commits
attributed to `youh4ck3dme`, are Git metadata, not legal proof of authorship
or rights. Confirm whether both identities represent the claimant and which
files were independently created versus inherited from upstream.

## Commit-level attribution (not a copyright determination)

| Source commit | Recorded Git author | Observable changes |
| --- | --- | --- |
| `dfceae4` (PR #14) | `erikbabcan-commits <erikbabcan@gmail.com>` | STIX digest pinning in `core/threat_intel.py` and `workers/pool.py`; synthetic regression tests |
| `3bb4007` (PR #12) | `Codex <codex@openai.com>` | Security-scan failure coverage, dependency review and README |
| `2472186` (PR #12) | `Codex <codex@openai.com>` | HTTP MCP tool/auth smoke test |

PR #12 is marked as AI-agent-authored in the commit metadata; do not present
those changes as exclusively human-written code. PR #14 is a candidate for a
more focused provenance review, but neither its Git author nor merge proves
rights to the imported base code, any external data or contributions.

## Verification scope

### Vercel preview correction (2026-10-30)

Vercel deployment `dpl_EQvmgfHPjJaVC8Re2AY8U1Xnkyps` reported build
`READY`, but runtime requests to `/` and `/favicon.ico` failed with
`FUNCTION_INVOCATION_FAILED`. Runtime logs identified `OSError: [Errno 30]
Read-only file system: 'data'` during `core.config.AppConfig` initialization.
The Vercel entrypoint now serves a stateless portfolio preview, an SVG favicon
and an explicit `PREVIEW_ONLY` health status. All real MCP operational endpoints
return 503; `core.main` remains the persistent/VPS entrypoint. See
`tests/integration/test_vercel_preview.py` for an import-boundary check and HTTP
tests. This is **not** proof of a functional hosted MCP backend.

The PR-only `CI` workflow includes Poetry install, lock check, compileall,
ruff, mypy, pytest, security scan, Docker Compose validation and image build.
This draft adds optional `workflow_dispatch` for manual main-HEAD validation;
no CI workflow has been dispatched by PHASE 10.

Custom MCP header **values** must never be included in registry lists or
registry exports. The local change returns header names and a presence flag
only; export format increments to version 2. Outbound configured requests keep
their headers. This changes the management response contract and must be
reviewed with any external API clients before merge.

This is response/export redaction, **not encryption at rest**. The registry
persists `custom_headers_json` as plaintext JSON in SQLite. A separately
reviewed storage/key-management design is needed if at-rest protection is
required. Until then, restrict access to the DB and its backups.

## Owner decisions

- [ ] Determine original authors, third-party components and permitted reuse.
- [ ] Choose a license (or keep the project all-rights-reserved) explicitly.
- [ ] If approved, update LICENSE, SPDX metadata and an architecture decision.
- [ ] Check `custom_headers` callers against the response contract change.
- [ ] Record successful application pytest on the exact future HEAD.
- [ ] Identify one owned change suitable for an independently reproducible task.

No checklist item is automatically satisfied by GitHub repository ownership.
