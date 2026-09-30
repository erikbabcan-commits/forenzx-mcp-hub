# LICENSE — STATUS: UNRESOLVED (manual blocker)

**The license of ForenZX MCP Hub has NOT been determined.**

Until it is, this repository must be treated as **all rights reserved** by
the copyright holder. No redistribution or external use is authorized.

## Why this file exists

Phase 1 of the enterprise baseline required a LICENSE file. Publishing an
invented license (MIT, Apache-2.0, …) without the copyright holder's
decision would create a false legal statement, so this TODO documents the
blocker instead.

## Facts gathered during the audit

- Several forensic *pack manifests* reference MIT-licensed third-party
  tools/images. That covers those third-party components only — it says
  nothing about the license of the ForenZX MCP Hub code itself.
- No copyright notice, license header, or `LICENSE` file exists in the
  baseline (commit `b48d204`).

## Resolution checklist

1. The project owner decides on a license (private/internal, MIT, Apache-2.0,
   or other).
2. Replace this file with the actual license text (e.g. `LICENSE`) and add
   matching SPDX metadata to `pyproject.toml`.
3. Record the decision as an ADR under `docs/architecture/adr/`.
4. Remove this blocker mention from `CHANGELOG.md` and
   `docs/audit/PHASE1_RESULT.md` follow-ups.

Until step 2 happens, **deployment outside the owner's own infrastructure
is not permitted.**
