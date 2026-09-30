# LICENSE — TODO (must be resolved before public releases)

**The licensing of the ForenZX MCP Hub codebase is currently undetermined.** No LICENSE file is shipped because no explicit license statement exists for the hub itself:

- The `mobile_compromise` pack manifest declares `MIT` — but that is the license of the *pack description metadata* (and aligns with the MVT project it wraps), **not** a license grant for the hub's source code.
- `pyproject.toml`, the README and the docs contain no license statement for the `core/`, `workers/`, `scripts/` and dashboard code.

Until resolved, **no redistribution rights are granted** for this repository's own code.

## Required decision (owner action)
1. Choose a license (e.g. MIT/Apache-2.0 for permissive, or a source-available/proprietary terms for forensic tooling with usage restrictions).
2. Create a real `LICENSE` file at the repository root, add the SPDX identifier to `pyproject.toml`, and delete this file.
3. Record the decision in `CHANGELOG.md`.

> Do not treat this file as a license. It is a tracking TODO per the enterprise baseline audit (finding DOC-1, severity MEDIUM).
