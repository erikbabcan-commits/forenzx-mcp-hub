# FX-008: server-enforced reporting credentials

A reporting credential is a signed, expiring HS256 JWT with `roles: ["reporter"]`, a concrete `organization`, and explicit `report_case_ids` and `report_job_ids` arrays. Only trusted server-side provisioning may sign these claims. Never give the JWT signing secret to a client. Reissue short-lived tokens when grants change; live revocation is not implemented here.

Reporter permits only `forenzx_analysis_status` and `forenzx_analysis_results`, including their existing aliases. It requires BOTH signed grants, the stored job-to-case relationship, matching job organization, and matching registered case organization. Same user ID, same organization alone, or access through a different case never grants reporter access. Unknown/unrestored cases fail closed; provision case ACL after a restart before reporting.

The central dispatcher checks permission after alias normalization, before parameters, pack lookup, job creation, downloads or cancellation. Both HTTP routes share it. Mixed-role tokens containing reporter remain restricted. Empty/unknown roles cannot call tools or access SSE jobs. Discovery shows only permitted tools; direct calls are still enforced independently.

SSE inherits the same reporter job/case checks. Local stdio remains an administrative examiner interface under OS process permissions; it is NOT a report-only credential and must not be exposed as one. No new reporter stdio mode is claimed.

Existing ordinary API keys remain analyst credentials in `default_org`. They intentionally retain broad legacy analyst ACL semantics and must NOT be supplied to a reporting client. A different ordinary API key is not tenant isolation. Reporter JWTs do not fix the legacy analyst OR policy, evidence-level grants, result identity validation, FX-009 data flow, issuer/audience policy, or production provisioning. Production report generation remains disabled pending those gates.

Regression tests: `tests/security/test_reporter.py`, with synthetic fixture `tests/fixtures/reporter-completed-synthetic.json`. No engine, model, network server or real case data is used. Run against an isolated temporary database and storage paths set BEFORE imports; the standard Hub tests create synthetic jobs in configured storage.

The original 53-check FX-008 characterization is pinned to the unmodified baseline. Its historical FAIL is preserved; these regression tests are a separate acceptance suite for the new reporter policy, not a rewrite of baseline evidence.
