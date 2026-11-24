# FX-008: server-enforced reporting credentials

A reporting credential is a signed, expiring HS256 JWT with `roles: ["reporter"]`, a concrete `organization`, and explicit `report_case_ids` and `report_job_ids` arrays. Only trusted server-side provisioning may sign these claims. Never give the JWT signing secret to a client. The local operator CLI below issues short-lived credentials and revokes an individual credential durably.

Reporter permits only `forenzx_analysis_status` and `forenzx_analysis_results`, including their existing aliases. It requires BOTH signed grants, the stored job-to-case relationship, matching job organization, and matching registered case organization. Same user ID, same organization alone, or access through a different case never grants reporter access. Migration 3 adds persistent case registrations and revocations to the same SQLite database as jobs. Existing cases without an explicit registration still fail closed; migration does not infer permissions from historical jobs. Once registered, a case survives a restart using that database.

The central dispatcher checks permission after alias normalization, before parameters, pack lookup, job creation, downloads or cancellation. Both HTTP routes share it. Mixed-role tokens containing reporter remain restricted. Empty/unknown roles cannot call tools or access SSE jobs. Discovery shows only permitted tools; direct calls are still enforced independently.

SSE inherits the same reporter job/case checks. Local stdio remains an administrative examiner interface under OS process permissions; it is NOT a report-only credential and must not be exposed as one. No new reporter stdio mode is claimed.

Existing ordinary API keys remain analyst credentials in `default_org`. They intentionally retain broad legacy analyst ACL semantics and must NOT be supplied to a reporting client. A different ordinary API key is not tenant isolation. Reporter JWTs do not fix the legacy analyst OR policy, evidence-level grants, result identity validation, FX-009 data flow, issuer/audience policy, or deployment approval. Production report generation remains disabled pending those gates.

Regression tests: `tests/security/test_reporter.py`, with synthetic fixture `tests/fixtures/reporter-completed-synthetic.json`. No engine, model, network server or real case data is used. Run against an isolated temporary database and storage paths set BEFORE imports; the standard Hub tests create synthetic jobs in configured storage.

The original 53-check FX-008 characterization is pinned to the unmodified baseline. Its historical FAIL is preserved; these regression tests are a separate acceptance suite for the new reporter policy, not a rewrite of baseline evidence.

## Local operator workflow (self-hosted Hub only)

Run these commands on the Hub host, from its checkout and Python environment,
with the **same** `DATABASE_PATH`, `JWT_SECRET_KEY` and deployment configuration
as the server. The operator must already have OS access to that database and
signing secret. This is not a public token-issuance API or client-side command.
Replace the example IDs with a reviewed case, its owner/organization and an
existing job in that case. A conflicting case registration is rejected.

```bash
python -m core.reporter_credentials register-case \
  --case-id CASE_ID --owner OWNER_ID --organization ORGANIZATION_ID
python -m core.reporter_credentials issue \
  --subject REPORTER_ID --organization ORGANIZATION_ID --case-id CASE_ID \
  --job-id JOB_ID --ttl 900 --output /private/operator/reporter.jwt
python -m core.reporter_credentials revoke \
  --token-file /private/operator/reporter.jwt
```

The operator creates the private output directory in advance. Issuance validates
the case/job organization and relationship; repeat `--job-id` for multiple jobs
in the same case. TTL is 1–3600 seconds (default 900). Each issuance has a unique
`jti`. The output file is exclusively created with mode 0600; an existing file or
symlink is rejected. The token is never printed. Transfer it through an approved
secret channel. Files remain the operator's responsibility; revocation does not
delete them or erase copies held by clients.

After signature and expiry validation, every new reporter HTTP authentication
checks the SQLite revocation store. Revocation commits before CLI success and
is idempotent. The stored digest is SHA-256 of the JWT's authenticated
`header.payload`, **not** a hash of raw forensic data or a claim about identity.
It also covers legacy reporter JWTs without `jti`. Alternate base64url encodings
of the same signature cannot evade this lookup. Raw tokens and signing keys are
not stored in the revocation table. A database lookup error rejects authentication.

The next authentication after a committed revocation is denied (HTTP 401).
Already-authorized requests and open SSE streams are not cancelled retroactively.
All serving processes must run this code and share the same database; independent
SQLite copies do not synchronize. A restore from an older backup can lose newer
revocations: reconcile revocations or rotate the signing secret before reopening
access. The denylist is retained without automatic pruning. Back up SQLite with
the existing consistent backup procedure before migration; old binaries do not
enforce the new denylist. An operator's successful CLI exit is not a full issuance
audit trail, centralized identity system, or authorization for production release.

`tests/security/test_reporter_lifecycle.py` adds synthetic issuance, expiry,
revocation, storage failure, scope and private-file tests. Its process test starts
Uvicorn on loopback, revokes a credential from a separate process, stops/restarts
the server against the same temporary SQLite file, and checks both status/results
on both HTTP routes. The revoked token remains denied while a second token still
reads the fixture. Lifespan/background schedulers are disabled for this test;
it does not exercise Codex, Fedora, a deployed Hub, or real evidence.
