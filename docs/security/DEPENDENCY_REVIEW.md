# Dependency review — 2026-10-22

The committed lock has advisory matches for certifi, cryptography,
python-multipart, starlette and the development-only pytest. These are scanner
matches, not demonstrated exploits. Multipart parsing is relevant to request
handling, cryptography to credential/signing boundaries, and certifi to TLS
trust. Starlette's request stack is runtime code. Test-only dependencies still
matter to the build environment.

This PR fixes the scanner exit gate without silently changing incompatible
framework or cryptography constraints. The lock remains unchanged. Resolving
the advisory set needs a separately reviewed compatibility update with the
complete auth/ACL, vault, signing and HTTP tests. Until then deployment/showcase
security acceptance is BLOCKED; there is no risk acceptance for production.
Reassess by 2026-10-29. Reproduce with a pinned-version pip-audit of poetry.lock
in an isolated environment; do not use production credentials.
