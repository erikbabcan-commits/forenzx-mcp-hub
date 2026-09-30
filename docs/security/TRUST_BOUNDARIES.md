# Trust Boundaries

| # | Boundary | Crossing data | Protection |
|---|----------|---------------|------------|
| TB-1 | Internet → reverse proxy → control plane | HTTP (MCP JSON-RPC, dashboard, ops API) | TLS terminated at proxy; API key / JWT auth; strict CORS; CSP; security headers; HSTS in production |
| TB-2 | MCP client → MCP engine | Tool calls with case/evidence/pack IDs | Auth + fail-closed case ACL; input validation (patterns, max lengths); no shell, argv only |
| TB-3 | Control plane → evidence vault | Evidence file paths | ID sanitization, path-traversal & symlink checks, vault-root containment (`core/vault.py`) |
| TB-4 | Control plane → forensic worker container | Evidence (read-only), IoC bundle (read-only), scratch (rw, cleaned) | Digest-pinned image, read-only rootfs, `cap_drop=ALL`, `no-new-privileges`, network off, mem/cpu/pids limits, noexec tmpfs |
| TB-5 | Control plane → Docker daemon | Container lifecycle commands | Docker socket NOT mounted in control-plane container by default (ADR-0003); separate worker host preferred |
| TB-6 | Control plane → remote MCP servers | Probes with stored credentials | Fernet-encrypted secrets at rest, secrets never returned to clients, no redirects followed, admin-only management |
| TB-7 | Intelligence plane (LLM) → hub | Read-only signed results over remote MCP | AI output stored only as marked `AIInterpretation`; no write path to evidence/findings (ADR-0004) |
| TB-8 | Config/environment → process | Secrets, paths | Pydantic validation; production rejects weak/placeholder/dev credentials and memory-only persistence |
| TB-9 | Pack source (repo/mount) → control plane | Manifests + adapter code | Fail-closed validation (ADR-0005); adapters are trusted code executed in-process — read-only mount; real RepoDigest required before any execution |
| TB-10 | Database file → backups | SQLite snapshot | Online Backup API (WAL-consistent); backups inherit filesystem permissions of `BACKUPS_DIR` |

## Least-privilege summary

- Control-plane container: non-root, read-only rootfs, no capabilities, no docker socket.
- Worker containers: non-root context, no network by default, no capabilities, pids-capped.
- Dashboard: metadata only; secrets and shell access are unreachable by design.
