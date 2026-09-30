# Production Deployment (single node)

Intentionally simple: one VPS, docker compose, SQLite, one volume. No Kubernetes.

## Prerequisites
- Docker Engine + compose plugin
- A reverse proxy with TLS (Caddy/nginx/Traefik) — the service itself speaks HTTP
- Persistent storage for `/data` (DB, signing key, backups), the vault and the threat-intel directory
- A separate worker host for forensic execution (recommended; see ADR-0003)

## Steps
1. Checkout: `git clone https://github.com/erikbabcan-commits/forenzx-mcp-hub && cd forenzx-mcp-hub`
2. Secrets: `./scripts/first_run.sh` (generates random 48-byte secrets, 0600 `.env`) — then edit `.env`:
   - `ENVIRONMENT=production`
   - `ALLOWED_ORIGINS=["https://your-domain"]`
   - real deployment API keys (dev/placeholder values are rejected at startup)
   - `DATABASE_PATH` on persistent storage (memory/`/tmp` rejected in production)
3. Build & run: `docker compose up -d --build`
4. Front it with TLS, e.g. Caddy: `your-domain { reverse_proxy 127.0.0.1:8000 }`
5. Verify: `curl -fsS https://your-domain/health/ready` — production with no enabled pack intentionally returns `BLOCKED` (503).
6. Configure the MVT pack: set the real RepoDigest via the dashboard/API (see README §7).

## Hardening checklist
- [ ] TLS enforced at the proxy; HSTS emitted by the app in production
- [ ] `.env` permissions 0600, never committed
- [ ] Firewall: only 80/443 exposed; the app port not public
- [ ] `/data` volume persistent and backed up (BACKUP_RESTORE.md)
- [ ] Docker socket NOT mounted into the app container
- [ ] Forensic workers on a separate host (or local-Docker mode consciously accepted per ADR-0003)
- [ ] Vault & threat-intel mounts read-only
- [ ] Real RepoDigest pinned for every enabled pack
- [ ] Restore tested at least once

## Scaling later (not now)
The design allows: vertical scale (bigger node), worker pool size up (`WORKER_POOL_SIZE`), forensic execution moved to a dedicated host, and a PostgreSQL backend implemented behind `core/db.py`'s storage interface. None of these are needed for the single-node baseline.
