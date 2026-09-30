# ADR-0003: The control plane never mounts the Docker socket by default

- Status: Accepted
- Date: 2026-09-30

## Context

Local forensic pack execution needs Docker. Mounting `/var/run/docker.sock` into the control-plane container would grant it root-equivalent control of the host: a control-plane compromise (e.g. via a malicious registry entry or dashboard bug) would become a host compromise.

## Decision

1. `docker-compose.yml` deliberately does NOT mount the Docker socket.
2. The hub runs, serves the dashboard and the MCP registry without any Docker access.
3. Forensic execution belongs on a separate worker host (preferred production model). Enabling local Docker execution is a conscious, documented operator decision, taken only after reviewing `docs/security/SECURITY-BOUNDARIES.md`.
4. Worker containers themselves are maximally hardened regardless: digest-pinned images, `cap_drop=ALL`, `no-new-privileges`, read-only rootfs, `network_mode=none`, pids/mem/cpu limits, noexec tmpfs, argv-only commands.

## Consequences

- Default deployment cannot run forensic packs locally (they fail closed); this is intentional.
- The registry and evidence layers are immune to control-plane-to-host escalation by default.
