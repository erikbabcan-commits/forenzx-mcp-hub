# ADR-0003: No Docker socket in the control plane

## Status
Accepted (Phase 1)

## Context
Mounting /var/run/docker.sock into the application container is equivalent
to granting host root. A forensic platform whose control plane holds the
Docker socket would let any control-plane compromise escape to the host and
tamper with evidence, other containers, or the kernel.

## Decision
The production control plane never mounts or requires the Docker socket.
Forensic worker isolation is implemented via the workers/pool layer and
container hardening (read_only, cap_drop ALL, no-new-privileges, tmpfs).
If a development convenience feature ever needs the Docker socket, it must
be clearly marked DEV / HIGH TRUST ONLY and excluded from production
configuration.

## Consequences
- Host compromise via Docker socket is structurally prevented.
- Development workflows may need extra steps to run container-based packs.
- Deployment documentation must keep asserting the socket is absent.

## Alternatives
- Docker socket mounted read-only: rejected — the socket API cannot be
  meaningfully read-only; it still allows container creation with host
  mounts.
- Rootless Docker/Podman socket: deferred — better than the default socket
  but still unnecessary for the current single-node worker model.
- DooD with a filtering proxy: rejected for now — complexity without a
  current need.
