# ForenZX MCP Hub — Architecture

## Overview

ForenZX MCP Hub is a single-node forensic analysis platform exposing
deterministic forensic tooling through an MCP (Model Context Protocol)
server and an HTTP API, with optional LLM-assisted interpretation. It is
deliberately a low-maintenance single-VPS deployment; there is no Kubernetes
and no microservice decomposition.

## Three planes

The system is organized into three security planes. The plane boundary is
the central design invariant: **control code never fabricates evidence, and
evidence code never gains privileges of control.**

```
┌──────────────────────────────────────────────────────────────┐
│ INTELLIGENCE PLANE (advisory only)                            │
│ Gemini / Mistral / future LLM integrations                   │
│ interpretation · correlation · report drafting               │
└──────────────────────── ▲ input only ─────────────────────────┘
┌──────────────────────────────────────────────────────────────┐
│ CONTROL PLANE                                                │
│ FastAPI HTTP API · MCP server · dashboard · MCP registry     │
│ authentication · ACL/policy · job orchestration · audit       │
│ metadata · maintenance                                       │
└──────────────────────── ▼ dispatch/collect ──────────────────┘
┌──────────────────────────────────────────────────────────────┐
│ EVIDENCE PLANE                                               │
│ isolated forensic workers · packs · evidence vault            │
│ deterministic parsers · hashing · execution signing          │
└──────────────────────────────────────────────────────────────┘
```

### Control plane

`core/` — FastAPI application (`core/main.py`), MCP server (`core/server.py`),
dashboard (`core/dashboard/`), MCP registry (`core/mcp_registry.py`),
pack registry (`core/pack_registry.py`), auth (API keys/JWT), ACL
(`core/acl.py`), jobs (`core/jobs.py`), audit (`core/db.py` registry events),
maintenance & backup (`core/maintenance.py`), configuration
(`core/config.py`).

### Evidence plane

`workers/` (worker pool, isolation), `packs/` (deterministic analysis
packs), evidence vault, hashing, Ed25519/HMAC execution signing
(`core/signing.py`). All evidence-producing work happens here, dispatched by
the control plane, with results signed and hashed deterministically.

### Intelligence plane

LLM integrations (`docs/architecture/GOOGLE-AI-STUDIO.md` for the current
Gemini flow). The intelligence plane can *read* evidence and metadata and
*produce drafts and interpretations*, but its output is advisory. See
`docs/security/AI_EVIDENCE_BOUNDARY.md` for the hard restrictions.

## Key invariants

1. **Fail closed** — invalid pack digests, weak secrets, or missing
   components disable/abort; never downgrade silently.
2. **AI output is not evidence** — see the boundary document.
3. **HEALTHY != TRUSTED** — remote MCP servers start `UNVERIFIED`.
4. **No Docker socket in the production control plane** — workers are
   isolated by configuration, not by the control plane's container runtime.

## Decision records

All significant decisions are recorded in `adr/` (ADR-0001 through
ADR-0006). Component inventory: `COMPONENTS.md`. Request/data flow:
`DATA_FLOW.md`. Security models: `../security/`.
