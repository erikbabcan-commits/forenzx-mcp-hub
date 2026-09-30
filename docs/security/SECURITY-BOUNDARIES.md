# ForenZX MCP Hub v5 — Security boundaries

## 1. Browser / operator boundary

The dashboard is an operations client, not a trusted source of identity. Every management API request is authenticated server-side. Remote MCP credentials are write-only: the browser can set them but the API never returns their plaintext.

## 2. MCP client boundary

`POST /mcp` requires an API key or bearer JWT. MCP tool arguments are validated before they reach pack execution. Header/body routing mismatches are rejected.

## 3. MCP registry boundary

The registry can contact explicitly configured remote MCP URLs. Secrets are encrypted before SQLite storage. Registry exports omit credentials. A restart action is an HTTP POST only to an explicitly configured maintenance URL; there is no shell command field.

## 4. Evidence boundary

Evidence identifiers are sanitized. Vault paths are checked for lexical symlink components before resolution, and then checked again for vault-root containment. Evidence is mounted read-only into forensic containers. Pre/post hashes must match or the result is security-blocked.

## 5. Container boundary

Forensic packs use exact argv arrays, not `shell=True`. The sandbox defaults to:

- read-only root filesystem
- network disabled unless a pack explicitly requires it
- all Linux capabilities dropped
- `no-new-privileges`
- PID, memory and CPU limits
- secure tmpfs
- explicit evidence/output mounts
- cleanup in `finally`

A Docker image must expose a canonical RepoDigest matching the configured `sha256:<64hex>` pin. Short image IDs are not accepted.

## 6. Pack boundary

A malformed or placeholder digest disables the pack. Operators can store a verified digest override in SQLite without making the `packs/` source tree writable.

## 7. AI boundary

Deterministic findings and execution records are not model output. The data model reserves a separate `AIInterpretation` schema marked `INTERPRETATION_NOT_EVIDENCE`. Gemini may explain evidence; it must not invent evidence.

## 8. Signing boundary

Execution records keep the v4 HMAC verification contract for compatibility and additionally support Ed25519 signatures. The Ed25519 private key is generated into the persistent data volume on first run and must never be included in source control or release archives.

## 9. Maintenance boundary

Dashboard maintenance is allowlisted: database backup, SQLite VACUUM, event pruning, pack reload and registry export. There is intentionally no arbitrary terminal or command executor.
