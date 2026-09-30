# MCP Manager design

## Registry record

Each remote server stores:

- UUID
- name
- server type
- MCP endpoint URL
- transport (`streamable_http` or `legacy_jsonrpc`)
- enabled flag
- authentication type
- encrypted authentication secret
- custom safe headers
- tags
- notes
- optional maintenance URL
- last probe time/status/latency/error
- last discovered tool names

## Security decisions

- Secrets are write-only from the dashboard/API.
- Secrets are encrypted before SQLite persistence.
- API responses return only `has_auth_secret`.
- Management requires an admin principal.
- Remote restart is only an HTTPS/HTTP POST to an explicitly configured maintenance endpoint.
- The dashboard cannot execute arbitrary local shell commands.
- `tools/list` is read-only discovery.
- A remote server can be disabled without deleting its configuration.

## Health monitor

The process periodically probes enabled servers using `tools/list`.

Status values:

- `READY`
- `DOWN`
- `UNKNOWN`
- `DISABLED`

The interval is controlled by `MCP_HEALTH_INTERVAL_SECONDS`.
