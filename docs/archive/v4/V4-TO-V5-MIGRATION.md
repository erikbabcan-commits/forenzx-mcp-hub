# v4 → v5 delta

| v4 | v5 |
|---|---|
| `/mcp/jsonrpc` only | canonical `/mcp` + compatibility route |
| four old `mcp_*` tools | `forenzx_*` tool namespace + aliases |
| in-memory jobs/results | SQLite durable jobs/results |
| no MCP fleet UI | MCP Manager dashboard |
| no remote registry | encrypted multi-server registry |
| placeholder MVT digest could appear loaded | placeholder is disabled and reported |
| RepoDigest parsing could compare full `repo@sha256:` incorrectly | canonical `sha256:<64hex>` extraction |
| short image ID fallback | removed; execution blocks without RepoDigest |
| HMAC execution signature | HMAC compatibility + Ed25519 signature |
| ad-hoc maintenance | allowlisted backup/vacuum/prune/reload actions |
| process restart loses live job truth | active jobs become `INTERRUPTED_BY_RESTART` |
