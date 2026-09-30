# Google AI Studio / Gemini integration

The ZIP is intentionally usable as a standalone MCP service. Google AI Studio/Gemini should consume it as a **remote MCP server**, not as a browser-side secret holder.

## Remote MCP URL

After deploying behind HTTPS:

```text
https://mcp.example.com/mcp
```

Authenticate with an analyst API key or a short-lived bearer token. Do not put an admin API key in a browser bundle.

## Server-side Gemini example

Use the current Google Gemini SDK / Interactions API syntax available in your AI Studio project. The logical configuration is:

```ts
const forenzxMcp = {
  type: "mcp_server",
  name: "forenzx",
  url: process.env.FORENZX_MCP_URL,
  headers: {
    "X-API-Key": process.env.FORENZX_ANALYST_API_KEY,
  },
  allowed_tools: [
    "forenzx_health",
    "forenzx_capabilities",
    "forenzx_packs_list",
    "forenzx_analysis_status",
    "forenzx_analysis_results",
  ],
};
```

Keep execution-triggering tools such as `forenzx_analysis_start` out of a model's default allowlist unless the product flow explicitly authorizes them.

## Recommended AI boundary

Gemini may:

- summarize deterministic findings
- explain a timeline
- correlate already-produced findings
- draft a report
- propose follow-up examination steps

Gemini must not manufacture:

- observed timestamps
- hashes
- IOC matches
- chain-of-custody entries
- execution records
- deterministic forensic findings

Treat model output as `INTERPRETATION_NOT_EVIDENCE`.

## AI Studio project prompt

When importing this ZIP into a coding workspace, instruct the model to preserve these boundaries:

1. Keep `/mcp` and dashboard management APIs server-side.
2. Never expose registry secrets in frontend responses.
3. Do not replace deterministic MVT output with synthetic Gemini results.
4. Keep `packs/` read-only in normal deployment.
5. Use the dashboard's SQLite digest override rather than editing a container image dynamically.
6. Do not add a generic shell/terminal maintenance action.
7. Treat `/health/live` and `/health/ready` as separate concepts.
