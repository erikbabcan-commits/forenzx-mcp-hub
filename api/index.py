"""Stateless Vercel preview; the persistent MCP backend runs on a VPS.

Importing ``core.main`` starts SQLite migrations and creates a persistent
Ed25519 signing key. Vercel Functions have a read-only deployment filesystem and
ephemeral instances, so they MUST NOT host this stateful forensic control plane.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="15" fill="#141a26"/>
<path d="M15 13h34v9H25v9h20v9H25v13H15z" fill="#72e4c2"/>
<path d="M44 48l6 6 8-12" fill="none" stroke="#f4bb69" stroke-width="4"
 stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

PREVIEW_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <meta name="theme-color" content="#141a26">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <title>ForenZX MCP Hub — Technical preview</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, -apple-system, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; color: #e9eef6; background: #10151e;
      background-image: radial-gradient(circle at 70% 0%, #1a3d3b 0%, transparent 44%); }
    main { max-width: 850px; margin: auto; padding: clamp(32px, 8vw, 100px) 24px 64px; }
    .eyebrow { color: #72e4c2; text-transform: uppercase; font-size: .8rem;
      font-weight: 750; letter-spacing: .16em; }
    h1 { font-size: clamp(2.5rem, 7vw, 5rem); line-height: 1.05; margin: 16px 0; }
    .lead { color: #b9c6d6; font-size: clamp(1.05rem, 2.5vw, 1.3rem); line-height: 1.65;
      max-width: 680px; }
    .badge { display: inline-flex; padding: 9px 14px; border: 1px solid #5c7c73;
      border-radius: 100px; font-weight: 600; color: #a9f4dd; background: #20312f; }
    section { background: #18202c; border: 1px solid #344153; border-radius: 18px;
      padding: 24px; margin-top: 26px; }
    h2 { margin: 0 0 12px; font-size: 1.25rem; }
    p, li { line-height: 1.65; }
    li + li { margin-top: 8px; }
    ul { padding-left: 22px; color: #b9c6d6; }
    a { color: #83dfec; overflow-wrap: anywhere; }
    code { color: #b8f1db; }
    small { color: #8da0b6; }
  </style>
</head>
<body>
<main>
  <div class="eyebrow">VORKEI / ForenZX Engineering</div>
  <h1>ForenZX MCP Hub</h1>
  <p class="lead">A forensic MCP control-plane prototype with remote server registry,
    integrity checks, authorization boundaries, and deterministic tests.</p>
  <span class="badge">Read-only technical preview</span>

  <section>
    <h2>What this preview shows</h2>
    <ul>
      <li>The public project identity and its implementation scope.</li>
      <li>A stateless deployment health endpoint: <a href="/health"><code>/health</code></a>.</li>
      <li>The source, tests and change history in
        <a href="https://github.com/erikbabcan-commits/forenzx-mcp-hub">the GitHub repository</a>.</li>
    </ul>
  </section>

  <section>
    <h2>Why is the forensic API disabled here?</h2>
    <p>Real MCP operations depend on persistent SQLite, Ed25519 keys, a worker pool,
      and isolated execution. Vercel Functions do not provide the required durable
      filesystem or worker lifecycle. The application backend remains intended
      for a separately configured persistent host.</p>
    <p>Requests to operational endpoints return <code>503 PREVIEW_ONLY</code>.
      This page is not a production deployment or a hosted evidence-processing demo.
      Do not upload evidence, credentials or personal data to this preview.</p>
  </section>
  <p><small>Licensing and external code-reuse rights remain subject to owner review.</small></p>
</main>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def portfolio_preview() -> HTMLResponse:
    return HTMLResponse(PREVIEW_HTML)


@app.get("/favicon.svg")
async def favicon_svg() -> Response:
    return Response(FAVICON, media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico() -> RedirectResponse:
    return RedirectResponse("/favicon.svg", status_code=307)


@app.get("/health")
async def preview_health() -> dict[str, str | bool]:
    return {"service": "forenzx-mcp-hub", "status": "PREVIEW_ONLY", "persistent_backend": False}


@app.api_route("/health/ready", methods=["GET", "HEAD"])
async def backend_readiness() -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"status": "PREVIEW_ONLY", "ready": False, "detail": "Persistent MCP backend is not hosted here."},
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def operational_endpoints_unavailable(path: str) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": "PREVIEW_ONLY", "detail": "Forensic API operations require a persistent backend."},
    )
