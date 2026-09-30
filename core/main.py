"""ForenZX MCP Hub v5: forensic MCP endpoint + low-maintenance MCP server dashboard."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import jwt
import uvicorn
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from core.acl import CaseAccessController, TokenUser, case_access_provider
from core.config import config
from core.db import db
from core.jobs import job_manager
from core.maintenance import backup_database, export_registry, prune_events, system_summary, vacuum_database
from core.mcp_registry import MCPServerCreate, MCPServerUpdate, mcp_registry
from core.pack_registry import pack_registry
from core.server import MCPServer
from core.signing import signer
from core.utils.logger import get_logger
from workers.pool import WorkerPool

logger = get_logger("forenzx.main")
BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BASE_DIR / "dashboard"

pack_registry.load_packs()
worker_pool = WorkerPool(config.worker_pool_size)
mcp_server = MCPServer(pool=worker_pool)


_health_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _health_task
    _register_dev_cases()
    pack_registry.load_packs()
    if config.mcp_auto_health_enabled:
        _health_task = asyncio.create_task(_health_monitor())
    logger.info(f"ForenZX MCP Hub v5 started in {config.environment} mode")
    try:
        yield
    finally:
        if _health_task:
            _health_task.cancel()
            with suppress(asyncio.CancelledError):
                await _health_task
            _health_task = None


app = FastAPI(
    lifespan=lifespan,
    title="ForenZX MCP Hub",
    version="5.0.0",
    description="Forensic MCP control plane, remote MCP registry and maintenance dashboard",
)

if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

if config.environment == "production":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type", "MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.allowed_origins or ["http://localhost:8000"],
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "X-API-Key",
            "Content-Type",
            "X-Dev-Bypass",
            "MCP-Protocol-Version",
            "Mcp-Method",
            "Mcp-Name",
        ],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if config.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class AuthConfig:
    @staticmethod
    def api_key_user(api_key: str) -> Optional[TokenUser]:
        if api_key in config.admin_api_keys:
            digest = hashlib.sha256(api_key.encode()).hexdigest()[:12]
            return TokenUser(user_id=f"admin_key_{digest}", roles=["admin", "analyst"], organization="default_org")
        if api_key in config.api_keys:
            digest = hashlib.sha256(api_key.encode()).hexdigest()[:12]
            return TokenUser(user_id=f"api_key_{digest}", roles=["analyst"], organization="default_org")
        return None

    @staticmethod
    def jwt_user(token: str) -> Optional[TokenUser]:
        try:
            payload = jwt.decode(
                token,
                config.jwt_secret_key,
                algorithms=["HS256"],
                options={"verify_signature": True, "verify_exp": True, "require": ["exp"]},
            )
            user_id = payload.get("sub") or payload.get("user_id")
            if not user_id:
                return None
            roles = payload.get("roles", ["analyst"])
            if isinstance(roles, str):
                roles = [roles]
            if not isinstance(roles, list):
                return None
            return TokenUser(
                user_id=str(user_id),
                roles=[str(x) for x in roles],
                organization=str(payload.get("organization") or payload.get("org") or "default_org"),
            )
        except Exception:
            return None

    # v4 compatibility helpers used by older integrations/tests.
    verify_jwt = jwt_user

    @staticmethod
    def verify_api_key(api_key: str) -> bool:
        return AuthConfig.api_key_user(api_key) is not None


async def get_current_user(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    x_api_key: Annotated[Optional[str], Header()] = None,
) -> TokenUser:
    api_key = x_api_key
    if not api_key and authorization and authorization.startswith("APIKey "):
        api_key = authorization[7:].strip()
    if api_key:
        user = AuthConfig.api_key_user(api_key)
        if user:
            return user
        raise HTTPException(status_code=401, detail="Invalid API key")

    if authorization and authorization.startswith("Bearer "):
        user = AuthConfig.jwt_user(authorization[7:].strip())
        if user:
            return user
        raise HTTPException(status_code=401, detail="Invalid or expired JWT", headers={"WWW-Authenticate": "Bearer"})

    if config.environment in {"development", "test"} and request.headers.get("X-Dev-Bypass") == "allowed":
        return TokenUser(user_id="dev_analyst", roles=["analyst"], organization="dev_org")
    raise HTTPException(status_code=401, detail="Authentication required")


async def get_admin(user: TokenUser = Depends(get_current_user)) -> TokenUser:
    if "admin" not in user.roles:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _register_dev_cases() -> None:
    if config.environment in {"development", "test"}:
        case_access_provider.register_case("CASE-001", "dev_analyst", "dev_org")
        case_access_provider.register_case("CASE-002", "dev_analyst", "dev_org")


async def _health_monitor() -> None:
    while True:
        try:
            for server in mcp_registry.list():
                if server["enabled"]:
                    await mcp_registry.probe(server["id"])
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"MCP health monitor error: {exc}")
        await asyncio.sleep(max(15, config.mcp_health_interval_seconds))


@app.get("/")
async def root():
    return (
        RedirectResponse("/dashboard")
        if config.dashboard_enabled
        else JSONResponse({"service": "forenzx_mcp", "version": "5.0.0"})
    )


@app.get("/dashboard")
async def dashboard():
    if not config.dashboard_enabled:
        raise HTTPException(status_code=404)
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.post("/mcp")
async def handle_mcp(
    request: Request,
    user: TokenUser = Depends(get_current_user),
    mcp_protocol_version: Annotated[Optional[str], Header(alias="MCP-Protocol-Version")] = None,
    mcp_method: Annotated[Optional[str], Header(alias="Mcp-Method")] = None,
    mcp_name: Annotated[Optional[str], Header(alias="Mcp-Name")] = None,
):
    if mcp_protocol_version and mcp_protocol_version != mcp_server.MCP_PROTOCOL_VERSION:
        raise HTTPException(status_code=400, detail=f"Unsupported MCP protocol version: {mcp_protocol_version}")
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="MCP request must be a JSON object")
    if mcp_method and body.get("method") != mcp_method:
        raise HTTPException(status_code=400, detail="Mcp-Method header/body mismatch")
    if mcp_name and body.get("method") == "tools/call" and (body.get("params") or {}).get("name") != mcp_name:
        raise HTTPException(status_code=400, detail="Mcp-Name header/body mismatch")
    raw = json.dumps(body)
    return JSONResponse(content=json.loads(await mcp_server.process_json_rpc(raw, user=user)))


@app.post("/mcp/jsonrpc")
async def legacy_mcp(request: Request, user: TokenUser = Depends(get_current_user)):
    """Compatibility route for v4 clients. New integrations should use POST /mcp."""
    raw = (await request.body()).decode("utf-8")
    response = JSONResponse(content=json.loads(await mcp_server.process_json_rpc(raw, user=user)))
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</mcp>; rel="successor-version"'
    return response


@app.get("/api/v1/jobs/{job_id}/events")
async def stream_job_events(job_id: str, user: TokenUser = Depends(get_current_user)):
    spec = job_manager.get_spec(job_id)
    if not spec:
        raise HTTPException(status_code=404, detail="Job not found")
    CaseAccessController.enforce_job_access(user, job_id, spec.case_id)

    async def event_generator():
        while True:
            st = job_manager.get_status(job_id)
            if not st:
                yield 'data: {"error":"Job not found"}\n\n'
                return
            yield f"data: {st.model_dump_json()}\n\n"
            if st.state.value in {"COMPLETED", "FAILED", "CANCELLED", "SECURITY_BLOCKED"}:
                return
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/health/live")
async def health_live():
    return {"status": "ALIVE", "version": "5.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health/ready")
async def health_ready():
    enabled_packs = [p for p in pack_registry.list_packs() if p.enabled]
    errors = pack_registry.errors()
    state = "READY"
    status_code = 200
    if errors:
        state = "DEGRADED"
    if config.environment == "production" and not enabled_packs:
        state = "BLOCKED"
        status_code = 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": state,
            "version": "5.0.0",
            "database": "READY" if config.database_path.exists() else "DEGRADED",
            "packs_enabled": len(enabled_packs),
            "pack_errors": errors,
            "signing": signer.public_info(),
        },
    )


@app.get("/health")
async def health_compat():
    return await health_live()


@app.get("/api/system/capabilities")
async def capabilities(user: TokenUser = Depends(get_current_user)):
    return {
        "service": "forenzx_mcp",
        "version": "5.0.0",
        "mcpProtocol": "2026-07-28",
        "dashboard": config.dashboard_enabled,
        "packs": pack_registry.describe(),
        "signing": signer.public_info(),
    }


@app.get("/api/keys")
async def public_keys():
    return {"keys": [signer.public_info()]}


# ---- MCP Manager API -------------------------------------------------------
@app.get("/api/v1/mcp-servers")
async def list_mcp_servers(_: TokenUser = Depends(get_admin)):
    return {"servers": mcp_registry.list()}


@app.post("/api/v1/mcp-servers", status_code=201)
async def create_mcp_server(payload: MCPServerCreate, user: TokenUser = Depends(get_admin)):
    return mcp_registry.create(payload, user.user_id)


@app.put("/api/v1/mcp-servers/{server_id}")
async def update_mcp_server(server_id: str, payload: MCPServerUpdate, user: TokenUser = Depends(get_admin)):
    result = mcp_registry.update(server_id, payload, user.user_id)
    if not result:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return result


@app.delete("/api/v1/mcp-servers/{server_id}")
async def delete_mcp_server(server_id: str, user: TokenUser = Depends(get_admin)):
    if not mcp_registry.delete(server_id, user.user_id):
        raise HTTPException(status_code=404, detail="MCP server not found")
    return {"ok": True}


@app.post("/api/v1/mcp-servers/{server_id}/toggle")
async def toggle_mcp_server(server_id: str, enabled: bool = Body(embed=True), user: TokenUser = Depends(get_admin)):
    result = mcp_registry.toggle(server_id, enabled, user.user_id)
    if not result:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return result


@app.post("/api/v1/mcp-servers/{server_id}/probe")
async def probe_mcp_server(server_id: str, user: TokenUser = Depends(get_admin)):
    try:
        return await mcp_registry.probe(server_id, user.user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="MCP server not found")


@app.get("/api/v1/mcp-servers/{server_id}/tools")
async def mcp_server_tools(server_id: str, _: TokenUser = Depends(get_admin)):
    try:
        return {"tools": await mcp_registry.tools(server_id)}
    except KeyError:
        raise HTTPException(status_code=404, detail="MCP server not found")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.put("/api/v1/mcp-servers/{server_id}/trust")
async def set_mcp_server_trust(
    server_id: str,
    trust_state: str = Body(embed=True),
    user: TokenUser = Depends(get_admin),
    x_trace_id: Annotated[Optional[str], Header()] = None,
):
    """Explicitly set remote MCP trust state (admin decision, never automatic).

    HEALTHY != TRUSTED: probes never promote a server; only this endpoint does.
    """
    from core.mcp_registry import VALID_TRUST_STATES

    if trust_state not in VALID_TRUST_STATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid trust_state; expected one of {sorted(VALID_TRUST_STATES)}",
        )
    result = mcp_registry.set_trust_state(server_id, trust_state, user.user_id, trace_id=x_trace_id)
    if not result:
        raise HTTPException(status_code=404, detail="MCP server not found")
    return result


@app.post("/api/v1/mcp-servers/{server_id}/restart")
async def restart_mcp_server(server_id: str, user: TokenUser = Depends(get_admin)):
    try:
        return await mcp_registry.restart(server_id, user.user_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="MCP server not found")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ---- Operations API -------------------------------------------------------
@app.get("/api/v1/ops/summary")
async def ops_summary(_: TokenUser = Depends(get_admin)):
    return system_summary()


@app.get("/api/v1/ops/events")
async def ops_events(limit: int = 100, _: TokenUser = Depends(get_admin)):
    limit = max(1, min(500, limit))
    return {"events": db.fetchall("SELECT * FROM registry_events ORDER BY id DESC LIMIT ?", (limit,))}


@app.get("/api/v1/ops/jobs")
async def ops_jobs(limit: int = 100, _: TokenUser = Depends(get_admin)):
    return {"jobs": job_manager.list_recent(limit)}


@app.get("/api/v1/ops/packs")
async def ops_packs(_: TokenUser = Depends(get_admin)):
    return {"packs": pack_registry.describe(), "errors": pack_registry.errors()}


@app.post("/api/v1/ops/packs/reload")
async def reload_packs(user: TokenUser = Depends(get_admin)):
    pack_registry.load_packs()
    db.event(user.user_id, "PACKS_RELOAD", None, True, {"count": len(pack_registry.list_packs())})
    return {"packs": pack_registry.describe(), "errors": pack_registry.errors()}


@app.post("/api/v1/ops/packs/{pack_id}/digest")
async def set_pack_digest(pack_id: str, digest: str = Body(embed=True), user: TokenUser = Depends(get_admin)):
    try:
        result = pack_registry.set_digest(pack_id, digest)
        db.event(user.user_id, "PACK_DIGEST_UPDATE", pack_id, True, {"digest": digest[:20] + "…"})
        return result
    except KeyError:
        raise HTTPException(status_code=404, detail="Pack not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/v1/ops/maintenance/vacuum")
async def maintenance_vacuum(user: TokenUser = Depends(get_admin)):
    vacuum_database()
    db.event(user.user_id, "DB_VACUUM", None, True, {})
    return {"ok": True, "summary": system_summary()}


@app.post("/api/v1/ops/maintenance/prune")
async def maintenance_prune(days: int = Body(default=30, embed=True), user: TokenUser = Depends(get_admin)):
    deleted = prune_events(days)
    db.event(user.user_id, "AUDIT_PRUNE", None, True, {"days": days, "deleted": deleted})
    return {"ok": True, "deleted": deleted}


@app.post("/api/v1/ops/maintenance/backup")
async def maintenance_backup(user: TokenUser = Depends(get_admin)):
    path = backup_database()
    db.event(user.user_id, "DB_BACKUP", None, True, {"file": path.name})
    return {"ok": True, "file": path.name, "download": f"/api/v1/ops/backups/{path.name}"}


@app.get("/api/v1/ops/backups/{name}")
async def download_backup(name: str, _: TokenUser = Depends(get_admin)):
    safe = Path(name).name
    path = (config.backups_dir / safe).resolve()
    if path.parent != config.backups_dir.resolve() or not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@app.get("/api/v1/ops/registry-export")
async def registry_export(_: TokenUser = Depends(get_admin)):
    return export_registry()


async def run_cli_stdio() -> None:
    logger.info("ForenZX MCP Engine running in STDIO compatibility mode")
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    user = TokenUser(user_id="cli_examiner", roles=["admin", "analyst"], organization="local")
    while True:
        line = await reader.readline()
        if not line:
            break
        text = line.decode().strip()
        if text:
            print(await mcp_server.process_json_rpc(text, user=user), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="ForenZX MCP Hub v5")
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()
    if args.stdio:
        asyncio.run(run_cli_stdio())
    else:
        uvicorn.run(
            "core.main:app",
            host=args.host or config.host,
            port=args.port or config.port,
            reload=config.environment == "development",
            log_level="info",
        )


if __name__ == "__main__":
    main()
