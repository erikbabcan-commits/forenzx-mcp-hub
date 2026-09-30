"""Remote MCP registry, encrypted credentials and safe health/tool discovery."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import uuid4

import httpx
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field, HttpUrl, field_validator

from core.config import config
from core.db import db, utcnow


ServerType = Literal["forenzx", "generic", "filesystem", "github", "database", "browser", "custom"]
TransportType = Literal["streamable_http", "legacy_jsonrpc"]
AuthType = Literal["none", "bearer", "api_key"]


class MCPServerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    server_type: ServerType = "generic"
    url: HttpUrl
    transport: TransportType = "streamable_http"
    enabled: bool = True
    auth_type: AuthType = "none"
    auth_secret: str | None = Field(default=None, max_length=8192)
    custom_headers: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=32)
    notes: str = Field(default="", max_length=4000)
    maintenance_url: HttpUrl | None = None

    @field_validator("custom_headers")
    @classmethod
    def safe_headers(cls, value: dict[str, str]) -> dict[str, str]:
        forbidden = {"host", "content-length", "transfer-encoding", "connection"}
        out: dict[str, str] = {}
        for k, v in value.items():
            if k.lower() in forbidden:
                raise ValueError(f"Header {k} is not allowed")
            if len(k) > 128 or len(v) > 4096:
                raise ValueError("Header too long")
            out[k] = v
        return out


class MCPServerUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    server_type: ServerType | None = None
    url: HttpUrl | None = None
    transport: TransportType | None = None
    enabled: bool | None = None
    auth_type: AuthType | None = None
    auth_secret: str | None = Field(default=None, max_length=8192)
    clear_auth_secret: bool = False
    custom_headers: dict[str, str] | None = None
    tags: list[str] | None = None
    notes: str | None = Field(default=None, max_length=4000)
    maintenance_url: HttpUrl | None = None
    clear_maintenance_url: bool = False


class MCPRegistry:
    def __init__(self) -> None:
        digest = hashlib.sha256(config.server_hmac_signing_key.encode("utf-8")).digest()
        self._fernet = Fernet(base64.urlsafe_b64encode(digest))

    def _encrypt(self, secret: str | None) -> str | None:
        if not secret:
            return None
        return self._fernet.encrypt(secret.encode("utf-8")).decode("ascii")

    def _decrypt(self, token: str | None) -> str | None:
        if not token:
            return None
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": row["id"], "name": row["name"], "server_type": row["server_type"], "url": row["url"],
            "transport": row["transport"], "enabled": bool(row["enabled"]), "auth_type": row["auth_type"],
            "has_auth_secret": bool(row.get("auth_secret_encrypted")),
            "custom_headers": json.loads(row.get("custom_headers_json") or "{}"),
            "tags": json.loads(row.get("tags_json") or "[]"), "notes": row.get("notes") or "",
            "maintenance_url": row.get("maintenance_url"), "created_at": row["created_at"], "updated_at": row["updated_at"],
            "last_checked_at": row.get("last_checked_at"), "last_status": row.get("last_status") or "UNKNOWN",
            "last_latency_ms": row.get("last_latency_ms"), "last_error": row.get("last_error"),
            "last_tools": json.loads(row.get("last_tools_json") or "[]"),
        }

    def list(self) -> list[dict[str, Any]]:
        return [self._public(r) for r in db.fetchall("SELECT * FROM mcp_servers ORDER BY name COLLATE NOCASE")]

    def get(self, server_id: str, public: bool = True) -> dict[str, Any] | None:
        row = db.fetchone("SELECT * FROM mcp_servers WHERE id=?", (server_id,))
        if not row:
            return None
        return self._public(row) if public else row

    def create(self, payload: MCPServerCreate, actor: str) -> dict[str, Any]:
        server_id = str(uuid4())
        now = utcnow()
        db.execute(
            """INSERT INTO mcp_servers(id,name,server_type,url,transport,enabled,auth_type,auth_secret_encrypted,
            custom_headers_json,tags_json,notes,maintenance_url,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (server_id, payload.name, payload.server_type, str(payload.url), payload.transport, int(payload.enabled),
             payload.auth_type, self._encrypt(payload.auth_secret), json.dumps(payload.custom_headers), json.dumps(payload.tags),
             payload.notes, str(payload.maintenance_url) if payload.maintenance_url else None, now, now),
        )
        db.event(actor, "MCP_SERVER_CREATE", server_id, True, {"name": payload.name, "type": payload.server_type})
        return self.get(server_id) or {}

    def update(self, server_id: str, payload: MCPServerUpdate, actor: str) -> dict[str, Any] | None:
        row = self.get(server_id, public=False)
        if not row:
            return None
        data = payload.model_dump(exclude_unset=True)
        mapping = {
            "name": "name", "server_type": "server_type", "url": "url", "transport": "transport",
            "enabled": "enabled", "auth_type": "auth_type", "notes": "notes"
        }
        sets: list[str] = []
        values: list[Any] = []
        for key, column in mapping.items():
            if key in data:
                val = data[key]
                if key == "url" and val is not None:
                    val = str(val)
                if key == "enabled":
                    val = int(bool(val))
                sets.append(f"{column}=?")
                values.append(val)
        if "custom_headers" in data and data["custom_headers"] is not None:
            sets.append("custom_headers_json=?"); values.append(json.dumps(data["custom_headers"]))
        if "tags" in data and data["tags"] is not None:
            sets.append("tags_json=?"); values.append(json.dumps(data["tags"]))
        if data.get("clear_auth_secret"):
            sets.append("auth_secret_encrypted=?"); values.append(None)
        elif "auth_secret" in data and data["auth_secret"] is not None:
            sets.append("auth_secret_encrypted=?"); values.append(self._encrypt(data["auth_secret"]))
        if data.get("clear_maintenance_url"):
            sets.append("maintenance_url=?"); values.append(None)
        elif "maintenance_url" in data and data["maintenance_url"] is not None:
            sets.append("maintenance_url=?"); values.append(str(data["maintenance_url"]))
        sets.append("updated_at=?"); values.append(utcnow())
        values.append(server_id)
        db.execute(f"UPDATE mcp_servers SET {', '.join(sets)} WHERE id=?", tuple(values))
        db.event(actor, "MCP_SERVER_UPDATE", server_id, True, {"fields": sorted(k for k in data if k not in {"auth_secret"})})
        return self.get(server_id)

    def delete(self, server_id: str, actor: str) -> bool:
        if not self.get(server_id, public=False):
            return False
        db.execute("DELETE FROM mcp_servers WHERE id=?", (server_id,))
        db.event(actor, "MCP_SERVER_DELETE", server_id, True, {})
        return True

    def toggle(self, server_id: str, enabled: bool, actor: str) -> dict[str, Any] | None:
        if not self.get(server_id, public=False):
            return None
        db.execute("UPDATE mcp_servers SET enabled=?, updated_at=? WHERE id=?", (int(enabled), utcnow(), server_id))
        db.event(actor, "MCP_SERVER_TOGGLE", server_id, True, {"enabled": enabled})
        return self.get(server_id)

    def _headers(self, row: dict[str, Any]) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        headers.update(json.loads(row.get("custom_headers_json") or "{}"))
        secret = self._decrypt(row.get("auth_secret_encrypted"))
        if row.get("auth_type") == "bearer" and secret:
            headers["Authorization"] = f"Bearer {secret}"
        elif row.get("auth_type") == "api_key" and secret:
            headers["X-API-Key"] = secret
        if row.get("transport") == "streamable_http":
            headers["MCP-Protocol-Version"] = "2026-07-28"
        return headers

    async def _rpc(self, row: dict[str, Any], method: str, params: dict[str, Any] | None = None) -> tuple[dict[str, Any], int]:
        body = {"jsonrpc": "2.0", "id": f"hub-{int(time.time()*1000)}", "method": method}
        if params is not None:
            body["params"] = params
        started = time.perf_counter()
        async with httpx.AsyncClient(timeout=config.mcp_probe_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(row["url"], headers=self._headers(row), json=body)
            latency = int((time.perf_counter() - started) * 1000)
            response.raise_for_status()
            ctype = response.headers.get("content-type", "")
            if "application/json" not in ctype and not response.text.lstrip().startswith("{"):
                raise ValueError(f"Unexpected content type: {ctype or 'unknown'}")
            return response.json(), latency

    async def probe(self, server_id: str, actor: str = "health-monitor") -> dict[str, Any]:
        row = self.get(server_id, public=False)
        if not row:
            raise KeyError(server_id)
        if not bool(row["enabled"]):
            result = {"status": "DISABLED", "latency_ms": None, "error": None, "tools": []}
            self._store_probe(server_id, result)
            return result
        try:
            data, latency = await self._rpc(row, "tools/list", {})
            if "error" in data:
                raise ValueError(data["error"].get("message", "MCP error"))
            tools = [t.get("name", "") for t in data.get("result", {}).get("tools", []) if t.get("name")]
            result = {"status": "READY", "latency_ms": latency, "error": None, "tools": tools}
            self._store_probe(server_id, result)
            db.event(actor, "MCP_SERVER_PROBE", server_id, True, {"latency_ms": latency, "tool_count": len(tools)})
            return result
        except Exception as exc:
            result = {"status": "DOWN", "latency_ms": None, "error": str(exc)[:1000], "tools": []}
            self._store_probe(server_id, result)
            db.event(actor, "MCP_SERVER_PROBE", server_id, False, {"error": str(exc)[:500]})
            return result

    def _store_probe(self, server_id: str, result: dict[str, Any]) -> None:
        db.execute(
            "UPDATE mcp_servers SET last_checked_at=?, last_status=?, last_latency_ms=?, last_error=?, last_tools_json=? WHERE id=?",
            (utcnow(), result["status"], result["latency_ms"], result["error"], json.dumps(result["tools"]), server_id),
        )

    async def tools(self, server_id: str) -> list[dict[str, Any]]:
        row = self.get(server_id, public=False)
        if not row:
            raise KeyError(server_id)
        data, _ = await self._rpc(row, "tools/list", {})
        if "error" in data:
            raise ValueError(data["error"].get("message", "MCP error"))
        return data.get("result", {}).get("tools", [])

    async def call_tool(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        row = self.get(server_id, public=False)
        if not row:
            raise KeyError(server_id)
        data, _ = await self._rpc(row, "tools/call", {"name": tool_name, "arguments": arguments})
        return data

    async def restart(self, server_id: str, actor: str) -> dict[str, Any]:
        row = self.get(server_id, public=False)
        if not row:
            raise KeyError(server_id)
        url = row.get("maintenance_url")
        if not url:
            raise ValueError("Maintenance URL is not configured for this server")
        headers = self._headers(row)
        headers.pop("MCP-Protocol-Version", None)
        async with httpx.AsyncClient(timeout=config.mcp_probe_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(url, headers=headers, json={"action": "restart"})
            response.raise_for_status()
        db.event(actor, "MCP_SERVER_RESTART", server_id, True, {})
        return {"ok": True, "status_code": response.status_code}


mcp_registry = MCPRegistry()
