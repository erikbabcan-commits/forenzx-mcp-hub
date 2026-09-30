from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.config import config
from core.db import db
from core.jobs import AsyncJobManager
from core.main import app
from core.mcp_registry import MCPRegistry, MCPServerCreate


@pytest.fixture
def isolated_db(tmp_path):
    old = db.path
    db.path = tmp_path / "hub-test.db"
    db.init_schema()
    try:
        yield db.path
    finally:
        db.path = old


def test_registry_encrypts_secret_and_never_returns_it(isolated_db):
    registry = MCPRegistry()
    created = registry.create(
        MCPServerCreate(
            name="Remote test",
            server_type="generic",
            url="https://example.com/mcp",
            auth_type="bearer",
            auth_secret="super-secret-token",
            tags=["test"],
        ),
        actor="pytest",
    )
    assert created["has_auth_secret"] is True
    assert "auth_secret" not in created
    raw = db.fetchone("SELECT auth_secret_encrypted FROM mcp_servers WHERE id=?", (created["id"],))
    assert raw is not None
    assert raw["auth_secret_encrypted"] != "super-secret-token"
    assert "super-secret-token" not in raw["auth_secret_encrypted"]


def test_job_idempotency_prevents_duplicate_rows(isolated_db):
    manager = AsyncJobManager()
    a, _ = manager.create_job("CASE-X", "EVID-X", "pack", "u", "o", idempotency_key="same")
    b, _ = manager.create_job("CASE-X", "EVID-X", "pack", "u", "o", idempotency_key="same")
    assert a == b
    row = db.fetchone("SELECT COUNT(*) AS c FROM jobs WHERE idempotency_key='same'")
    assert row and row["c"] == 1


def test_dashboard_management_api_requires_admin(monkeypatch, isolated_db):
    monkeypatch.setattr(config, "environment", "test")
    monkeypatch.setattr(config, "admin_api_keys", ["unit-admin-key"])
    client = TestClient(app)

    denied = client.get("/api/v1/mcp-servers", headers={"X-Dev-Bypass": "allowed"})
    assert denied.status_code == 403

    allowed = client.get("/api/v1/mcp-servers", headers={"X-API-Key": "unit-admin-key"})
    assert allowed.status_code == 200
    assert "servers" in allowed.json()


def test_modern_mcp_route_validates_routing_headers(monkeypatch):
    monkeypatch.setattr(config, "environment", "test")
    client = TestClient(app)
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

    ok = client.post(
        "/mcp",
        json=req,
        headers={
            "X-Dev-Bypass": "allowed",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/list",
        },
    )
    assert ok.status_code == 200
    assert "tools" in ok.json()["result"]

    mismatch = client.post(
        "/mcp",
        json=req,
        headers={"X-Dev-Bypass": "allowed", "Mcp-Method": "tools/call"},
    )
    assert mismatch.status_code == 400
