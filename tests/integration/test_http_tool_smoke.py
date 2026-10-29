"""Synthetic ASGI HTTP -> auth -> MCP dispatcher -> read-only tool round trip."""

import json

from fastapi.testclient import TestClient

from core.config import config
from core.main import app


def test_http_tool_call_requires_auth_and_returns_structured_packs(monkeypatch):
    monkeypatch.setattr(config, "environment", "production")
    monkeypatch.setattr(config, "api_keys", ["synthetic-analyst-fixture"])
    request = {
        "jsonrpc": "2.0",
        "id": 17,
        "method": "tools/call",
        "params": {"name": "mcp_list_packs", "arguments": {}},
    }
    client = TestClient(app)
    assert client.post("/mcp", json=request).status_code == 401
    accepted = client.post("/mcp", json=request, headers={"X-API-Key": "synthetic-analyst-fixture"})
    assert accepted.status_code == 200
    response = accepted.json()
    assert response["id"] == 17
    content = json.loads(response["result"]["content"][0]["text"])
    assert isinstance(content["packs"], list)
