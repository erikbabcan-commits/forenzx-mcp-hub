"""Synthetic credentials must never appear in registry API projections or export."""

from __future__ import annotations

import json

import pytest

from core.db import db
from core.maintenance import export_registry
from core.mcp_registry import MCPRegistry, MCPServerCreate


@pytest.fixture
def isolated_db(tmp_path):
    original_path = db.path
    db.path = tmp_path / "registry-redaction.db"
    db.init_schema()
    try:
        yield
    finally:
        db.path = original_path


def test_custom_header_values_remain_write_only(isolated_db):
    registry = MCPRegistry()
    secret = "synthetic-regression-secret-DO-NOT-USE"
    created = registry.create(
        MCPServerCreate(
            name="Synthetic remote MCP",
            url="https://example.com/mcp",
            custom_headers={"Authorization": f"Bearer {secret}", "X-Partner-Token": secret},
        ),
        actor="pytest",
    )

    assert created["has_custom_headers"] is True
    assert created["custom_header_names"] == ["Authorization", "X-Partner-Token"]
    assert "custom_headers" not in created
    assert secret not in json.dumps(created)

    listed = registry.list()
    assert len(listed) == 1
    assert secret not in json.dumps(listed)
    assert secret not in json.dumps(registry.get(created["id"]))

    exported = export_registry()
    assert exported["version"] == 2
    assert exported["secrets_included"] is False
    assert exported["custom_header_values_included"] is False
    assert exported["servers"][0]["custom_header_names"] == ["Authorization", "X-Partner-Token"]
    assert "custom_headers" not in exported["servers"][0]
    assert secret not in json.dumps(exported)

    # Credentials must still work for an explicitly configured outbound request.
    raw = registry.get(created["id"], public=False)
    assert registry._headers(raw)["Authorization"] == f"Bearer {secret}"
