"""Remote MCP trust model verification (ADR-0006).

HEALTHY != TRUSTED:
- a newly registered server defaults to UNVERIFIED,
- a successful health probe never promotes trust,
- trust changes only via an explicit, audited admin decision,
- invalid trust states are rejected.
"""

from __future__ import annotations

import re

import pytest

from core.db import db
from core.mcp_registry import MCPRegistry, MCPServerCreate


@pytest.fixture
def isolated_db(tmp_path):
    old = db.path
    db.path = tmp_path / "trust-test.db"
    db.init_schema()
    try:
        yield db.path
    finally:
        db.path = old


def _make_server(registry: MCPRegistry) -> dict:
    return registry.create(
        MCPServerCreate(name="Trusted-flow test", server_type="generic", url="https://example.com/mcp"),
        actor="pytest",
    )


class TestMCPTrustModel:
    def test_new_server_defaults_to_unverified(self, isolated_db):
        registry = MCPRegistry()
        created = _make_server(registry)
        assert created["trust_state"] == "UNVERIFIED"

    def test_successful_probe_does_not_promote_trust(self, isolated_db, monkeypatch):
        registry = MCPRegistry()
        created = _make_server(registry)
        server_id = created["id"]

        async def fake_rpc(row, method, params=None):
            return (
                {"result": {"tools": [{"name": "tool_a"}, {"name": "tool_b"}]}},
                5,
            )

        monkeypatch.setattr(registry, "_rpc", fake_rpc)
        result = registry.probe(server_id, actor="health-monitor")
        assert result["status"] == "READY"
        # HEALTHY != TRUSTED: probe may not touch trust_state
        assert registry.get(server_id)["trust_state"] == "UNVERIFIED"
        # but the tool surface hash is recorded for drift detection
        tools_hash = registry.get(server_id)["tools_hash"]
        assert tools_hash and re.fullmatch(r"[0-9a-f]{64}", tools_hash)

    def test_failed_probe_leaves_trust_untouched(self, isolated_db, monkeypatch):
        registry = MCPRegistry()
        created = _make_server(registry)

        async def failing_rpc(row, method, params=None):
            raise RuntimeError("connection refused")

        monkeypatch.setattr(registry, "_rpc", failing_rpc)
        result = registry.probe(created["id"])
        assert result["status"] == "DOWN"
        assert registry.get(created["id"])["trust_state"] == "UNVERIFIED"

    def test_explicit_trust_change_is_audited(self, isolated_db):
        registry = MCPRegistry()
        created = _make_server(registry)
        updated = registry.set_trust_state(created["id"], "TRUSTED", actor="admin-1", trace_id="trace-42")
        assert updated["trust_state"] == "TRUSTED"
        event = db.fetchone(
            "SELECT action, target_id, trace_id, details_json FROM registry_events "
            "WHERE action='MCP_SERVER_TRUST_CHANGE' ORDER BY id DESC"
        )
        assert event["target_id"] == created["id"]
        assert event["trace_id"] == "trace-42"
        assert '"to": "TRUSTED"' in event["details_json"]

    def test_quarantine_and_disable_states(self, isolated_db):
        registry = MCPRegistry()
        created = _make_server(registry)
        assert registry.set_trust_state(created["id"], "QUARANTINED", "a")["trust_state"] == "QUARANTINED"
        assert registry.set_trust_state(created["id"], "DISABLED", "a")["trust_state"] == "DISABLED"

    def test_invalid_trust_state_rejected(self, isolated_db):
        registry = MCPRegistry()
        created = _make_server(registry)
        with pytest.raises(ValueError, match="Invalid trust state"):
            registry.set_trust_state(created["id"], "SUPER_TRUSTED", "a")

    def test_unknown_server_returns_none(self, isolated_db):
        registry = MCPRegistry()
        assert registry.set_trust_state("no-such-id", "TRUSTED", "a") is None
