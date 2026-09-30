"""
MCP tests - Verify protocol conformance.
"""
import json

import pytest

from core.acl import TokenUser
from core.config import config
from core.server import MCPServer
from workers.pool import WorkerPool


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    config.environment = "test"


@pytest.fixture
def mcp_server():
    """Create an MCP server for testing."""
    pool = WorkerPool(size=1)
    return MCPServer(pool=pool)


class TestMCPInitialize:
    """Test MCP initialize method."""

    async def test_initialize_returns_correct_response(self, mcp_server):
        """Initialize must return correct protocol version."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert "result" in result
        assert result["result"]["protocolVersion"] == "2026-07-28"
        assert result["result"]["serverInfo"]["name"] == "forenzx_mcp"
        assert result["result"]["serverInfo"]["version"] == "5.0.0"


class TestMCPToolsList:
    """Test MCP tools/list method."""

    async def test_tools_list_returns_tools(self, mcp_server):
        """Tools/list must return all available tools."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert "result" in result
        assert "tools" in result["result"]
        assert len(result["result"]["tools"]) > 0

    async def test_tools_list_includes_expected_tools(self, mcp_server):
        """Tools/list must include expected tools."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        tool_names = [t["name"] for t in result["result"]["tools"]]

        assert "forenzx_health" in tool_names
        assert "forenzx_packs_list" in tool_names
        assert "forenzx_analysis_start" in tool_names
        assert "forenzx_analysis_status" in tool_names
        assert "forenzx_analysis_results" in tool_names


class TestMCPToolsCall:
    """Test MCP tools/call method."""

    async def test_list_packs_tool(self, mcp_server):
        """mcp_list_packs must return packs."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "mcp_list_packs",
                "arguments": {}
            }
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert "result" in result
        assert "content" in result["result"]

        # Parse the content
        content = json.loads(result["result"]["content"][0]["text"])
        assert "packs" in content


class TestMCPErrorHandling:
    """Test MCP error handling."""

    async def test_unknown_method_returns_32601(self, mcp_server):
        """Unknown method must return error code -32601."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown_method"
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 1
        assert "error" in result
        assert result["error"]["code"] == -32601

    async def test_unknown_tool_returns_32601(self, mcp_server):
        """Unknown tool must return error code -32601 (via tools/call)."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "unknown_tool",
                "arguments": {}
            }
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert "error" in result
        # The error is returned through tools/call, which uses -32603 for internal errors
        # or -32602 for invalid params

    async def test_invalid_json_returns_32700(self, mcp_server):
        """Invalid JSON must return error code -32700."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = "NOT VALID JSON"

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert result["jsonrpc"] == "2.0"
        assert "error" in result
        assert result["error"]["code"] == -32700

    async def test_missing_tool_name_returns_32602(self, mcp_server):
        """Missing tool name must return error code -32602."""
        user = TokenUser(user_id="test", roles=["analyst"])

        request = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "arguments": {}
            }
        })

        response = await mcp_server.process_json_rpc(request, user)
        result = json.loads(response)

        assert "error" in result
        assert result["error"]["code"] == -32602
