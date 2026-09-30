import pytest

from core.config import config
from core.server import MCPServer
from workers.pool import WorkerPool


@pytest.mark.asyncio
async def test_analysis_start_advertises_presigned_evidence_contract():
    config.environment = "test"
    schema = await MCPServer(WorkerPool(size=1)).list_tools_schema()
    tool = next(item for item in schema if item["name"] == "forenzx_analysis_start")
    properties = tool["inputSchema"]["properties"]

    assert properties["download_url"]["pattern"] == "^https://"
    assert properties["download_filename"]["maxLength"] == 200
    assert "download_url" not in tool["inputSchema"]["required"]

