"""Vercel's read-only preview must never bootstrap persistent forensic services."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from api.index import app


@pytest.mark.asyncio
async def test_preview_root_and_favicon_are_served_without_persistent_storage():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert "Read-only technical preview" in page.text
        assert 'href="/favicon.svg"' in page.text
        assert "not a production deployment" in page.text

        icon_redirect = await client.get("/favicon.ico", follow_redirects=False)
        assert icon_redirect.status_code == 307
        assert icon_redirect.headers["location"] == "/favicon.svg"
        icon = await client.get("/favicon.ico", follow_redirects=True)
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/svg+xml")
        assert "<svg" in icon.text


@pytest.mark.asyncio
async def test_preview_reports_truthful_readiness_and_rejects_operations():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/health")).json() == {
            "service": "forenzx-mcp-hub",
            "status": "PREVIEW_ONLY",
            "persistent_backend": False,
        }
        assert (await client.get("/health/ready")).status_code == 503
        assert (await client.post("/mcp", json={"method": "tools/list"})).status_code == 503
        assert (await client.get("/dashboard")).json()["error"] == "PREVIEW_ONLY"


def test_vercel_entrypoint_does_not_import_stateful_core(tmp_path):
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(root)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    command = (
        "import api.index, sys; "
        "assert 'core.main' not in sys.modules; "
        "assert 'core.config' not in sys.modules; "
        "assert 'core.db' not in sys.modules; "
        "assert 'core.signing' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-c", command],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
