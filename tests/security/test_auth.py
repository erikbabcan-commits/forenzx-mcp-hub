"""
Authentication tests - Verify production auth doesn't allow fake admin.
"""

import os

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from core.acl import TokenUser
from core.config import config
from core.main import app


@pytest.fixture
def test_client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_env():
    """Setup test environment."""
    os.environ["ENVIRONMENT"] = "test"
    from core.config import config

    config.environment = "test"


class TestAuthentication:
    """Test authentication flow."""

    def test_production_missing_auth_fails(self, monkeypatch):
        """Production: missing credential -> HTTP 401"""
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "api_keys", [])

        client = TestClient(app)

        # Try to access MCP endpoint without auth
        response = client.post("/mcp/jsonrpc", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_production_invalid_api_key_fails(self, monkeypatch):
        """Production: invalid credential -> HTTP 401"""
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "api_keys", ["valid-key-123"])

        client = TestClient(app)

        response = client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"X-API-Key": "invalid-key"},
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_production_valid_api_key_succeeds(self, monkeypatch):
        """Production: valid API key -> success"""
        monkeypatch.setattr(config, "environment", "production")
        monkeypatch.setattr(config, "api_keys", ["valid-key-123"])

        client = TestClient(app)

        response = client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"X-API-Key": "valid-key-123"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "result" in data

    def test_dev_bypass_works_in_dev(self, monkeypatch):
        """Development: bypass works only in dev/test"""
        monkeypatch.setattr(config, "environment", "development")

        client = TestClient(app)

        response = client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"X-Dev-Bypass": "allowed"},
        )

        assert response.status_code == 200

    def test_dev_bypass_fails_in_production(self, monkeypatch):
        """Production: dev bypass explicitly blocked"""
        monkeypatch.setattr(config, "environment", "production")

        client = TestClient(app)

        response = client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"X-Dev-Bypass": "allowed"},
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_no_auto_admin_in_production(self, monkeypatch):
        """Production: never auto-assign admin role without auth"""
        monkeypatch.setattr(config, "environment", "production")

        # Even if someone tries to bypass, they shouldn't get admin
        client = TestClient(app)

        response = client.post("/mcp/jsonrpc", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

        # Must be 401, not 200 with admin user
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestTokenUser:
    """Test TokenUser creation."""

    def test_token_user_creation(self):
        """TokenUser can be created with proper fields."""
        user = TokenUser(user_id="test_user", roles=["analyst"], organization="test_org")

        assert user.user_id == "test_user"
        assert "analyst" in user.roles
        assert user.organization == "test_org"

    def test_token_user_not_admin_by_default(self):
        """TokenUser is not admin by default."""
        user = TokenUser(user_id="test_user", roles=["analyst"])

        assert "admin" not in user.roles
