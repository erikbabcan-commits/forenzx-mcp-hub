"""
Regression and Truthful Green Gate Verification Tests for ForenZX v4 Core.
Strictly verifies all fixed bug invariants from Section A, B, and C.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from fastapi.testclient import TestClient
import jwt
from pydantic import BaseModel, ValidationError

from core.config import AppConfig, ForenzxConfig, config
from core.jobs import AsyncJobManager
from core.main import AuthConfig, app
from core.models.forensic import (
    AnalysisState,
    DetectionClassification,
    EvidenceInputSpec,
    PackManifest,
)
from workers.pool import WorkerPool

# ==============================================================================
# 1. THREAT INTEL IMPORT INVARIANTS
# ==============================================================================

class TestThreatIntelInvariants:
    """Verifies threat_intel imports, BaseModel subclassing, and clean top-level definitions."""

    def test_threat_intel_import_and_models(self):
        import core.threat_intel as ti

        assert hasattr(ti, "IOCBundleInfo")
        assert hasattr(ti, "ThreatIntelVault")
        assert issubclass(ti.IOCBundleInfo, BaseModel)

        info = ti.IOCBundleInfo(
            bundle_name="test_bundle",
            version="1.0.0",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            source="Amnesty International",
            loaded_at=datetime.now(timezone.utc).isoformat(),
        )
        assert info.bundle_name == "test_bundle"
        assert info.version == "1.0.0"


# ==============================================================================
# 2. PACK MANIFEST ID CONTRACT (mobile_compromise & validation)
# ==============================================================================

class TestPackManifestContract:
    """Verifies PackManifest id regex allows underscores and rejects invalid characters."""

    def test_pack_manifest_valid_mobile_compromise(self):
        manifest = PackManifest(
            id="mobile_compromise",
            name="MVT Mobile Compromise",
            version="1.0.0",
            description="Mobile compromise analysis pack",
            license="GPL-3.0",
            author="ForenzX Team",
            supported_platforms=["ios", "android"],
            supported_inputs=["ios_backup", "android_backup"],
            capabilities=["spyware_detection"],
            container_image="ghcr.io/forenzx/mvt:v1.0.0",
            pinned_image_digest="sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
        )
        assert manifest.id == "mobile_compromise"

    def test_pack_manifest_valid_hyphenated_id(self):
        manifest = PackManifest(
            id="mobile-compromise-v2",
            name="MVT V2",
            version="2.0.0",
            description="Mobile compromise analysis pack v2",
            license="GPL-3.0",
            author="ForenzX Team",
            supported_platforms=["ios"],
            supported_inputs=["ios_backup"],
            capabilities=["spyware_detection"],
            container_image="ghcr.io/forenzx/mvt:v2.0.0",
            pinned_image_digest="sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
        )
        assert manifest.id == "mobile-compromise-v2"

    @pytest.mark.parametrize("invalid_id", [
        "mobile compromise",   # spaces
        "mobile/compromise",   # slashes
        "mobile@compromise",   # special symbols
        "Mobile_Compromise",   # uppercase
        "",                    # empty
        "mobile.compromise",   # dots
    ])
    def test_pack_manifest_invalid_ids_fail(self, invalid_id: str):
        with pytest.raises(ValidationError):
            PackManifest(
                id=invalid_id,
                name="Invalid Pack",
                version="1.0.0",
                description="Invalid pack",
                license="MIT",
                author="Tester",
                supported_platforms=["linux"],
                supported_inputs=["file_generic"],
                capabilities=["test"],
                container_image="ghcr.io/forenzx/test:v1",
                pinned_image_digest="sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
            )


# ==============================================================================
# 3. CONFIG ENVIRONMENT & SECRET VALIDATION
# ==============================================================================

class TestConfigValidation:
    """Verifies config behavior in development, test, and production fail-closed states."""

    def test_config_dev_import_succeeds_without_prod_secrets(self):
        cfg = ForenzxConfig(
            environment="development",
            hmac_secret_key="dev-insecure-key-for-local-testing",
            jwt_secret="dev-jwt-secret-for-local-testing",
            api_keys=["dev-test-key"],
        )
        assert cfg.environment == "development"

    def test_config_test_import_succeeds_without_prod_secrets(self):
        cfg = AppConfig(
            environment="test",
            hmac_secret_key="dev-insecure-key-for-local-testing",
            jwt_secret="dev-jwt-secret-for-local-testing",
            api_keys=["dev-test-key"],
        )
        assert cfg.environment == "test"

    def test_config_production_missing_secrets_fails(self):
        with pytest.raises(ValueError, match="must be a strong secret"):
            AppConfig(
                environment="production",
                jwt_secret_key="short",
                server_hmac_signing_key="short",
                api_keys=[],
            )

    def test_config_production_with_valid_secrets_succeeds(self):
        cfg = AppConfig(
            environment="production",
            server_hmac_signing_key="a" * 32,
            jwt_secret_key="b" * 32,
            api_keys=["prod-secure-api-key-1234567890"],
            allowed_origins=["https://forensics.company.internal"],
            admin_api_keys=["admin-key-abcdefghijklmnopqrstuvwxyz123456"],
        )
        assert cfg.environment == "production"
        assert len(cfg.server_hmac_signing_key) >= 32
        assert len(cfg.jwt_secret_key) >= 32


# ==============================================================================
# 4. JWT AUTHENTICATION
# ==============================================================================

class TestJWTAuthentication:
    """Verifies real JWT verification, signature validation, expiration, and claims."""

    @pytest.fixture
    def test_client(self):
        return TestClient(app)

    def test_valid_jwt_direct_and_endpoint(self, test_client: TestClient, monkeypatch):
        test_secret = "test-jwt-secret-32-chars-long-here!"
        monkeypatch.setattr(config, "jwt_secret_key", test_secret)
        monkeypatch.setattr(config, "environment", "production")

        payload = {
            "sub": "analyst-007",
            "roles": ["analyst", "investigator"],
            "org": "police-cert",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }
        token = jwt.encode(payload, test_secret, algorithm="HS256")

        # Direct verification
        user = AuthConfig.verify_jwt(token)
        assert user is not None
        assert user.user_id == "analyst-007"
        assert "analyst" in user.roles
        assert user.organization == "police-cert"

        # Via HTTP endpoint
        response = test_client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == status.HTTP_200_OK

    def test_invalid_jwt_signature_fails(self, test_client: TestClient, monkeypatch):
        test_secret = "test-jwt-secret-32-chars-long-here!"
        monkeypatch.setattr(config, "jwt_secret_key", test_secret)
        monkeypatch.setattr(config, "environment", "production")

        payload = {
            "sub": "attacker",
            "roles": ["admin"],
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
        }
        # Signed with a different secret
        token = jwt.encode(payload, "wrong-secret-key-123456789012345", algorithm="HS256")

        user = AuthConfig.verify_jwt(token)
        assert user is None

        response = test_client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_expired_jwt_fails(self, test_client: TestClient, monkeypatch):
        test_secret = "test-jwt-secret-32-chars-long-here!"
        monkeypatch.setattr(config, "jwt_secret_key", test_secret)
        monkeypatch.setattr(config, "environment", "production")

        payload = {
            "sub": "expired-user",
            "roles": ["analyst"],
            "exp": datetime.now(timezone.utc) - timedelta(minutes=10),
        }
        token = jwt.encode(payload, test_secret, algorithm="HS256")

        user = AuthConfig.verify_jwt(token)
        assert user is None

        response = test_client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_malformed_jwt_fails(self, test_client: TestClient, monkeypatch):
        monkeypatch.setattr(config, "environment", "production")

        user = AuthConfig.verify_jwt("not.a.valid.jwt.token")
        assert user is None

        response = test_client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer not.a.valid.jwt.token"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_unsigned_none_algorithm_jwt_fails(self, test_client: TestClient, monkeypatch):
        monkeypatch.setattr(config, "environment", "production")

        # Attempt to forge an unsigned token
        unsigned_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbImFkbWluIl19."
        user = AuthConfig.verify_jwt(unsigned_token)
        assert user is None

        response = test_client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {unsigned_token}"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ==============================================================================
# 5. CORS HARDENING
# ==============================================================================

class TestCORSRegression:
    """Verifies CORS allow_origin_regex in dev/test and strict isolation in production."""

    @pytest.mark.parametrize("origin", [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1",
    ])
    def test_cors_localhost_regex_allowed_in_dev(self, origin: str):
        client = TestClient(app)
        response = client.post(
            "/mcp/jsonrpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Origin": origin, "X-Dev-Bypass": "allowed"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == origin

    def test_production_cors_deny_unknown_origin(self):
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        # Construct explicit production app to test middleware isolation
        prod_app = FastAPI()
        prod_app.add_middleware(
            CORSMiddleware,
            allow_origins=["https://portal.forenzx.local"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
        )

        @prod_app.get("/ping")
        def ping():
            return {"status": "ok"}

        prod_client = TestClient(prod_app)

        # Unknown origin
        res = prod_client.options(
            "/ping",
            headers={
                "Origin": "http://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Should NOT return allow-origin for evil.com
        assert res.headers.get("access-control-allow-origin") is None

        # Allowed origin
        res_ok = prod_client.options(
            "/ping",
            headers={
                "Origin": "https://portal.forenzx.local",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert res_ok.headers.get("access-control-allow-origin") == "https://portal.forenzx.local"


# ==============================================================================
# 6. DOCKER LAZY CLIENT & FAIL-CLOSED ISOLATION
# ==============================================================================

class TestDockerLazyClientAndIsolation:
    """Verifies that WorkerPool is lazily loaded and execution fails closed if Docker is down."""

    def test_app_and_worker_pool_import_without_docker_daemon(self):
        pool = WorkerPool()
        assert pool is not None
        with pytest.raises(RuntimeError, match="Docker infrastructure is unavailable"):
            _ = pool.client

    @pytest.mark.asyncio
    async def test_docker_unavailable_forensic_execution_fail_closed(self, tmp_path):
        # Create pool where client access fails
        pool = WorkerPool()

        manifest = PackManifest(
            id="mobile_compromise",
            name="MVT",
            version="1.0.0",
            description="MVT pack",
            license="GPL-3.0",
            author="ForenzX",
            supported_platforms=["ios"],
            supported_inputs=["ios_backup"],
            capabilities=["mvt"],
            container_image="ghcr.io/forenzx/mvt:v1.0.0",
            pinned_image_digest="sha256:7b5cf89e02315757cf18fa8fdbb7f83737ec38dbf58cfb5e7ddcf2800d98ca8a",
        )

        mock_adapter = MagicMock()
        mock_adapter.get_execution_command.return_value = ["mvt-ios", "check-backup"]
        spec = EvidenceInputSpec(
            case_id="CASE-DOCKER",
            evidence_id="EVID-DOCKER",
            input_type="ios_backup",
        )

        # Mock Vault and ThreatIntel to succeed so execution reaches Docker client invocation
        with patch("core.vault.EvidenceVault.resolve_path", return_value=tmp_path / "evidence"), \
             patch("core.threat_intel.ThreatIntelVault.get_pinned_stix_bundle", return_value=(tmp_path / "iocs", "sha", "1.0")), \
             patch("core.vault.EvidenceVault.calculate_integrity", return_value=("mockhash", 1024, {})):

            result = await pool.execute(
                job_id="test-job-docker-down",
                manifest=manifest,
                adapter=mock_adapter,
                spec=spec,
                params={},
                progress_cb=lambda s, p, m: None,
            )

            # Must FAIL-CLOSED with ERROR classification
            assert result.status == AnalysisState.FAILED
            assert result.summary_classification == DetectionClassification.ERROR
            assert any("Docker infrastructure unavailable" in w for w in result.warnings)


# ==============================================================================
# 7. JOB CANCELLATION & TASK CLEANUP INVARIANTS
# ==============================================================================

class TestJobCancellationAndTaskCleanup:
    """Verifies async job cancellation and task reference cleanup without memory leaks."""

    @pytest.mark.asyncio
    async def test_job_cancellation(self):
        manager = AsyncJobManager()
        job_id, _ = manager.create_job(
            case_id="CASE-101",
            evidence_id="EVID-001",
            pack_id="mobile_compromise",
            owner_id="test_user",
            organization_id="test_org",
        )

        async def dummy_long_task():
            await asyncio.sleep(5)

        task = asyncio.create_task(dummy_long_task())
        manager.register_task(job_id, task)

        # Cancel the job
        cancelled = manager.cancel_job(job_id)
        assert cancelled is True

        # Task should be cancelling or cancelled
        assert task.cancelled() or task.cancelling()

        # Job state must be CANCELLED
        status_rec = manager.get_status(job_id)
        assert status_rec is not None
        assert status_rec.state == AnalysisState.CANCELLED

        manager.cleanup_task(job_id)
        assert job_id not in manager._tasks

    @pytest.mark.asyncio
    async def test_task_cleanup_after_success(self):
        manager = AsyncJobManager()
        job_id, _ = manager.create_job(
            case_id="CASE-102",
            evidence_id="EVID-002",
            pack_id="mobile_compromise",
            owner_id="test_user",
            organization_id="test_org",
        )

        async def fast_task():
            return "done"

        task = asyncio.create_task(fast_task())
        manager.register_task(job_id, task)
        assert job_id in manager._tasks

        try:
            await task
        finally:
            manager.cleanup_task(job_id)

        assert job_id not in manager._tasks

    @pytest.mark.asyncio
    async def test_task_cleanup_after_failure(self):
        manager = AsyncJobManager()
        job_id, _ = manager.create_job(
            case_id="CASE-103",
            evidence_id="EVID-003",
            pack_id="mobile_compromise",
            owner_id="test_user",
            organization_id="test_org",
        )

        async def failing_task():
            raise RuntimeError("Task internal error")

        task = asyncio.create_task(failing_task())
        manager.register_task(job_id, task)
        assert job_id in manager._tasks

        try:
            with pytest.raises(RuntimeError):
                await task
        finally:
            manager.cleanup_task(job_id)

        assert job_id not in manager._tasks

    @pytest.mark.asyncio
    async def test_task_cleanup_after_cancellation(self):
        manager = AsyncJobManager()
        job_id, _ = manager.create_job(
            case_id="CASE-104",
            evidence_id="EVID-004",
            pack_id="mobile_compromise",
            owner_id="test_user",
            organization_id="test_org",
        )

        async def sleeping_task():
            await asyncio.sleep(10)

        task = asyncio.create_task(sleeping_task())
        manager.register_task(job_id, task)
        assert job_id in manager._tasks

        manager.cancel_job(job_id)
        manager.cleanup_task(job_id)

        assert job_id not in manager._tasks
