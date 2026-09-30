"""Unit tests for configuration hardening: weak-secret detection helper.

The helper must reject placeholders AND obviously low-entropy values where a
simple ``len(secret) >= 32`` check would pass.
"""
from __future__ import annotations

import pytest

from core.config import AppConfig


class TestWeakSecretDetection:
    def test_repeated_character_secret_rejected(self):
        assert AppConfig.is_obviously_weak_secret("a" * 64) is True
        assert AppConfig.is_obviously_weak_secret("1234567890" * 8) is True

    def test_keyboard_walk_rejected(self):
        assert AppConfig.is_obviously_weak_secret("qwertyuiopasdfghjklzxcvbnmqwerty") is True

    def test_placeholder_patterns_rejected(self):
        assert AppConfig.is_obviously_weak_secret("CHANGE_ME_WITH_AT_LEAST_32_RANDOM_CHARACTERS") is True
        assert AppConfig.is_obviously_weak_secret("dev-secret-dev-secret-dev-secret-32x!") is True
        assert AppConfig.is_obviously_weak_secret("my-very-secure-insecure-secret-key-32") is True

    def test_short_secrets_rejected(self):
        assert AppConfig.is_obviously_weak_secret("short") is True
        assert AppConfig.is_obviously_weak_secret("") is True

    def test_high_entropy_secret_accepted(self):
        assert AppConfig.is_obviously_weak_secret("k7Vq2mZx9LpRtWn4BhGc8JdF3sYe6Aq1") is False
        assert AppConfig.is_obviously_weak_secret("9f3Kq7Pz2mV8xL5Rt4Wn6B1yH0jD3GcZ") is False

    def test_production_uses_helper_for_api_keys(self, tmp_path):
        valid = dict(
            environment="production",
            jwt_secret_key="Nv5Xw8Km2Qz7Pd4Rb9Th6Jg3Yf1Lc0Se7Uw2Zx5Vq8",
            server_hmac_signing_key="k7Vq2mZx9LpRtWn4BhGc8JdF3sYe6Aq1Mr5Tb0Yn3",
            api_keys=["prod-analyst-key-0123456789abcdef"],
            admin_api_keys=["prod-admin-key-0123456789abcdef"],
        )
        # a low-entropy API key must be rejected even though it is long enough
        with pytest.raises(ValueError, match="API keys"):
            AppConfig(
                **{**valid, "api_keys": ["a" * 40]},
                database_path=tmp_path / "prod" / "forenzx.db",
                data_dir=tmp_path / "prod",
            )
        # a valid config still passes
        cfg = AppConfig(**valid, database_path=tmp_path / "prod" / "forenzx.db", data_dir=tmp_path / "prod")
        assert cfg.environment == "production"
