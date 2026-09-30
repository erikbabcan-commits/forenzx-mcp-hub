"""ForenZX v5 configuration with safe defaults and fail-closed production checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["production", "staging", "development", "test"] = "development"
    host: str = "0.0.0.0"
    port: int = 8000
    timeout_seconds: int = 60

    data_dir: Path = Field(default=Path("./data"))
    database_path: Path = Field(default=Path("./data/forenzx.db"))
    backups_dir: Path = Field(default=Path("./backups"))
    dashboard_enabled: bool = True

    vault_base_dir: Path = Field(default=Path("/var/forensics/vault"))
    scratch_base_dir: Path = Field(default=Path("/tmp/forenzx_scratch"))
    threat_intel_dir: Path = Field(default=Path("/var/forensics/threat_intel"))
    packs_dir: Path = Field(default=Path("./packs"))

    worker_pool_size: int = 4
    worker_max_memory_mb: int = 4096
    worker_max_cpu_cores: float = 2.0
    worker_timeout_seconds: int = 3600

    jwt_secret_key: str = Field(default="")
    server_hmac_signing_key: str = Field(default="")
    api_keys: List[str] = Field(default_factory=list)
    admin_api_keys: List[str] = Field(default_factory=list)

    allowed_origins: List[str] = Field(default_factory=list)

    mcp_probe_timeout_seconds: float = 8.0
    mcp_health_interval_seconds: int = 60
    mcp_auto_health_enabled: bool = True
    maintenance_event_retention_days: int = 30

    @model_validator(mode="before")
    @classmethod
    def handle_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "jwt_secret" in data and "jwt_secret_key" not in data:
                data["jwt_secret_key"] = data.pop("jwt_secret")
            if "hmac_secret_key" in data and "server_hmac_signing_key" not in data:
                data["server_hmac_signing_key"] = data.pop("hmac_secret_key")
        return data

    @property
    def jwt_secret(self) -> str:
        return self.jwt_secret_key

    @property
    def hmac_secret_key(self) -> str:
        return self.server_hmac_signing_key

    @model_validator(mode="after")
    def validate_config(self) -> "AppConfig":
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

        env = self.environment.lower()
        if env in {"production", "staging"}:
            self._require_strong_secret(self.jwt_secret_key, "jwt_secret_key")
            self._require_strong_secret(self.server_hmac_signing_key, "server_hmac_signing_key")
            if not self.admin_api_keys:
                raise ValueError("Production requires at least one ADMIN_API_KEYS entry.")
            db_path = str(self.database_path)
            if db_path in {":memory:", ""} or db_path.startswith("file::memory:"):
                raise ValueError(
                    "Production/staging requires persistent DATABASE_PATH; memory-only persistence is rejected."
                )
            for key in (*self.admin_api_keys, *self.api_keys):
                lowered = key.lower()
                forbidden_values = {
                    "dev-admin-key",
                    "dev-analyst-key",
                    "changeme",
                    "admin",
                    "password",
                    "secret",
                    "test",
                    "insecure",
                }
                weak = (
                    not key
                    or lowered.startswith("change_me")
                    or lowered in forbidden_values
                    or any(x in lowered for x in ("change_me", "placeholder", "insecure", "dev-secret"))
                    or self._secret_entropy_too_low(key)
                )
                if weak:
                    raise ValueError(
                        "Production requires real per-deployment API keys; development, placeholder "
                        "and low-entropy keys are rejected."
                    )
        else:
            if not self.jwt_secret_key:
                self.jwt_secret_key = "dev-jwt-secret-key-32-characters-minimum-only"
            if not self.server_hmac_signing_key:
                self.server_hmac_signing_key = "dev-hmac-secret-key-32-characters-minimum-only"
            if not self.admin_api_keys:
                self.admin_api_keys = ["dev-admin-key"]
            if not self.api_keys:
                self.api_keys = ["dev-analyst-key"]
        return self

    # Obviously weak placeholder substrings; production rejects all of them.
    _FORBIDDEN_SECRET_SUBSTRINGS = (
        "change_me",
        "changeme",
        "insecure",
        "dev-secret",
        "dev-jwt",
        "dev-hmac",
        "placeholder",
        "example",
        "password",
        "default",
        "forenzx.local",
    )

    @staticmethod
    def _secret_entropy_too_low(value: str) -> bool:
        """Reject obviously low-entropy secrets (e.g. "a"*32, keyboard walks).

        A 32+ char random value almost always has >= max(8, len/4) distinct
        characters; repeated-character or single-symbol secrets do not.
        """
        distinct = len(set(value))
        return distinct < max(8, len(value) // 4)

    @classmethod
    def is_obviously_weak_secret(cls, value: str) -> bool:
        """Public helper: True if the value is a placeholder or low-entropy secret."""
        lowered = (value or "").lower()
        return (
            not value
            or len(value) < 32
            or any(x in lowered for x in cls._FORBIDDEN_SECRET_SUBSTRINGS)
            or cls._secret_entropy_too_low(value)
        )

    @classmethod
    def _require_strong_secret(cls, value: str, name: str) -> None:
        if cls.is_obviously_weak_secret(value):
            raise ValueError(
                f"{name} must be a strong secret: at least 32 characters, high entropy, "
                "free of placeholder patterns (dev-secret/default/insecure/...)."
            )


ForenzxConfig = AppConfig
config = AppConfig()
