"""Persistent Ed25519 signing key for independently verifiable execution records."""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.config import config


class Ed25519Signer:
    def __init__(self, key_path: Path | None = None) -> None:
        self.key_path = key_path or (config.data_dir / "ed25519-private.pem")
        self._private = self._load_or_create()
        public_raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.key_id = "forenzx-ed25519-" + hashlib.sha256(public_raw).hexdigest()[:16]

    def _load_or_create(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            return serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return key

    def sign(self, payload: bytes) -> str:
        return base64.b64encode(self._private.sign(payload)).decode("ascii")

    def verify(self, payload: bytes, signature_b64: str) -> bool:
        try:
            self._private.public_key().verify(base64.b64decode(signature_b64), payload)
            return True
        except Exception:
            return False

    def public_info(self) -> dict[str, str]:
        raw = self._private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {"kid": self.key_id, "algorithm": "Ed25519", "publicKeyBase64": base64.b64encode(raw).decode("ascii")}


signer = Ed25519Signer()
