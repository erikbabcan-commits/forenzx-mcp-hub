"""Pack registry with safe degraded loading and digest maintenance."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Type

from core.config import config
from core.db import db, utcnow
from core.models.forensic import PackManifest
from core.utils.logger import get_logger
from packs.base import ForensicPackAdapter

logger = get_logger(__name__)
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class PackRegistryError(Exception):
    pass


class PackRegistry:
    def __init__(self, packs_dir: Optional[Path] = None):
        self.packs_dir = packs_dir
        self._packs: Dict[str, PackManifest] = {}
        self._adapters: Dict[str, Type[ForensicPackAdapter]] = {}
        self._manifest_paths: Dict[str, Path] = {}
        self._errors: Dict[str, str] = {}

    @staticmethod
    def _looks_placeholder(digest: str) -> bool:
        d = digest.lower()
        body = d.removeprefix("sha256:")
        return (not DIGEST_RE.fullmatch(d)) or len(set(body)) < 8 or body.startswith("1234567890abcdef")

    def load_packs(self) -> None:
        self._packs.clear(); self._adapters.clear(); self._manifest_paths.clear(); self._errors.clear()
        packs_dir = (self.packs_dir or config.packs_dir).resolve()
        if not packs_dir.exists():
            self._errors["__registry__"] = f"Packs directory not found: {packs_dir}"
            return
        for pack_dir in sorted(p for p in packs_dir.iterdir() if p.is_dir()):
            manifest_path = pack_dir / "manifest.json"
            if manifest_path.exists():
                self._load_pack(manifest_path)

    def _load_pack(self, manifest_path: Path) -> None:
        pack_id = manifest_path.parent.name
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            override = db.fetchone("SELECT pinned_digest,enabled FROM pack_overrides WHERE pack_id=?", (pack_id,))
            if override:
                data["pinned_image_digest"] = override["pinned_digest"]
                data["enabled"] = bool(override["enabled"])
            manifest = PackManifest(**data)
            if self._looks_placeholder(manifest.pinned_image_digest):
                self._errors[pack_id] = "Pinned image digest is placeholder/invalid. Pack disabled until a real RepoDigest is configured."
                manifest = manifest.model_copy(update={"enabled": False})
            self._packs[pack_id] = manifest
            self._manifest_paths[pack_id] = manifest_path
            adapter_path = manifest_path.parent / "adapter.py"
            if adapter_path.exists():
                self._import_adapter(pack_id, adapter_path)
            logger.info(f"Loaded pack: {pack_id} v{manifest.version} | Enabled: {manifest.enabled}")
        except Exception as exc:
            self._errors[pack_id] = str(exc)
            logger.error(f"Pack {pack_id} disabled: {exc}")

    def _import_adapter(self, pack_id: str, adapter_path: Path) -> None:
        try:
            packs_dir = str((self.packs_dir or config.packs_dir).resolve())
            if packs_dir not in sys.path:
                sys.path.insert(0, packs_dir)
            spec = importlib.util.spec_from_file_location(f"packs.{pack_id}.adapter", str(adapter_path))
            if not spec or not spec.loader:
                raise RuntimeError("Unable to load adapter module")
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"packs.{pack_id}.adapter"] = module
            spec.loader.exec_module(module)
            for obj in vars(module).values():
                if isinstance(obj, type) and issubclass(obj, ForensicPackAdapter) and obj is not ForensicPackAdapter:
                    self._adapters[pack_id] = obj
                    return
            raise RuntimeError("No ForensicPackAdapter subclass found")
        except Exception as exc:
            self._errors[pack_id] = f"Adapter error: {exc}"

    def list_packs(self) -> list[PackManifest]:
        return list(self._packs.values())

    def describe(self) -> list[dict]:
        return [{**p.model_dump(), "registry_error": self._errors.get(p.id)} for p in self._packs.values()]

    def errors(self) -> dict[str, str]:
        return dict(self._errors)

    def get_pack(self, pack_id: str) -> Optional[PackManifest]:
        manifest = self._packs.get(pack_id)
        return manifest if manifest and manifest.enabled else None

    def get_adapter(self, pack_id: str) -> Optional[Type[ForensicPackAdapter]]:
        return self._adapters.get(pack_id) if self.get_pack(pack_id) else None

    def get_pack_path(self, pack_id: str) -> Optional[Path]:
        p = self._manifest_paths.get(pack_id)
        return p.parent if p else None

    def is_pack_enabled(self, pack_id: str) -> bool:
        return self.get_pack(pack_id) is not None

    def get_supported_inputs(self, pack_id: str) -> list[str]:
        p = self.get_pack(pack_id)
        return p.supported_inputs if p else []

    def set_digest(self, pack_id: str, digest: str) -> dict:
        d = digest.lower().strip()
        if self._looks_placeholder(d):
            raise ValueError("Digest must be a real canonical sha256:<64 hex> RepoDigest, not a placeholder")
        if pack_id not in self._manifest_paths:
            raise KeyError(pack_id)
        db.execute(
            "INSERT INTO pack_overrides(pack_id,pinned_digest,enabled,updated_at) VALUES(?,?,1,?) ON CONFLICT(pack_id) DO UPDATE SET pinned_digest=excluded.pinned_digest, enabled=1, updated_at=excluded.updated_at",
            (pack_id, d, utcnow()),
        )
        self.load_packs()
        p = self._packs.get(pack_id)
        return {**(p.model_dump() if p else {}), "registry_error": self._errors.get(pack_id)}


pack_registry = PackRegistry()
