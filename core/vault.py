"""
Evidence Vault s Merkle Tree hashingom, detekciou symlinkov a zaručeným cleanupom.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from pathlib import Path
from typing import Any, Dict, Tuple

from core.config import config
from core.utils.logger import get_logger

logger = get_logger(__name__)


class SecurityPathError(ValueError):
    """Raised when a path violates security constraints."""

    pass


class EvidenceVault:
    """Secure evidence vault with Merkle tree hashing and path traversal protection."""

    _ALLOWED_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")

    @staticmethod
    def sanitize_id(val: str, name: str) -> str:
        """Sanitize case/evidence IDs to prevent path traversal."""
        if not val:
            raise SecurityPathError(f"{name} cannot be empty")
        if not EvidenceVault._ALLOWED_ID_PATTERN.match(val):
            raise SecurityPathError(f"Neplatný formát {name}: '{val}'. Only alphanumeric, hyphen, underscore allowed.")
        if len(val) > 256:
            raise SecurityPathError(f"{name} too long: {len(val)} > 256")
        return val

    @classmethod
    def resolve_path(cls, case_id: str, evidence_id: str) -> Path:
        """Resolve evidence path with full security validation."""
        clean_case = cls.sanitize_id(case_id, "case_id")
        clean_evd = cls.sanitize_id(evidence_id, "evidence_id")

        vault_root = config.vault_base_dir.resolve()
        lexical_target = vault_root / clean_case / clean_evd

        # Inspect lexical components BEFORE resolve(); otherwise a symlink disappears into its target.
        curr = lexical_target
        visited = set()
        while curr != vault_root and curr != curr.parent:
            if curr in visited:
                raise SecurityPathError(f"Circular path detected: {curr}")
            visited.add(curr)
            if curr.is_symlink():
                real_path = curr.resolve()
                if not real_path.is_relative_to(vault_root):
                    raise SecurityPathError(f"Symlink escape detected: {curr} -> {real_path}")
                raise SecurityPathError(f"Symlink detected in evidence path: {curr}")
            curr = curr.parent

        target = lexical_target.resolve()
        if not target.is_relative_to(vault_root):
            logger.critical(f"PATH TRAVERSAL BLOCKED: {case_id}/{evidence_id} resolves to {target}")
            raise SecurityPathError("Attempt to access a path outside the evidence vault")

        if not target.exists():
            raise FileNotFoundError(f"Dôkaz sa nenašiel vo Vaulte: {clean_case}/{clean_evd}")

        return target

    @staticmethod
    def compute_file_sha256(path: Path) -> Tuple[str, int]:
        """Compute SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
                size += len(chunk)
        return hasher.hexdigest().lower(), size

    @staticmethod
    def compute_directory_merkle_hash(dir_path: Path) -> Tuple[str, int, Dict[str, str]]:
        """Compute Merkle root hash for a directory."""
        manifest: Dict[str, str] = {}
        total_size = 0
        root_hasher = hashlib.sha256()

        for file_p in sorted([p for p in dir_path.glob("**/*") if p.is_file()]):
            # Skip symlinks
            if file_p.is_symlink():
                raise SecurityPathError(f"Symlink found in evidence directory: {file_p}")

            rel_path = str(file_p.relative_to(dir_path)).replace("\\", "/")
            f_hash, size = EvidenceVault.compute_file_sha256(file_p)
            manifest[rel_path] = f_hash
            total_size += size
            root_hasher.update(f"{rel_path}:{f_hash}\n".encode("utf-8"))

        return root_hasher.hexdigest().lower(), total_size, manifest

    @classmethod
    def calculate_integrity(cls, path: Path) -> Tuple[str, int, Dict[str, Any]]:
        """Calculate integrity hash for file or directory."""
        if path.is_file():
            if path.is_symlink():
                raise SecurityPathError(f"Symlink detected: {path}")
            h, s = cls.compute_file_sha256(path)
            return h, s, {"type": "file", "sha256": h}
        elif path.is_dir():
            h, s, m = cls.compute_directory_merkle_hash(path)
            return h, s, {"type": "directory_merkle", "sha256": h, "file_count": len(m)}
        raise ValueError(f"Neplatná cesta: {path}")

    @staticmethod
    def cleanup_scratch(scratch_dir: Path) -> None:
        """Safely cleanup scratch directory."""
        try:
            res_scratch = scratch_dir.resolve()
            res_base = config.scratch_base_dir.resolve()
            if res_scratch.is_relative_to(res_base) and res_scratch != res_base:
                if res_scratch.exists():
                    shutil.rmtree(res_scratch, ignore_errors=True)
                    logger.info(f"Scratch úložisko uvoľnené: {res_scratch}")
        except Exception as e:
            logger.error(f"Chyba pri čistení scratch disku: {e}")
