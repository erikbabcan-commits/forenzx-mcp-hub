"""Fail-closed downloader for Pandora S3 presigned evidence URLs."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

from core.config import config
from core.vault import EvidenceVault, SecurityPathError

MAX_DOWNLOAD_BYTES = int(os.getenv("FORENZX_VAULT_MAX_DOWNLOAD_BYTES", str(20 * 1024**3)))
CHUNK_SIZE = 256 * 1024


class VaultDownloadError(RuntimeError):
    pass


def _allowed_hosts() -> list[str]:
    return [item.strip().lower().lstrip(".") for item in os.getenv("FORENZX_PRESIGNED_ALLOWED_HOSTS", "").split(",") if item.strip()]


def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise VaultDownloadError("Only HTTPS presigned URLs with a hostname are accepted.")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "0.0.0.0", "::1"} or host.startswith(("127.", "10.", "192.168.", "169.254.")):
        raise VaultDownloadError(f"Blocked SSRF hostname: {host}")
    allowed = _allowed_hosts()
    if not allowed and config.environment.lower() in {"production", "staging"}:
        raise VaultDownloadError("FORENZX_PRESIGNED_ALLOWED_HOSTS is required in staging/production.")
    if allowed and not any(host == item or host.endswith(f".{item}") for item in allowed):
        raise VaultDownloadError(f"Host '{host}' is not in the presigned URL allow-list.")


def _safe_filename(value: Optional[str], url: str) -> str:
    candidate = value or urlparse(url).path.rsplit("/", 1)[-1] or "evidence.bin"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", candidate)[:200]
    return safe if safe not in {"", ".", ".."} else "evidence.bin"


async def download_evidence_to_vault(
    case_id: str,
    evidence_id: str,
    presigned_url: str,
    expected_sha256: Optional[str],
    filename: Optional[str] = None,
    timeout_seconds: float = 300.0,
) -> Path:
    _validate_url(presigned_url)
    if expected_sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise VaultDownloadError("expected_sha256 must be a SHA-256 digest.")

    clean_case = EvidenceVault.sanitize_id(case_id, "case_id")
    clean_evidence = EvidenceVault.sanitize_id(evidence_id, "evidence_id")
    root = config.vault_base_dir.resolve()
    target_dir = (root / clean_case / clean_evidence).resolve()
    if not target_dir.is_relative_to(root):
        raise SecurityPathError("Download target escapes the evidence vault.")
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / _safe_filename(filename, presigned_url)
    fd, temporary_name = tempfile.mkstemp(prefix=".download-", dir=target_dir)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    size = 0
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(timeout_seconds)) as client:
            async with client.stream("GET", presigned_url) as response:
                if response.status_code != 200:
                    raise VaultDownloadError(f"Presigned URL returned HTTP {response.status_code}.")
                with os.fdopen(fd, "wb") as output:
                    async for chunk in response.aiter_bytes(CHUNK_SIZE):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD_BYTES:
                            raise VaultDownloadError(f"Download exceeds {MAX_DOWNLOAD_BYTES} bytes.")
                        digest.update(chunk)
                        output.write(chunk)
        actual = digest.hexdigest()
        if expected_sha256 and actual.lower() != expected_sha256.lower():
            raise VaultDownloadError(f"SHA-256 mismatch: expected {expected_sha256.lower()}, got {actual}.")
        temporary.replace(target)
        return target
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

