import hashlib

import pytest

from core import vault_downloader
from core.config import config
from core.vault_downloader import VaultDownloadError, download_evidence_to_vault


class _FakeResponse:
    def __init__(self, payload: bytes, status_code: int = 200):
        self.status_code = status_code
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def aiter_bytes(self, _chunk_size: int):
        yield self._payload


class _FakeClient:
    def __init__(self, response: _FakeResponse):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, _method: str, _url: str):
        return self.response


@pytest.mark.asyncio
async def test_downloader_streams_and_verifies_sha256(monkeypatch, tmp_path):
    payload = b"forenzx-regression-fixture\n"
    monkeypatch.setattr(config, "vault_base_dir", tmp_path)
    monkeypatch.setattr(config, "environment", "test")
    monkeypatch.setenv("FORENZX_PRESIGNED_ALLOWED_HOSTS", "s3.example.test")
    monkeypatch.setattr(vault_downloader.httpx, "AsyncClient", lambda **_kwargs: _FakeClient(_FakeResponse(payload)))

    path = await download_evidence_to_vault(
        "case-1",
        "evidence-1",
        "https://s3.example.test/bucket/evidence.bin",
        hashlib.sha256(payload).hexdigest(),
        "evidence.bin",
    )

    assert path.read_bytes() == payload
    assert path == tmp_path / "case-1" / "evidence-1" / "evidence.bin"


@pytest.mark.asyncio
async def test_downloader_deletes_mismatched_download(monkeypatch, tmp_path):
    payload = b"tampered"
    monkeypatch.setattr(config, "vault_base_dir", tmp_path)
    monkeypatch.setattr(config, "environment", "test")
    monkeypatch.setenv("FORENZX_PRESIGNED_ALLOWED_HOSTS", "s3.example.test")
    monkeypatch.setattr(vault_downloader.httpx, "AsyncClient", lambda **_kwargs: _FakeClient(_FakeResponse(payload)))

    with pytest.raises(VaultDownloadError, match="SHA-256 mismatch"):
        await download_evidence_to_vault(
            "case-1",
            "evidence-1",
            "https://s3.example.test/bucket/evidence.bin",
            "0" * 64,
            "evidence.bin",
        )

    assert not list((tmp_path / "case-1" / "evidence-1").glob("*"))


def test_downloader_rejects_redirect_and_ssrf_hosts(monkeypatch):
    monkeypatch.setattr(config, "environment", "staging")
    monkeypatch.setenv("FORENZX_PRESIGNED_ALLOWED_HOSTS", "s3.example.test")

    with pytest.raises(VaultDownloadError):
        vault_downloader._validate_url("http://s3.example.test/file")
    with pytest.raises(VaultDownloadError):
        vault_downloader._validate_url("https://127.0.0.1/file")
    with pytest.raises(VaultDownloadError):
        vault_downloader._validate_url("https://evil.example.test/file")

