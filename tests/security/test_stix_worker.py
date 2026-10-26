"""The bytes consumed by a worker must match the accepted STIX digest."""

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.config import config
from core.models.forensic import AnalysisState, DetectionClassification, EvidenceInputSpec, PackManifest
from workers.pool import WorkerPool


@pytest.fixture
def worker_setup(monkeypatch, tmp_path):
    intel_dir = tmp_path / "intel"
    intel_dir.mkdir()
    bundle = intel_dir / "pegasus_predator.stix2"
    accepted_bytes = b'{"type":"bundle","id":"bundle--worker-test","objects":[]}'
    bundle.write_bytes(accepted_bytes)
    digest = hashlib.sha256(accepted_bytes).hexdigest()
    monkeypatch.setattr(config, "environment", "test")
    monkeypatch.setattr(config, "threat_intel_dir", intel_dir)
    monkeypatch.setattr(config, "forenzx_trusted_stix_digests", digest)
    monkeypatch.setattr(config, "scratch_base_dir", tmp_path / "scratch")

    evidence = tmp_path / "evidence"
    evidence.write_bytes(b"forensic evidence")
    monkeypatch.setattr("workers.pool.EvidenceVault.resolve_path", lambda *_: evidence)

    manifest = PackManifest(
        id="mobile_compromise",
        name="MVT",
        version="1.0.0",
        description="Worker parity test",
        license="MIT",
        author="ForenZX",
        supported_platforms=["ios"],
        supported_inputs=["ios_backup"],
        capabilities=["ioc_matching"],
        container_image="trusted-worker",
        pinned_image_digest="sha256:" + "a" * 64,
    )
    adapter = MagicMock()
    adapter.get_execution_command.return_value = ["mvt-ios", "check-backup"]
    adapter.parse_output_artifacts = AsyncMock(return_value=(DetectionClassification.NO_KNOWN_IOC, [], [], []))
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = b""
    client = MagicMock()
    client.containers.create.return_value = container
    mounted = {}

    def get_config(_image, mounts, *_args, **_kwargs):
        mounted.update({mount["container_path"]: mount for mount in mounts})
        return {"image": "trusted-worker"}

    monkeypatch.setattr("workers.pool.SandboxSecurityManager.get_config", get_config)
    return bundle, accepted_bytes, digest, adapter, container, client, mounted, manifest


async def execute_worker(setup, progress_cb=lambda *_: None):
    *_, adapter, _container, client, _mounted, manifest = setup
    return await WorkerPool(size=1, client=client).execute(
        job_id="stix-worker-test",
        manifest=manifest,
        adapter=adapter,
        spec=EvidenceInputSpec(
            case_id="CASE-STIX", evidence_id="EVID-STIX", input_type="ios_backup", claimed_sha256=None
        ),
        params={},
        progress_cb=progress_cb,
    )


@pytest.mark.asyncio
async def test_worker_mounts_accepted_snapshot_when_shared_source_changes(worker_setup):
    bundle, accepted, digest, adapter, container, _client, mounted, _manifest = worker_setup

    def progress(_state, percent, _message):
        if percent == 20:
            bundle.write_bytes(b'{"type":"bundle","objects":[{"untrusted":true}]}')

    def wait():
        mount = mounted["/evidence/ioc/bundle.stix2"]
        snapshot = Path(mount["host_path"])
        assert snapshot != bundle
        assert snapshot.read_bytes() == accepted
        assert mount["mode"] == "ro"
        assert snapshot.stat().st_mode & 0o222 == 0
        return {"StatusCode": 0}

    container.wait.side_effect = wait
    result = await execute_worker(worker_setup, progress)

    assert result.status == AnalysisState.COMPLETED
    assert result.execution_record.ioc_bundle_sha256 == digest
    adapter.parse_output_artifacts.assert_awaited_once()
    assert not Path(mounted["/evidence/ioc/bundle.stix2"]["host_path"]).exists()


@pytest.mark.asyncio
async def test_source_replaced_before_snapshot_is_rejected(worker_setup):
    bundle, _accepted, _digest, adapter, _container, client, _mounted, _manifest = worker_setup

    def progress(_state, percent, _message):
        if percent == 15:
            bundle.write_bytes(b'{"type":"bundle","objects":[{"untrusted":true}]}')

    result = await execute_worker(worker_setup, progress)

    assert result.status == AnalysisState.FAILED
    assert result.summary_classification == DetectionClassification.ERROR
    assert any("snapshot digest mismatch" in warning for warning in result.warnings)
    client.containers.create.assert_not_called()
    adapter.parse_output_artifacts.assert_not_awaited()


@pytest.mark.asyncio
async def test_snapshot_tamper_during_execution_blocks_parsing(worker_setup):
    _bundle, _accepted, digest, adapter, container, _client, mounted, _manifest = worker_setup

    def wait():
        snapshot = Path(mounted["/evidence/ioc/bundle.stix2"]["host_path"])
        snapshot.chmod(0o600)
        snapshot.write_bytes(b'{"type":"bundle","objects":[{"untrusted":true}]}')
        return {"StatusCode": 0}

    container.wait.side_effect = wait
    result = await execute_worker(worker_setup)

    assert result.status == AnalysisState.SECURITY_BLOCKED
    assert result.summary_classification == DetectionClassification.ERROR
    assert result.findings == []
    assert any("Threat intelligence snapshot integrity changed" in warning for warning in result.warnings)
    assert result.execution_record.ioc_bundle_sha256 == digest
    adapter.parse_output_artifacts.assert_not_awaited()
