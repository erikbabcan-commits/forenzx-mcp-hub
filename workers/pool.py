"""
Paralelný worker pool s garanciou cleanupu.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict

try:
    import docker  # type: ignore
except ImportError:
    docker = None  # type: ignore

from core.config import config
from core.models.forensic import (
    AnalysisResult,
    AnalysisState,
    ChainOfCustodyEntry,
    DetectionClassification,
    EvidenceInputSpec,
    ExecutionRecord,
    PackManifest,
)
from core.signing import signer
from core.threat_intel import ThreatIntelError, ThreatIntelVault
from core.utils.logger import get_logger
from core.vault import EvidenceVault
from workers.isolation import DockerDigestVerificationError, SandboxSecurityManager

logger = get_logger(__name__)


class WorkerPool:
    """Worker pool for parallel forensic analysis execution."""

    def __init__(self, size: int = 8, client: Any = None) -> None:
        self._semaphore = asyncio.Semaphore(size)
        self._client: Any = client

    @property
    def client(self) -> Any:
        """Lazily initialize and return the Docker client."""
        if self._client is None:
            try:
                if docker is None:
                    raise RuntimeError("Docker SDK is not installed")
                cli = docker.from_env()
                cli.ping()
                self._client = cli
            except Exception as e:
                logger.error(f"Docker client initialization failed: {e}")
                raise RuntimeError(f"Docker infrastructure is unavailable or not running: {e}") from e
        return self._client

    async def execute(
        self,
        job_id: str,
        manifest: PackManifest,
        adapter: Any,
        spec: EvidenceInputSpec,
        params: Dict[str, Any],
        progress_cb: Callable[[AnalysisState, int, str], None],
    ) -> AnalysisResult:
        """
        Execute a forensic analysis in a Docker sandbox.

        Guarantees:
        - Container cleanup on success/failure
        - Scratch directory cleanup
        - Proper error handling and classification
        """
        async with self._semaphore:
            container = None
            scratch_dir: Path | None = None

            try:
                # 1. Resolve evidence path with security validation
                progress_cb(AnalysisState.RUNNING, 5, "Validating evidence path")
                evd_path = EvidenceVault.resolve_path(spec.case_id, spec.evidence_id)

                # 2. Load and verify IOC bundle (FAIL CLOSED)
                progress_cb(AnalysisState.RUNNING, 10, "Loading threat intelligence")
                try:
                    ioc_path, ioc_sha256, ioc_ver = ThreatIntelVault.get_pinned_stix_bundle()
                except ThreatIntelError as e:
                    logger.error(f"Threat intelligence load failed: {e}")
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=0.0,
                        status=AnalysisState.FAILED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={},
                        findings=[],
                        warnings=[str(e)],
                        limitations=["Threat intelligence validation failed"],
                        chain_of_custody=[],
                        execution_record=ExecutionRecord(
                            case_id=spec.case_id,
                            evidence_id=spec.evidence_id,
                            pack_id=manifest.id,
                            pack_version=manifest.version,
                            container_digest="",
                            input_root_sha256="",
                            ioc_bundle_sha256="",
                            ioc_bundle_version="",
                            tool_command=[],
                            exit_code=-1,
                            started_at=datetime.now(timezone.utc).isoformat(),
                            completed_at=datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                # 3. Calculate pre-flight integrity hash
                progress_cb(AnalysisState.RUNNING, 15, "Calculating evidence integrity")
                root_hash, size_b, meta = EvidenceVault.calculate_integrity(evd_path)

                if spec.claimed_sha256 and spec.claimed_sha256.lower() != root_hash.lower():
                    raise ValueError(f"PRE-FLIGHT HASH MISMATCH: {spec.claimed_sha256} != {root_hash}")

                # 4. Create scratch directory
                scratch_dir = config.scratch_base_dir / job_id
                out_dir = scratch_dir / "output"
                out_dir.mkdir(parents=True, exist_ok=True)

                # 5. Setup Docker mounts (read-only for evidence)
                mounts = [
                    {"host_path": evd_path, "container_path": "/evidence/input", "mode": "ro"},
                    {"host_path": ioc_path, "container_path": "/evidence/ioc/bundle.stix2", "mode": "ro"},
                    {"host_path": out_dir, "container_path": "/evidence/output", "mode": "rw"},
                ]

                # 6. Get execution command (argv list, no shell)
                progress_cb(AnalysisState.RUNNING, 20, "Preparing execution command")
                cmd = adapter.get_execution_command(spec, params)

                # Validate command is a list
                if not isinstance(cmd, list):
                    raise ValueError(f"Command must be a list, got {type(cmd)}")
                if not all(isinstance(arg, str) for arg in cmd):
                    raise ValueError("All command arguments must be strings")

                # 7. Create Docker config with digest verification
                progress_cb(AnalysisState.RUNNING, 25, "Creating sandbox container")
                try:
                    docker_client = self.client
                    docker_cfg = SandboxSecurityManager.get_config(
                        manifest.container_image,
                        mounts,
                        cmd,
                        manifest.max_memory_mb,
                        manifest.max_cpu_cores,
                        manifest.network_required,
                        manifest.pinned_image_digest,
                        client=docker_client,
                    )
                except DockerDigestVerificationError as e:
                    logger.error(f"Image digest verification failed: {e}")
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=0.0,
                        status=AnalysisState.FAILED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={"root_sha256": root_hash, "size_bytes": size_b, "meta": meta},
                        findings=[],
                        warnings=[str(e)],
                        limitations=["Docker image digest mismatch"],
                        chain_of_custody=[],
                        execution_record=ExecutionRecord(
                            case_id=spec.case_id,
                            evidence_id=spec.evidence_id,
                            pack_id=manifest.id,
                            pack_version=manifest.version,
                            container_digest="",
                            input_root_sha256=root_hash,
                            ioc_bundle_sha256=ioc_sha256,
                            ioc_bundle_version=ioc_ver,
                            tool_command=cmd,
                            exit_code=-1,
                            started_at=datetime.now(timezone.utc).isoformat(),
                            completed_at=datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                except Exception as e:
                    logger.error(f"Docker infrastructure unavailable: {e}")
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        duration_seconds=0.0,
                        status=AnalysisState.FAILED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={"root_sha256": root_hash, "size_bytes": size_b, "meta": meta},
                        findings=[],
                        warnings=[f"Docker infrastructure unavailable: {e}"],
                        limitations=["Isolated Docker sandbox unavailable - execution failed closed"],
                        chain_of_custody=[],
                        execution_record=ExecutionRecord(
                            case_id=spec.case_id,
                            evidence_id=spec.evidence_id,
                            pack_id=manifest.id,
                            pack_version=manifest.version,
                            container_digest="",
                            input_root_sha256=root_hash,
                            ioc_bundle_sha256=ioc_sha256,
                            ioc_bundle_version=ioc_ver,
                            tool_command=cmd,
                            exit_code=-1,
                            started_at=datetime.now(timezone.utc).isoformat(),
                            completed_at=datetime.now(timezone.utc).isoformat(),
                        ),
                    )

                # 8. Start container
                started_at = datetime.now(timezone.utc)
                try:
                    container = docker_client.containers.create(**docker_cfg)
                    container.start()
                    progress_cb(AnalysisState.RUNNING, 30, "Forenzný kontajner aktívny v read-only sandboxe")
                except Exception as e:
                    logger.error(f"Failed to start container: {e}")
                    raise

                # 9. Wait for container completion with timeout
                try:
                    loop = asyncio.get_running_loop()
                    res = await asyncio.wait_for(
                        loop.run_in_executor(None, container.wait), timeout=manifest.timeout_seconds
                    )
                    exit_code = res.get("StatusCode", -1)
                    logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
                except asyncio.TimeoutError:
                    logger.error(f"Container execution timed out after {manifest.timeout_seconds}s")
                    raise ValueError(f"Execution timed out after {manifest.timeout_seconds} seconds")
                except Exception as e:
                    logger.error(f"Error waiting for container: {e}")
                    raise

                # 10. Post-execution integrity check
                progress_cb(AnalysisState.RUNNING, 80, "Verifying evidence integrity")
                try:
                    post_hash, _, _ = EvidenceVault.calculate_integrity(evd_path)
                except Exception as e:
                    logger.error(f"Post-execution integrity check failed: {e}")
                    post_hash = "UNKNOWN"

                # Build chain of custody
                coc = [
                    ChainOfCustodyEntry(
                        action="VAULT_PRE_FLIGHT_VERIFIED",
                        actor="vault_engine",
                        sha256_before=root_hash,
                        sha256_after=root_hash,
                        details={"evidence_path": str(evd_path)},
                    ),
                    ChainOfCustodyEntry(
                        action="DOCKER_SANDBOX_EXECUTION",
                        actor=manifest.container_image,
                        sha256_before=root_hash,
                        sha256_after=post_hash,
                        details={"container_id": container.short_id if container else "unknown"},
                    ),
                ]

                # Check for forensic integrity breach
                if post_hash != root_hash:
                    logger.critical(f"FORENSIC INTEGRITY BREACH: Pre={root_hash}, Post={post_hash}")
                    coc.append(
                        ChainOfCustodyEntry(
                            action="INTEGRITY_BREACH_DETECTED",
                            actor="system",
                            sha256_before=root_hash,
                            sha256_after=post_hash,
                            details={"severity": "CRITICAL"},
                        )
                    )

                # 11. Create execution record and sign it
                completed_at = datetime.now(timezone.utc)
                duration = (completed_at - started_at).total_seconds()

                rec = ExecutionRecord(
                    case_id=spec.case_id,
                    evidence_id=spec.evidence_id,
                    pack_id=manifest.id,
                    pack_version=manifest.version,
                    container_digest=manifest.pinned_image_digest,
                    input_root_sha256=root_hash,
                    ioc_bundle_sha256=ioc_sha256,
                    ioc_bundle_version=ioc_ver,
                    tool_command=cmd,
                    exit_code=exit_code,
                    started_at=started_at.isoformat(),
                    completed_at=completed_at.isoformat(),
                )

                # Sign the record
                try:
                    rec.sign_record(config.server_hmac_signing_key)
                    rec.signature_algorithm = "Ed25519"
                    rec.signing_key_id = signer.key_id
                    rec.ed25519_signature = signer.sign(rec.canonical_payload())
                except Exception as e:
                    logger.error(f"Failed to sign execution record: {e}")

                # Hard stop if read-only evidence changed despite sandbox policy.
                if post_hash != root_hash:
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=started_at.isoformat(),
                        completed_at=completed_at.isoformat(),
                        duration_seconds=duration,
                        status=AnalysisState.SECURITY_BLOCKED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={
                            "root_sha256_before": root_hash,
                            "root_sha256_after": post_hash,
                            "size_bytes": size_b,
                        },
                        findings=[],
                        warnings=["Evidence integrity changed during analysis; result blocked"],
                        limitations=["Security boundary violation"],
                        chain_of_custody=coc,
                        execution_record=rec,
                    )

                # 12. STRIKTNÝ INVARIANT: exit_code != 0 -> VÝHRADNE ERROR
                if exit_code != 0:
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=started_at.isoformat(),
                        completed_at=completed_at.isoformat(),
                        duration_seconds=duration,
                        status=AnalysisState.FAILED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={"root_sha256": root_hash, "size_bytes": size_b, "meta": meta},
                        findings=[],
                        warnings=[f"Kontajner zlyhal (Exit {exit_code})", logs[-400:] if len(logs) > 400 else logs],
                        limitations=[
                            "Container execution failed",
                            "Absence of known IOC matches does not prove absence of compromise.",
                        ],
                        chain_of_custody=coc,
                        execution_record=rec,
                    )

                # 13. Parse output artifacts
                progress_cb(AnalysisState.RUNNING, 90, "Parsing results")
                try:
                    classification, findings, timeline, warnings_list = await adapter.parse_output_artifacts(out_dir)
                except Exception as e:
                    logger.error(f"Failed to parse output artifacts: {e}")
                    return AnalysisResult(
                        job_id=job_id,
                        pack_id=manifest.id,
                        pack_version=manifest.version,
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        started_at=started_at.isoformat(),
                        completed_at=completed_at.isoformat(),
                        duration_seconds=duration,
                        status=AnalysisState.FAILED,
                        summary_classification=DetectionClassification.ERROR,
                        input_integrity={"root_sha256": root_hash, "size_bytes": size_b, "meta": meta},
                        findings=[],
                        warnings=[f"Parser error: {e}"],
                        limitations=["Output parsing failed"],
                        chain_of_custody=coc,
                        execution_record=rec,
                    )

                return AnalysisResult(
                    job_id=job_id,
                    pack_id=manifest.id,
                    pack_version=manifest.version,
                    case_id=spec.case_id,
                    evidence_id=spec.evidence_id,
                    started_at=started_at.isoformat(),
                    completed_at=completed_at.isoformat(),
                    duration_seconds=duration,
                    status=AnalysisState.COMPLETED,
                    summary_classification=classification,
                    input_integrity={"root_sha256": root_hash, "size_bytes": size_b, "meta": meta},
                    findings=findings,
                    timeline=timeline,
                    warnings=warnings_list,
                    limitations=["Absence of known IOC matches does not prove absence of compromise."]
                    if classification == DetectionClassification.NO_KNOWN_IOC
                    else [],
                    chain_of_custody=coc,
                    execution_record=rec,
                )

            except Exception as e:
                # Catch any unexpected exceptions and return FAILED with ERROR
                logger.error(f"Unexpected error in job {job_id}: {e}", exc_info=True)
                return AnalysisResult(
                    job_id=job_id,
                    pack_id=manifest.id if manifest else "unknown",
                    pack_version=manifest.version if manifest else "unknown",
                    case_id=spec.case_id,
                    evidence_id=spec.evidence_id,
                    started_at=datetime.now(timezone.utc).isoformat(),
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    duration_seconds=0.0,
                    status=AnalysisState.FAILED,
                    summary_classification=DetectionClassification.ERROR,
                    input_integrity={},
                    findings=[],
                    warnings=[f"Unexpected error: {str(e)}"],
                    limitations=["Unexpected execution error"],
                    chain_of_custody=[],
                    execution_record=ExecutionRecord(
                        case_id=spec.case_id,
                        evidence_id=spec.evidence_id,
                        pack_id=manifest.id if manifest else "unknown",
                        pack_version=manifest.version if manifest else "unknown",
                        container_digest="",
                        input_root_sha256="",
                        ioc_bundle_sha256="",
                        ioc_bundle_version="",
                        tool_command=[],
                        exit_code=-1,
                        started_at=datetime.now(timezone.utc).isoformat(),
                        completed_at=datetime.now(timezone.utc).isoformat(),
                    ),
                )

            finally:
                # ALWAYS cleanup - guarantee no orphan containers
                if container:
                    try:
                        container.stop(timeout=5)
                    except Exception:
                        pass
                    try:
                        container.remove(force=True)
                        logger.info(
                            f"Container cleaned up: {container.short_id if hasattr(container, 'short_id') else 'unknown'}"
                        )
                    except Exception as e:
                        logger.error(f"Failed to remove container: {e}")

                if scratch_dir:
                    try:
                        EvidenceVault.cleanup_scratch(scratch_dir)
                    except Exception as e:
                        logger.error(f"Failed to cleanup scratch: {e}")
