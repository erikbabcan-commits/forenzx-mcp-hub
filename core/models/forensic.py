"""Pydantic models for deterministic forensic entities and integrity records."""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionClassification(str, enum.Enum):
    HIT = "HIT"
    SUSPICIOUS = "SUSPICIOUS"
    NO_KNOWN_IOC = "NO_KNOWN_IOC"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class AnalysisState(str, enum.Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    RUNNING = "RUNNING"
    PARSING = "PARSING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SECURITY_BLOCKED = "SECURITY_BLOCKED"


class EvidenceInputSpec(BaseModel):
    case_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    evidence_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    input_type: Literal[
        "ios_backup",
        "ios_sysdiagnose",
        "ios_mobileconfig",
        "ios_app_container",
        "android_backup",
        "android_bugreport",
        "android_app_export",
        "android_filesystem_export",
        "mobile_generic_archive",
        "disk_raw",
        "evtx_logs",
        "pcap",
        "file_generic",
    ]
    claimed_sha256: Optional[str] = Field(None, pattern=r"^[a-fA-F0-9]{64}$")
    examiner: str = "authenticated_analyst"


class ChainOfCustodyEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    action: str
    actor: str
    sha256_before: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$")
    sha256_after: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$")
    details: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def verify_hash_immutability(self) -> "ChainOfCustodyEntry":
        # Integrity breach records are allowed to represent differing hashes explicitly.
        if self.action != "INTEGRITY_BREACH_DETECTED" and self.sha256_before.lower() != self.sha256_after.lower():
            raise ValueError("FORENSIC INTEGRITY BREACH: evidence changed during a custody action")
        return self


class ForensicFinding(BaseModel):
    id: str
    classification: DetectionClassification
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    ioc_type: str
    ioc_name: Optional[str] = None
    artifact_path: str
    artifact_hash: Optional[str] = None
    timestamp: Optional[str] = None
    severity: FindingSeverity
    description: str
    raw_evidence_ref: Optional[Dict[str, Any]] = None
    is_ai_assisted: Literal[False] = False


class TimelineEvent(BaseModel):
    timestamp: str
    event_type: str
    source_tool: str
    description: str
    relevance_score: float = Field(ge=0.0, le=1.0, default=0.5)
    original_timestamp: Optional[str] = None
    timezone: Optional[str] = None
    normalization_notes: Optional[str] = None


class AIInterpretation(BaseModel):
    id: str
    case_id: str
    job_id: str
    finding_refs: List[str] = Field(default_factory=list)
    summary: str
    hypotheses: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "LOW"
    limitations: List[str] = Field(default_factory=list)
    model: str
    model_version: Optional[str] = None
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ai_assisted: Literal[True] = True
    evidentiary_status: Literal["INTERPRETATION_NOT_EVIDENCE"] = "INTERPRETATION_NOT_EVIDENCE"


class PackManifest(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9_-]+$")
    name: str
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    description: str
    license: str
    author: str
    supported_platforms: List[Literal["ios", "android", "windows", "linux", "macos", "cloud", "agnostic"]]
    supported_inputs: List[str]
    capabilities: List[str]
    container_image: str
    pinned_image_digest: str = Field(..., pattern=r"^sha256:[a-fA-F0-9]{64}$")
    read_only_strictly_enforced: bool = True
    network_required: bool = False
    max_memory_mb: int = Field(default=4096, ge=128, le=65536)
    max_cpu_cores: float = Field(default=2.0, gt=0, le=32)
    timeout_seconds: int = Field(default=3600, ge=1, le=86400)
    healthcheck_cmd: List[str] = Field(default_factory=list)
    enabled: bool = True


class ExecutionRecord(BaseModel):
    """Canonical execution record; HMAC stays for compatibility and Ed25519 is independently verifiable."""

    record_version: str = "2"
    case_id: str
    evidence_id: str
    pack_id: str
    pack_version: str
    container_digest: str
    input_root_sha256: str
    ioc_bundle_sha256: str
    ioc_bundle_version: str
    tool_command: List[str]
    exit_code: int
    started_at: str
    completed_at: str
    manifest_canonical_sha256: str = ""
    server_hmac_signature: str = ""
    signature_algorithm: str = ""
    signing_key_id: str = ""
    ed25519_signature: str = ""

    def canonical_payload(self) -> bytes:
        data = {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "container_digest": self.container_digest,
            "input_root_sha256": self.input_root_sha256,
            "ioc_bundle_sha256": self.ioc_bundle_sha256,
            "ioc_bundle_version": self.ioc_bundle_version,
            "tool_command": self.tool_command,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def sign_record(self, signing_key: str) -> None:
        canonical = self.canonical_payload()
        self.manifest_canonical_sha256 = hashlib.sha256(canonical).hexdigest()
        # Keep the v4 HMAC contract for backward verification: HMAC over canonical SHA-256 hex.
        self.server_hmac_signature = hmac.new(
            signing_key.encode("utf-8"), self.manifest_canonical_sha256.encode("utf-8"), hashlib.sha256
        ).hexdigest()


class AnalysisResult(BaseModel):
    job_id: str
    pack_id: str
    pack_version: str
    case_id: str
    evidence_id: str
    started_at: str
    completed_at: str
    duration_seconds: float
    status: AnalysisState
    summary_classification: DetectionClassification
    input_integrity: Dict[str, Any]
    findings: List[ForensicFinding] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    chain_of_custody: List[ChainOfCustodyEntry] = Field(default_factory=list)
    execution_record: ExecutionRecord

    @model_validator(mode="after")
    def enforce_failure_invariant(self) -> "AnalysisResult":
        if (
            self.status in {AnalysisState.FAILED, AnalysisState.SECURITY_BLOCKED}
            and self.summary_classification != DetectionClassification.ERROR
        ):
            raise ValueError("INVARIANT VIOLATION: failed/security-blocked analysis must have classification ERROR")
        return self


class JobSpec(BaseModel):
    job_id: str
    case_id: str
    evidence_id: str
    pack_id: str
    owner_id: str
    organization_id: str
    created_at: str
    status: AnalysisState = AnalysisState.QUEUED
