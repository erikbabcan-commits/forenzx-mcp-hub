"""
Reálny MVT Adaptér pre iOS a Android s plnou podporou STIX2 a SUSPICIOUS nálezov.
Uses exact argv list format - NO shell strings.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.models.forensic import (
    DetectionClassification,
    EvidenceInputSpec,
    FindingSeverity,
    ForensicFinding,
    PackManifest,
    TimelineEvent,
)
from packs.base import ForensicPackAdapter


class MobileCompromiseAdapter(ForensicPackAdapter):
    """Adapter for MVT mobile forensic analysis."""

    SUPPORTED_INPUT_TYPES = ["ios_backup", "android_backup"]

    def __init__(self, manifest: PackManifest, scratch_dir: Path) -> None:
        super().__init__(manifest, scratch_dir)

    def get_execution_command(self, spec: EvidenceInputSpec, params: Dict[str, Any]) -> List[str]:
        """
        Get execution command as exact argv list.
        NO shell strings, NO string interpolation that could be exploited.
        """
        ioc_mount = "/evidence/ioc/bundle.stix2"
        output_dir = "/evidence/output"
        input_path = "/evidence/input"

        if spec.input_type == "ios_backup":
            # Exact argv list - no shell injection possible
            return ["mvt-ios", "check-backup", "--iocs", ioc_mount, "--output", output_dir, input_path]
        elif spec.input_type == "android_backup":
            return ["mvt-android", "check-backup", "--iocs", ioc_mount, "--output", output_dir, input_path]
        else:
            raise ValueError(f"Nepodporovaný typ: {spec.input_type}")

    async def validate_input(self, spec: EvidenceInputSpec) -> bool:
        """Validate input specification."""
        return spec.input_type in self.SUPPORTED_INPUT_TYPES

    async def parse_output_artifacts(
        self, output_dir: Path
    ) -> Tuple[DetectionClassification, List[ForensicFinding], List[TimelineEvent], List[str]]:
        """Parse MVT output artifacts."""
        findings: List[ForensicFinding] = []
        timeline: List[TimelineEvent] = []
        warnings: List[str] = []
        has_hit = False
        has_suspicious = False

        if not output_dir.exists():
            return (DetectionClassification.ERROR, [], [], ["Výstupný adresár neexistuje."])

        if not any(output_dir.iterdir()):
            warnings.append("Výstupný adresár je prázdny: žiadne výstupné artefakty.")

        # 1. Detegované IoC (HIT)
        for jf in output_dir.glob("*_detected.json"):
            try:
                with open(jf, "r", encoding="utf-8") as f:
                    records = json.load(f)
                mod = jf.stem.replace("_detected", "")
                for idx, r in enumerate(records):
                    has_hit = True
                    ioc_d = r.get("matched_indicator", {})
                    findings.append(
                        ForensicFinding(
                            id=f"mvt-{mod}-{idx+1}",
                            classification=DetectionClassification.HIT,
                            confidence="HIGH",
                            ioc_type="spyware_trace",
                            ioc_name=ioc_d.get("name") or ioc_d.get("value", "Identifikovaný Spyware"),
                            artifact_path=r.get("file_path", jf.name),
                            artifact_hash=ioc_d.get("sha256"),
                            timestamp=r.get("timestamp"),
                            severity=FindingSeverity.CRITICAL,
                            description=f"Zhoda so signatúrou v module {mod}: {json.dumps(r.get('data', {}))[:180]}",
                            is_ai_assisted=False,
                        )
                    )
            except Exception as e:
                warnings.append(f"Zlyhanie čítania {jf.name}: {e}")

        # 2. Podozrivé nálezy (SUSPICIOUS)
        for sf in output_dir.glob("*_suspicious.json"):
            try:
                with open(sf, "r", encoding="utf-8") as f:
                    s_records = json.load(f)
                for idx, sr in enumerate(s_records):
                    has_suspicious = True
                    findings.append(
                        ForensicFinding(
                            id=f"susp-{sf.stem}-{idx+1}",
                            classification=DetectionClassification.SUSPICIOUS,
                            confidence="MEDIUM",
                            ioc_type="heuristic_anomaly",
                            artifact_path=sr.get("file_path", sf.name),
                            severity=FindingSeverity.MEDIUM,
                            description=f"Anomália v {sf.stem}: {json.dumps(sr)[:160]}",
                            is_ai_assisted=False,
                        )
                    )
            except Exception as e:
                warnings.append(f"Zlyhanie čítania {sf.name}: {e}")

        # Determine summary classification
        summary = DetectionClassification.NO_KNOWN_IOC
        if has_hit:
            summary = DetectionClassification.HIT
        elif has_suspicious:
            summary = DetectionClassification.SUSPICIOUS

        # Add standard limitation
        if summary == DetectionClassification.NO_KNOWN_IOC:
            pass
        else:
            pass

        return summary, findings, timeline, warnings
