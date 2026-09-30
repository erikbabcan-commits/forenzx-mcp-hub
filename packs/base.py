"""
Abstraktný ForensicPackAdapter - základ pre všetky forenzné packy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.models.forensic import (
    DetectionClassification,
    EvidenceInputSpec,
    ForensicFinding,
    PackManifest,
    TimelineEvent,
)


class ForensicPackAdapter(ABC):
    """Abstract base class for forensic analysis pack adapters."""

    def __init__(self, manifest: PackManifest, scratch_dir: Path) -> None:
        self.manifest = manifest
        self.scratch_dir = scratch_dir

    @abstractmethod
    def get_execution_command(self, spec: EvidenceInputSpec, params: Dict[str, Any]) -> List[str]:
        """
        Get the execution command as a list of arguments.

        IMPORTANT: Must use argv list format, NOT shell string.
        Direct command execution only, no shell wrappers or string concatenation.
        """
        pass

    @abstractmethod
    async def validate_input(self, spec: EvidenceInputSpec) -> bool:
        """Validate that the input spec is supported by this pack."""
        pass

    @abstractmethod
    async def parse_output_artifacts(
        self, output_dir: Path
    ) -> Tuple[DetectionClassification, List[ForensicFinding], List[TimelineEvent], List[str]]:
        """
        Parse output artifacts from the analysis.

        Returns:
            - summary_classification: Overall detection classification
            - findings: List of forensic findings
            - timeline: List of timeline events
            - warnings: List of warning messages
        """
        pass
