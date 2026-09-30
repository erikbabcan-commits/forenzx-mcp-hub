# ForenZX v4 - Pack Registry Specification

## Overview

The Pack Registry is the central component for managing forensic analysis packs in ForenZX v4. It provides a secure, fail-closed mechanism for loading, validating, and accessing packs.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        Pack Registry                       │
├─────────────────────────────────────────────────────────┤
│  PackRegistry                                             │
│  ├── _packs: Dict[str, PackManifest]                      │
│  ├── _adapters: Dict[str, Type[ForensicPackAdapter]]     │
│  └── _manifest_paths: Dict[str, Path]                    │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Packs Directory                          │
├─────────────────────────────────────────────────────────┤
│  packs/                                                  │
│  ├── mobile_compromise/                                 │
│  │   ├── manifest.json                                  │
│  │   └── adapter.py                                     │
│  ├── exif/                                             │
│  │   ├── manifest.json                                  │
│  │   └── adapter.py                                     │
│  └── tsk/                                              │
│      ├── manifest.json                                  │
│      └── adapter.py                                     │
└─────────────────────────────────────────────────────────┘
```

## Pack Manifest

Each pack must have a `manifest.json` file with the following schema:

```json
{
  "id": "unique-pack-identifier",
  "name": "Human-readable pack name",
  "version": "1.0.0",
  "description": "Pack description",
  "license": "License identifier",
  "author": "Pack author",
  "supported_platforms": ["ios", "android", "linux"],
  "supported_inputs": ["ios_backup", "android_backup"],
  "capabilities": ["ioc_matching", "file_analysis"],
  "container_image": "docker-image-name",
  "pinned_image_digest": "sha256:abc123...",
  "read_only_strictly_enforced": true,
  "network_required": false,
  "max_memory_mb": 4096,
  "max_cpu_cores": 2.0,
  "timeout_seconds": 3600,
  "healthcheck_cmd": ["mvt-ios", "--version"],
  "enabled": true
}
```

### PackManifest Model

```python
class PackManifest(BaseModel):
    id: str = Field(..., pattern=r"^[a-z0-9\-]+$")
    name: str
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+$")
    description: str
    license: str
    author: str
    supported_platforms: List[Literal["ios", "android", "windows", "linux", "macos", "cloud", "agnostic"]]
    supported_inputs: List[str]
    capabilities: List[str]
    container_image: str
    pinned_image_digest: str
    read_only_strictly_enforced: bool = True
    network_required: bool = False
    max_memory_mb: int = 4096
    max_cpu_cores: float = 2.0
    timeout_seconds: int = 3600
    healthcheck_cmd: List[str]
    enabled: bool = True
```

## Pack Adapter

Each pack must have an `adapter.py` file that defines a class inheriting from `ForensicPackAdapter`:

```python
from packs.base import ForensicPackAdapter
from core.models.forensic import PackManifest, EvidenceInputSpec, DetectionClassification, ForensicFinding, TimelineEvent
from pathlib import Path
from typing import Any, Dict, List, Tuple

class MyPackAdapter(ForensicPackAdapter):
    def get_execution_command(self, spec: EvidenceInputSpec, params: Dict[str, Any]) -> List[str]:
        """Return execution command as argv list."""
        return ["my-tool", "--input", "/evidence/input", "--output", "/evidence/output"]
    
    async def validate_input(self, spec: EvidenceInputSpec) -> bool:
        """Validate input specification."""
        return spec.input_type in self.SUPPORTED_INPUT_TYPES
    
    async def parse_output_artifacts(
        self, output_dir: Path
    ) -> Tuple[DetectionClassification, List[ForensicFinding], List[TimelineEvent], List[str]]:
        """Parse output artifacts."""
        findings = []
        timeline = []
        warnings = []
        classification = DetectionClassification.NO_KNOWN_IOC
        
        # Parse output files...
        
        return classification, findings, timeline, warnings
```

### ForensicPackAdapter Interface

```python
class ForensicPackAdapter(ABC):
    def __init__(self, manifest: PackManifest, scratch_dir: Path) -> None:
        self.manifest = manifest
        self.scratch_dir = scratch_dir
    
    @abstractmethod
    def get_execution_command(self, spec: EvidenceInputSpec, params: Dict[str, Any]) -> List[str]:
        """Get execution command as argv list."""
        pass
    
    @abstractmethod
    async def validate_input(self, spec: EvidenceInputSpec) -> bool:
        """Validate input specification."""
        pass
    
    @abstractmethod
    async def parse_output_artifacts(
        self, output_dir: Path
    ) -> Tuple[DetectionClassification, List[ForensicFinding], List[TimelineEvent], List[str]]:
        """Parse output artifacts."""
        pass
```

## Registry Operations

### Loading Packs

```python
registry = PackRegistry()
registry.load_packs()  # Loads all packs from packs/*/manifest.json
```

### Listing Packs

```python
packs = registry.list_packs()  # Returns List[PackManifest]
```

### Getting a Pack

```python
manifest = registry.get_pack("mobile_compromise")  # Returns PackManifest or None
# Returns None if:
# - Pack doesn't exist
# - Pack is disabled
```

### Getting an Adapter

```python
adapter_class = registry.get_adapter("mobile_compromise")  # Returns Type[ForensicPackAdapter] or None
# Returns None if:
# - Pack doesn't exist
# - Pack is disabled
# - Adapter not found
```

### Checking Support

```python
inputs = registry.get_supported_inputs("mobile_compromise")  # Returns List[str]
enabled = registry.is_pack_enabled("mobile_compromise")  # Returns bool
```

## Fail-Closed Semantics

The Pack Registry follows fail-closed principles:

1. **Unknown Pack**: Returns `None` (not an error, but caller should treat as FAIL CLOSED)
2. **Disabled Pack**: Returns `None` (FAIL CLOSED)
3. **Invalid Manifest**: Raises `PackRegistryError` (SERVER STARTUP FAIL)
4. **Missing Adapter**: Returns `None` for adapter (FAIL CLOSED)

## Validation

### PackManifest Validation

- `id`: Must match pattern `^[a-z0-9\-]+$`
- `version`: Must match pattern `^\d+\.\d+\.\d+$`
- All required fields must be present
- All types must be correct

### Adapter Validation

- Must inherit from `ForensicPackAdapter`
- Must implement all abstract methods
- Must be importable from `adapter.py`

## Security Considerations

### Image Digest Pinning

Each pack specifies a `pinned_image_digest` that must match the actual Docker image digest before execution. This prevents:
- Supply chain attacks via image substitution
- Use of unpinned tags like `:latest`
- Execution of unverified images

### Read-Only Filesystem

Packs can specify `read_only_strictly_enforced = True` to ensure the container filesystem is read-only. This prevents:
- Evidence tampering
- Malware installation in container
- Persistent modifications

### Network Isolation

Packs can specify `network_required = False` (default) to disable network access. This prevents:
- Exfiltration of evidence
- Download of additional malware
- Communication with C2 servers

## Built-in Packs

### mobile_compromise

- **ID**: `mobile_compromise`
- **Version**: `2.3.2`
- **Description**: Mobile Verification Toolkit for iOS and Android
- **Platforms**: `ios`, `android`
- **Inputs**: `ios_backup`, `android_backup`
- **Capabilities**: `ioc_matching`, `spyware_detection`, `file_analysis`, `timeline_analysis`
- **Image**: `ghcr.io/mvt-project/mvt`
- **Digest**: Pinned SHA-256
- **Network**: Not required (read-only evidence)

### Future Packs

Additional packs can be added by creating a directory under `packs/` with:
1. `manifest.json` - Pack configuration
2. `adapter.py` - Pack adapter implementation

## Error Handling

### PackRegistryError

Raised when pack loading fails:
- Invalid manifest JSON
- Missing required fields
- Invalid field values

### Handling Errors

```python
try:
    registry.load_packs()
except PackRegistryError as e:
    # Handle error - typically during server startup
    logger.error(f"Failed to load packs: {e}")
    # Server should fail to start
```

## Configuration

### Environment Variables

```bash
# Pack directory
EXPORT PACKS_DIR=./packs
```

### Default Values

- `packs_dir`: `./packs` (relative to project root)

## Usage Example

```python
from core.pack_registry import pack_registry
from core.jobs import job_manager
from core.models.forensic import EvidenceInputSpec

# Load packs at startup
pack_registry.load_packs()

# Create a job with a specific pack
manifest = pack_registry.get_pack("mobile_compromise")
adapter_class = pack_registry.get_adapter("mobile_compromise")

if manifest and adapter_class:
    spec = EvidenceInputSpec(
        case_id="CASE-001",
        evidence_id="EVIDENCE-001",
        input_type="ios_backup"
    )
    
    # Execute analysis...
else:
    # Pack not found or disabled - fail closed
    raise ValueError("Pack not available")
```

---

*Document Version: 1.0*
*Last Updated: 2026-09-29*
