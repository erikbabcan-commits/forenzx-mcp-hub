# ForenZX v4 - Security Boundaries

## Overview

This document defines the security boundaries and trust model for ForenZX v4 Core.

## Trust Model

### Zero-Trust Principles

1. **Never Trust, Always Verify**: Every request must be authenticated and authorized
2. **Fail Closed**: Unknown cases, jobs, packs must DENY access
3. **Least Privilege**: Users have minimum necessary access
4. **Defense in Depth**: Multiple layers of security checks

## Security Boundaries

### 1. Authentication Boundary

**Component**: `core/main.py` (FastAPI)

**Responsibilities**:
- Verify credentials (JWT or API Key)
- Production: Strict verification required
- Development: Explicit bypass only with env config
- Never auto-assign admin role

**Trust Level**: HIGH

**Controls**:
- JWT signature verification
- API key allowlist
- Environment-based bypass restriction
- No hardcoded credentials

### 2. Authorization Boundary

**Component**: `core/acl.py` (CaseAccessProvider)

**Responsibilities**:
- Check user access to cases
- Check user access to jobs
- Enforce ownership and organization constraints
- Fail closed on unknown resources

**Trust Level**: HIGH

**Controls**:
- Interface-based access control
- Ownership tracking
- Organization isolation
- Admin override capability

### 3. Input Validation Boundary

**Component**: `core/vault.py` (EvidenceVault)

**Responsibilities**:
- Validate case and evidence IDs
- Prevent path traversal attacks
- Detect symlink attacks
- Verify file system integrity

**Trust Level**: CRITICAL

**Controls**:
- Regex-based ID sanitization
- Path resolution validation
- Symlink chain detection
- Merkle tree hashing
- SHA-256 integrity verification

### 4. Threat Intelligence Boundary

**Component**: `core/threat_intel.py` (ThreatIntelVault)

**Responsibilities**:
- Load STIX2 IOC bundles
- Verify bundle integrity
- Fail closed on missing/corrupt bundles
- Track bundle metadata

**Trust Level**: HIGH

**Controls**:
- Hash verification
- File existence check
- JSON validation
- Version tracking
- Fail-closed semantics

### 5. Docker Sandbox Boundary

**Component**: `workers/isolation.py` (SandboxSecurityManager)

**Responsibilities**:
- Verify Docker image digests
- Configure container security
- Prevent privilege escalation

**Trust Level**: CRITICAL

**Controls**:
- Image digest pinning
- Read-only root filesystem
- Capability dropping (ALL)
- No new privileges
- Memory limits
- CPU limits
- PID limits
- Tmpfs with secure options

### 6. Execution Boundary

**Component**: `workers/pool.py` (WorkerPool)

**Responsibilities**:
- Execute containers safely
- Verify pre/post execution integrity
- Cleanup resources
- Handle errors gracefully

**Trust Level**: CRITICAL

**Controls**:
- Digest verification before execution
- Read-only evidence mounts
- Output directory isolation
- Container cleanup guarantee
- Scratch cleanup guarantee
- Error classification invariant

### 7. Pack Registry Boundary

**Component**: `core/pack_registry.py` (PackRegistry)

**Responsibilities**:
- Load pack manifests
- Validate pack configurations
- Register adapters
- Enforce enabled/disabled state

**Trust Level**: HIGH

**Controls**:
- Pydantic manifest validation
- Fail-closed on invalid packs
- Enabled/disabled state checking
- Dynamic adapter loading

### 8. MCP Protocol Boundary

**Component**: `core/server.py` (MCPServer)

**Responsibilities**:
- Handle JSON-RPC requests
- Validate tool calls
- Return proper error codes
- Enforce authentication

**Trust Level**: MEDIUM

**Controls**:
- MCP error codes (-32700, -32601, -32602, -32603)
- Tool parameter validation
- Authentication enforcement
- Capabilities honesty

## Data Flow Security

### Request Flow

```
Client Request
     ↓
HTTP Auth (JWT/API Key)
     ↓
MCP Server (JSON-RPC)
     ↓
ACL Check (Case/Job Access)
     ↓
Pack Registry (Validate Pack)
     ↓
Threat Intel (Load IOC Bundle)
     ↓
Evidence Vault (Resolve Path)
     ↓
Worker Pool (Execute Container)
     ↓
Result Verification
     ↓
Response
```

### Data Classification

#### CRITICAL
- Evidence files
- Chain of custody
- Execution records
- HMAC signatures

#### HIGH
- API keys
- JWT tokens
- Case metadata
- Job metadata

#### MEDIUM
- Pack manifests
- IOC bundles
- Log data

## Attack Surface Reduction

### Removed Attack Vectors

1. **Path Traversal**: Blocked by EvidenceVault
2. **Symlink Attacks**: Detected and blocked
3. **Shell Injection**: No shell strings, only argv lists
4. **Privilege Escalation**: Docker capabilities dropped
5. **Credential Leakage**: No hardcoded credentials
6. **CORS Attacks**: Explicit allowlist in production

### Isolated Components

1. **Docker Sandbox**: Evidence mounted read-only
2. **Worker Pool**: Semaphore-limited concurrency
3. **Scratch Directories**: Unique per job, always cleaned up
4. **Network Access**: Disabled by default

## Security Invariants

### Always True

1. `exit_code != 0` → `status == FAILED` AND `classification == ERROR`
2. Unknown case → `403 FORBIDDEN`
3. Unknown job → `403 FORBIDDEN`
4. Pre-execution hash == Post-execution hash (or breach detected)
5. `is_ai_assisted == False` for all deterministic findings

### Never True

1. Admin role without authentication
2. Shell string commands
3. `shell=True` in subprocess
4. Wildcard CORS with credentials in production
5. Synthetic IOC bundles in production

## Monitoring and Auditing

### Logged Events

All security-relevant events are logged with:
- Timestamp
- User ID
- Case ID
- Job ID
- Action
- Status
- Details

### Audit Trail

1. **Authentication**: All auth attempts logged
2. **Authorization**: All access denials logged
3. **Execution**: All job executions logged
4. **Integrity**: All hash verifications logged
5. **Cleanup**: All cleanup operations logged

## Compliance

### Forensic Requirements
- Chain of custody maintained
- Evidence integrity verified
- All findings traceable
- No AI as direct evidence

### Security Requirements
- Zero-trust architecture
- Fail-closed semantics
- Least privilege
- Defense in depth

---

*Document Version: 1.0*
*Last Updated: 2026-09-29*
