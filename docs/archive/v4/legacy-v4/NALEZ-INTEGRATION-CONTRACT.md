# NALEZ Integration Contract

## Overview

This document defines the integration contract between ForenZX v4 Core and the NALEZ mobile application. It specifies only the interface that NALEZ needs to implement or use, not the frontend implementation.

## Interface Definition

### 1. Start Analysis

**Endpoint**: `POST /mcp/jsonrpc`

**Method**: `mcp_start_analysis`

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp_start_analysis",
    "arguments": {
      "case_id": "string",
      "evidence_id": "string",
      "pack_id": "string",
      "input_type": "ios_backup" | "android_backup" | "disk_raw" | "evtx_logs",
      "claimed_sha256": "string (optional)"
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"job_id\": \"uuid-string\", \"status\": \"QUEUED\", \"message\": \"Analýza beží na pozadí...\"}"
      }
    ]
  }
}
```

**Requirements**:
- `case_id`: Unique case identifier (alphanumeric, hyphen, underscore)
- `evidence_id`: Unique evidence identifier (same format as case_id)
- `pack_id`: Registered pack identifier (e.g., "mobile_compromise")
- `input_type`: Supported input type for the pack
- `claimed_sha256`: Optional SHA-256 hash for integrity verification

**Authentication**: Required (JWT or API Key)

**ACL**: User must have access to the case

---

### 2. Get Status

**Endpoint**: `POST /mcp/jsonrpc`

**Method**: `mcp_get_job_status`

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp_get_job_status",
    "arguments": {
      "job_id": "string"
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"job_id\": \"uuid\", \"case_id\": \"CASE-001\", \"evidence_id\": \"EVIDENCE-001\", \"pack_id\": \"mobile_compromise\", \"state\": \"RUNNING\", \"progress_percent\": 50, \"current_stage\": \"Processing\", \"started_at\": \"ISO8601\", \"updated_at\": \"ISO8601\", \"error_message\": null}"
      }
    ]
  }
}
```

**Requirements**:
- `job_id`: UUID of the job

**Authentication**: Required

**ACL**: User must own the job or have case access

**States**:
- `QUEUED`: Job is waiting to start
- `RUNNING`: Job is executing
- `COMPLETED`: Job finished successfully
- `FAILED`: Job failed
- `CANCELLED`: Job was cancelled

---

### 3. Get Results

**Endpoint**: `POST /mcp/jsonrpc`

**Method**: `mcp_get_results`

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp_get_results",
    "arguments": {
      "job_id": "string"
    }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{...AnalysisResult...}"
      }
    ]
  }
}
```

**AnalysisResult Schema**:
```json
{
  "job_id": "uuid",
  "pack_id": "string",
  "pack_version": "string",
  "case_id": "string",
  "evidence_id": "string",
  "started_at": "ISO8601",
  "completed_at": "ISO8601",
  "duration_seconds": 123.45,
  "status": "COMPLETED" | "FAILED" | "CANCELLED",
  "summary_classification": "HIT" | "SUSPICIOUS" | "NO_KNOWN_IOC" | "INCONCLUSIVE" | "ERROR",
  "input_integrity": {
    "root_sha256": "string",
    "size_bytes": 12345,
    "meta": {}
  },
  "findings": [
    {
      "id": "string",
      "classification": "HIT" | "SUSPICIOUS" | "NO_KNOWN_IOC" | "INCONCLUSIVE" | "ERROR",
      "confidence": "HIGH" | "MEDIUM" | "LOW",
      "ioc_type": "string",
      "ioc_name": "string (optional)",
      "artifact_path": "string",
      "artifact_hash": "string (optional)",
      "timestamp": "string (optional)",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "description": "string",
      "raw_evidence_ref": "object (optional)",
      "is_ai_assisted": false
    }
  ],
  "timeline": [
    {
      "timestamp": "string",
      "event_type": "string",
      "source_tool": "string",
      "description": "string",
      "relevance_score": 0.0
    }
  ],
  "warnings": ["string"],
  "limitations": ["string"],
  "chain_of_custody": [
    {
      "timestamp": "ISO8601",
      "action": "string",
      "actor": "string",
      "sha256_before": "string",
      "sha256_after": "string",
      "details": {}
    }
  ],
  "execution_record": {
    "case_id": "string",
    "evidence_id": "string",
    "pack_id": "string",
    "pack_version": "string",
    "container_digest": "string",
    "input_root_sha256": "string",
    "ioc_bundle_sha256": "string",
    "ioc_bundle_version": "string",
    "tool_command": ["string"],
    "exit_code": 0,
    "started_at": "ISO8601",
    "completed_at": "ISO8601",
    "manifest_canonical_sha256": "string",
    "server_hmac_signature": "string"
  }
}
```

**Requirements**:
- `job_id`: UUID of the job

**Authentication**: Required

**ACL**: User must own the job or have case access

---

### 4. Stream Progress

**Endpoint**: `GET /api/v1/jobs/{job_id}/events`

**Response**: Server-Sent Events (SSE)

```
data: {"job_id": "uuid", "case_id": "CASE-001", "evidence_id": "EVIDENCE-001", "pack_id": "mobile_compromise", "state": "RUNNING", "progress_percent": 50, "current_stage": "Processing", "started_at": "ISO8601", "updated_at": "ISO8601", "error_message": null}

...

data: {"job_id": "uuid", "case_id": "CASE-001", "evidence_id": "EVIDENCE-001", "pack_id": "mobile_compromise", "state": "COMPLETED", "progress_percent": 100, "current_stage": "COMPLETED", ...}

```

**Requirements**:
- `job_id`: UUID of the job (in path)

**Authentication**: Required

**ACL**: User must own the job or have case access

**Events**:
- State transitions (QUEUED → RUNNING → COMPLETED/FAILED)
- Progress updates (every % change or stage change)
- Final state (COMPLETED, FAILED, CANCELLED)

---

### 5. List Packs

**Endpoint**: `POST /mcp/jsonrpc`

**Method**: `mcp_list_packs`

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "mcp_list_packs",
    "arguments": {}
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"packs\": [{\"id\": \"mobile_compromise\", \"name\": \"...\", \"version\": \"2.3.2\", ...}]}"
      }
    ]
  }
}
```

**Authentication**: Required

**ACL**: All users can list packs

---

## Authentication

### JWT Authentication

**Header**: `Authorization: Bearer <token>`

**Requirements**:
- Valid JWT signature
- Not expired
- Proper claims

### API Key Authentication

**Header**: `X-API-Key: <key>`

**Requirements**:
- Key must be in configured allowlist
- Proper format

## Error Handling

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized (missing/invalid credentials) |
| 403 | Forbidden (access denied) |
| 404 | Not Found |
| 422 | Validation Error |
| 500 | Internal Server Error |

### MCP Error Codes

| Code | Description |
|------|-------------|
| -32700 | Parse Error |
| -32601 | Method Not Found |
| -32602 | Invalid Params |
| -32603 | Internal Error |

## Rate Limiting

**Not Currently Implemented**

Recommended: Implement rate limiting at the API gateway level:
- Max requests per minute per user
- Max concurrent jobs per user
- Burst protection

## Caching

**Not Currently Implemented**

Recommended: Implement caching for:
- Pack registry (reload on change)
- IOC bundles (cached in memory)
- Job results (cached for 24 hours)

## Health Checks

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "version": "4.0.0",
  "environment": "production",
  "timestamp": "ISO8601"
}
```

## WebSocket / SSE Considerations

- SSE endpoints are long-lived connections
- Proper cleanup on client disconnect
- Reconnection handling
- Authentication must be maintained

## Security Considerations

### NALEZ Must

1. Always provide valid authentication credentials
2. Validate all inputs before sending to ForenZX
3. Handle errors gracefully
4. Never expose API keys/JWT tokens in client-side code
5. Use HTTPS for all communication

### NALEZ Must Not

1. Assume any job ID format (it's UUIDv4)
2. Cache authentication tokens indefinitely
3. Ignore ACL errors
4. Retry failed jobs without user action
5. Modify evidence after submission

## Versioning

### API Version

- Current: `4.0.0`
- Format: Semantic Versioning (MAJOR.MINOR.PATCH)

### Backward Compatibility

- MAJOR version changes may break compatibility
- MINOR version changes are backward compatible
- PATCH version changes are backward compatible

## Deprecation Policy

- Deprecated endpoints will be marked in responses
- Minimum 6 months notice before removal
- Migration guides provided

## Support

### Contact

For integration support, contact: secops@forenzx.local

### Documentation

- This file: Integration contract
- SECURITY-BOUNDARIES.md: Security model
- PACK-REGISTRY.md: Pack management
- PRE-INTEGRATION-HARDENING.md: Hardening report

---

*Document Version: 1.0*
*Last Updated: 2026-09-29*
*Status: READY_FOR_INTEGRATION*
