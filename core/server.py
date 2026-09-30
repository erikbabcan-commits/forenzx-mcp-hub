"""ForenZX v5 MCP engine with canonical tools and backward-compatible aliases."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, cast

from fastapi import HTTPException

from core.acl import CaseAccessController, TokenUser
from core.config import config
from core.jobs import job_manager
from core.models.forensic import AnalysisState, EvidenceInputSpec
from core.pack_registry import pack_registry
from core.signing import signer
from core.utils.logger import get_logger
from core.vault_downloader import download_evidence_to_vault
from workers.pool import WorkerPool

logger = get_logger(__name__)


class MCPError(Exception):
    pass


class MCPServer:
    MCP_PROTOCOL_VERSION = "2026-07-28"
    SERVER_NAME = "forenzx_mcp"
    SERVER_VERSION = "5.0.0"

    ALIASES = {
        "mcp_list_packs": "forenzx_packs_list",
        "mcp_start_analysis": "forenzx_analysis_start",
        "mcp_get_job_status": "forenzx_analysis_status",
        "mcp_get_results": "forenzx_analysis_results",
    }

    def __init__(self, pool: WorkerPool) -> None:
        self.pool = pool

    async def list_tools_schema(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "forenzx_health",
                "description": "Return ForenZX MCP service health and version metadata.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "forenzx_capabilities",
                "description": "Return enabled forensic packs, supported inputs and signing capability.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "forenzx_packs_list",
                "description": "List registered forensic analysis packs and their capabilities.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "forenzx_analysis_start",
                "description": "Start an asynchronous deterministic forensic analysis in an isolated worker.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "case_id": {"type": "string", "maxLength": 128},
                        "evidence_id": {"type": "string", "maxLength": 128},
                        "pack_id": {"type": "string", "maxLength": 128},
                        "input_type": {"type": "string"},
                        "claimed_sha256": {"type": "string", "pattern": "^[a-fA-F0-9]{64}$"},
                        "download_url": {"type": "string", "format": "uri", "pattern": "^https://"},
                        "download_filename": {"type": "string", "maxLength": 200},
                        "idempotency_key": {"type": "string", "maxLength": 128},
                        "params": {"type": "object", "additionalProperties": True},
                    },
                    "required": ["case_id", "evidence_id", "pack_id", "input_type"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "forenzx_analysis_status",
                "description": "Get durable status and progress for an analysis job.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "maxLength": 128}},
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "forenzx_analysis_cancel",
                "description": "Cancel an analysis job owned by the current principal or accessible case.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "maxLength": 128}},
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "forenzx_analysis_results",
                "description": "Return deterministic forensic results and signed execution record for a completed job.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "maxLength": 128}},
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
            },
        ]

    async def handle_tool_call(self, name: str, args: Dict[str, Any], user: TokenUser) -> Dict[str, Any]:
        name = self.ALIASES.get(name, name)

        if name == "forenzx_health":
            return {
                "status": "READY",
                "service": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
                "protocol": self.MCP_PROTOCOL_VERSION,
            }

        if name == "forenzx_capabilities":
            packs = pack_registry.describe()
            return {
                "service": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
                "mcp_protocol": self.MCP_PROTOCOL_VERSION,
                "packs": packs,
                "signing": signer.public_info(),
            }

        if name == "forenzx_packs_list":
            return {"packs": pack_registry.describe()}

        if name == "forenzx_analysis_start":
            for param in ("case_id", "evidence_id", "pack_id", "input_type"):
                if param not in args:
                    raise MCPError(f"Missing required parameter: {param}")

            case_id = str(args["case_id"])
            evidence_id = str(args["evidence_id"])
            pack_id = str(args["pack_id"])
            input_type = str(args["input_type"])
            claimed_sha256 = args.get("claimed_sha256")
            download_url = args.get("download_url")
            download_filename = args.get("download_filename")
            idempotency_key = args.get("idempotency_key")
            params = args.get("params", {})

            CaseAccessController.enforce(user, case_id)
            manifest = pack_registry.get_pack(pack_id)
            if not manifest:
                err = pack_registry.errors().get(pack_id)
                suffix = f" ({err})" if err else ""
                raise MCPError(f"Pack '{pack_id}' is unavailable or disabled{suffix}.")
            if input_type not in manifest.supported_inputs:
                raise MCPError(f"Pack '{pack_id}' does not support input '{input_type}'.")
            adapter_class = pack_registry.get_adapter(pack_id)
            if not adapter_class:
                raise MCPError(f"No adapter is available for pack '{pack_id}'.")

            spec = EvidenceInputSpec(
                case_id=case_id,
                evidence_id=evidence_id,
                # Runtime validation of the literal happens in EvidenceInputSpec (fail closed).
                input_type=cast(Any, input_type),
                claimed_sha256=claimed_sha256,
            )
            job_id, _, created = job_manager.create_job_ex(
                case_id=case_id,
                evidence_id=evidence_id,
                pack_id=pack_id,
                owner_id=user.user_id,
                organization_id=user.organization or "default_org",
                idempotency_key=str(idempotency_key) if idempotency_key else None,
            )
            if not created:
                current = job_manager.get_status(job_id)
                return {
                    "job_id": job_id,
                    "status": current.state.value if current else "UNKNOWN",
                    "deduplicated": True,
                }

            async def run_bg() -> None:
                try:
                    scratch_dir = config.scratch_base_dir / job_id
                    if download_url:
                        await download_evidence_to_vault(
                            case_id,
                            evidence_id,
                            str(download_url),
                            str(claimed_sha256) if claimed_sha256 else None,
                            str(download_filename) if download_filename else None,
                        )
                        job_manager.update_progress(job_id, AnalysisState.RUNNING, 2, "Downloading evidence from S3")
                    adapter = adapter_class(manifest, scratch_dir)
                    result = await self.pool.execute(
                        job_id,
                        manifest,
                        adapter,
                        spec,
                        params,
                        lambda state, prog, stage: job_manager.update_progress(job_id, state, prog, stage),
                    )
                    job_manager.store_result(job_id, result)
                except asyncio.CancelledError:
                    job_manager.update_progress(job_id, AnalysisState.CANCELLED, 100, "CANCELLED", "Job was cancelled")
                    raise
                except Exception as exc:
                    job_manager.fail_job(job_id, str(exc))
                    logger.exception(f"Background job {job_id} failed")
                finally:
                    job_manager.cleanup_task(job_id)

            task = asyncio.create_task(run_bg())
            job_manager.register_task(job_id, task)
            return {"job_id": job_id, "status": "QUEUED", "deduplicated": False}

        if name in {"forenzx_analysis_status", "forenzx_analysis_cancel", "forenzx_analysis_results"}:
            target_job_id = str(args.get("job_id") or "")
            if not target_job_id:
                raise MCPError("Missing job_id parameter")
            job_spec = job_manager.get_spec(target_job_id)
            if not job_spec:
                raise MCPError("Job not found")
            CaseAccessController.enforce_job_access(user, target_job_id, job_spec.case_id)

            if name == "forenzx_analysis_status":
                status = job_manager.get_status(target_job_id)
                if not status:
                    raise MCPError("Job status unavailable")
                return status.model_dump(mode="json")

            if name == "forenzx_analysis_cancel":
                return {"job_id": target_job_id, "cancelled": job_manager.cancel_job(target_job_id)}

            result = job_manager.get_result(target_job_id)
            if result:
                return result.model_dump(mode="json")
            status = job_manager.get_status(target_job_id)
            return {
                "job_id": target_job_id,
                "status": status.state.value if status else "UNKNOWN",
                "message": "Results are not available yet.",
            }

        raise MCPError(f"Tool '{name}' does not exist.")

    async def process_json_rpc(self, raw_req: str, user: TokenUser, request_id: Optional[int | str] = None) -> str:
        try:
            req = json.loads(raw_req)
            if not isinstance(req, dict):
                raise json.JSONDecodeError("request must be object", raw_req, 0)
            req_id = req.get("id", request_id)
            method = req.get("method")
            params = req.get("params") or {}

            if req.get("jsonrpc") not in (None, "2.0"):
                return self._error(req_id, -32600, "Invalid Request: jsonrpc must be 2.0")

            # Compatibility only. The modern /mcp route does not require an initialize session.
            if method == "initialize":
                return json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": self.MCP_PROTOCOL_VERSION,
                            "serverInfo": {"name": self.SERVER_NAME, "version": self.SERVER_VERSION},
                            "capabilities": {"tools": {}},
                        },
                    }
                )

            if method == "ping":
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})

            if method == "tools/list":
                return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {"tools": await self.list_tools_schema()}})

            if method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {})
                if not name:
                    return self._error(req_id, -32602, "Missing tool name")
                if not isinstance(arguments, dict):
                    return self._error(req_id, -32602, "arguments must be an object")
                try:
                    result = await self.handle_tool_call(str(name), arguments, user)
                    return json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                                "isError": False,
                            },
                        },
                        ensure_ascii=False,
                    )
                except (MCPError, ValueError) as exc:
                    return self._error(req_id, -32602, str(exc))
                except HTTPException as exc:
                    return self._error(req_id, -32603, str(exc.detail))

            return self._error(req_id, -32601, f"Method '{method}' is not supported")
        except json.JSONDecodeError as exc:
            return self._error(None, -32700, f"Invalid JSON: {exc}")
        except Exception:
            logger.exception("Internal JSON-RPC error")
            return self._error(None, -32603, "Internal server error")

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> str:
        return json.dumps(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}, ensure_ascii=False
        )
