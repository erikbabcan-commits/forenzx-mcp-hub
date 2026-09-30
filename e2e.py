"""Strict staging-only ForenZX Hub regression test.

All runtime values come from the staging regression environment. No secret or API
key is embedded in this file and no response body is printed.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from typing import Any

import httpx

TERMINAL_STATES = {"COMPLETED", "FAILED", "CANCELLED", "SECURITY_BLOCKED"}
CONFIRMATION = "RUN_AGAINST_STAGING"


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name}=MISSING")
    return value


def runtime_config() -> tuple[str, str]:
    if required("FORENZX_REGRESSION_CONFIRM") != CONFIRMATION:
        raise RuntimeError("FORENZX_REGRESSION_CONFIRM must be RUN_AGAINST_STAGING")
    base_url = required("FORENZX_REGRESSION_MCP_URL").rstrip("/")
    api_key = os.getenv("FORENZX_REGRESSION_MCP_API_KEY") or os.getenv("FORENZX_MCP_API_KEY")
    if not api_key:
        raise RuntimeError("FORENZX_REGRESSION_MCP_API_KEY=MISSING")
    return base_url, api_key


BASE_URL, API_KEY = runtime_config()


def rpc_call(method: str, params: dict[str, Any] | None = None, api_key: str = API_KEY) -> httpx.Response:
    return httpx.post(
        f"{BASE_URL}/mcp/jsonrpc",
        headers={"X-Api-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        },
        timeout=30,
    )


def mcp_call(name: str, args: dict[str, Any], api_key: str = API_KEY) -> httpx.Response:
    return rpc_call(
        "tools/call",
        {"name": name, "arguments": args},
        api_key,
    )


def json_body(response: httpx.Response) -> dict[str, Any]:
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("MCP returned a non-object JSON response")
    return payload


def tool_result(response: httpx.Response) -> dict[str, Any]:
    payload = json_body(response)
    if response.status_code != 200 or "error" in payload:
        raise RuntimeError("MCP tool call failed")
    content = payload.get("result", {}).get("content", [])
    for item in content:
        if item.get("type") == "text":
            parsed = json.loads(item["text"])
            if isinstance(parsed, dict):
                return parsed
    raise RuntimeError("MCP tool returned no JSON result")


def fixture_args() -> dict[str, Any]:
    return {
        "case_id": required("FORENZX_REGRESSION_CASE_ID"),
        "evidence_id": required("FORENZX_REGRESSION_EVIDENCE_ID"),
        "pack_id": required("FORENZX_REGRESSION_PACK_ID"),
        "input_type": required("FORENZX_REGRESSION_INPUT_TYPE"),
        "claimed_sha256": required("FORENZX_REGRESSION_SHA256"),
        "download_url": required("FORENZX_REGRESSION_DOWNLOAD_URL"),
        "download_filename": required("FORENZX_REGRESSION_DOWNLOAD_FILENAME"),
        "idempotency_key": os.getenv(
            "FORENZX_REGRESSION_IDEMPOTENCY_KEY",
            "forenzx-regression:" + required("FORENZX_REGRESSION_EVIDENCE_ID"),
        ),
    }


def assert_tool_contract() -> None:
    response = rpc_call("tools/list")
    payload = json_body(response)
    if response.status_code != 200:
        raise RuntimeError("tools/list failed")
    tools = payload.get("result", {}).get("tools", [])
    tool = next((item for item in tools if item.get("name") == "forenzx_analysis_start"), None)
    properties = tool.get("inputSchema", {}).get("properties", {}) if tool else {}
    if not tool or "download_url" not in properties or "download_filename" not in properties:
        raise RuntimeError("forenzx_analysis_start contract is incomplete")


def start_job(args: dict[str, Any]) -> str:
    result = tool_result(mcp_call("forenzx_analysis_start", args))
    job_id = result.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        raise RuntimeError("analysis_start did not return job_id")
    return job_id


def wait_terminal(job_id: str) -> str:
    with httpx.stream(
        "GET",
        f"{BASE_URL}/api/v1/jobs/{job_id}/events",
        headers={"X-Api-Key": API_KEY},
        timeout=None,
    ) as stream:
        for raw_line in stream.iter_lines():
            line = raw_line.decode() if isinstance(raw_line, bytes) else raw_line
            if not line.startswith("data: "):
                continue
            event = json.loads(line[6:])
            state = event.get("state")
            if state in TERMINAL_STATES:
                return state
    raise RuntimeError("SSE ended before a terminal state")


def assert_error(response: httpx.Response) -> None:
    if response.status_code < 400 and "error" not in json_body(response):
        result_text = json.dumps(json_body(response).get("result", {}))
        if "error" not in result_text.lower():
            raise RuntimeError("expected request rejection")


def run_positive_test() -> None:
    job_id = start_job(fixture_args())
    state = wait_terminal(job_id)
    if state != "COMPLETED":
        raise RuntimeError(f"positive fixture ended in {state}")
    result = tool_result(mcp_call("forenzx_analysis_results", {"job_id": job_id}))
    if not isinstance(result.get("findings"), list):
        raise RuntimeError("completed result has no findings array")
    if not isinstance(result.get("execution_record"), dict):
        raise RuntimeError("completed result has no execution_record")
    print("positive=PASS")


def run_negative_tests() -> None:
    base = fixture_args()

    wrong_hash = {**base, "claimed_sha256": "0" * 64, "idempotency_key": f"{base['idempotency_key']}:wrong-hash"}
    failed_job = start_job(wrong_hash)
    if wait_terminal(failed_job) != "FAILED":
        raise RuntimeError("wrong hash was not FAILED")
    print("wrong_hash=PASS")

    localhost = {**base, "download_url": "http://127.0.0.1/", "idempotency_key": f"{base['idempotency_key']}:localhost"}
    assert_error(mcp_call("forenzx_analysis_start", localhost))
    print("localhost_ssrf=PASS")

    disallowed = {**base, "download_url": "https://example.invalid/evidence.bin", "idempotency_key": f"{base['idempotency_key']}:host"}
    assert_error(mcp_call("forenzx_analysis_start", disallowed))
    print("hostname_allowlist=PASS")

    duplicate_key = f"{base['idempotency_key']}:duplicate"
    duplicate_args = {**base, "idempotency_key": duplicate_key}
    first = start_job(duplicate_args)
    second = tool_result(mcp_call("forenzx_analysis_start", duplicate_args))
    if second.get("job_id") != first or second.get("deduplicated") is not True:
        raise RuntimeError("duplicate idempotency key created a second job")
    print("idempotency=PASS")

    bad_key = mcp_call("forenzx_analysis_start", base, api_key="invalid-staging-key")
    if bad_key.status_code != 401:
        raise RuntimeError("invalid API key was not rejected with 401")
    print("api_key=PASS")


def main() -> int:
    try:
        assert_tool_contract()
        run_positive_test()
        run_negative_tests()
    except Exception as error:
        print(f"LOCAL E2E FAILED: {type(error).__name__}", file=sys.stderr)
        return 1
    print("LOCAL E2E PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

