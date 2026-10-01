import httpx
import json

API_KEY = "forenzx_admin_557c99b7-eec5-4097-97f0-10940cddfca1"
BASE_URL = "http://127.0.0.1:8000"

resp = httpx.post(
    f"{BASE_URL}/mcp/jsonrpc",
    headers={"X-Api-Key": API_KEY},
    json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "forenzx_analysis_start",
            "arguments": {
                "case_id": "CASE-001",
                "evidence_id": "EV-1",
                "pack_id": "mobile_compromise",
                "input_type": "ios_backup",
                "download_url": "http://127.0.0.1/",
                "download_filename": "dummy.txt",
                "idempotency_key": "test_local"
            }
        }
    }
)
job_id = json.loads(resp.json()["result"]["content"][0]["text"])["job_id"]
import time
time.sleep(2)
status_resp = httpx.post(
    f"{BASE_URL}/mcp/jsonrpc",
    headers={"X-Api-Key": API_KEY},
    json={
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "forenzx_analysis_results",
            "arguments": {"job_id": job_id}
        }
    }
)
print("SSRF Test Results:")
print(status_resp.json()["result"]["content"][0]["text"])
