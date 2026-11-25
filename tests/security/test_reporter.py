"""Real production HTTP auth and dispatcher; synthetic jobs, no engines or models."""

import json
import time
from pathlib import Path
from unittest.mock import Mock

import jwt
import pytest
from fastapi.testclient import TestClient

from core.acl import DatabaseBackedCaseAccessProvider, TokenUser, case_access_provider
from core.config import config
from core.db import db
from core.jobs import job_manager
from core.main import app
from core.models.forensic import AnalysisResult, AnalysisState
from core.pack_registry import pack_registry


@pytest.fixture
def scenario(monkeypatch):
    monkeypatch.setattr(config, "environment", "production")
    monkeypatch.setattr(config, "jwt_secret_key", "synthetic-reporter-test-secret-only-123456789")
    case = "SYNTHETIC-REPORTER-CASE"
    case_access_provider.register_case(case, "owner", "org-a")
    job, _ = job_manager.create_job(
        case_id=case, evidence_id="SYNTHETIC-EVIDENCE", pack_id="synthetic", owner_id="owner", organization_id="org-a"
    )
    client = TestClient(app)  # no lifespan; no network, health scheduler or worker

    def headers(**overrides):
        claims = {
            "sub": "reader",
            "organization": "org-a",
            "roles": ["reporter"],
            "report_case_ids": [case],
            "report_job_ids": [job],
            "exp": int(time.time()) + 120,
        }
        claims.update(overrides)
        return {"Authorization": "Bearer " + jwt.encode(claims, config.jwt_secret_key, algorithm="HS256")}

    def rpc(name, route="/mcp", arguments=None, **claims):
        return client.post(
            route,
            headers=headers(**claims),
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {"job_id": job}},
            },
        )

    return case, job, client, headers, rpc


def snapshot():
    return json.dumps(
        {
            "jobs": db.fetchall("SELECT * FROM jobs ORDER BY job_id"),
            "results": db.fetchall("SELECT * FROM job_results ORDER BY job_id"),
        },
        sort_keys=True,
    )


@pytest.mark.parametrize("route", ["/mcp", "/mcp/jsonrpc"])
@pytest.mark.parametrize("name", ["forenzx_analysis_start", "mcp_start_analysis", "forenzx_analysis_cancel"])
@pytest.mark.parametrize("roles", [["reporter"], ["reporter", "admin", "analyst"], []])
def test_writes_denied_before_side_effects(scenario, monkeypatch, route, name, roles):
    _, job, _, _, rpc = scenario
    lookup = Mock(side_effect=AssertionError("pack lookup reached"))
    monkeypatch.setattr(pack_registry, "get_pack", lookup)
    before = snapshot()
    tasks = dict(job_manager._tasks)
    response = rpc(name, route, roles=roles)
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32603
    assert not lookup.called
    assert snapshot() == before
    assert job_manager._tasks == tasks
    assert job_manager.get_status(job).state == AnalysisState.QUEUED


@pytest.mark.parametrize("route", ["/mcp", "/mcp/jsonrpc"])
@pytest.mark.parametrize("name", ["forenzx_analysis_status", "mcp_get_job_status"])
def test_granted_status(scenario, route, name):
    case, job, _, _, rpc = scenario
    response = rpc(name, route)
    payload = json.loads(response.json()["result"]["content"][0]["text"])
    assert payload["job_id"] == job
    assert payload["case_id"] == case
    assert payload["evidence_id"] == "SYNTHETIC-EVIDENCE"


@pytest.mark.parametrize(
    "claims",
    [
        {"report_case_ids": []},
        {"report_job_ids": []},
        {"organization": "org-b", "sub": "owner"},
        {"report_case_ids": ["foreign-case"]},
        {"report_job_ids": ["foreign-job"]},
        {"roles": []},
    ],
)
@pytest.mark.parametrize("route", ["/mcp", "/mcp/jsonrpc"])
@pytest.mark.parametrize(
    "name", ["forenzx_analysis_status", "mcp_get_job_status", "forenzx_analysis_results", "mcp_get_results"]
)
def test_ungranted_reads_denied(scenario, claims, route, name):
    *_, rpc = scenario
    before = snapshot()
    assert rpc(name, route, **claims).json()["error"]["code"] == -32603
    assert snapshot() == before


def test_sse_and_discovery(scenario):
    _, job, client, headers, _ = scenario
    job_manager.update_progress(job, AnalysisState.CANCELLED, 100, "CANCELLED")
    assert client.get(f"/api/v1/jobs/{job}/events", headers=headers()).status_code == 200
    assert client.get(f"/api/v1/jobs/{job}/events", headers=headers(report_job_ids=[])).status_code == 403
    response = client.post("/mcp", headers=headers(), json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert {tool["name"] for tool in response.json()["result"]["tools"]} == {
        "forenzx_analysis_status",
        "forenzx_analysis_results",
    }


def test_malformed_grants_rejected(scenario):
    _, _, client, headers, _ = scenario
    for grant in ["wildcard", [1], None, {"job": True}]:
        response = client.post("/mcp", headers=headers(report_job_ids=grant), json={"method": "tools/list"})
        assert response.status_code == 401


def test_case_fallback_cannot_cross_job_org():
    acl = DatabaseBackedCaseAccessProvider()
    acl.register_case("case", "reader", "org-a")
    acl.register_job("job", "reader", "org-b", "case")
    user = TokenUser(
        user_id="reader", roles=["reporter"], organization="org-a", report_case_ids=["case"], report_job_ids=["job"]
    )
    assert not acl.can_access_job(user, "job", "case")
    acl.register_job("job", "reader", "org-a", "different-case")
    assert not acl.can_access_job(user, "job", "case")


@pytest.mark.parametrize("route", ["/mcp", "/mcp/jsonrpc"])
@pytest.mark.parametrize("name", ["forenzx_analysis_results", "mcp_get_results"])
def test_granted_results_preserve_payload(scenario, route, name):
    case, job, _, _, rpc = scenario
    payload = json.loads((Path(__file__).parents[1] / "fixtures/reporter-completed-synthetic.json").read_text())
    payload.update(job_id=job, case_id=case, evidence_id="SYNTHETIC-EVIDENCE")
    payload["execution_record"].update(case_id=case, evidence_id="SYNTHETIC-EVIDENCE")
    model = AnalysisResult.model_validate(payload)
    job_manager.store_result(job, model)
    before = snapshot()
    response = rpc(name, route)
    actual = json.loads(response.json()["result"]["content"][0]["text"])
    assert actual == model.model_dump(mode="json")
    assert actual["warnings"] == payload["warnings"]
    assert snapshot() == before
