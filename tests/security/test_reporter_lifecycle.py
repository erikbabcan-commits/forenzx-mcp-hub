"""Synthetic credential lifecycle: real auth plus an independent process restart."""

import importlib
import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from core.acl import PersistentCaseAccessProvider, case_access_provider
from core.config import config
from core.db import Database
from core.jobs import job_manager
from core.main import AuthConfig, app
from core.reporter_credentials import issue_reporter, main, revoke_reporter, write_private_token


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    database = Database(tmp_path / "lifecycle.sqlite")
    for module in ("core.db", "core.jobs", "core.reporter_credentials"):
        monkeypatch.setattr(importlib.import_module(module), "db", database)
    monkeypatch.setattr(config, "environment", "production")
    monkeypatch.setattr(config, "jwt_secret_key", secrets.token_urlsafe(48))
    case_access_provider.register_case("case", "owner", "org")
    job, _ = job_manager.create_job("case", "evidence", "synthetic", "owner", "org")
    return database, job


def issue(job):
    return issue_reporter(subject="reader", organization="org", case_id="case", job_ids=[job])


@pytest.mark.parametrize("route", ["/mcp", "/mcp/jsonrpc"])
def test_revoke_next_request_and_keep_other_credential(isolated, route):
    database, job = isolated
    first, second = issue(job), issue(job)
    client = TestClient(app)

    def request(token):
        return client.post(
            route,
            headers={"Authorization": "Bearer " + token},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "forenzx_analysis_status", "arguments": {"job_id": job}},
            },
        )

    assert "result" in request(first).json()
    revoke_reporter(first)
    revoke_reporter(first)  # idempotent
    assert request(first).status_code == 401
    assert "result" in request(second).json()
    assert len(database.fetchall("SELECT * FROM revoked_reporter_tokens")) == 1
    assert first not in str(database.fetchall("SELECT * FROM revoked_reporter_tokens"))


def test_signature_encoding_cannot_bypass_revocation(isolated):
    _, job = isolated
    token = issue(job)
    alternate = token + "="  # accepted base64 padding, same authenticated input
    assert AuthConfig.jwt_user(alternate) is not None
    revoke_reporter(token)
    assert AuthConfig.jwt_user(alternate) is None


def test_expiry_and_store_failure_deny(isolated, monkeypatch):
    database, job = isolated
    token = issue(job)
    claims = jwt.decode(token, config.jwt_secret_key, algorithms=["HS256"])
    claims["exp"] = int(time.time()) - 1
    assert AuthConfig.jwt_user(jwt.encode(claims, config.jwt_secret_key, algorithm="HS256")) is None

    def unavailable(*args, **kwargs):
        raise OSError("synthetic database outage")

    monkeypatch.setattr(database, "fetchone", unavailable)
    assert AuthConfig.jwt_user(token) is None


@pytest.mark.parametrize(
    "change",
    [
        {"organization": "foreign"},
        {"case_id": "unknown"},
        {"job_ids": ["unknown"]},
        {"job_ids": []},
        {"ttl": 0},
        {"ttl": 3601},
        {"subject": " "},
    ],
)
def test_issue_rejects_invalid_scope(isolated, change):
    _, job = isolated
    args = dict(subject="reader", organization="org", case_id="case", job_ids=[job])
    args.update(change)
    with pytest.raises(ValueError):
        issue_reporter(**args)


def test_persistent_acl_rejects_conflicting_registration(isolated):
    _, job = isolated
    restored = PersistentCaseAccessProvider()
    assert restored.get_case_owner("case") == "owner"
    assert restored.get_job_owner(job) == ("owner", "org")
    with pytest.raises(ValueError):
        restored.register_case("case", "attacker", "foreign")
    assert restored.get_case_organization("case") == "org"


def test_legacy_no_jti_can_be_revoked_and_analyst_rejected(isolated):
    _, job = isolated
    claims = jwt.decode(issue(job), config.jwt_secret_key, algorithms=["HS256"])
    del claims["jti"]
    token = jwt.encode(claims, config.jwt_secret_key, algorithm="HS256")
    assert AuthConfig.jwt_user(token) is not None
    revoke_reporter(token)
    assert AuthConfig.jwt_user(token) is None
    claims["roles"] = ["analyst"]
    with pytest.raises(ValueError):
        revoke_reporter(jwt.encode(claims, config.jwt_secret_key, algorithm="HS256"))


def test_case_lookup_has_no_stale_authorization_cache(isolated):
    database, job = isolated
    user = AuthConfig.jwt_user(issue(job))
    assert case_access_provider.can_access_job(user, job, "case")
    database.execute("DELETE FROM case_acl WHERE case_id=?", ("case",))
    assert not case_access_provider.can_access_job(user, job, "case")


def test_invalid_signature_cannot_write_revocation(isolated):
    database, job = isolated
    claims = jwt.decode(issue(job), config.jwt_secret_key, algorithms=["HS256"])
    forged = jwt.encode(claims, secrets.token_urlsafe(48), algorithm="HS256")
    with pytest.raises(jwt.InvalidSignatureError):
        revoke_reporter(forged)
    assert database.fetchall("SELECT * FROM revoked_reporter_tokens") == []


def test_cli_private_output_no_overwrite_or_secret_print(isolated, tmp_path, capsys):
    _, job = isolated
    output = tmp_path / "reporter.jwt"
    args = [
        "issue",
        "--subject",
        "reader",
        "--organization",
        "org",
        "--case-id",
        "case",
        "--job-id",
        job,
        "--output",
        str(output),
    ]
    assert main(args) == 0
    token = output.read_text().strip()
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert AuthConfig.jwt_user(token) is not None
    assert main(args) == 1
    assert output.read_text().strip() == token
    link = tmp_path / "link.jwt"
    link.symlink_to(output)
    with pytest.raises(FileExistsError):
        write_private_token(link, "replacement")
    assert main(["revoke", "--token-file", str(output)]) == 0
    assert AuthConfig.jwt_user(token) is None
    assert token not in capsys.readouterr().out


@contextmanager
def live_server(env, log_path):
    # Parent owns the listening socket and child; no port race or unrelated kill.
    with socket.socket() as sock, log_path.open("wb") as log:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "core.main:app",
                "--fd",
                str(sock.fileno()),
                "--lifespan",
                "off",
                "--no-access-log",
            ],
            env=env,
            pass_fds=(sock.fileno(),),
            stdout=log,
            stderr=log,
        )
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(100):
                if proc.poll() is not None:
                    pytest.fail("synthetic Hub exited before readiness")
                try:
                    if httpx.get(url + "/health", timeout=0.2, trust_env=False).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("synthetic Hub readiness timed out")
            yield url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def test_real_process_restart_preserves_revocation_and_other_reporter(tmp_path):
    env = dict(
        os.environ,
        ENVIRONMENT="production",
        DATA_DIR=str(tmp_path / "data"),
        DATABASE_PATH=str(tmp_path / "hub.sqlite"),
        BACKUPS_DIR=str(tmp_path / "backups"),
        VAULT_BASE_DIR=str(tmp_path / "vault"),
        SCRATCH_BASE_DIR=str(tmp_path / "scratch"),
        THREAT_INTEL_DIR=str(tmp_path / "intel"),
        JWT_SECRET_KEY=secrets.token_urlsafe(48),
        SERVER_HMAC_SIGNING_KEY=secrets.token_urlsafe(48),
        ADMIN_API_KEYS=json.dumps([secrets.token_urlsafe(48)]),
        API_KEYS="[]",
        SYNTHETIC_CREDENTIAL_FILE=str(tmp_path / "credentials.json"),
    )
    seed = """
import json
import os
from pathlib import Path
from core.acl import case_access_provider
from core.jobs import job_manager
from core.models.forensic import AnalysisResult
from core.reporter_credentials import issue_reporter, write_private_token
case_access_provider.register_case("restart-case", "owner", "org")
job, _ = job_manager.create_job("restart-case", "evidence", "synthetic", "owner", "org")
payload = json.loads(Path("tests/fixtures/reporter-completed-synthetic.json").read_text())
payload.update(job_id=job, case_id="restart-case", evidence_id="evidence")
payload["execution_record"].update(case_id="restart-case", evidence_id="evidence")
job_manager.store_result(job, AnalysisResult.model_validate(payload))
def issue():
    return issue_reporter(subject="reader", organization="org", case_id="restart-case", job_ids=[job])
write_private_token(Path(os.environ["SYNTHETIC_CREDENTIAL_FILE"]), json.dumps({"job": job, "a": issue(), "b": issue()}))
"""
    seeded = subprocess.run([sys.executable, "-c", seed], env=env, capture_output=True, text=True, timeout=30)
    assert seeded.returncode == 0, "synthetic fixture initialization failed"
    creds = json.loads(Path(env["SYNTHETIC_CREDENTIAL_FILE"]).read_text())
    token_file = tmp_path / "revoked.jwt"
    write_private_token(token_file, creds["a"])

    def reads(url, token, expected):
        for route in ("/mcp", "/mcp/jsonrpc"):
            for tool in ("forenzx_analysis_status", "forenzx_analysis_results"):
                response = httpx.post(
                    url + route,
                    trust_env=False,
                    headers={"Authorization": "Bearer " + token},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": {"job_id": creds["job"]}},
                    },
                )
                assert response.status_code == expected
                if expected == 200:
                    payload = json.loads(response.json()["result"]["content"][0]["text"])
                    assert payload["job_id"] == creds["job"]
                    if tool.endswith("results"):
                        assert payload["findings"][0]["id"] == "demo-finding-001"

    with live_server(env, tmp_path / "first.log") as url:
        reads(url, creds["a"], 200)
        reads(url, creds["b"], 200)
        revoked = subprocess.run(
            [sys.executable, "-m", "core.reporter_credentials", "revoke", "--token-file", str(token_file)],
            env=env,
            capture_output=True,
            timeout=30,
        )
        assert revoked.returncode == 0
        reads(url, creds["a"], 401)
        reads(url, creds["b"], 200)
    with live_server(env, tmp_path / "restarted.log") as url:
        reads(url, creds["a"], 401)
        reads(url, creds["b"], 200)
    for log in (tmp_path / "first.log", tmp_path / "restarted.log"):
        assert creds["a"] not in log.read_text()
        assert creds["b"] not in log.read_text()
