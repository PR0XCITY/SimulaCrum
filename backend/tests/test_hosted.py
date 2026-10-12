"""Hosted mode (GHOSTOPS_HOSTED=1): API key on every mutating endpoint, no server paths,
CORS origins from GHOSTOPS_CORS_ORIGINS, and a server that refuses a public bind without it."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api import API_KEY_HEADER, create_app
from app.config import ConfigError, check_required, cors_origins
from app.server import is_loopback
from app.store import Store
from tests.test_api import FakeAnalyzer, SECRET

FIXTURES = Path(__file__).parent / "fixtures"
BACKEND = Path(__file__).resolve().parents[1]
API_KEY = "hosted-test-key-" + "x9y8z7" * 4
GOOD_PLAN = json.loads((FIXTURES / "good_plan.json").read_text(encoding="utf-8"))
VERCEL = "https://ghostops-demo.vercel.app"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "1")
    monkeypatch.setenv("GHOSTOPS_API_KEY", API_KEY)
    monkeypatch.setenv("GHOSTOPS_CORS_ORIGINS", f" {VERCEL}/ , *, ftp://nope.example, https://*.vercel.app")


@pytest.fixture
def analyzer():
    return FakeAnalyzer()


@pytest.fixture
def client(tmp_path, analyzer):
    with TestClient(create_app(store=Store(tmp_path / "ghostops.db"), analyzer=analyzer)) as c:
        yield c


KEY = {API_KEY_HEADER: API_KEY}


@pytest.mark.parametrize("headers", [{}, {API_KEY_HEADER: ""}, {API_KEY_HEADER: "wrong"},
                                     {API_KEY_HEADER: API_KEY + "x"}, {API_KEY_HEADER: API_KEY.upper()}])
@pytest.mark.parametrize(("method", "path"), [
    ("POST", "/analyze"), ("POST", "/analyze/demo/good"), ("POST", "/architectures/check"),
    ("POST", "/architectures/analyze"), ("POST", "/architectures/preview"), ("PUT", "/comparisons/A"),
    ("DELETE", "/comparisons/A"), ("POST", "/certificates/" + "0" * 64 + "/decision"),
])
def test_mutating_endpoints_need_the_key(client, analyzer, method, path, headers):
    r = client.request(method, path, json={"plan": GOOD_PLAN}, headers=headers)
    assert r.status_code == 401, r.text
    assert API_KEY_HEADER in r.json()["detail"]
    assert API_KEY not in r.text
    assert analyzer.calls == []


def test_reads_need_no_key(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/certificates").status_code == 200
    assert client.get("/demos").status_code == 200


def test_correct_key_is_accepted(client, analyzer):
    r = client.post("/analyze", json={"plan": GOOD_PLAN, "use_groq": False}, headers=KEY)
    assert r.status_code == 200, r.text
    assert analyzer.calls == [{"tf_dir": None, "use_groq": False}]
    assert client.post("/analyze/demo/good", headers=KEY).status_code == 200
    assert client.delete("/comparisons/A", headers=KEY).status_code == 404  # authorised, slot empty


@pytest.mark.parametrize("kwargs", [
    {"json": {"plan_path": str(FIXTURES / "good_plan.json")}},
    {"json": {"plan_path": "/etc/passwd.json"}},
    {"json": {"plan": GOOD_PLAN, "tf_dir": str(BACKEND.parent / "demo" / "good")}},
    {"files": {"plan": ("p.json", json.dumps(GOOD_PLAN).encode(), "application/json")},
     "data": {"tf_dir": str(BACKEND.parent / "demo" / "good")}},
])
def test_server_paths_are_refused(client, analyzer, kwargs):
    r = client.post("/analyze", headers=KEY, **kwargs)
    assert r.status_code == 403, r.text
    assert "disabled on a hosted SimulaCrum" in r.json()["detail"]
    assert analyzer.calls == []


def test_upload_still_works(client):
    r = client.post("/analyze", headers=KEY,
                    files={"plan": ("p.json", json.dumps(GOOD_PLAN).encode(), "application/json")})
    assert r.status_code == 200
    assert r.json()["verdict"] == "BLOCKED_PENDING_REVIEW"  # no shadow run: fail closed


def test_cors_origins_from_env():
    assert cors_origins() == ["http://localhost:3000", "http://127.0.0.1:3000", VERCEL]


def test_cors_preflight_and_401_carry_cors_headers(client):
    pre = client.options("/analyze", headers={"Origin": VERCEL, "Access-Control-Request-Method": "POST",
                                              "Access-Control-Request-Headers": f"content-type,{API_KEY_HEADER}"})
    assert pre.status_code == 200
    assert pre.headers["access-control-allow-origin"] == VERCEL
    assert API_KEY_HEADER.lower() in pre.headers["access-control-allow-headers"].lower()
    denied = client.post("/analyze", json={}, headers={"Origin": VERCEL})
    assert denied.status_code == 401
    assert denied.headers["access-control-allow-origin"] == VERCEL  # browser can read the 401
    evil = client.options("/analyze", headers={"Origin": "https://evil.example",
                                               "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in evil.headers


def test_cors_defaults_when_env_unset(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_CORS_ORIGINS", "")
    assert cors_origins() == ["http://localhost:3000", "http://127.0.0.1:3000"]


@pytest.mark.parametrize(("value", "message"), [("", "GHOSTOPS_API_KEY is not set"), ("short", "shorter than 24")])
def test_hosted_requires_a_strong_api_key(monkeypatch, value, message):
    monkeypatch.setenv("GHOSTOPS_API_KEY", value)
    with pytest.raises(ConfigError, match=message) as exc:
        check_required()
    assert SECRET not in str(exc.value)


def test_local_mode_ignores_the_key(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")
    monkeypatch.setenv("GHOSTOPS_API_KEY", "")
    with TestClient(create_app(store=Store(tmp_path / "g.db"), analyzer=FakeAnalyzer())) as c:
        r = c.post("/analyze", json={"plan_path": str(FIXTURES / "good_plan.json")})
    assert r.status_code == 200


@pytest.mark.parametrize(("host", "loopback"), [("127.0.0.1", True), ("localhost", True), ("::1", True),
                                                ("0.0.0.0", False), ("::", False), ("example.com", False)])
def test_is_loopback(host, loopback):
    assert is_loopback(host) is loopback


def test_server_refuses_public_bind_without_hosted_mode():
    env = {**os.environ, "GHOSTOPS_HMAC_SECRET": SECRET, "GHOSTOPS_HOSTED": "0", "GHOSTOPS_HOST": "0.0.0.0"}
    proc = subprocess.run([sys.executable, "-m", "app.server", "--port", "8998"], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert "refusing to listen on 0.0.0.0 without GHOSTOPS_HOSTED=1" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_hosted_cost_note_has_no_login_steps(monkeypatch):
    from app import certificate
    from app.cost import AUTH_HELP, InfracostAuthError

    def no_login(*_args, **_kwargs):
        raise InfracostAuthError(AUTH_HELP)

    monkeypatch.setattr(certificate, "plan_cost", no_login)
    cost, breakdown = certificate.cost_section(GOOD_PLAN)
    assert cost["monthly_usd"] is None and breakdown == []
    assert "not available on a hosted SimulaCrum" in cost["note"] and "auth login" not in cost["note"]
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")
    assert "infracost auth login" in certificate.cost_section(GOOD_PLAN)[0]["note"]
