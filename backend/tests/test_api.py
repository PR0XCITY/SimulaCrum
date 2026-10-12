import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import cli
from app.api import create_app
from app.certificate import build_certificate, verify
from app.config import ConfigError, SecretRedactingFilter
from app.shadow import ShadowResult
from app.store import Store
from conftest import raw_execute

FIXTURES = Path(__file__).parent / "fixtures"
BACKEND = Path(__file__).resolve().parents[1]
SECRET = "test-secret-" + "a1b2c3d4" * 6
GROQ_KEY = "gsk_TESTKEYshouldNEVERappearINlogs123456"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GROQ_API_KEY", GROQ_KEY)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")  # explicit, so a local .env cannot switch it on


class FakeAnalyzer:
    """build_certificate with the slow parts (MiniStack, Infracost, Groq) injected."""

    def __init__(self):
        self.calls = []

    def __call__(self, plan, tf_dir=None, *, use_groq=True):
        self.calls.append({"tf_dir": tf_dir, "use_groq": use_groq})
        shadow = ShadowResult(True, "complete", resources=[{"address": "x.y", "type": "x", "id": "1"}]) if tf_dir else None
        cost = {"monthly_delta_usd": 1.5, "complete": True, "unpriced": [], "resources": []}
        return build_certificate(plan, tf_dir, shadow_result=shadow, cost_result=cost, use_groq=False)


@pytest.fixture
def analyzer():
    return FakeAnalyzer()


@pytest.fixture
def store(make_store):  # SQLite, and Postgres too when TEST_DATABASE_URL is set (see conftest.py)
    return make_store()


@pytest.fixture
def client(store, analyzer):
    with TestClient(create_app(store=store, analyzer=analyzer)) as c:
        yield c


def analyze(client, fixture, tf_dir="demo/good"):
    body = {"plan_path": str(FIXTURES / fixture), "tf_dir": str(BACKEND.parent / tf_dir) if tf_dir else None}
    return client.post("/analyze", json=body)


# --- /analyze ------------------------------------------------------------------------------


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_by_path(client, store):
    bad = analyze(client, "bad_plan.json", "demo/bad")
    assert bad.status_code == 200
    cert = bad.json()
    assert cert["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert list(cert)[-1] == "signature" and verify(cert)
    assert store.get_certificate(cert["plan_id"]) == cert
    good = analyze(client, "good_plan.json").json()
    assert good["verdict"] == "AUTO_APPROVED"


def test_analyze_inline_plan(client):
    plan = json.loads((FIXTURES / "good_plan.json").read_text(encoding="utf-8"))
    r = client.post("/analyze", json={"plan": plan, "tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": False})
    assert r.status_code == 200 and r.json()["verdict"] == "AUTO_APPROVED"


def test_analyze_upload(client, analyzer):
    with open(FIXTURES / "good_plan.json", "rb") as fh:
        r = client.post("/analyze", files={"plan": ("plan.json", fh, "application/json")},
                        data={"tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": "false"})
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "AUTO_APPROVED"
    assert analyzer.calls[-1] == {"tf_dir": str(BACKEND.parent / "demo" / "good"), "use_groq": False}


def test_upload_without_tf_dir_is_blocked_unverified(client):
    with open(FIXTURES / "good_plan.json", "rb") as fh:
        cert = client.post("/analyze", files={"plan": ("plan.json", fh, "application/json")}).json()
    assert cert["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert cert["shadow_run"]["applied"] is False


@pytest.mark.parametrize(("kwargs", "status", "detail"), [
    ({"json": {}}, 422, "exactly one of plan_path or plan"),
    ({"json": {"plan_path": "x.json", "plan": {}}}, 422, "exactly one of plan_path or plan"),
    ({"json": {"plan_path": "C:/nope/missing.json"}}, 400, "existing .json file"),
    ({"json": {"plan_path": __file__}}, 400, "existing .json file"),
    ({"json": {"plan": {"no": "format_version"}}}, 422, "not a usable Terraform plan"),
    ({"json": {"plan": {"format_version": "1.2"}, "tf_dir": "C:/nope"}}, 400, "tf_dir must be an existing directory"),
    ({"content": b"not json", "headers": {"content-type": "application/json"}}, 422, "invalid request body"),
    ({"files": {"other": ("p.json", b"{}", "application/json")}}, 400, 'file field named "plan"'),
    ({"files": {"plan": ("p.json", b"{oops", "application/json")}}, 422, "not valid JSON"),
    ({"files": {"plan": ("p.json", b"[1, 2]", "application/json")}}, 422, "must be a JSON object"),
])
def test_analyze_rejects_bad_input(client, kwargs, status, detail):
    r = client.post("/analyze", **kwargs)
    assert r.status_code == status, r.text
    assert detail in r.json()["detail"]


def test_demos(client, analyzer):
    assert [d["name"] for d in client.get("/demos").json()] == ["bad", "good"]
    bad = client.post("/analyze/demo/bad?use_groq=false")
    assert bad.status_code == 200 and bad.json()["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert analyzer.calls[-1] == {"tf_dir": str(BACKEND.parent / "demo" / "bad"), "use_groq": False}
    good = client.post("/analyze/demo/good")
    assert good.json()["verdict"] == "AUTO_APPROVED"
    assert client.get(f"/certificates/{good.json()['plan_id']}").status_code == 200
    assert client.post("/analyze/demo/..%2F..%2Fetc").status_code == 404
    assert client.post("/analyze/demo/evil").status_code == 404


def test_catalog_endpoint(client):
    r = client.get("/catalog")
    assert r.status_code == 200
    services = r.json()
    assert [s["type"] for s in services] == ["ec2", "s3", "rds", "vpc", "iam", "lambda", "dynamodb",
                                            "cloudwatch_alarm", "alb"]
    ec2 = services[0]
    assert ec2["shadow_supported"] is True and ec2["pricing"] == "fixed"
    assert {f["name"] for f in ec2["fields"]} >= {"instance_type", "count", "volume_gb", "ssh_source_cidr"}


def test_architecture_preview_returns_terraform_only(client, analyzer, store):
    body = {"services": [{"type": "ec2", "config": {"name": "web", "count": 2}},
                         {"type": "s3", "config": {"name": "assets"}}]}
    r = client.post("/architectures/preview", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert set(out) == {"terraform", "filename", "resources", "services"}
    assert out["filename"] == "main.tf" and 'resource "aws_instance" "web"' in out["terraform"]
    assert "aws_s3_bucket.assets" in out["resources"]
    assert out["services"][0] == {"type": "ec2", "name": "web", "shadow_supported": True, "usage": {},
                                  "config": {"name": "web", "instance_type": "t3.micro", "count": 2,
                                             "volume_gb": 20, "ssh_source_cidr": "10.0.0.0/16",
                                             "expected_cpu_percent": 40},
                                  "resources": ["aws_security_group.web_ssh", "aws_instance.web",
                                                "aws_ebs_volume.web", "aws_volume_attachment.web"]}
    assert analyzer.calls == [] and client.get("/certificates").json() == []  # nothing analysed or stored


def test_architecture_preview_validation_errors(client):
    r = client.post("/architectures/preview", json={"services": [{"type": "ec2", "config": {"count": 99}},
                                                                 {"type": "warp-drive"}]})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["message"] == "invalid architecture"
    assert {(e["service"], e["field"]) for e in detail["errors"]} == {(0, "count"), (1, "type")}
    bad = client.post("/architectures/preview", content=b"nope", headers={"content-type": "application/json"})
    assert bad.status_code == 422


# --- /certificates ----------------------------------------------------------------------------


def test_list_and_get_certificates(client):
    bad = analyze(client, "bad_plan.json", "demo/bad").json()
    good = analyze(client, "good_plan.json").json()
    listing = client.get("/certificates").json()
    assert {c["plan_id"] for c in listing} == {bad["plan_id"], good["plan_id"]}
    summary = next(c for c in listing if c["plan_id"] == bad["plan_id"])
    assert summary["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert summary["risk_flag_counts"] == {"CRITICAL": 3, "HIGH": 5, "MEDIUM": 3, "LOW": 4}  # + advisory pillar findings
    assert summary["resource_change_count"] == 8 and summary["latest_decision"] is None
    assert summary["source"] == {"kind": "plan", "services": []}  # a Terraform plan, not a Builder design
    assert summary["blocking_count"] == 8
    assert set(summary["pillar_scores"]) == {"security", "reliability", "cost", "performance"}
    assert summary["pillar_scores"]["security"] == 0
    assert client.get(f"/certificates/{bad['plan_id']}").json() == bad


def test_unknown_and_malformed_plan_ids(client):
    assert client.get("/certificates/" + "0" * 64).status_code == 404
    assert client.get("/certificates/not-a-hash").status_code == 422
    assert client.get("/verify/" + "f" * 64).status_code == 404
    assert client.post("/certificates/" + "0" * 64 + "/decision",
                       json={"decision": "approve", "reviewer": "ana"}).status_code == 404


# --- decisions & audit log -------------------------------------------------------------------


def test_decision_is_recorded_and_never_applied(client, analyzer, store):
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    calls_before = len(analyzer.calls)
    r = client.post(f"/certificates/{cert['plan_id']}/decision",
                    json={"decision": "deny", "reviewer": "ana.lee@example.com", "comment": "SSH must not be public"})
    assert r.status_code == 200
    entry = r.json()
    assert entry["decision"] == "deny" and entry["reviewer"] == "ana.lee@example.com"
    assert entry["applied"] is False and "never applies changes" in entry["note"]
    assert entry["certificate_signature"] == cert["signature"]
    assert entry["verdict_at_decision"] == "BLOCKED_PENDING_REVIEW"
    assert len(analyzer.calls) == calls_before  # nothing re-run, nothing applied

    client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "lead"})
    log = client.get(f"/certificates/{cert['plan_id']}/decisions").json()
    assert [(d["decision"], d["reviewer"]) for d in log] == [("deny", "ana.lee@example.com"), ("approve", "lead")]
    latest = next(c for c in client.get("/certificates").json() if c["plan_id"] == cert["plan_id"])["latest_decision"]
    assert latest["decision"] == "approve" and latest["reviewer"] == "lead"


@pytest.mark.parametrize("body", [
    {"decision": "maybe", "reviewer": "ana"}, {"decision": "approve", "reviewer": ""},
    {"decision": "approve"}, {"decision": "approve", "reviewer": "<script>"},
    {"decision": "approve", "reviewer": "ana", "comment": "x" * 1001},
])
def test_decision_validation(client, body):
    cert = analyze(client, "good_plan.json").json()
    assert client.post(f"/certificates/{cert['plan_id']}/decision", json=body).status_code == 422


def test_audit_log_is_append_only(client, store):
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    r = client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "ana"})
    assert r.status_code == 200
    with pytest.raises(Exception, match="append-only"):  # sqlite3 / psycopg DatabaseError
        raw_execute(store, "UPDATE audit_log SET decision = 'deny'")
    with pytest.raises(Exception, match="append-only"):
        raw_execute(store, "DELETE FROM audit_log")
    if store.backend == "postgres":
        with pytest.raises(Exception, match="append-only"):
            raw_execute(store, "TRUNCATE audit_log")
    assert [d["decision"] for d in store.decisions(cert["plan_id"])] == ["approve"]


def test_auto_approved_certificates_take_no_decisions(client, store):
    cert = analyze(client, "good_plan.json").json()
    assert cert["verdict"] == "AUTO_APPROVED"
    r = client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "ana"})
    assert r.status_code == 409 and "auto-approved by policy" in r.json()["detail"]
    assert store.decisions(cert["plan_id"]) == []
    summary = next(c for c in client.get("/certificates").json() if c["plan_id"] == cert["plan_id"])
    assert summary["latest_decision"] is None


def test_decisions_on_an_earlier_version_are_not_the_current_decision(client, store):
    first = analyze(client, "bad_plan.json", "demo/bad").json()
    client.post(f"/certificates/{first['plan_id']}/decision", json={"decision": "deny", "reviewer": "ana"})
    __import__("time").sleep(1.1)  # timestamps have 1 s resolution; a real re-analysis takes far longer
    second = analyze(client, "bad_plan.json", "demo/bad").json()  # re-analysis: new timestamp + signature
    assert second["plan_id"] == first["plan_id"] and second["signature"] != first["signature"]
    summary = next(c for c in client.get("/certificates").json() if c["plan_id"] == second["plan_id"])
    assert summary["latest_decision"] is None  # still awaiting review for this version
    assert len(store.decisions(second["plan_id"])) == 1  # the old decision stays in the log


# --- /verify ----------------------------------------------------------------------------------


def tamper(store, plan_id):
    [row] = raw_execute(store, "SELECT body FROM certificates WHERE plan_id = ?", (plan_id,))
    body = json.loads(row["body"])
    body["verdict"] = "AUTO_APPROVED"
    raw_execute(store, "UPDATE certificates SET body = ? WHERE plan_id = ?", (json.dumps(body), plan_id))


def test_verify_detects_tampering_in_the_database(client, store):
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    ok = client.get(f"/verify/{cert['plan_id']}").json()
    assert ok == {"plan_id": cert["plan_id"], "valid": True, "verdict": "BLOCKED_PENDING_REVIEW",
                  "timestamp": cert["timestamp"], "signature": cert["signature"]}
    tamper(store, cert["plan_id"])
    assert client.get(f"/verify/{cert['plan_id']}").json()["valid"] is False
    r = client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "approve", "reviewer": "ana"})
    assert r.status_code == 409


# --- CORS -------------------------------------------------------------------------------------


def test_cors_allows_only_the_dashboard(client):
    preflight = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    ok = client.options("/analyze", headers={"Origin": "http://localhost:3000", **preflight})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:3000"
    evil = client.options("/analyze", headers={"Origin": "http://evil.example", **preflight})
    assert "access-control-allow-origin" not in evil.headers
    get = client.get("/certificates", headers={"Origin": "http://localhost:3000"})
    assert get.headers["access-control-allow-origin"] == "http://localhost:3000"


# --- startup & secrets -------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "too-short"])
def test_refuses_to_start_without_a_valid_secret(monkeypatch, tmp_path, value):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", value)
    with pytest.raises(ConfigError, match="GHOSTOPS_HMAC_SECRET"):
        create_app(store=Store(tmp_path / "db"))


def test_server_exits_with_clear_message_when_secret_missing():
    env = {**__import__("os").environ, "GHOSTOPS_HMAC_SECRET": ""}
    proc = subprocess.run([sys.executable, "-m", "app.server", "--port", "8999"], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert "GhostOps cannot start" in proc.stderr and "GHOSTOPS_HMAC_SECRET is not set" in proc.stderr
    assert "Traceback" not in proc.stderr and proc.stdout == ""


def test_secrets_never_reach_the_logs(client, caplog):
    caplog.set_level(logging.DEBUG)
    cert = analyze(client, "bad_plan.json", "demo/bad").json()
    client.post(f"/certificates/{cert['plan_id']}/decision", json={"decision": "deny", "reviewer": "ana"})
    client.get(f"/verify/{cert['plan_id']}")
    client.get("/certificates")
    assert caplog.records, "expected some log output"
    assert SECRET not in caplog.text and GROQ_KEY not in caplog.text


def test_log_filter_redacts_a_leaked_secret():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "boom %s and %s", (SECRET, GROQ_KEY), None)
    SecretRedactingFilter().filter(record)
    assert record.getMessage() == "boom [redacted] and [redacted]"


# --- CLI ----------------------------------------------------------------------------------------


@pytest.fixture
def fast_cli(monkeypatch, analyzer):
    import app.certificate
    monkeypatch.setattr(app.certificate, "build_certificate", lambda plan, tf, use_groq=True: analyzer(plan, tf))


def test_cli_exit_codes_and_output(fast_cli, capsys):
    good = str(FIXTURES / "good_plan.json")
    assert cli.main(["analyze", str(FIXTURES / "bad_plan.json"), "--tf", str(BACKEND.parent / "demo" / "bad"),
                     "--no-store"]) == 1
    out = capsys.readouterr().out
    assert "VERDICT: BLOCKED_PENDING_REVIEW" in out and "CRITICAL GO-SG-001" in out and "(verified)" in out
    assert cli.main(["analyze", good, "--tf", str(BACKEND.parent / "demo" / "good"), "--no-store"]) == 0
    assert "VERDICT: AUTO_APPROVED" in capsys.readouterr().out
    assert cli.main(["analyze", good, "--no-store"]) == 1  # no shadow run: unverified
    assert "Shadow run: NOT applied" in capsys.readouterr().out
    assert cli.main(["analyze", good, "--tf", str(BACKEND.parent / "demo" / "good"), "--no-store", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "AUTO_APPROVED"


def test_cli_errors_exit_2(fast_cli, monkeypatch, tmp_path, capsys):
    assert cli.main(["analyze", str(tmp_path / "missing.json")]) == 2
    (tmp_path / "bad.json").write_text("{nope", encoding="utf-8")
    assert cli.main(["analyze", str(tmp_path / "bad.json")]) == 2
    assert cli.main(["analyze", str(FIXTURES / "good_plan.json"), "--tf", str(tmp_path / "nodir")]) == 2
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", "")
    assert cli.main(["analyze", str(FIXTURES / "good_plan.json")]) == 2
    assert "GhostOps cannot start" in capsys.readouterr().err


def test_ghostops_command_is_installed():
    exe = Path(sys.executable).parent / ("ghostops.exe" if sys.platform == "win32" else "ghostops")
    proc = subprocess.run([str(exe), "analyze", "--help"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0 and "plan JSON file" in proc.stdout


def test_summary_names_the_builder_design(make_store):
    store = make_store()
    flags = [{"rule": "GO-REL-006", "severity": "LOW", "resource": "aws_instance.web[0]", "message": "m",
              "pillar": "reliability"}]
    store.save_certificate({
        "plan_id": "a" * 64, "timestamp": "2026-10-08T12:00:00Z", "verdict": "AUTO_APPROVED",
        "generated_by": "template", "signature": "s" * 64, "resource_changes": [],
        "blast_radius": {"risk_flags": flags}, "cost_delta": {"monthly_usd": 9.19}, "shadow_run": {"applied": True},
        "architecture": {"services": [{"type": "ec2", "name": "web", "config": {}}, {"type": "s3", "name": "assets", "config": {}}]},
        "pillars": {"security": {"score": 100, "findings": []}, "reliability": {"score": 95, "findings": []},
                    "cost": {"score": 100, "findings": []}, "performance": {"score": 100, "findings": []}},
    })
    [summary] = store.list_certificates()
    assert summary["source"] == {"kind": "builder", "services": [{"name": "web", "type": "ec2"},
                                                                 {"name": "assets", "type": "s3"}]}
    assert summary["pillar_scores"] == {"security": 100, "reliability": 95, "cost": 100, "performance": 100}
    assert summary["blocking_count"] == 0


# --- background Certify jobs --------------------------------------------------------------


def _wait_for(client, job_id, timeout=10):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/jobs/{job_id}").json()
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {job}")


def _fake_cert(plan_id="c" * 64, verdict="AUTO_APPROVED"):
    return {"plan_id": plan_id, "timestamp": "2026-10-09T00:00:00Z", "verdict": verdict, "generated_by": "template",
            "signature": "s" * 64, "resource_changes": [], "blast_radius": {"risk_flags": []},
            "cost_delta": {"monthly_usd": 1.0}, "shadow_run": {"applied": True}, "architecture": None}


def test_certify_runs_in_the_background_and_stores_the_certificate(make_store):
    import threading

    release = threading.Event()
    calls = []

    def slow_analyzer(body, use_groq=True):
        calls.append(body)
        release.wait(5)  # stands in for minutes of Terraform + MiniStack
        return _fake_cert()

    body = {"services": [{"type": "s3", "config": {"name": "logs"}}]}
    with TestClient(create_app(store=make_store(), architecture_analyzer=slow_analyzer)) as client:
        started = client.post("/architectures/certify", json=body)
        assert started.status_code == 202  # returns at once, while the analysis is still running
        job = started.json()
        assert job["status"] in ("queued", "running") and len(job["job_id"]) == 32
        # a double click / Retry for the same design gets the same job, not a second run
        assert client.post("/architectures/certify", json=body).json()["job_id"] == job["job_id"]
        release.set()
        done = _wait_for(client, job["job_id"])
        assert done["status"] == "done" and done["plan_id"] == "c" * 64 and done["verdict"] == "AUTO_APPROVED"
        assert client.get(f"/certificates/{'c' * 64}").status_code == 200
        assert len(calls) == 1
        # once finished, certifying again starts a new job
        assert client.post("/architectures/certify", json=body).json()["job_id"] != job["job_id"]


def test_certify_job_reports_errors_and_validates_first(tmp_path):
    from app.shadow import ShadowError
    from app.store import Store

    def failing(body, use_groq=True):
        raise ShadowError("terraform plan failed: boom")

    with TestClient(create_app(store=Store(tmp_path / "db"), architecture_analyzer=failing)) as client:
        job = client.post("/architectures/certify", json={"services": [{"type": "s3", "config": {}}]}).json()
        failed = _wait_for(client, job["job_id"])
        assert failed["status"] == "error"
        assert failed["error"] == "could not plan the generated Terraform: terraform plan failed: boom"
        assert client.get("/certificates").json() == []
        bad = client.post("/architectures/certify", json={"services": [{"type": "ec2", "config": {"count": 0}}]})
        assert bad.status_code == 422
        assert client.get("/jobs/" + "f" * 32).status_code == 404
        assert client.get("/jobs/not-a-job").status_code == 422
