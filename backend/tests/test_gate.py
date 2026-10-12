"""The enforced gate: apply decision logic, CI runner, safe-apply guards, MCP server.

Everything slow (terraform, MiniStack, Infracost, Groq, the HTTP API) is mocked; the
real runs are `python -m app.gate ci --tf ../demo/bad|good` (see the README)."""

import io
import json
import subprocess
from pathlib import Path

import pytest

from app import gate
from app.certificate import build_certificate, compute_plan_id
from app.mcp_gate import TOOLS, GateServer
from app.shadow import ShadowError, ShadowResult
from app.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parents[2]
SECRET = "test-secret-" + "a1b2c3d4" * 6


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")


def plan(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def certify(plan_json: dict) -> dict:
    """A real signed certificate; MiniStack, Infracost and Groq results are injected."""
    shadow = ShadowResult(True, "complete", resources=[{"address": "x.y", "type": "x", "id": "1"}])
    cost = {"monthly_delta_usd": 1.5, "complete": True, "unpriced": [], "resources": []}
    return build_certificate(plan_json, "demo", shadow_result=shadow, cost_result=cost, use_groq=False)


@pytest.fixture(scope="module")
def bad_cert():
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
        return certify(plan("bad_plan.json"))


@pytest.fixture(scope="module")
def good_cert():
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
        return certify(plan("good_plan.json"))


def decision(cert: dict, verdict: str, row_id: int, signature: str | None = None) -> dict:
    return {"id": row_id, "plan_id": cert["plan_id"], "decision": verdict, "reviewer": "Asha",
            "comment": None, "certificate_signature": signature or cert["signature"],
            "verdict_at_decision": cert["verdict"], "decided_at": f"2026-10-12T10:0{row_id}:00Z"}


# --- apply decision ------------------------------------------------------------------


def test_fixtures_have_the_expected_verdicts(bad_cert, good_cert):
    assert bad_cert["verdict"] == gate.BLOCKED
    assert good_cert["verdict"] == gate.APPROVED


def test_auto_approved_may_apply(good_cert):
    allowed, reason = gate.apply_decision(good_cert, [], True, plan("good_plan.json"))
    assert allowed and "AUTO_APPROVED" in reason


def test_blocked_without_review_is_refused(bad_cert):
    allowed, reason = gate.apply_decision(bad_cert, [], True)
    assert not allowed and "no reviewer" in reason


def test_blocked_and_approved_may_apply(bad_cert):
    allowed, reason = gate.apply_decision(bad_cert, [decision(bad_cert, "approve", 1)], True)
    assert allowed and "approved by Asha" in reason


def test_latest_decision_wins(bad_cert):
    assert not gate.apply_decision(bad_cert, [decision(bad_cert, "approve", 1), decision(bad_cert, "deny", 2)], True)[0]
    assert gate.apply_decision(bad_cert, [decision(bad_cert, "deny", 1), decision(bad_cert, "approve", 2)], True)[0]


def test_approval_of_an_earlier_certificate_version_does_not_count(bad_cert):
    old = decision(bad_cert, "approve", 1, signature="0" * 64)
    assert not gate.apply_decision(bad_cert, [old], True)[0]


def test_invalid_signature_is_refused_even_if_auto_approved(good_cert):
    allowed, reason = gate.apply_decision(good_cert, [], False)
    assert not allowed and "INVALID" in reason


def test_certificate_for_another_plan_is_refused(good_cert):
    allowed, reason = gate.apply_decision(good_cert, [], True, plan("bad_plan.json"))
    assert not allowed and "different plan" in reason


def test_unknown_verdict_is_refused(good_cert):
    assert not gate.apply_decision({**good_cert, "verdict": "MAYBE"}, [], True)[0]


def test_summary_lists_blocking_findings_only(bad_cert):
    summary = gate.summarize(bad_cert, [], True)
    rules = {f["rule"] for f in summary["blocking_findings"]}
    assert {"GO-SG-001", "GO-IAM-001", "GO-S3-001", "GO-RDS-001"} <= rules
    assert all(f["severity"] in ("CRITICAL", "HIGH") for f in summary["blocking_findings"])
    assert summary["certificate_id"] == bad_cert["plan_id"] and summary["apply_allowed"] is False
    assert summary["dashboard_url"].endswith(bad_cert["plan_id"])
    assert set(summary["pillar_scores"]) == {"security", "reliability", "cost", "performance"}


# --- certificates from a client (API or local) ----------------------------------------


class FakeClient:
    def __init__(self, certs=None, decisions=None, valid=True):
        self.certs, self.log, self.valid, self.analyzed = dict(certs or {}), dict(decisions or {}), valid, []

    def get_certificate(self, plan_id):
        return self.certs.get(plan_id)

    def decisions(self, plan_id):
        return self.log.get(plan_id, [])

    def signature_valid(self, plan_id):
        return self.valid

    def analyze(self, plan_path, tf_dir, use_groq):
        self.analyzed.append((plan_path, tf_dir, use_groq))
        cert = certify(json.loads(Path(plan_path).read_text(encoding="utf-8")))
        self.certs[cert["plan_id"]] = cert
        return cert


def test_check_plan_analyses_a_new_plan(tmp_path):
    client = FakeClient()
    result = gate.check_plan(client, FIXTURES / "good_plan.json", REPO / "demo" / "good", use_groq=False)
    assert result["verdict"] == gate.APPROVED and result["apply_allowed"]
    assert client.analyzed == [(str((FIXTURES / "good_plan.json").resolve()), str((REPO / "demo" / "good").resolve()), False)]


def test_check_plan_reuses_the_stored_certificate_so_the_review_counts(bad_cert):
    client = FakeClient({bad_cert["plan_id"]: bad_cert}, {bad_cert["plan_id"]: [decision(bad_cert, "approve", 1)]})
    result = gate.check_plan(client, FIXTURES / "bad_plan.json", REPO / "demo" / "bad")
    assert client.analyzed == []
    assert result["verdict"] == gate.BLOCKED and result["apply_allowed"]
    assert result["review"]["decision"] == "approve"


def test_check_plan_rejects_bad_inputs(tmp_path):
    with pytest.raises(gate.GateError, match="cannot read"):
        gate.check_plan(FakeClient(), tmp_path / "missing.json", None)
    (tmp_path / "x.json").write_text("not json", encoding="utf-8")
    with pytest.raises(gate.GateError, match="not valid JSON"):
        gate.check_plan(FakeClient(), tmp_path / "x.json", None)
    with pytest.raises(gate.GateError, match="tf_dir"):
        gate.check_plan(FakeClient(), FIXTURES / "good_plan.json", tmp_path / "nope")


def test_plan_with_utf8_bom_is_accepted(tmp_path):
    path = tmp_path / "plan.json"
    path.write_bytes(b"\xef\xbb\xbf" + (FIXTURES / "good_plan.json").read_bytes())  # PowerShell 5.1 Out-File
    assert gate.load_plan(path) == plan("good_plan.json")


def test_get_certificate(bad_cert):
    client = FakeClient({bad_cert["plan_id"]: bad_cert}, {bad_cert["plan_id"]: [decision(bad_cert, "deny", 1)]})
    result = gate.get_certificate(client, bad_cert["plan_id"])
    assert result["apply_allowed"] is False and "denied" in result["reason"]
    with pytest.raises(gate.GateError, match="64-character"):
        gate.get_certificate(client, "../etc/passwd")
    with pytest.raises(gate.GateError, match="no certificate"):
        gate.get_certificate(client, "a" * 64)


def test_local_client_round_trip(tmp_path, bad_cert):
    store = Store(tmp_path / "g.db")
    client = gate.LocalClient(store)
    store.save_certificate(bad_cert)
    store.add_decision(bad_cert, "approve", "Asha", None)
    result = gate.get_certificate(client, bad_cert["plan_id"])
    assert result["signature_valid"] and result["apply_allowed"]


def test_api_client_maps_responses(monkeypatch, bad_cert):
    calls = []

    def fake_request(self, method, path, body=None):
        calls.append((method, path, body))
        if path == "/health":
            return {"status": "ok"}
        if path.startswith("/verify/"):
            return {"valid": True}
        if path.endswith("/decisions"):
            return [decision(bad_cert, "approve", 3)]
        if path == "/analyze":
            return bad_cert
        return None  # 404: not stored yet

    monkeypatch.setattr(gate.ApiClient, "_request", fake_request)
    api = gate.ApiClient("http://127.0.0.1:8000/")
    assert api.healthy()
    result = gate.check_plan(api, FIXTURES / "bad_plan.json", REPO / "demo" / "bad", use_groq=False)
    assert result["apply_allowed"] and result["certificate_id"] == bad_cert["plan_id"]
    assert ("POST", "/analyze", {"plan_path": str((FIXTURES / "bad_plan.json").resolve()),
                                 "tf_dir": str((REPO / "demo" / "bad").resolve()), "use_groq": False}) in calls


def test_api_client_unreachable_is_a_gate_error():
    api = gate.ApiClient("http://127.0.0.1:9", timeout=2)
    assert not api.healthy()
    with pytest.raises(gate.GateError, match="not reachable"):
        api.get_certificate("a" * 64)


def test_default_client_falls_back_to_local(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTOPS_API_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("GHOSTOPS_DB_PATH", str(tmp_path / "g.db"))
    assert isinstance(gate.default_client(), gate.LocalClient)


# --- safe-apply guards ---------------------------------------------------------------


def test_guard_accepts_the_demos_on_loopback_ministack():
    assert gate.guard_apply_target(REPO / "demo" / "good", "http://localhost:4566") == (REPO / "demo" / "good").resolve()
    assert gate.guard_apply_target(REPO / "demo" / "bad", "http://127.0.0.1:4566")


@pytest.mark.parametrize("target", [REPO, REPO / "demo", REPO / "backend", REPO / "demo" / "good" / ".." / ".." / "backend"])
def test_guard_refuses_anything_but_a_demo(target):
    with pytest.raises(gate.GateError, match="not inside"):
        gate.guard_apply_target(target, "http://localhost:4566")


def test_guard_refuses_a_dir_without_terraform(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "DEMO_ROOT", tmp_path)
    (tmp_path / "empty").mkdir()
    with pytest.raises(gate.GateError, match="no \\*.tf"):
        gate.guard_apply_target(tmp_path / "empty", "http://localhost:4566")


@pytest.mark.parametrize("url", ["https://ec2.us-east-1.amazonaws.com", "http://10.0.0.5:4566", "ministack:4566"])
def test_guard_refuses_a_non_loopback_endpoint(url):
    with pytest.raises(gate.GateError, match="not loopback"):
        gate.guard_apply_target(REPO / "demo" / "good", url)


def test_override_forces_ministack(tmp_path):
    path = gate.write_override(tmp_path)
    text = path.read_text(encoding="utf-8")
    assert path.name == "ghostops_shadow_override.tf"
    assert 'access_key                  = "test"' in text and "amazonaws.com" not in text
    assert 'ec2             = "http://localhost:4566"' in text


def test_decide_exit_codes(monkeypatch, bad_cert, good_cert, capsys):
    def run(cert, decisions):
        monkeypatch.setattr(gate, "default_client", lambda: FakeClient({cert["plan_id"]: cert}, {cert["plan_id"]: decisions}))
        name = "bad_plan.json" if cert is bad_cert else "good_plan.json"
        return gate.main(["decide", "--plan", str(FIXTURES / name), "--tf", str(REPO / "demo" / "good")])

    assert run(good_cert, []) == gate.EXIT_ALLOW
    assert run(bad_cert, []) == gate.EXIT_REFUSE
    assert run(bad_cert, [decision(bad_cert, "approve", 1)]) == gate.EXIT_ALLOW
    assert run(bad_cert, [decision(bad_cert, "deny", 1)]) == gate.EXIT_REFUSE
    assert json.loads(capsys.readouterr().out.split("\n}\n")[0] + "\n}")["apply_allowed"] is True


def test_decide_refuses_outside_demo_and_on_errors(monkeypatch, capsys):
    assert gate.main(["decide", "--plan", str(FIXTURES / "good_plan.json"), "--tf", str(REPO / "backend")]) == gate.EXIT_ERROR

    def broken():
        raise RuntimeError("database is locked")

    monkeypatch.setattr(gate, "default_client", broken)
    assert gate.main(["decide", "--plan", str(FIXTURES / "good_plan.json"), "--tf", str(REPO / "demo" / "good")]) == gate.EXIT_ERROR
    assert "database is locked" in capsys.readouterr().err


def test_safe_apply_script_never_applies_without_the_gate():
    script = (REPO / "scripts" / "safe-apply.ps1").read_text(encoding="utf-8")
    gate_call, apply_call = script.index("app.gate\", \"decide\""), script.index("apply -input=false")
    assert script.index("app.gate prepare-apply") < gate_call < apply_call
    assert "if ($Code -ne 0) { throw" in script[gate_call:apply_call]
    assert "-auto-approve" not in script  # it applies the saved, certified plan file only
    assert 'Remove-Item "Env:$($_.Name)"' in script  # AWS_* scrubbed


# --- CI runner -----------------------------------------------------------------------


class FakeProc:
    def __init__(self, code, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = code, stdout, stderr


def run_ci(monkeypatch, tmp_path, proc, expect=None, plan_error=None):
    def fake_plan_json(tf_dir):
        if plan_error:
            raise plan_error
        return plan("bad_plan.json")

    monkeypatch.setattr("app.shadow.plan_json", fake_plan_json)
    monkeypatch.setattr(gate.subprocess, "run", lambda cmd, **kw: proc)
    summary, output = tmp_path / "summary.md", tmp_path / "output.txt"
    code = gate.run_ci("demo/bad", out_dir=tmp_path / "out", use_groq=False, summary_file=str(summary),
                       output_file=str(output), expect=expect)
    return code, summary.read_text(encoding="utf-8"), output.read_text(encoding="utf-8")


def test_ci_blocked_fails_the_job_with_a_summary(monkeypatch, tmp_path, bad_cert):
    code, summary, output = run_ci(monkeypatch, tmp_path, FakeProc(1, json.dumps(bad_cert)))
    assert code == 1
    assert "**Verdict: BLOCKED_PENDING_REVIEW" in summary
    assert "| CRITICAL | GO-SG-001 |" in summary and "### Pillar scores" in summary
    assert "Monthly cost delta: +$1.50" in summary
    assert f"plan-id={bad_cert['plan_id']}" in output and "verdict=BLOCKED_PENDING_REVIEW" in output
    assert json.loads((tmp_path / "out" / "plan.json").read_text(encoding="utf-8")) == plan("bad_plan.json")


def test_ci_approved_passes(monkeypatch, tmp_path, good_cert):
    code, summary, _ = run_ci(monkeypatch, tmp_path, FakeProc(0, json.dumps(good_cert)))
    assert code == 0 and "**Verdict: AUTO_APPROVED**" in summary and "Blocking findings (0)" in summary


def test_ci_unknown_cost_is_reported(monkeypatch, tmp_path, good_cert):
    cert = {**good_cert, "cost_delta": {"monthly_usd": None, "note": "Cost not estimated: no Infracost login"}}
    code, summary, _ = run_ci(monkeypatch, tmp_path, FakeProc(0, json.dumps(cert)))
    assert code == 0 and "Monthly cost delta: unknown" in summary


def test_ci_expect_turns_a_block_into_a_pass(monkeypatch, tmp_path, bad_cert, good_cert):
    assert run_ci(monkeypatch, tmp_path, FakeProc(1, json.dumps(bad_cert)), expect=gate.BLOCKED)[0] == 0
    assert run_ci(monkeypatch, tmp_path, FakeProc(0, json.dumps(good_cert)), expect=gate.BLOCKED)[0] == 1


@pytest.mark.parametrize("proc, plan_error", [
    (FakeProc(2, "", "ghostops: GHOSTOPS_HMAC_SECRET missing"), None),
    (FakeProc(1, "{not json", "Traceback: PermissionError WinError 32"), None),
    (FakeProc(0), ShadowError("terraform plan failed: boom")),
])
def test_ci_errors_fail_closed(monkeypatch, tmp_path, proc, plan_error):
    code, summary, output = run_ci(monkeypatch, tmp_path, proc, plan_error=plan_error)
    assert code == 2 and "**Verdict: ERROR**" in summary and "verdict=ERROR" in output
    assert (proc.stderr or "terraform plan failed").split(":")[0] in summary


def test_ci_error_is_not_hidden_by_expect(monkeypatch, tmp_path):
    code, _, _ = run_ci(monkeypatch, tmp_path, FakeProc(2, "", "boom"), expect=gate.BLOCKED)
    assert code == 2


def test_ci_invokes_the_ghostops_cli(monkeypatch, tmp_path, bad_cert):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return FakeProc(1, json.dumps(bad_cert))

    monkeypatch.setattr("app.shadow.plan_json", lambda tf_dir: plan("bad_plan.json"))
    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    gate.run_ci("demo/bad", out_dir=tmp_path, use_groq=False, summary_file=None, output_file=None, expect=None)
    assert seen["cmd"][1:4] == ["-m", "app.cli", "analyze"]
    assert {"--tf", "--json", "--no-store", "--no-groq"} <= set(seen["cmd"])


# --- MCP server ----------------------------------------------------------------------


def rpc(server, *messages):
    out = io.StringIO()
    server.serve(io.StringIO("".join(json.dumps(m) + "\n" for m in messages)), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_mcp_handshake_and_tool_list():
    init, listed = rpc(GateServer(FakeClient),
                       {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}},
                       {"jsonrpc": "2.0", "method": "notifications/initialized"},
                       {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["serverInfo"]["name"] == "ghostops-gate"
    assert "terraform apply" in init["result"]["instructions"]
    names = [t["name"] for t in listed["result"]["tools"]]
    assert names == ["ghostops_check_plan", "ghostops_get_certificate"]
    assert TOOLS[0]["inputSchema"]["required"] == ["plan_json_path", "tf_dir"]


def test_mcp_check_plan_tool(bad_cert):
    client = FakeClient()
    server = GateServer(lambda: client)
    result = server.ghostops_check_plan(str(FIXTURES / "bad_plan.json"), str(REPO / "demo" / "bad"))
    assert result["verdict"] == gate.BLOCKED and result["apply_allowed"] is False
    assert result["certificate_id"] == compute_plan_id(plan("bad_plan.json"))
    assert any(f["rule"] == "GO-IAM-001" for f in result["blocking_findings"])

    (response,) = rpc(server, {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                               "params": {"name": "ghostops_get_certificate", "arguments": {"plan_id": result["plan_id"]}}})
    assert response["id"] == 7 and response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["verdict"] == gate.BLOCKED
    assert json.loads(response["result"]["content"][0]["text"])["certificate_id"] == result["plan_id"]


def test_mcp_get_certificate_sees_the_approval(bad_cert):
    client = FakeClient({bad_cert["plan_id"]: bad_cert}, {bad_cert["plan_id"]: [decision(bad_cert, "approve", 1)]})
    assert GateServer(lambda: client).ghostops_get_certificate(bad_cert["plan_id"])["apply_allowed"] is True


def test_mcp_errors_are_tool_errors_never_approvals():
    server = GateServer(FakeClient)
    responses = rpc(server,
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "ghostops_get_certificate", "arguments": {"plan_id": "a" * 64}}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": "ghostops_check_plan", "arguments": {"plan_json_path": "x.json"}}},
                    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "terraform_apply", "arguments": {}}},
                    {"jsonrpc": "2.0", "id": 4, "method": "resources/list"})
    assert responses[0]["result"]["isError"] and "Do NOT apply" in responses[0]["result"]["content"][0]["text"]
    assert responses[1]["result"]["isError"] and "bad arguments" in responses[1]["result"]["content"][0]["text"]
    assert responses[2]["result"]["isError"] and "unknown tool" in responses[2]["result"]["content"][0]["text"]
    assert responses[3]["error"]["code"] == -32601


def test_mcp_parse_error_and_ping():
    out = io.StringIO()
    GateServer(FakeClient).serve(io.StringIO('garbage\n\n{"jsonrpc":"2.0","id":5,"method":"ping"}\n'), out)
    first, second = [json.loads(line) for line in out.getvalue().splitlines()]
    assert first["error"]["code"] == -32700 and second == {"jsonrpc": "2.0", "id": 5, "result": {}}


def test_mcp_server_runs_over_stdio(tmp_path):
    """The real process: stdout must carry only JSON-RPC lines."""
    import sys

    messages = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    proc = subprocess.run([sys.executable, "-m", "app.mcp_gate"], input="".join(json.dumps(m) + "\n" for m in messages),
                          capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=REPO / "backend")
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [m["id"] for m in lines] == [1, 2]
    assert lines[0]["result"]["protocolVersion"] == "2024-11-05"
    assert len(lines[1]["result"]["tools"]) == 2
