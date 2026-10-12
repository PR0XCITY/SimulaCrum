import copy
import json
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app import certificate
from app.certificate import (
    AUTO_APPROVED, BLOCKED, CertificateError, build_certificate, compute_plan_id, decide, explainer_facts,
    resource_type, sanitize_text, sign, verify,
)
from app.config import setting
from app.policy_engine import PolicyEngineError
from app.shadow import ShadowResult

FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "0123456789abcdef" * 4
NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)
TOP_LEVEL = ["plan_id", "timestamp", "resource_changes", "blast_radius", "shadow_run", "cost_delta",
             "verdict", "risk_explanation", "generated_by", "cost_breakdown", "generated_terraform",
             "architecture", "pillars", "signature_alg", "signature"]


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def shadow_ok(n):
    return ShadowResult(True, "complete", resources=[{"address": f"r.{i}", "type": "r", "id": str(i)} for i in range(n)])


def cost_result(delta, note=None):
    return {"monthly_delta_usd": delta, "complete": True, "unpriced": [],
            "resources": [{"address": "aws_s3_bucket.x", "note": note}]}


def make(name="bad_plan.json", shadow=None, cost=None, **kwargs):
    return build_certificate(load(name), shadow_result=shadow or shadow_ok(8), cost_result=cost or cost_result(23.832),
                             use_groq=False, secret=SECRET, now=NOW, **kwargs)


# --- schema -------------------------------------------------------------------------------


def test_exact_dashboard_schema():
    cert = make()
    assert list(cert) == TOP_LEVEL
    assert set(cert["blast_radius"]) == {"newly_public", "iam_widened", "risk_flags", "graph"}
    assert set(cert["blast_radius"]["graph"]) == {"nodes", "edges"}
    assert set(cert["shadow_run"]) == {"applied", "resources_created", "error", "resources", "inventory_error"}
    assert set(cert["cost_delta"]) == {"monthly_usd", "note"}
    assert all(set(r) == {"resource", "action", "before", "after"} for r in cert["resource_changes"])
    flags = cert["blast_radius"]["risk_flags"]
    assert all(set(f) == {"rule", "severity", "resource", "message", "pillar", "remediation"} for f in flags)
    assert list(cert["pillars"]) == ["security", "reliability", "cost", "performance"]
    assert all(set(p) == {"score", "findings"} for p in cert["pillars"].values())
    assert all(set(x) == {"rule", "severity", "resource", "penalty"} for p in cert["pillars"].values() for x in p["findings"])
    assert all(set(f["remediation"]) == {"summary", "config_change", "generated_by"} for f in flags)
    assert cert["generated_terraform"] is None and cert["architecture"] is None  # plain plan, not an architecture
    assert isinstance(cert["cost_breakdown"], list)
    assert cert["timestamp"] == "2026-10-06T12:00:00Z"
    assert cert["generated_by"] == "template"
    assert cert["signature_alg"] == "hmac-sha256"  # secret= given; Ed25519 is in test_signing.py
    assert len(cert["signature"]) == 64 and int(cert["signature"], 16) >= 0


def test_plan_id_is_sha256_of_canonical_plan():
    plan = load("good_plan.json")
    reformatted = json.loads(json.dumps(plan, indent=7, sort_keys=False))
    assert compute_plan_id(plan) == compute_plan_id(reformatted)
    plan["planned_values"]["root_module"]["resources"][0]["values"]["bucket"] = "other"
    assert compute_plan_id(plan) != compute_plan_id(reformatted)
    assert len(compute_plan_id(plan)) == 64


# --- verdict --------------------------------------------------------------------------------


def test_bad_demo_is_blocked_with_flags_from_every_source():
    cert = make()
    assert cert["verdict"] == BLOCKED
    rules = {f["rule"] for f in cert["blast_radius"]["risk_flags"]}
    assert {"GO-SG-001", "GO-IAM-001", "GO-S3-001", "GO-RDS-001", "GO-EXPOSE-001", "GO-IAMW-001"} <= rules
    severities = [f["severity"] for f in cert["blast_radius"]["risk_flags"]]
    assert severities == sorted(severities, key=certificate.SEVERITY_ORDER.get)


def test_good_demo_is_auto_approved():
    cert = make("good_plan.json", shadow=shadow_ok(2), cost=cost_result(0.1))
    assert cert["verdict"] == AUTO_APPROVED
    # only advisory findings: the bucket has no versioning or encryption resource
    assert {(f["pillar"], f["rule"]) for f in cert["blast_radius"]["risk_flags"]} == {
        ("reliability", "GO-REL-003"), ("security", "GO-S3-002")}
    assert cert["shadow_run"] == {"applied": True, "resources_created": 2, "error": None,
                                  "resources": [], "inventory_error": None}
    assert cert["cost_delta"]["monthly_usd"] == 0.1


def test_failed_shadow_apply_blocks_a_clean_plan():
    failed = ShadowResult(False, "apply", error="Error: boom", findings=[
        {"rule_id": "GO-SHADOW-001", "severity": "HIGH", "address": "aws_s3_bucket.logs", "message": "failed"}])
    cert = make("good_plan.json", shadow=failed)
    assert cert["verdict"] == BLOCKED
    assert cert["shadow_run"] == {"applied": False, "resources_created": 0, "error": "Error: boom",
                                  "resources": [], "inventory_error": None}
    assert cert["blast_radius"]["risk_flags"][0]["rule"] == "GO-SHADOW-001"


def test_no_terraform_dir_means_unverified_and_blocked():
    cert = build_certificate(load("good_plan.json"), None, cost_result=cost_result(0.1),
                             use_groq=False, secret=SECRET, now=NOW)
    assert cert["verdict"] == BLOCKED
    assert cert["shadow_run"]["applied"] is False
    assert "no Terraform directory" in cert["shadow_run"]["error"]


def test_destroy_only_warns_and_is_approved():
    cert = make("good_destroy_plan.json", shadow=shadow_ok(0), cost=cost_result(-0.1))
    assert {f["severity"] for f in cert["blast_radius"]["risk_flags"]} == {"MEDIUM"}
    assert cert["verdict"] == AUTO_APPROVED


@pytest.mark.parametrize(("severities", "applied", "verdict"), [
    ([], True, AUTO_APPROVED), (["MEDIUM", "LOW"], True, AUTO_APPROVED), (["HIGH"], True, BLOCKED),
    (["CRITICAL"], True, BLOCKED), ([], False, BLOCKED), (["MEDIUM"], False, BLOCKED),
])
def test_decide(severities, applied, verdict):
    flags = [{"rule": "r", "severity": s, "resource": "x", "message": "m"} for s in severities]
    assert decide(flags, {"applied": applied}) == verdict


def test_policy_engine_failure_blocks(monkeypatch):
    def broken(_plan):
        raise PolicyEngineError("opa binary not found")
    monkeypatch.setattr(certificate, "evaluate", broken)
    cert = make("good_plan.json", shadow=shadow_ok(2))
    assert cert["verdict"] == BLOCKED
    assert cert["blast_radius"]["risk_flags"][0]["rule"] == "GO-ENGINE-001"


def test_cost_unavailable_is_null_with_note(monkeypatch):
    def no_cost(_plan):
        raise certificate.CostError("Infracost is not logged in")
    monkeypatch.setattr(certificate, "plan_cost", no_cost)
    cert = build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), use_groq=False, secret=SECRET)
    assert cert["cost_delta"] == {"monthly_usd": None, "note": "Cost not estimated: Infracost is not logged in"}
    assert "could not be estimated" in cert["risk_explanation"]


# --- signature ------------------------------------------------------------------------------


def leaf_paths(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaf_paths(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaf_paths(v, path + (i,))
    else:
        yield path


def mutated(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if value is None:
        return "tampered"
    return f"{value}x"


def test_valid_certificate_verifies():
    cert = make()
    assert verify(cert, secret=SECRET)
    assert verify(cert, secret=SECRET, plan=load("bad_plan.json"))
    reordered = dict(reversed(list(cert.items())))
    assert verify(reordered, secret=SECRET)  # key order does not matter, content does


def test_editing_any_field_breaks_verification():
    cert = make()
    paths = [p for p in leaf_paths(cert) if p != ("signature",)]
    assert len(paths) > 100  # every value in the certificate, not a sample
    for path in paths:
        tampered = copy.deepcopy(cert)
        target = tampered
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = mutated(target[path[-1]])
        assert not verify(tampered, secret=SECRET), f"edit at {path} was not detected"


def test_adding_or_removing_fields_breaks_verification():
    cert = make()
    for key in TOP_LEVEL[:-1]:
        removed = {k: v for k, v in cert.items() if k != key}
        assert not verify(removed, secret=SECRET), key
    assert not verify({**cert, "approved_by": "attacker"}, secret=SECRET)
    flags = copy.deepcopy(cert)
    flags["blast_radius"]["risk_flags"].pop()
    assert not verify(flags, secret=SECRET)
    flipped = {**cert, "verdict": AUTO_APPROVED}
    assert not verify(flipped, secret=SECRET)


def test_signature_is_bound_to_the_secret_and_the_plan():
    cert = make()
    assert not verify(cert, secret="f" * 64)
    assert not verify({**cert, "signature": "0" * 64}, secret=SECRET)
    assert not verify({k: v for k, v in cert.items() if k != "signature"}, secret=SECRET)
    assert not verify(cert, secret=SECRET, plan=load("good_plan.json"))
    # moving a body onto another plan_id (and re-signing nothing) fails too
    assert not verify({**cert, "plan_id": compute_plan_id(load("good_plan.json"))}, secret=SECRET)


def test_missing_or_short_secret_is_refused():
    with pytest.raises(CertificateError):
        build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), cost_result=cost_result(0.1),
                          use_groq=False, secret="short")
    with pytest.raises(CertificateError):
        sign({"plan_id": "x"}, secret="")


def test_real_secret_from_env_signs_and_verifies():
    assert setting("GHOSTOPS_HMAC_SECRET"), "GHOSTOPS_HMAC_SECRET missing from .env"
    cert = build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), cost_result=cost_result(0.1),
                             use_groq=False)
    assert verify(cert)
    if cert["signature_alg"] == "hmac-sha256":  # .env has no GHOSTOPS_SIGNING_KEY
        assert not verify(cert, secret=SECRET)


# --- sensitive values -------------------------------------------------------------------------


def test_sensitive_values_are_redacted():
    plan = {"format_version": "1.2", "resource_changes": [{
        "address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance", "name": "db",
        "change": {"actions": ["update"],
                   "before": {"password": "old-secret", "tags": {"a": "b"}, "users": ["u1", "u2"]},
                   "after": {"password": "new-secret", "tags": {"a": "c"}, "users": ["u1", "u3"]},
                   "before_sensitive": {"password": True, "users": [False, True]},
                   "after_sensitive": {"password": True, "users": [False, True]}}}]}
    cert = build_certificate(plan, shadow_result=shadow_ok(1), cost_result=cost_result(0.0), use_groq=False,
                             secret=SECRET)
    [rc] = cert["resource_changes"]
    assert rc["before"] == {"password": "(sensitive)", "tags": {"a": "b"}, "users": ["u1", "(sensitive)"]}
    assert rc["after"] == {"password": "(sensitive)", "tags": {"a": "c"}, "users": ["u1", "(sensitive)"]}
    assert "secret" not in json.dumps(cert)


# --- explainer: what may leave the machine ----------------------------------------------------


@pytest.mark.parametrize("text", [
    "key AKIAIOSFODNN7EXAMPLE here", "account 123456789012", "arn:aws:iam::123456789012:role/admin",
    "password=hunter2", "Token: abc.def.ghi", "gsk_FAKEexampleKEYnotREAL0123456789",
    "secret aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRva2VuIDEyMw==",
])
def test_sanitize_strips_secrets(text):
    cleaned = sanitize_text(text)
    assert "[redacted]" in cleaned
    for needle in ("AKIAIOSFODNN7EXAMPLE", "123456789012", "hunter2", "abc.def.ghi", "gsk_FAKE", "aGVsbG8"):
        assert needle not in cleaned


@pytest.mark.parametrize("text", ["aws_vpc_security_group_ingress_rule", "aws_s3_bucket_public_access_block",
                                  "GO-IAM-001", "CRITICAL", "port 22 from 0.0.0.0/0"])
def test_sanitize_keeps_structure(text):
    assert sanitize_text(text) == text


def test_resource_type_never_leaks_names():
    assert resource_type("aws_s3_bucket.prod_db_password_backup") == "aws_s3_bucket"
    assert resource_type("module.billing[0].aws_iam_role.admin") == "aws_iam_role"
    assert resource_type("(shadow run)") == "resource"


def test_groq_receives_only_sanitized_structure(monkeypatch):
    sent = {}

    def fake_post(url, body, headers, timeout):
        sent.update(url=url, body=body, headers=headers)
        return {"choices": [{"message": {"content": "This change is blocked. It opens SSH to the internet."}}]}

    monkeypatch.setattr(certificate, "_post_json", fake_post)
    monkeypatch.setattr(certificate, "setting", lambda name, default=None: {"GROQ_API_KEY": "gsk_test"}.get(name, default))
    cert = build_certificate(load("bad_plan.json"), shadow_result=shadow_ok(8), cost_result=cost_result(23.8),
                             secret=SECRET, now=NOW)
    assert cert["generated_by"] == "groq"
    assert cert["risk_explanation"] == "This change is blocked. It opens SSH to the internet."
    assert sent["url"] == "https://api.groq.com/openai/v1/chat/completions"
    facts = json.loads(sent["body"]["messages"][1]["content"])
    assert set(facts) == {"verdict", "resource_change_count", "shadow_apply_succeeded", "findings"}
    assert all(set(f) == {"rule", "title", "severity", "resource_type", "pillar", "blocks_change"}
               for f in facts["findings"])
    outbound = json.dumps(sent["body"])
    for leak in ("ssh_open", "admin_star", "ghostops-bad", "unencrypted", "0.0.0.0/0", "arn:aws", "23.8", "ami-"):
        assert leak not in outbound, leak


@pytest.mark.parametrize("failure", [
    urllib.error.HTTPError(certificate.GROQ_URL, 429, "Too Many Requests", {}, None),
    urllib.error.URLError("network down"),
    TimeoutError("timed out"),
    KeyError("choices"),
])
def test_groq_failure_falls_back_to_template(monkeypatch, failure):
    def fail(*_, **__):
        raise failure
    monkeypatch.setattr(certificate, "_post_json", fail)
    monkeypatch.setattr(certificate, "setting", lambda name, default=None: {"GROQ_API_KEY": "gsk_test"}.get(name, default))
    cert = build_certificate(load("bad_plan.json"), shadow_result=shadow_ok(8), cost_result=cost_result(23.832),
                             secret=SECRET, now=NOW)
    assert cert["generated_by"] == "template"
    assert cert["risk_explanation"].startswith("SimulaCrum blocked this change for human review: it has 3 critical")
    assert "Estimated monthly cost change: +$23.83." in cert["risk_explanation"]
    assert verify(cert, secret=SECRET)


def test_template_for_approved_change():
    cert = make("good_plan.json", shadow=shadow_ok(2), cost=cost_result(0.1))
    assert cert["risk_explanation"] == (
        "SimulaCrum auto-approved this change of 2 resource(s): no critical or high-severity security findings, "
        "only 2 advisory finding(s) (S3 bucket has no versioning; S3 bucket has no encryption configuration in code). "
        "It applied cleanly on the MiniStack emulator (2 resources). Estimated monthly cost change: +$0.10.")


def test_explainer_facts_shape():
    flags = [{"rule": "GO-SG-001", "severity": "CRITICAL", "resource": "aws_security_group.prod_admin", "message": "m"}]
    facts = explainer_facts(flags, {"applied": True}, BLOCKED, 3)
    assert facts == {"verdict": BLOCKED, "resource_change_count": 3, "shadow_apply_succeeded": True, "findings": [
        {"rule": "GO-SG-001", "title": "SSH or RDP open to the internet", "severity": "CRITICAL",
         "resource_type": "aws_security_group", "pillar": "security", "blocks_change": True}]}


# --- pillars ------------------------------------------------------------------------------


def db_plan(after):
    return {"format_version": "1.2", "resource_changes": [{
        "address": "aws_db_instance.db", "mode": "managed", "type": "aws_db_instance", "name": "db",
        "change": {"actions": ["create"], "before": None, "after": after}}]}


def test_pillar_scores_follow_the_published_formula():
    cert = make()
    pillars = cert["pillars"]
    for name, pillar in pillars.items():
        assert pillar["score"] == max(0, 100 - sum(x["penalty"] for x in pillar["findings"]))
        assert all(x["penalty"] == certificate.PENALTY[x["severity"]] for x in pillar["findings"])
    flags = cert["blast_radius"]["risk_flags"]
    assert sum(len(p["findings"]) for p in pillars.values()) == len(flags)
    assert pillars["security"]["score"] == 0  # 3 critical + 5 high
    # reliability: GO-REL-001, -003, -004 (MEDIUM, 10 each) + GO-REL-006 (LOW, 5)
    assert pillars["reliability"]["score"] == 100 - 3 * 10 - 5
    assert pillars["cost"]["score"] == 100 - 2 * 5  # two untagged resources
    assert pillars["performance"] == {"score": 100, "findings": []}


def test_advisory_high_finding_does_not_block():
    after = {"storage_encrypted": True, "multi_az": True, "backup_retention_period": 0, "tags": {"Name": "db"}}
    cert = build_certificate(db_plan(after), shadow_result=shadow_ok(1), cost_result=cost_result(15.0),
                             use_groq=False, secret=SECRET, now=NOW)
    rel = [f for f in cert["blast_radius"]["risk_flags"] if f["rule"] == "GO-REL-002"]
    assert rel and rel[0]["severity"] == "HIGH" and rel[0]["pillar"] == "reliability"
    assert cert["verdict"] == AUTO_APPROVED
    assert cert["pillars"]["reliability"]["score"] == 100 - 25 - 5  # REL-002 HIGH + REL-006 LOW (no alarm)
    assert cert["pillars"]["security"]["score"] == 100


def test_security_high_finding_still_blocks():
    after = {"storage_encrypted": False, "multi_az": True, "backup_retention_period": 7, "tags": {"Name": "db"}}
    cert = build_certificate(db_plan(after), shadow_result=shadow_ok(1), cost_result=cost_result(15.0),
                             use_groq=False, secret=SECRET, now=NOW)
    assert cert["verdict"] == BLOCKED
    assert cert["pillars"]["security"] == {"score": 75, "findings": [
        {"rule": "GO-RDS-001", "severity": "HIGH", "resource": "aws_db_instance.db", "penalty": 25}]}


def test_low_security_finding_does_not_block():
    flags = [certificate.flag("GO-S3-002", "LOW", "aws_s3_bucket.b", "m", "security"),
             certificate.flag("GO-REL-002", "HIGH", "aws_db_instance.d", "m", "reliability"),
             certificate.flag("GO-PERF-002", "MEDIUM", "aws_lambda_function.f", "m", "performance")]
    assert certificate.decide(flags, {"applied": True}) == AUTO_APPROVED
    flags.append(certificate.flag("GO-EXPOSE-001", "HIGH", "aws_instance.w", "m"))  # graph flags are security
    assert certificate.decide(flags, {"applied": True}) == BLOCKED


def test_pillar_scores_floor_at_zero():
    flags = [certificate.flag("GO-REL-002", "HIGH", f"aws_db_instance.d{i}", "m", "reliability") for i in range(6)]
    assert certificate.pillars_section(flags)["reliability"]["score"] == 0


@pytest.mark.integration
@pytest.mark.skipif(not setting("GROQ_API_KEY"), reason="GROQ_API_KEY not set")
def test_live_groq_explanation():
    cert = build_certificate(load("bad_plan.json"), shadow_result=shadow_ok(8), cost_result=cost_result(23.832),
                             secret=SECRET)
    assert cert["generated_by"] == "groq", "Groq call failed (template fallback used)"
    assert 20 <= len(cert["risk_explanation"]) <= 800
    assert verify(cert, secret=SECRET)


# --- budget gate (GO-BUDGET-001) ------------------------------------------------------------


def test_over_budget_blocks_an_otherwise_clean_change():
    cert = make("good_plan.json", shadow=shadow_ok(2), cost=cost_result(7128.0))
    [budget] = [f for f in cert["blast_radius"]["risk_flags"] if f["rule"] == "GO-BUDGET-001"]
    assert budget["severity"] == "HIGH" and budget["pillar"] == "cost"
    assert "$7,128.00 per month, over the $500.00 monthly budget" in budget["message"]
    assert budget["remediation"]["config_change"] == []
    assert cert["verdict"] == BLOCKED
    assert cert["pillars"]["cost"]["score"] == 75
    assert cert["risk_explanation"].startswith("SimulaCrum blocked this change for human review: it has 0 critical "
                                               "and 1 high-severity blocking findings (Monthly cost increase is over budget)")


def test_under_budget_and_unknown_cost_do_not_block():
    under = make("good_plan.json", shadow=shadow_ok(2), cost=cost_result(499.99))
    assert under["verdict"] == AUTO_APPROVED
    assert "GO-BUDGET-001" not in {f["rule"] for f in under["blast_radius"]["risk_flags"]}
    unknown = {"monthly_delta_usd": None, "complete": False, "unpriced": ["aws_s3_bucket.logs"], "resources": []}
    assert make("good_plan.json", shadow=shadow_ok(2), cost=unknown)["verdict"] == AUTO_APPROVED


def test_budget_setting(monkeypatch):
    def with_budget(value):
        monkeypatch.setattr(certificate, "setting", lambda name, default=None:
                            {"GHOSTOPS_MONTHLY_BUDGET_USD": value}.get(name, default))
        return certificate.monthly_budget()

    assert with_budget(None) == 500.0
    assert with_budget("1000") == 1000.0
    assert with_budget("off") is None
    assert with_budget("lots") == 500.0  # a typo must not switch the gate off
    assert certificate.budget_flags({"monthly_usd": 600.0})[0]["rule"] == "GO-BUDGET-001"  # "lots" -> 500
    with_budget("off")
    assert certificate.budget_flags({"monthly_usd": 600000.0}) == []  # gate off
    assert certificate.budget_flags({"monthly_usd": 20.0}, budget=10.0)[0]["rule"] == "GO-BUDGET-001"
    assert certificate.blocks(certificate.budget_flags({"monthly_usd": 20.0}, budget=10.0)[0])
