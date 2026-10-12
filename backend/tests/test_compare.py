"""Compare slots A/B: diff, highlights, snapshot and the /comparisons endpoints."""

import shutil

import pytest
from fastapi.testclient import TestClient

from app import certificate
from app.api import create_app
from app.compare import diff, highlights, snapshot
from app.store import Store
from conftest import reopen

SECRET = "compare-test-secret-" + "beef" * 8

SMALL = {"services": [
    {"type": "ec2", "config": {"name": "web", "instance_type": "t3.micro"}},
    {"type": "s3", "config": {"name": "assets"}, "usage": {"monthly_get_requests": 1000}},
]}
BIG = {"services": [
    {"type": "ec2", "config": {"name": "web", "instance_type": "m5.large", "count": 2}},
    {"type": "s3", "config": {"name": "assets", "versioning": True}, "usage": {"monthly_get_requests": 5000}},
    {"type": "rds", "config": {"name": "db"}},
]}


@pytest.fixture(autouse=True)
def signing_secret(monkeypatch):
    monkeypatch.setattr(certificate, "setting", lambda name, default=None:
                        {"GHOSTOPS_HMAC_SECRET": SECRET}.get(name, default))
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)


def fake_check(flags, monthly, services=None, breakdown=None):
    return {
        "verdict_preview": "BLOCKED_PENDING_REVIEW" if any(certificate.blocks(f) for f in flags) else "AUTO_APPROVED",
        "risk_flags": flags,
        "pillars": certificate.pillars_section(flags),
        "cost_delta": {"monthly_usd": monthly, "note": None},
        "cost_breakdown": breakdown or [],
        "resource_count": 4,
        "services": services or [],
    }


def f(rule, severity, pillar="security", resource="aws_x.y"):
    return certificate.flag(rule, severity, resource, "m", pillar)


# --- diff -------------------------------------------------------------------------------------


def test_diff_lists_services_and_changed_settings():
    d = diff(SMALL, BIG)
    assert d["only_in_a"] == [] and d["only_in_b"] == [{"name": "db", "type": "rds"}]
    changed = {(c["service"], c["field"]): (c["a"], c["b"]) for c in d["changed_settings"]}
    assert changed == {
        ("web", "instance_type"): ("t3.micro", "m5.large"),
        ("web", "count"): (1, 2),
        ("assets", "usage.monthly_get_requests"): (1000, 5000),
    }  # versioning=True is the default, so it is not a difference
    assert d["identical"] is False


def test_diff_fills_defaults_so_unset_equals_default():
    explicit = {"services": [{"type": "ec2", "config": {"name": "web", "instance_type": "t3.micro", "count": 1}}]}
    implicit = {"services": [{"type": "ec2", "config": {"name": "web"}}]}
    assert diff(explicit, implicit) == {"only_in_a": [], "only_in_b": [], "changed_settings": [], "identical": True}


def test_same_name_different_type_counts_as_removed_and_added():
    a = {"services": [{"type": "s3", "config": {"name": "store"}}]}
    b = {"services": [{"type": "dynamodb", "config": {"name": "store"}}]}
    d = diff(a, b)
    assert d["only_in_a"] == [{"name": "store", "type": "s3"}]
    assert d["only_in_b"] == [{"name": "store", "type": "dynamodb"}]
    assert d["changed_settings"] == []


# --- highlights -------------------------------------------------------------------------------


def test_cheaper_and_fewer_risks_can_be_different_designs():
    a = snapshot(fake_check([f("GO-SG-001", "CRITICAL")], 10.0))
    b = snapshot(fake_check([f("GO-REL-003", "MEDIUM", "reliability"), f("GO-REL-006", "LOW", "reliability")], 25.5))
    h = highlights(a, b)
    assert h["cheaper"] == {"slot": "A", "difference_usd": 15.5, "reason": "Design A costs $15.50 less per month."}
    # A has fewer findings (1 vs 2) but one of them blocks: blocking findings count first
    assert h["fewer_risks"]["slot"] == "B"
    assert h["fewer_risks"]["reason"] == "Design B has fewer risks: 0 blocking finding(s) against 1."


def test_fewer_risks_falls_back_to_count_then_penalty():
    one = snapshot(fake_check([f("GO-REL-003", "MEDIUM", "reliability")], 5.0))
    two = snapshot(fake_check([f("GO-REL-003", "MEDIUM", "reliability"), f("GO-COST-003", "LOW", "cost")], 5.0))
    assert highlights(one, two)["fewer_risks"]["slot"] == "A"
    low = snapshot(fake_check([f("GO-COST-003", "LOW", "cost")], 5.0))
    assert highlights(one, low)["fewer_risks"] == {
        "slot": "B", "reason": "Design B has fewer risks: lighter findings (5 penalty points against 10)."}


def test_ties_and_unknown_cost():
    same = snapshot(fake_check([f("GO-REL-003", "MEDIUM", "reliability")], 7.0))
    h = highlights(same, dict(same))
    assert h["cheaper"]["slot"] == "tie" and h["fewer_risks"]["slot"] == "tie"
    unknown = dict(same, monthly_usd=None)
    assert highlights(same, unknown)["cheaper"] == {
        "slot": None, "difference_usd": None, "reason": "The monthly cost of one design is unknown."}


def test_snapshot_totals_cost_per_service():
    services = [{"name": "web", "type": "ec2", "resources": ["aws_instance.web", "aws_ebs_volume.web"]},
                {"name": "assets", "type": "s3", "resources": ["aws_s3_bucket.assets"]}]
    breakdown = [{"resource": "aws_instance.web[0]", "monthly_usd": 7.59},
                 {"resource": "aws_ebs_volume.web[0]", "monthly_usd": 1.6},
                 {"resource": "aws_s3_bucket.assets", "monthly_usd": None}]
    snap = snapshot(fake_check([f("GO-SG-001", "CRITICAL"), f("GO-REL-004", "MEDIUM", "reliability")],
                               9.19, services, breakdown))
    assert snap["services"] == [{"name": "web", "type": "ec2", "monthly_usd": 9.19},
                                {"name": "assets", "type": "s3", "monthly_usd": None}]
    assert snap["blocking_count"] == 1 and snap["risk_count"] == 2 and snap["penalty"] == 50
    assert snap["pillars"]["security"]["score"] == 60 and snap["pillars"]["reliability"]["score"] == 90
    assert snap["verdict"] == "BLOCKED_PENDING_REVIEW"


# --- endpoints + store (SQLite; Postgres too with TEST_DATABASE_URL) ------------------------------------------------------------------------


def test_save_compare_and_delete_slots(make_store):
    checks = {
        "web-t3.micro": fake_check([f("GO-REL-004", "MEDIUM", "reliability")], 9.19),
        "web-m5.large": fake_check([f("GO-COST-001", "MEDIUM", "cost"), f("GO-REL-001", "MEDIUM", "reliability")], 160.2),
    }

    def checker(body):
        web = next(s for s in body["services"] if s["config"]["name"] == "web")
        return checks[f"web-{web['config']['instance_type']}"]

    store = make_store()
    with TestClient(create_app(store=store, architecture_checker=checker)) as client:
        empty = client.get("/comparisons").json()
        assert empty["A"] is None and empty["B"] is None and empty["diff"] is None and empty["highlights"] is None

        saved = client.put("/comparisons/A", json=SMALL)
        assert saved.status_code == 200, saved.text
        assert saved.json()["snapshot"]["monthly_usd"] == 9.19
        one = client.get("/comparisons").json()
        assert one["A"]["architecture"] == SMALL and one["B"] is None and one["diff"] is None

        assert client.put("/comparisons/B", json=BIG).status_code == 200
        both = client.get("/comparisons").json()
        assert both["highlights"]["cheaper"]["slot"] == "A"
        assert both["highlights"]["fewer_risks"]["slot"] == "A"  # 1 finding against 2
        assert {"name": "db", "type": "rds"} in both["diff"]["only_in_b"]

        # saving a slot again replaces it
        assert client.put("/comparisons/A", json=BIG).status_code == 200
        assert client.get("/comparisons").json()["diff"]["identical"] is True

        assert client.delete("/comparisons/B").json() == {"slot": "B", "deleted": True}
        assert client.delete("/comparisons/B").status_code == 404
        assert client.get("/comparisons").json()["B"] is None

    # kept in the database: a new app on the same database still has slot A
    with TestClient(create_app(store=reopen(store), architecture_checker=checker)) as client:
        assert client.get("/comparisons").json()["A"]["architecture"] == BIG


def test_invalid_slot_and_architecture_are_rejected(make_store):
    def never(body):
        raise AssertionError("must not run the check for an invalid request")

    with TestClient(create_app(store=make_store(), architecture_checker=never)) as client:
        assert client.put("/comparisons/C", json=SMALL).status_code == 422
        bad = client.put("/comparisons/A", json={"services": [{"type": "ec2", "config": {"count": 0}}]})
        assert bad.status_code == 422 and bad.json()["detail"]["errors"][0]["field"] == "count"
        assert client.get("/comparisons").json()["A"] is None


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform missing")
def test_compare_real_static_checks(tmp_path):
    """Two real designs through terraform plan + OPA (cost stubbed to avoid Infracost calls)."""
    from functools import partial

    from app.architecture import check_architecture

    no_cost = {"monthly_delta_usd": 0.0, "complete": True, "unpriced": [], "resources": []}
    risky = {"services": [{"type": "ec2", "config": {"name": "web", "ssh_source_cidr": "0.0.0.0/0"}}]}
    safe = {"services": [{"type": "ec2", "config": {"name": "web", "count": 2}},
                         {"type": "cloudwatch_alarm", "config": {"name": "web-cpu"}}]}
    checker = partial(check_architecture, cost_result=no_cost)
    with TestClient(create_app(store=Store(tmp_path / "db"), architecture_checker=checker)) as client:
        assert client.put("/comparisons/A", json=risky).status_code == 200
        assert client.put("/comparisons/B", json=safe).status_code == 200
        out = client.get("/comparisons").json()
    assert out["A"]["snapshot"]["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert out["B"]["snapshot"]["verdict"] == "AUTO_APPROVED"
    assert out["highlights"]["fewer_risks"]["slot"] == "B"
    assert out["highlights"]["cheaper"]["slot"] == "tie"  # cost stubbed to 0 for both
    changed = {(c["service"], c["field"]) for c in out["diff"]["changed_settings"]}
    assert changed == {("web", "ssh_source_cidr"), ("web", "count")}
    assert out["diff"]["only_in_b"] == [{"name": "web-cpu", "type": "cloudwatch_alarm"}]
