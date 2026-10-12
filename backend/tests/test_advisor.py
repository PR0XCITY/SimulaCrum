"""Trusted Advisor: candidates, measured impact, ranking, the combined plan and the API job.

`terraform plan` and Infracost are faked; the OPA rules, graph diff and pillar formula are
real. The fake planner reads the generated main.tf, so a candidate's config change really
flows through the generator into the plan that is scored."""

import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import advisor
from app.api import create_app
from app.shadow import ShadowError
from app.store import Store

SECRET = "test-secret-" + "a1b2c3d4" * 6
PRICE = {"t3.micro": 7.5, "t3.small": 15.0, "t3.medium": 30.0, "t3.large": 60.0}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")
    monkeypatch.setenv("GHOSTOPS_MONTHLY_BUDGET_USD", "500")


def fake_plan(directory: str) -> dict:
    """A real-shaped plan for an EC2 service: its SSH security group and instance(s)."""
    tf = Path(directory, "main.tf").read_text(encoding="utf-8")
    instance_type = re.search(r'instance_type\s*=\s*"([^"]+)"', tf).group(1)
    count = int(re.search(r"count\s*=\s*(\d+)", tf).group(1))
    ssh_cidr = re.search(r'ingress \{.*?cidr_blocks = \["([^"]+)"\]', tf, re.S).group(1)
    sg = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                       "cidr_blocks": [ssh_cidr], "ipv6_cidr_blocks": []}]}
    changes, resources = [], []
    for address, rtype, values in [("aws_security_group.web_ssh", "aws_security_group", sg)] + [
            (f"aws_instance.web[{i}]", "aws_instance", {"instance_type": instance_type, "tags": {"Name": "web"}})
            for i in range(count)]:
        changes.append({"address": address, "mode": "managed", "type": rtype, "name": address.split(".")[1],
                        "change": {"actions": ["create"], "before": None, "after": values}})
        resources.append({"address": address, "mode": "managed", "type": rtype, "values": values})
    return {"format_version": "1.2", "terraform_version": "1.16.4", "resource_changes": changes,
            "planned_values": {"root_module": {"resources": resources}}}


def fake_prices(plans, usage_files):
    def total(plan):
        return sum(PRICE[r["values"]["instance_type"]] for r in plan["planned_values"]["root_module"]["resources"]
                   if r["type"] == "aws_instance")
    return [total(p) for p in plans], None


def no_infracost(plans, usage_files):
    return [None] * len(plans), "Cost not estimated: Infracost is not logged in."


RISKY = {"services": [{"type": "ec2", "config": {"name": "web", "ssh_source_cidr": "0.0.0.0/0",
                                                 "instance_type": "t3.medium", "expected_cpu_percent": 30}}]}


def run(arch=RISKY, **kwargs):
    return advisor.advise(arch, planner=kwargs.pop("planner", fake_plan), pricer=kwargs.pop("pricer", fake_prices))


def test_fix_and_saving_are_measured_and_ranked():
    result = run()
    assert result["baseline"]["verdict"] == "BLOCKED_PENDING_REVIEW"
    assert result["baseline"]["monthly_usd"] == 30.0
    recs = result["recommendations"]
    fix = recs[0]
    assert fix["kind"] == "fix" and fix["changes"][0]["field"] == "ssh_source_cidr"
    assert fix["impact"]["unblocks"] and fix["impact"]["verdict_after"] == "AUTO_APPROVED"
    assert fix["impact"]["points_removed"]["security"] > 0 and fix["impact"]["cost_usd"] == 0
    assert "GO-SG-001" in fix["impact"]["fixed_rules"] and not fix["impact"]["tradeoffs"]
    save = next(r for r in recs if r["kind"] == "save")
    assert save["changes"] == [{"service": "web", "type": "ec2", "field": "instance_type", "from": "t3.medium", "to": "t3.small"}]
    assert save["impact"]["cost_usd"] == -15.0 and not save["impact"]["tradeoffs"]


def test_tradeoffs_are_measured_not_hidden():
    # GO-REL-004 (single instance) is fixed by count 2: better reliability, but it doubles the cost,
    # and with SSH still open it adds a blocking exposure of the second instance.
    trade = next(r for r in run()["recommendations"] if r["changes"][0]["field"] == "count")
    assert trade["impact"]["points_removed"]["reliability"] > 0
    assert "+$30.00/month" in trade["impact"]["tradeoffs"]


def test_combined_applies_every_tradeoff_free_change():
    result = run()
    combined = result["combined"]
    fields = {c["field"] for c in combined["changes"]}
    assert fields == {"ssh_source_cidr", "instance_type"}  # count (a trade-off) is left out
    assert combined["impact"]["verdict_after"] == "AUTO_APPROVED"
    assert combined["impact"]["cost_usd"] == -15.0 and combined["impact"]["monthly_after_usd"] == 15.0


def test_no_downsize_when_stated_cpu_is_high():
    busy = {"services": [{"type": "ec2", "config": {"name": "web", "instance_type": "t3.medium", "expected_cpu_percent": 80}}]}
    assert not [r for r in run(busy)["recommendations"] if r["kind"] == "save"]


def test_without_infracost_cost_only_suggestions_are_dropped():
    result = run(pricer=no_infracost)
    assert result["cost_note"].startswith("Cost not estimated")
    assert all(r["kind"] == "fix" for r in result["recommendations"])
    assert all(r["impact"]["cost_usd"] is None for r in result["recommendations"])


def test_a_candidate_that_cannot_be_planned_is_skipped():
    def flaky(directory):
        if '"t3.small"' in Path(directory, "main.tf").read_text(encoding="utf-8"):
            raise ShadowError("terraform plan failed")
        return fake_plan(directory)

    result = run(planner=flaky)
    assert result["candidates_failed"] == 1
    assert not [r for r in result["recommendations"] if r["kind"] == "save"]


def test_baseline_that_cannot_be_planned_is_an_error():
    def broken(directory):
        raise ShadowError("terraform init failed")

    with pytest.raises(ShadowError, match="current design"):
        run(planner=broken)


def test_unnamed_services_are_matched_by_the_generated_name():
    arch = {"services": [{"type": "ec2", "config": {"ssh_source_cidr": "0.0.0.0/0", "instance_type": "t3.medium"}}]}
    slugs = ["ec2-1"]
    changed = advisor.apply_changes(arch, slugs, [{"service": "ec2-1", "type": "ec2", "field": "instance_type",
                                                   "from": "t3.medium", "to": "t3.small"}])
    assert changed["services"][0]["config"]["instance_type"] == "t3.small"
    assert arch["services"][0]["config"]["instance_type"] == "t3.medium"  # the input is not modified


def test_price_all_attributes_each_module(monkeypatch):
    from app import cost

    seen = {}

    def fake_scan(planned_values, *, terraform_version, usage_file=None):
        seen["values"], seen["usage"] = planned_values, usage_file
        res = lambda name, usd: {"name": name, "cost_components": [{"total_monthly_cost": str(usd), "quantity": "1", "price": "1"}]}
        return {"currency": "USD", "projects": [{"resources": [
            res("module.c0.aws_instance.web[0]", 30), res("module.c1.aws_instance.web[0]", 15),
            res("module.c1.aws_s3_bucket.b", 0)]}]}

    monkeypatch.setattr(cost, "check_login", lambda: None)
    monkeypatch.setattr(cost, "scan", fake_scan)
    plan = {"terraform_version": "1.16.4", "planned_values": {"root_module": {"resources": [{"address": "aws_instance.web[0]"}]}}}
    prices, note = advisor.price_all([plan, plan], [{}, {"aws_s3_bucket.b": {"standard": {"storage_gb": 5}}}])
    assert note is None and prices == [30.0, 15.0]
    children = seen["values"]["root_module"]["child_modules"]
    assert [c["address"] for c in children] == ["module.c0", "module.c1"]
    assert children[1]["resources"][0]["address"] == "module.c1.aws_instance.web[0]"
    assert seen["usage"] == {"module.c1.aws_s3_bucket.b": {"standard": {"storage_gb": 5}}}


def test_price_all_without_login_returns_a_note(monkeypatch):
    from app import cost

    def not_logged_in():
        raise cost.InfracostAuthError("not logged in")

    monkeypatch.setattr(cost, "check_login", not_logged_in)
    prices, note = advisor.price_all([{"planned_values": {}}], [{}])
    assert prices == [None] and note.startswith("Cost not estimated")


def test_api_runs_the_advisor_as_a_job(tmp_path):
    def fake_advise(architecture):
        return {"baseline": {"verdict": "AUTO_APPROVED"}, "recommendations": [], "combined": None,
                "services": len(architecture["services"])}

    with TestClient(create_app(store=Store(tmp_path / "db"), architecture_advisor=fake_advise)) as client:
        bad = client.post("/architectures/advise", json={"services": [{"type": "nope"}]})
        assert bad.status_code == 422
        job = client.post("/architectures/advise", json={"services": [{"type": "s3"}]}).json()
        for _ in range(50):
            job = client.get(f"/architectures/advise/{job['job_id']}").json()
            if job["status"] == "done":
                break
            time.sleep(0.05)
        assert job["status"] == "done" and job["result"]["services"] == 1
        assert client.get("/architectures/advise/" + "0" * 32).status_code == 404
        # Certify jobs keep their shape (no result field)
        assert "result" not in client.app.state.jobs._public({**job, "id": "x", "key": "", "created": 0, "started": 0,
                                                              "finished": 0, "plan_id": None, "verdict": None,
                                                              "error": None, "result": None, "status": "done"})


def test_api_reports_advisor_failures(tmp_path):
    def broken(architecture):
        raise ShadowError("terraform init failed")

    with TestClient(create_app(store=Store(tmp_path / "db"), architecture_advisor=broken)) as client:
        job = client.post("/architectures/advise", json={"services": [{"type": "s3"}]}).json()
        for _ in range(50):
            job = client.get(f"/architectures/advise/{job['job_id']}").json()
            if job["status"] == "error":
                break
            time.sleep(0.05)
        assert job["status"] == "error" and "terraform init failed" in job["error"]
