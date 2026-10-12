import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from app import cost
from app.cost import AUTH_HELP, InfracostAuthError, plan_cost, plan_cost_file, price_resource

FIXTURES = Path(__file__).parent / "fixtures"


def infracost_logged_in() -> bool:
    # Never launches infracost without a stored login: that would open a browser page.
    try:
        cost.check_login()
        return True
    except cost.CostError:
        return False


def online(test):
    """Live Infracost pricing (network, login). Part of the slow `integration` set."""
    skip = pytest.mark.skipif(not infracost_logged_in(), reason="Infracost not logged in (infracost auth login)")
    return pytest.mark.integration(skip(test))


def by_address(result):
    return {r["address"]: r for r in result["resources"]}


# --- pricing one resource (Infracost output -> number or null) ------------------


def comp(name, total, price="1", quantity="1"):
    return {"name": name, "total_monthly_cost": total, "price": price, "quantity": quantity}


def test_free_resource_is_zero():
    assert price_resource({"type": "aws_iam_policy", "is_free": True}) == (0, cost.price_resource(
        {"type": "aws_iam_policy", "is_free": True})[1])
    assert "Free resource" in price_resource({"type": "aws_iam_policy", "is_free": True})[1]


def test_unsupported_resource_is_null_with_reason():
    value, note = price_resource({"type": "aws_iot_thing", "is_supported": False, "is_free": False})
    assert value is None
    assert note == "Infracost does not support pricing aws_iot_thing."


def test_resource_without_priced_components_is_null():
    value, note = price_resource({"type": "aws_x", "is_supported": True, "cost_components": [comp("a", None)]})
    assert value is None and "no priced cost components" in note


def test_components_and_subresources_are_summed():
    res = {"type": "aws_instance", "cost_components": [comp("Instance", "7.592", "0.0104", "730")],
           "subresources": [{"cost_components": [comp("Storage", "0.8", "0.1", "8")]}]}
    value, note = price_resource(res)
    assert str(value) == "8.392" and note is None


def test_unpriced_component_is_excluded_and_named():
    value, note = price_resource({"type": "aws_x", "cost_components": [comp("Hours", "5"), comp("Data", None)]})
    assert str(value) == "5" and "Not priced by Infracost (excluded): Data." in note


def test_zero_usage_components_are_flagged_as_lower_bound():
    res = {"type": "aws_s3_bucket", "subresources": [{"cost_components": [
        comp("Storage", "0", "0.023", "0"), comp("PUT requests", "0", "0.005", "0"), comp("Storage", "0", "0.0125", "0"),
        comp("Retrievals", "0", "0.01", "0")]}]}
    value, note = price_resource(res)
    assert value == 0
    assert note == ("4 usage-based cost components priced at zero usage (Storage; PUT requests; Retrievals); "
                    "the real cost depends on usage, so this is a lower bound.")


# --- delta assembly (scan stubbed) ------------------------------------------------


def rc(address, actions, before, after):
    return {"address": address, "mode": "managed", "type": address.split(".")[0], "name": address.split(".")[1],
            "change": {"actions": actions, "before": before, "after": after}}


def values(*addresses):
    return {"root_module": {"resources": [{"address": a, "mode": "managed", "type": a.split(".")[0]} for a in addresses]}}


def fake_scan(prices):
    def scan(planned_values, **_):
        names = [r["address"] for r in planned_values["root_module"]["resources"]]
        return {"currency": "USD", "summary": {"total_monthly_cost": "x"}, "projects": [{"resources": [
            {"name": n, "type": n.split(".")[0], "cost_components": [comp("c", prices[n])]}
            for n in names if n in prices]}]}
    return scan


def test_resource_missing_from_infracost_output_is_null_and_marks_incomplete(monkeypatch):
    monkeypatch.setattr(cost, "scan", fake_scan({"aws_instance.a": "10"}))
    monkeypatch.setattr(cost, "check_login", lambda: None)
    plan = {"format_version": "1.2",
            "resource_changes": [rc("aws_instance.a", ["create"], None, {}), rc("aws_lambda_function.b", ["create"], None, {})],
            "planned_values": values("aws_instance.a", "aws_lambda_function.b")}
    result = plan_cost(plan)
    b = by_address(result)["aws_lambda_function.b"]
    assert b["after_usd"] is None and b["delta_usd"] is None
    assert b["note"] == "Infracost did not return this resource, so it is not priced."
    assert result["complete"] is False and result["unpriced"] == ["aws_lambda_function.b"]
    assert result["monthly_after_usd"] == 10.0  # only priced resources are added


def test_no_resources_on_a_side_skips_infracost(monkeypatch):
    def boom(*_, **__):
        raise AssertionError("infracost must not be called when there is nothing to price")
    monkeypatch.setattr(cost, "scan", boom)
    monkeypatch.setattr(cost, "check_login", boom)
    result = plan_cost({"format_version": "1.2", "resource_changes": [],
                        "planned_values": {"root_module": {}}})
    assert result["monthly_delta_usd"] == 0.0 and result["complete"] is True


# --- live Infracost ------------------------------------------------------------------


@online
def test_bad_plan_delta():
    result = plan_cost_file(FIXTURES / "bad_plan.json")
    r = by_address(result)
    assert result["monthly_before_usd"] == 0.0
    assert result["monthly_after_usd"] == result["monthly_delta_usd"] == 23.832
    assert result["infracost_reported_total"] == {"before": None, "after": "23.832"}
    assert r["aws_db_instance.unencrypted"]["delta_usd"] == 15.44   # db.t3.micro 13.14 + 20 GB gp2 2.30
    assert r["aws_instance.web"]["delta_usd"] == 8.392              # t3.micro 7.592 + 8 GB root gp2 0.80
    assert r["aws_security_group.ssh_open"]["monthly_usd"] == 0.0
    assert "Free resource" in r["aws_security_group.ssh_open"]["note"]
    assert "zero usage" in r["aws_s3_bucket.public"]["note"]
    assert result["complete"] is True


@online
def test_good_plans_delta():
    created = plan_cost_file(FIXTURES / "good_plan.json")
    assert created["monthly_delta_usd"] == by_address(created)["aws_cloudwatch_metric_alarm.bucket_size"]["after_usd"] > 0
    modified = plan_cost_file(FIXTURES / "good_modified_plan.json")
    assert modified["monthly_delta_usd"] == 0.0  # tag change only
    assert modified["monthly_before_usd"] == modified["monthly_after_usd"] == created["monthly_after_usd"]
    destroyed = plan_cost_file(FIXTURES / "good_destroy_plan.json")
    assert destroyed["monthly_delta_usd"] == -created["monthly_after_usd"]
    assert destroyed["monthly_after_usd"] == 0.0


def instance(itype):
    return {"ami": "ami-1", "instance_type": itype}


@online
def test_resize_is_priced_on_both_sides():
    plan = {
        "format_version": "1.2", "terraform_version": "1.16.4",
        "resource_changes": [rc("aws_instance.web", ["update"], instance("t3.micro"), instance("t3.large"))],
        "prior_state": {"values": {"root_module": {"resources": [
            {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
             "provider_name": "registry.terraform.io/hashicorp/aws", "values": instance("t3.micro")}]}}},
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
             "provider_name": "registry.terraform.io/hashicorp/aws", "values": instance("t3.large")}]}},
    }
    r = by_address(plan_cost(plan))["aws_instance.web"]
    # 0.0104/h and 0.0832/h x 730 h, each plus Infracost's default 8 GB gp2 root disk (0.80)
    assert r["before_usd"] == 8.392 and r["after_usd"] == 61.536
    assert r["delta_usd"] == 53.144


@online
def test_unsupported_type_is_null_in_live_scan():
    plan = {
        "format_version": "1.2",
        "resource_changes": [rc("aws_iot_thing.t", ["create"], None, {"name": "t"})],
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_iot_thing.t", "mode": "managed", "type": "aws_iot_thing", "name": "t",
             "provider_name": "registry.terraform.io/hashicorp/aws", "values": {"name": "t"}}]}},
    }
    result = plan_cost(plan)
    assert by_address(result)["aws_iot_thing.t"]["monthly_usd"] is None
    assert by_address(result)["aws_iot_thing.t"]["note"] == "Infracost does not support pricing aws_iot_thing."
    assert result["complete"] is False


def test_not_logged_in_refuses_without_starting_infracost(monkeypatch, tmp_path):
    # Empty config dir = no stored login. Infracost must not even be started:
    # it would open a browser login page on the user's machine.
    for var in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(var, str(tmp_path))
    monkeypatch.setattr(cost.Path, "home", lambda: tmp_path)

    def no_process(*_, **__):
        raise AssertionError("infracost was started")
    monkeypatch.setattr(cost.subprocess, "Popen", no_process)
    with pytest.raises(InfracostAuthError) as exc:
        plan_cost_file(FIXTURES / "good_plan.json")
    assert str(exc.value) == AUTH_HELP
    assert "infracost auth login" in AUTH_HELP and "infracost doctor" in AUTH_HELP


def test_login_prompt_is_killed_immediately(monkeypatch):
    # Stand-in for infracost whose stored token stopped working: it prints the
    # login prompt and would wait a minute for a browser sign-in.
    monkeypatch.setattr(cost, "find_infracost", lambda: sys.executable)
    script = ("import time; print('Please go to the following URL to log in:', flush=True); "
              "print('https://login.example/authorize', flush=True); time.sleep(60)")
    started = time.monotonic()
    with pytest.raises(InfracostAuthError):
        cost._run_infracost(["-c", script], timeout=120)
    assert time.monotonic() - started < 10


def test_timeout_kills_the_plugin_processes_too(monkeypatch, tmp_path):
    # Stand-in for a hung `infracost scan`: it starts a plugin child that sits in the scan
    # directory (like infracost-parser-terraform), then hangs. On timeout the whole tree
    # must die, or the child keeps the directory locked on Windows.
    monkeypatch.setattr(cost, "find_infracost", lambda: sys.executable)
    work = tmp_path / "scan"
    work.mkdir()
    pid_file = tmp_path / "plugin.pid"
    script = (
        "import subprocess, sys, time; "
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'], cwd=sys.argv[1]); "
        "open(sys.argv[2], 'w').write(str(p.pid)); time.sleep(120)"
    )
    with pytest.raises(cost.CostError, match="timed out after 3s"):
        cost._run_infracost(["-c", script, str(work), str(pid_file)], cwd=str(work), timeout=3)
    plugin_pid = int(pid_file.read_text())

    deadline = time.monotonic() + 10
    while True:
        try:
            if sys.platform == "win32":
                shutil.rmtree(work)  # fails while a live process has it as its working directory
            else:
                os.kill(plugin_pid, 0)  # raises once the plugin is gone
                raise PermissionError("plugin still running")
            break
        except (PermissionError, OSError) as exc:
            if isinstance(exc, ProcessLookupError):
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"plugin process {plugin_pid} survived the timeout") from exc
            time.sleep(0.2)


def test_locked_scan_dir_does_not_hide_the_cost_error(monkeypatch):
    # A file still open in the scan directory when it is cleaned up (Windows: cannot be
    # deleted) must not turn the CostError into a PermissionError crash.
    handles = []

    def hung_scan(args, *, cwd=None, timeout=300):
        handles.append(open(Path(cwd, "plugin.lock"), "w"))
        raise cost.CostError("infracost scan timed out after 300s")

    monkeypatch.setattr(cost, "_run_infracost", hung_scan)
    try:
        with pytest.raises(cost.CostError, match="timed out"):
            cost.scan({"root_module": {}})
    finally:
        for handle in handles:
            handle.close()
