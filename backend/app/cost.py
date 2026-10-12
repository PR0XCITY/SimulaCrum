"""Monthly cost delta of a Terraform plan, priced by Infracost (v2 CLI).

Infracost v2 replaced `breakdown`/`diff` with `scan`; `diff` no longer exists.
`infracost scan <plan.json>` prices a plan's `planned_values` (the after state),
so the delta is built from two scans:
  after   the plan as-is
  before  the plan's `prior_state.values` placed in `planned_values`
A side with no resources (nothing exists yet / everything is destroyed) costs
$0 without calling Infracost. Every other number comes from Infracost.

Per resource: before_usd, after_usd, delta_usd, plus a note when relevant:
  - free resource types cost 0 ("free resource");
  - unsupported types, or resources Infracost did not return, are null with why;
  - usage-based components (storage, requests) that Infracost priced at zero
    usage are listed: the real cost depends on usage, so $0 is a lower bound.
Totals add only priced resources; `complete` is false and `unpriced` names the
resources when anything could not be priced.

Infracost v2 has no API key: it uses `infracost auth login`. If that is
missing, InfracostAuthError explains exactly what to run. Note that a scan
sends the planned resource attributes to Infracost's pricing service.

CLI: python -m app.cost <plan.json>   (prints the result as JSON)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from app.plan_parser import PlanParseError, parse_plan
from app.tools import find_tool

AUTH_HELP = (
    "Infracost is not logged in, so costs cannot be priced. Infracost v2 has no API key "
    "(INFRACOST_API_KEY is not used). In a terminal run:\n"
    "  infracost auth login\n"
    "finish the browser sign-in (free account), then check it with:\n"
    "  infracost doctor\n"
    "All Authentication checks should pass. Then retry."
)
LOGIN_PROMPT = b"please go to the following url to log in"
_ZERO = Decimal("0")


class CostError(RuntimeError):
    """Infracost could not produce a trustworthy price."""


class InfracostAuthError(CostError):
    """Infracost is installed but not logged in."""


def find_infracost() -> str:
    found = find_tool("infracost", "GHOSTOPS_INFRACOST_BIN")
    if not found:
        raise CostError("infracost not found. Install it from https://www.infracost.io/docs/ "
                        "or set GHOSTOPS_INFRACOST_BIN to its full path.")
    return found


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill infracost and the plugin processes it started (infracost-parser-*,
    infracost-provider-*). Killing only the parent leaves the plugins running, holding
    the scan's temp directory and the output pipes."""
    if sys.platform == "win32":
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        import signal

        try:
            os.killpg(proc.pid, signal.SIGKILL)  # started with start_new_session=True
        except OSError:
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def _run_infracost(args: list[str], *, cwd: str | None = None, timeout: float = 300) -> tuple[int, str, str]:
    """Run infracost non-interactively; (exit code, stdout, stderr).

    Without a stored login, infracost may start an interactive browser login and
    wait for it. GhostOps must never do that, so BROWSER=none stops a browser
    from opening, and the process is killed as soon as it prints the login
    prompt; that becomes InfracostAuthError with the steps the user must take.
    """
    env = dict(os.environ, BROWSER="none", NO_COLOR="1")
    proc = subprocess.Popen([find_infracost(), *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=sys.platform != "win32")
    out: list[bytes] = []
    err: list[bytes] = []
    prompted = threading.Event()

    def pump(stream, sink: list[bytes]) -> None:
        for line in iter(stream.readline, b""):
            sink.append(line)
            if LOGIN_PROMPT in line.lower():
                prompted.set()

    readers = [threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, err), daemon=True)]
    for r in readers:
        r.start()
    deadline = time.monotonic() + timeout
    while proc.poll() is None and not prompted.is_set() and time.monotonic() < deadline:
        time.sleep(0.05)
    if proc.poll() is None:
        _kill_tree(proc)
        for r in readers:
            r.join(timeout=5)
        if prompted.is_set():
            raise InfracostAuthError(AUTH_HELP)
        raise CostError(f"infracost {args[0]} timed out after {timeout}s")
    for r in readers:
        r.join(timeout=5)
    stdout = b"".join(out).decode("utf-8", errors="replace")
    stderr = b"".join(err).decode("utf-8", errors="replace")
    if prompted.is_set() or "not logged in" in f"{stdout}{stderr}".lower():
        raise InfracostAuthError(AUTH_HELP)
    return proc.returncode, stdout, stderr


def infracost_config_dir() -> Path:
    """Where infracost keeps its login (Go's os.UserConfigDir()/infracost)."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "infracost"


def has_stored_login() -> bool:
    return (infracost_config_dir() / "token.json").is_file()


def check_login(timeout: float = 60) -> None:
    """Fail fast if Infracost is not logged in, before any scan.

    No stored login: refuse without starting infracost at all, because infracost
    would open a browser login page. Stored login: confirm with `auth whoami`
    (refreshes the token if needed; the login-prompt kill in _run_infracost
    covers a refresh that fails).
    """
    if not has_stored_login():
        raise InfracostAuthError(AUTH_HELP)
    code, stdout, stderr = _run_infracost(["auth", "whoami"], timeout=timeout)
    if code != 0:
        raise CostError(f"infracost auth whoami failed (exit {code}): {(stderr + stdout).strip()[-400:]}")


def _decimal(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def to_yaml(data: dict[str, Any], indent: int = 0) -> str:
    """Minimal YAML for nested dicts of numbers/strings (Infracost usage + config files)."""
    lines = []
    for key, value in data.items():
        if not re.fullmatch(r"[A-Za-z0-9_.\[\]\-]+", str(key)):
            raise CostError(f"unsupported YAML key {key!r}")
        if isinstance(value, dict):
            lines.append(f"{' ' * indent}{key}:")
            lines.append(to_yaml(value, indent + 2))
        elif isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise CostError(f"unsupported YAML value for {key}: {value!r}")
        else:
            lines.append(f"{' ' * indent}{key}: {json.dumps(value)}")
    return "\n".join(lines)


def scan(planned_values: dict[str, Any], *, terraform_version: str = "1.0.0", timeout: float = 300,
         usage_file: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Run `infracost scan` on a plan document containing `planned_values`.

    usage_file: {resource address: usage keys} for usage-priced resources. Infracost v2
    has no --usage-file flag; it reads the usage file named in an infracost.yml project
    config next to the plan (verified: a bare infracost-usage.yml is ignored).
    """
    doc = {"format_version": "1.2", "terraform_version": terraform_version, "planned_values": planned_values}
    args = ["scan", "plan.json", "--json", "--no-color", "--currency", "USD"]
    if os.environ.get("INFRACOST_ORG"):
        args += ["--org", os.environ["INFRACOST_ORG"]]
    # ignore_cleanup_errors: a file still locked on Windows must not replace the real
    # result (or the CostError) with a PermissionError from the cleanup.
    with tempfile.TemporaryDirectory(prefix="ghostops-cost-", ignore_cleanup_errors=True) as tmp:
        Path(tmp, "plan.json").write_text(json.dumps(doc), encoding="utf-8")
        if usage_file:
            Path(tmp, "usage.yml").write_text(
                to_yaml({"version": "0.1", "resource_usage": usage_file}) + "\n", encoding="utf-8")
            Path(tmp, "infracost.yml").write_text(
                'version: 0.1\nprojects:\n  - path: plan.json\n    usage_file: usage.yml\n', encoding="utf-8")
        code, stdout, stderr = _run_infracost(args, cwd=tmp, timeout=timeout)
    if code != 0:
        raise CostError(f"infracost scan failed (exit {code}): {(stderr + stdout).strip()[-800:]}")
    try:
        result = json.loads(stdout)
        result["projects"]
    except (ValueError, KeyError, TypeError):
        raise CostError(f"infracost returned unexpected output: {stdout.strip()[:300]!r}") from None
    if result.get("currency") != "USD":
        raise CostError(f"infracost priced in {result.get('currency')!r}, expected USD")
    return result


def _walk_components(resource: dict[str, Any]) -> list[dict[str, Any]]:
    comps = list(resource.get("cost_components") or [])
    for sub in resource.get("subresources") or []:
        comps += _walk_components(sub)
    return comps


def price_resource(resource: dict[str, Any], usage_given: bool = False) -> tuple[Decimal | None, str | None]:
    """(monthly USD or None, note) for one resource from Infracost output."""
    rtype = resource.get("type", "resource")
    if resource.get("is_free"):
        return _ZERO, "Free resource: Infracost reports no charge for this type."
    if resource.get("is_supported") is False:
        return None, f"Infracost does not support pricing {rtype}."
    comps = _walk_components(resource)
    totals = [_decimal(c.get("total_monthly_cost")) for c in comps]
    known = [t for t in totals if t is not None]
    if not known:
        return None, f"Infracost returned no priced cost components for this {rtype}."

    notes = []
    unpriced = [c.get("name", "?") for c, t in zip(comps, totals) if t is None]
    if unpriced:
        notes.append(f"Not priced by Infracost (excluded): {', '.join(unpriced)}.")
    zero_usage = [
        c.get("name", "?") for c in comps
        if _decimal(c.get("quantity")) in (None, _ZERO) and (_decimal(c.get("price")) or _ZERO) > _ZERO
    ]
    if zero_usage:
        names = list(dict.fromkeys(zero_usage))
        examples = "; ".join(names[:3]) + ("; ..." if len(names) > 3 else "")
        if usage_given:
            notes.append(f"Priced with the usage assumptions given; {len(zero_usage)} component(s) without an "
                         f"assumption are priced at zero usage ({examples}).")
        else:
            notes.append(f"{len(zero_usage)} usage-based cost components priced at zero usage ({examples}); "
                         "the real cost depends on usage, so this is a lower bound.")
    return sum(known, _ZERO), " ".join(notes) or None


def _prices(scan_result: dict[str, Any] | None,
            usage_addresses: set[str] = frozenset()) -> tuple[dict[str, tuple[Decimal | None, str | None]], str | None]:
    if scan_result is None:
        return {}, None
    prices = {}
    for project in scan_result["projects"]:
        for res in project.get("resources") or []:
            prices[res["name"]] = price_resource(res, usage_given=res["name"] in usage_addresses)
    return prices, scan_result.get("summary", {}).get("total_monthly_cost")


def _has_resources(values: dict[str, Any] | None) -> bool:
    if not values:
        return False

    def visit(module: dict[str, Any]) -> bool:
        if any(r.get("mode", "managed") == "managed" for r in module.get("resources") or []):
            return True
        return any(visit(child) for child in module.get("child_modules") or [])

    return visit(values.get("root_module") or {})


def _usd(value: Decimal | None) -> float | None:
    return None if value is None else float(value.quantize(Decimal("0.0001")))


def plan_cost(plan: dict[str, Any], *, usage_file: dict[str, dict[str, Any]] | None = None,
              usage_inputs: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Cost delta of a plan. usage_file goes to Infracost (both sides, same assumptions);
    usage_inputs (flat, human-readable) is echoed per resource as usage_assumptions."""
    changes = parse_plan(plan)
    usage_inputs = usage_inputs or {}
    usage_addresses = set(usage_file or {})
    tf_version = str(plan.get("terraform_version", "1.0.0"))
    before_values = (plan.get("prior_state") or {}).get("values")
    after_values = plan.get("planned_values")
    if _has_resources(before_values) or _has_resources(after_values):
        check_login()

    before_prices, before_reported = _prices(
        scan(before_values, terraform_version=tf_version, usage_file=usage_file)
        if _has_resources(before_values) else None, usage_addresses)
    after_prices, after_reported = _prices(
        scan(after_values, terraform_version=tf_version, usage_file=usage_file)
        if _has_resources(after_values) else None, usage_addresses)

    def side(exists: bool, prices: dict, address: str) -> tuple[Decimal | None, str | None]:
        if not exists:
            return _ZERO, None  # the resource does not exist on this side: genuinely $0
        if address not in prices:
            return None, "Infracost did not return this resource, so it is not priced."
        return prices[address]

    resources, unpriced = [], []
    before_total = after_total = _ZERO
    for c in changes:
        before, before_note = side(c.before is not None, before_prices, c.address)
        after, after_note = side(c.after is not None, after_prices, c.address)
        note = after_note if c.after is not None else before_note
        if before is None or after is None:
            unpriced.append(c.address)
        before_total += before or _ZERO
        after_total += after or _ZERO
        resources.append({
            "address": c.address,
            "type": c.type,
            "action": c.action,
            "before_usd": _usd(before),
            "after_usd": _usd(after),
            "delta_usd": _usd(after - before) if before is not None and after is not None else None,
            "monthly_usd": _usd(after),
            "usage_assumptions": dict(usage_inputs.get(re.sub(r"\[[^\]]*\]", "", c.address), {})),
            "note": note,
        })

    return {
        "currency": "USD",
        "monthly_before_usd": _usd(before_total),
        "monthly_after_usd": _usd(after_total),
        "monthly_delta_usd": _usd(after_total - before_total),
        "complete": not unpriced,
        "unpriced": unpriced,
        "infracost_reported_total": {"before": before_reported, "after": after_reported},
        "resources": resources,
    }


def plan_cost_file(path: str | Path) -> dict[str, Any]:
    try:
        plan = json.loads(Path(path).read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanParseError(f"invalid JSON: {exc}") from None
    return plan_cost(plan)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m app.cost <plan.json>", file=sys.stderr)
        sys.exit(2)
    try:
        print(json.dumps(plan_cost_file(sys.argv[1]), indent=2))
    except InfracostAuthError as exc:
        print(exc, file=sys.stderr)
        sys.exit(3)
