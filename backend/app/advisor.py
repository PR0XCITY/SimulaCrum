"""Trusted Advisor for the Architecture Builder: which changes make a design better or cheaper.

    advise({"services": [...]}) -> {"baseline": ..., "recommendations": [...], "combined": ...}

Every number is measured, never estimated by hand or by an LLM:

1. Candidates come from fixed rules: the fix of every current finding (app/remediation.py,
   grouped when several findings share one fix) and one-size-smaller options for EC2 and
   RDS, plus on-demand billing for provisioned DynamoDB tables.
2. Each candidate is applied to a copy of the design, Terraform is generated and planned
   (the same `terraform plan` as the static check), and the plan is re-scored with the same
   OPA rules, graph diff and pillar formula.
3. The baseline and every candidate are priced in ONE Infracost scan (each plan wrapped as
   its own module), so all prices share the same price list and usage assumptions.

A recommendation shows what it fixes, the measured pillar and cost change, and any
trade-off (higher cost, more penalty points, a new finding). Changes that measure no
improvement are left out. "combined" is every trade-off-free recommendation applied
together, measured as one more design. Without Infracost, costs are null and cost-only
suggestions are skipped.
"""

from __future__ import annotations

import copy
import json
import logging
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

log = logging.getLogger("ghostops.advisor")
MAX_CANDIDATES = 12
PLAN_WORKERS = 4

# One size smaller. Only within reason: no suggestion below t3.micro / db.t3.micro.
SMALLER_EC2 = {"t3.small": "t3.micro", "t3.medium": "t3.small", "t3.large": "t3.medium",
               "m5.large": "t3.large", "m5.xlarge": "m5.large", "c5.large": "t3.medium"}
SMALLER_RDS = {"db.t3.small": "db.t3.micro", "db.t3.medium": "db.t3.small", "db.m5.large": "db.t3.medium"}
EC2_DOWNSIZE_MAX_CPU = 50  # stated expected CPU above this: a smaller size would be overloaded


# --- candidates ----------------------------------------------------------------------


def fix_candidates(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One candidate per distinct fix of the current findings (flags carry their remediation)."""
    grouped: dict[str, dict[str, Any]] = {}
    for f in flags:
        changes = (f.get("remediation") or {}).get("config_change") or []
        if not changes or any("service" not in c for c in changes):
            continue
        key = json.dumps(sorted((c["service"], c["field"], json.dumps(c["to"])) for c in changes))
        entry = grouped.setdefault(key, {"kind": "fix", "changes": changes, "rules": [],
                                         "summary": f["remediation"]["summary"], "worst": f["severity"]})
        if f["rule"] not in entry["rules"]:
            entry["rules"].append(f["rule"])
    return list(grouped.values())


def saving_candidates(services: list[Any]) -> list[dict[str, Any]]:
    """Cheaper options, from the generator's services (config with every default filled in)."""
    out = []
    for service in services:
        config, t, name = service.config, service.type, service.slug

        def change(field: str, to: Any) -> dict[str, Any]:
            return {"service": name, "type": t, "field": field, "from": config[field], "to": to}

        if t == "ec2" and config["instance_type"] in SMALLER_EC2 and config["expected_cpu_percent"] <= EC2_DOWNSIZE_MAX_CPU:
            to = SMALLER_EC2[config["instance_type"]]
            out.append({"kind": "save", "changes": [change("instance_type", to)], "rules": [], "summary": (
                f"Use {to} for {name} instead of {config['instance_type']}: less CPU and memory, which fits a stated "
                f"expected CPU of {config['expected_cpu_percent']}%. Check real usage before switching.")})
        if t == "rds" and config["instance_class"] in SMALLER_RDS:
            to = SMALLER_RDS[config["instance_class"]]
            out.append({"kind": "save", "changes": [change("instance_class", to)], "rules": [], "summary": (
                f"Use {to} for database {name} instead of {config['instance_class']}, if its load allows: "
                "watch CPU and memory after the change.")})
        if t == "dynamodb" and config["billing_mode"] == "PROVISIONED":
            out.append({"kind": "save", "changes": [change("billing_mode", "PAY_PER_REQUEST")], "rules": [],
                        "summary": f"Bill table {name} on demand (PAY_PER_REQUEST): you pay per request instead of "
                                   "for reserved capacity that may sit idle."})
    return out


def apply_changes(architecture: dict[str, Any], slugs: list[str], changes: list[dict[str, Any]]) -> dict[str, Any]:
    """A copy of the design with the changes made. slugs[i] is the generator's name of
    services[i] (a blank name becomes e.g. "ec2-1"), which is what changes refer to."""
    out = copy.deepcopy(architecture)
    for c in changes:
        i = slugs.index(c["service"])
        out["services"][i]["config"] = {**(out["services"][i].get("config") or {}), c["field"]: c["to"]}
    return out


def _change_key(changes: list[dict[str, Any]]) -> str:
    return json.dumps(sorted((c["service"], c["field"], json.dumps(c["to"])) for c in changes))


# --- measuring -----------------------------------------------------------------------


def plan_flags(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """The static check's findings for a plan (OPA rules + graph diff), before the budget gate."""
    from app.blast_radius import analyze as analyze_blast_radius
    from app.certificate import graph_flags, policy_flags

    return policy_flags(plan) + graph_flags(analyze_blast_radius(plan))


def score(plan: dict[str, Any], monthly_usd: float | None) -> dict[str, Any]:
    """Findings, pillar scores and verdict of one plan, exactly as the static check scores it."""
    from app.certificate import blocks, budget_flags, pillars_section

    flags = plan_flags(plan) + budget_flags({"monthly_usd": monthly_usd})
    pillars = pillars_section(flags)
    return {
        "verdict": "BLOCKED_PENDING_REVIEW" if any(blocks(f) for f in flags) else "AUTO_APPROVED",
        "pillars": {name: p["score"] for name, p in pillars.items()},
        # 100 minus penalties without the floor at 0, so fixing one of many findings still shows
        "penalty_points": {name: sum(f["penalty"] for f in p["findings"]) for name, p in pillars.items()},
        "blocking": sum(1 for f in flags if blocks(f)),
        "findings": sorted({(f["rule"], f["resource"]) for f in flags}),
        "monthly_usd": monthly_usd,
    }


def _prefixed(module: dict[str, Any], prefix: str) -> dict[str, Any]:
    module = copy.deepcopy(module)
    for resource in module.get("resources") or []:
        resource["address"] = f"{prefix}.{resource['address']}"
    module["child_modules"] = [_prefixed(child, prefix) for child in module.get("child_modules") or []]
    module["address"] = prefix
    return module


def price_all(plans: list[dict[str, Any]], usage_files: list[dict[str, Any]]) -> tuple[list[float | None], str | None]:
    """Monthly USD of each plan from one Infracost scan (None where any resource is unpriced)."""
    from app.cost import CostError, _ZERO, _usd, check_login, price_resource, scan

    children, usage = [], {}
    for i, (plan, usage_file) in enumerate(zip(plans, usage_files)):
        prefix = f"module.c{i}"
        children.append(_prefixed((plan.get("planned_values") or {}).get("root_module") or {}, prefix))
        usage.update({f"{prefix}.{address}": value for address, value in usage_file.items()})
    try:
        check_login()
        result = scan({"root_module": {"resources": [], "child_modules": children}},
                      terraform_version=str(plans[0].get("terraform_version", "1.0.0")), usage_file=usage or None)
    except CostError as exc:  # includes InfracostAuthError: no login, no prices, no browser
        return [None] * len(plans), f"Cost not estimated: {exc}"
    totals: list[Any] = [_ZERO] * len(plans)
    for project in result["projects"]:
        for resource in project.get("resources") or []:
            head = resource["name"].split(".", 2)
            if len(head) < 3 or head[0] != "module" or not head[1].startswith("c"):
                continue
            i = int(head[1][1:])
            price, _ = price_resource(resource, usage_given=resource["name"] in usage)
            totals[i] = None if price is None or totals[i] is None else totals[i] + price
    return [_usd(t) for t in totals], None


# --- the advisor ---------------------------------------------------------------------


def _impact(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    pillars = {name: after["pillars"][name] - before["pillars"][name] for name in before["pillars"]}
    points = {name: before["penalty_points"][name] - after["penalty_points"][name] for name in before["pillars"]}
    cost = (None if before["monthly_usd"] is None or after["monthly_usd"] is None
            else round(after["monthly_usd"] - before["monthly_usd"], 2))
    new = sorted({rule for rule, _ in set(after["findings"]) - set(before["findings"])})
    fixed = sorted({rule for rule, _ in set(before["findings"]) - set(after["findings"])})
    return {"verdict_after": after["verdict"], "unblocks": before["verdict"] != after["verdict"] == "AUTO_APPROVED",
            "blocking_removed": before["blocking"] - after["blocking"], "pillars": pillars,
            "points_removed": points, "pillars_after": after["pillars"], "cost_usd": cost,
            "monthly_after_usd": after["monthly_usd"], "fixed_rules": fixed, "new_rules": new,
            "tradeoffs": [f"{name}: {-delta:+d} penalty points" for name, delta in points.items() if delta < 0]
                         + ([f"{after['blocking'] - before['blocking']:+d} blocking finding(s)"]
                            if after["blocking"] > before["blocking"] else [])
                         + ([f"+${cost:,.2f}/month"] if cost is not None and cost > 0 else [])
                         + [f"new finding {rule}" for rule in new]}


def _useful(candidate: dict[str, Any], impact: dict[str, Any]) -> bool:
    gain = sum(d for d in impact["points_removed"].values() if d > 0)
    saves = impact["cost_usd"] is not None and impact["cost_usd"] < -0.005
    if candidate["kind"] == "save":
        return saves
    return gain > 0 or impact["blocking_removed"] > 0 or saves


def _rank(rec: dict[str, Any]) -> tuple:
    i = rec["impact"]
    return (not i["unblocks"], -i["blocking_removed"], len(i["tradeoffs"]) > 0,
            -sum(d for d in i["points_removed"].values() if d > 0), i["cost_usd"] if i["cost_usd"] is not None else 0)


def _title(changes: list[dict[str, Any]]) -> str:
    def value(v: Any) -> str:
        return ", ".join(map(str, v)) if isinstance(v, list) else str(v).lower() if isinstance(v, bool) else str(v)
    return "; ".join(f"{c['service']}: {c['field']} {value(c['from'])} -> {value(c['to'])}" for c in changes)


def advise(
    architecture: dict[str, Any],
    *,
    planner: Callable[[str], dict[str, Any]] | None = None,
    pricer: Callable[..., tuple[list[float | None], str | None]] = price_all,
) -> dict[str, Any]:
    from app.generator import generate
    from app.remediation import remediate
    from app.shadow import ShadowError, plan_json

    planner = planner or plan_json
    started = time.monotonic()
    base = generate(architecture)  # ArchitectureError on invalid input

    def plan_of(g) -> dict[str, Any] | None:
        with tempfile.TemporaryDirectory(prefix="ghostops-advise-") as tmp:
            g.write(tmp)
            try:
                return planner(tmp)
            except ShadowError as exc:
                log.warning("advisor could not plan a candidate: %s", exc)
                return None

    baseline_plan = plan_of(base)  # first, alone: fills the provider cache for the parallel plans
    if baseline_plan is None:
        raise ShadowError("could not plan the current design")
    flags = plan_flags(baseline_plan)
    for f, remediation in zip(flags, remediate(flags, base, use_groq=False)):
        f["remediation"] = remediation

    candidates, seen = [], set()
    for c in fix_candidates(flags) + saving_candidates(base.services):
        key = _change_key(c["changes"])
        if key not in seen:
            seen.add(key)
            candidates.append(c)
    candidates = candidates[:MAX_CANDIDATES]
    slugs = [s.slug for s in base.services]
    generated = [base] + [generate(apply_changes(architecture, slugs, c["changes"])) for c in candidates]
    with ThreadPoolExecutor(max_workers=PLAN_WORKERS, thread_name_prefix="advise-plan") as pool:
        plans = [baseline_plan] + list(pool.map(plan_of, generated[1:]))

    planned = [i for i, p in enumerate(plans) if p is not None]
    prices, cost_note = pricer([plans[i] for i in planned], [generated[i].usage_file() for i in planned])
    price_of = dict(zip(planned, prices))
    scores = {i: score(plans[i], price_of[i]) for i in planned}
    baseline = scores[0]

    recommendations, skipped = [], 0
    for i, candidate in enumerate(candidates, start=1):
        if i not in scores:
            skipped += 1
            continue
        impact = _impact(baseline, scores[i])
        if not _useful(candidate, impact):
            continue
        recommendations.append({"id": f"r{i}", "kind": candidate["kind"], "title": _title(candidate["changes"]),
                                "summary": candidate["summary"], "changes": candidate["changes"],
                                "rules": candidate["rules"], "impact": impact})
    recommendations.sort(key=_rank)

    # Round 2: everything without a trade-off, applied together, measured as one more design.
    combined = None
    clean = [r for r in recommendations if not r["impact"]["tradeoffs"]]
    if len(clean) > 1:
        changes = [c for r in clean for c in r["changes"]]
        design = generate(apply_changes(architecture, slugs, changes))
        plan = plan_of(design)
        if plan is not None:
            (_, price), _ = pricer([baseline_plan, plan], [base.usage_file(), design.usage_file()])
            combined = {"ids": [r["id"] for r in clean], "changes": changes,
                        "impact": _impact(baseline, score(plan, price))}
    elif len(clean) == 1:
        combined = {"ids": [clean[0]["id"]], "changes": clean[0]["changes"], "impact": clean[0]["impact"]}
    return {
        "baseline": baseline,
        "recommendations": recommendations,
        "combined": combined,
        "cost_note": cost_note,
        "candidates_measured": len(planned) - 1,
        "candidates_failed": skipped,
        "duration_s": round(time.monotonic() - started, 1),
    }
