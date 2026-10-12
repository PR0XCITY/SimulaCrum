"""Risk Certificate: every analysis combined into one signed JSON document.

Field names are a contract with the dashboard (dashboard/lib/types.ts mirrors them):
  plan_id, timestamp, resource_changes[{resource, action, before, after}],
  blast_radius{newly_public, iam_widened, risk_flags[{rule, severity, resource,
  message}], graph{nodes, edges}}, shadow_run{applied, resources_created, error},
  cost_delta{monthly_usd, note}, verdict, risk_explanation, generated_by, signature_alg,
  signature

plan_id     sha256 of the canonical plan JSON (sorted keys, no whitespace), so
            the same plan always gets the same id however it was formatted.
risk_flags  OPA findings, plus flags derived from the graph diff (a resource
            newly exposed to the internet: HIGH; IAM widened to admin: CRITICAL;
            IAM document unknown until apply: HIGH; other IAM widening: MEDIUM)
            and shadow-run failures (GO-SHADOW-001, HIGH). If OPA itself fails,
            GO-ENGINE-001 (CRITICAL) blocks rather than certifying unchecked.
verdict     BLOCKED_PENDING_REVIEW if any CRITICAL/HIGH flag of the security pillar,
            or the shadow apply did not succeed (including when it could not run);
            else AUTO_APPROVED. Reliability, cost and performance flags are advisory:
            they lower their pillar score but never block, with one exception: the
            budget gate GO-BUDGET-001 (cost, HIGH) blocks when the monthly cost
            increase exceeds GHOSTOPS_MONTHLY_BUDGET_USD (default 500; "off"
            disables it). An unknown cost never triggers it.
pillars     {security|reliability|cost|performance: {score, findings[{rule, severity,
            resource, penalty}]}}: score = max(0, 100 - sum of penalties), penalty
            CRITICAL 40, HIGH 25, MEDIUM 10, LOW 5 per flag of that pillar.
            Every flag carries its pillar; graph, shadow and engine flags are security.
explanation Groq gets only sanitized structure (rule ids/titles, resource types,
            severities, verdict, whether the shadow apply worked) - never addresses,
            values, ARNs or account ids. Any Groq failure -> template, generated_by
            "template".
signature_alg  "ed25519" when GHOSTOPS_SIGNING_KEY is set (preferred), else "hmac-sha256".
            It is part of the signed body, so it cannot be swapped. Certificates from
            before this field existed have none and are HMAC-SHA256.
signature   hex over plan_id + "\\n" + canonical JSON of every field except signature:
            Ed25519 with GHOSTOPS_SIGNING_KEY (anyone can verify with the public key
            from GET /public-key, e.g. scripts/verify_certificate.py), or HMAC-SHA256
            with GHOSTOPS_HMAC_SECRET (only secret holders can verify). verify()
            accepts both; editing any field breaks it.
before/after values Terraform marks sensitive are replaced with "(sensitive)".

CLI: python -m app.certificate --plan plan.json [--tf DIR] [--no-groq]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.blast_radius import analyze as analyze_blast_radius
from app.config import hosted, setting
from app.keys import SigningKeyError, load_private_key, load_public_key
from app.cost import CostError, InfracostAuthError, plan_cost
from app.plan_parser import PlanParseError, ResourceChange, parse_plan
from app.policy_engine import PolicyEngineError, evaluate
from app.shadow import ShadowError, ShadowResult, run_shadow

AUTO_APPROVED = "AUTO_APPROVED"
BLOCKED = "BLOCKED_PENDING_REVIEW"
BLOCKING = {"CRITICAL", "HIGH"}
PILLARS = ("security", "reliability", "cost", "performance")
PENALTY = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 5}
DEFAULT_BUDGET_USD = 500.0
GATING_RULES = {"GO-BUDGET-001"}  # non-security findings that still block
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SENSITIVE = "(sensitive)"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

RULE_TITLES = {
    "GO-SG-001": "SSH or RDP open to the internet",
    "GO-IAM-001": "IAM policy grants full admin (Action * on Resource *)",
    "GO-S3-001": "S3 bucket ACL is public",
    "GO-RDS-001": "RDS storage not encrypted",
    "GO-DEL-001": "Resource deleted or replaced",
    "GO-SHADOW-001": "Shadow apply on the emulator failed",
    "GO-EXPOSE-001": "Resource newly exposed to the internet",
    "GO-IAMW-001": "IAM permissions widened",
    "GO-ENGINE-001": "Policy engine could not run",
    "GO-S3-002": "S3 bucket has no encryption configuration in code",
    "GO-REL-001": "RDS database is not Multi-AZ",
    "GO-REL-002": "RDS automated backups are off",
    "GO-REL-003": "S3 bucket has no versioning",
    "GO-REL-004": "Single EC2 instance with no load balancer",
    "GO-REL-005": "DynamoDB table has no point-in-time recovery",
    "GO-REL-006": "No CloudWatch alarm for the new resources",
    "GO-COST-001": "EC2 instance larger than its stated usage needs",
    "GO-COST-002": "gp2 storage where gp3 is cheaper",
    "GO-COST-003": "Cost-bearing resource has no tags",
    "GO-PERF-001": "Lambda function at the minimum memory",
    "GO-PERF-002": "Lambda timeout at the 15-minute maximum",
    "GO-PERF-003": "DynamoDB provisioned capacity without auto scaling",
    "GO-BUDGET-001": "Monthly cost increase is over budget",
}


class CertificateError(RuntimeError):
    """A certificate cannot be produced (e.g. no signing secret)."""


ED25519 = "ed25519"
HMAC_SHA256 = "hmac-sha256"


# --- canonical form & signature ------------------------------------------------------


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def compute_plan_id(plan: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(plan)).hexdigest()


def _secret(secret: str | None) -> bytes:
    value = secret if secret is not None else setting("GHOSTOPS_HMAC_SECRET")
    if not value or len(value) < 32:
        raise CertificateError("GHOSTOPS_HMAC_SECRET is missing or shorter than 32 characters (see .env.example)")
    return value.encode("utf-8")


def _signing_input(cert: dict[str, Any]) -> bytes:
    body = {k: v for k, v in cert.items() if k != "signature"}
    return str(cert.get("plan_id", "")).encode("utf-8") + b"\n" + canonical(body)


def _private_key(signing_key: str | Ed25519PrivateKey | None) -> Ed25519PrivateKey:
    if isinstance(signing_key, Ed25519PrivateKey):
        return signing_key
    try:
        key = load_private_key(signing_key)
    except SigningKeyError as exc:
        raise CertificateError(str(exc)) from None
    if key is None:
        raise CertificateError("GHOSTOPS_SIGNING_KEY is not set (python -m app.keys generate)")
    return key


def _public_key(public_key: str | Ed25519PublicKey | None) -> Ed25519PublicKey | None:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if public_key is not None:
        return load_public_key(public_key)
    key = load_private_key()
    return key.public_key() if key else None


def signature_alg(cert: dict[str, Any]) -> str:
    """Certificates signed before signature_alg existed are HMAC-SHA256."""
    return cert.get("signature_alg", HMAC_SHA256)


def sign(cert: dict[str, Any], *, secret: str | None = None,
         signing_key: str | Ed25519PrivateKey | None = None) -> str:
    """Sign with the algorithm the certificate names in signature_alg."""
    alg = signature_alg(cert)
    if alg == ED25519:
        return _private_key(signing_key).sign(_signing_input(cert)).hex()
    if alg == HMAC_SHA256:
        return hmac.new(_secret(secret), _signing_input(cert), hashlib.sha256).hexdigest()
    raise CertificateError(f"unknown signature_alg {alg!r}")


def verify(cert: dict[str, Any], *, secret: str | None = None, plan: dict[str, Any] | None = None,
           public_key: str | Ed25519PublicKey | None = None) -> bool:
    """True only if the signature matches the body (and, if given, the plan).

    Ed25519 certificates are checked with public_key (default: derived from
    GHOSTOPS_SIGNING_KEY); HMAC-SHA256 ones, including old ones without signature_alg,
    with secret (default: GHOSTOPS_HMAC_SECRET)."""
    signature = cert.get("signature")
    if not isinstance(signature, str):
        return False
    if plan is not None and cert.get("plan_id") != compute_plan_id(plan):
        return False
    alg = signature_alg(cert)
    try:
        if alg == ED25519:
            key = _public_key(public_key)
            if key is None:
                return False
            key.verify(bytes.fromhex(signature), _signing_input(cert))
            return True
        if alg == HMAC_SHA256:
            return hmac.compare_digest(sign(cert, secret=secret), signature)
    except (InvalidSignature, CertificateError, TypeError, ValueError):
        return False
    return False


def _signer(secret: str | None, signing_key: str | Ed25519PrivateKey | None) -> tuple[str, Any]:
    """(alg, key) to sign with: an explicit argument wins, then GHOSTOPS_SIGNING_KEY, then
    GHOSTOPS_HMAC_SECRET. Raises CertificateError if there is nothing usable."""
    if signing_key is not None or (secret is None and setting("GHOSTOPS_SIGNING_KEY")):
        return ED25519, _private_key(signing_key)
    return HMAC_SHA256, _secret(secret).decode("utf-8")


# --- sections -------------------------------------------------------------------------


def redact(value: Any, mask: Any) -> Any:
    """Replace the parts of a Terraform value that its sensitivity mask marks."""
    if mask is True:
        return SENSITIVE if value is not None else None
    if isinstance(value, dict) and isinstance(mask, dict):
        return {k: redact(v, mask.get(k, False)) for k, v in value.items()}
    if isinstance(value, list) and isinstance(mask, list):
        return [redact(v, mask[i] if i < len(mask) else False) for i, v in enumerate(value)]
    return value


def resource_changes_section(changes: list[ResourceChange]) -> list[dict[str, Any]]:
    return [
        {
            "resource": c.address,
            "action": c.action,
            "before": redact(c.before, c.before_sensitive),
            "after": redact(c.after, c.after_sensitive),
        }
        for c in changes
    ]


def flag(rule: str, severity: str, resource: str, message: str, pillar: str = "security") -> dict[str, str]:
    return {"rule": rule, "severity": severity, "resource": resource, "message": message, "pillar": pillar}


def blocks(f: dict[str, Any]) -> bool:
    """Security CRITICAL/HIGH findings block, plus the budget gate; everything else is advisory."""
    if f["rule"] in GATING_RULES:
        return True
    return f.get("pillar", "security") == "security" and f["severity"] in BLOCKING


def monthly_budget() -> float | None:
    """GHOSTOPS_MONTHLY_BUDGET_USD: max monthly cost increase before review; None = gate off."""
    raw = (setting("GHOSTOPS_MONTHLY_BUDGET_USD") or "").strip().lower()
    if raw in ("off", "none", "disabled"):
        return None
    try:
        value = float(raw) if raw else DEFAULT_BUDGET_USD
    except ValueError:
        return DEFAULT_BUDGET_USD  # a typo must not switch the gate off
    return value if value >= 0 else DEFAULT_BUDGET_USD


def budget_flags(cost: dict[str, Any], budget: float | None = None) -> list[dict[str, str]]:
    """GO-BUDGET-001 when the monthly cost increase exceeds the budget. Unknown cost: no flag."""
    limit = monthly_budget() if budget is None else budget
    delta = cost.get("monthly_usd")
    if limit is None or delta is None or delta <= limit:
        return []
    return [flag("GO-BUDGET-001", "HIGH", "(monthly cost)",
                 f"This change adds ${delta:,.2f} per month, over the ${limit:,.2f} monthly budget "
                 "(GHOSTOPS_MONTHLY_BUDGET_USD), so a human must approve the spend.", "cost")]


def pillars_section(flags: list[dict[str, Any]]) -> dict[str, Any]:
    """Score per pillar: 100 minus a fixed penalty per flag of that pillar, floored at 0."""
    out = {}
    for pillar in PILLARS:
        found = [{"rule": f["rule"], "severity": f["severity"], "resource": f["resource"],
                  "penalty": PENALTY.get(f["severity"], 0)}
                 for f in flags if f.get("pillar", "security") == pillar]
        out[pillar] = {"score": max(0, 100 - sum(x["penalty"] for x in found)), "findings": found}
    return out


def policy_flags(plan: dict[str, Any]) -> list[dict[str, str]]:
    try:
        return [flag(f.rule_id, f.severity, f.address, f.message, f.pillar) for f in evaluate(plan)]
    except PolicyEngineError as exc:
        return [flag("GO-ENGINE-001", "CRITICAL", "(policy engine)",
                     f"The OPA policy engine could not evaluate this plan ({exc}); nothing can be certified.")]


def graph_flags(blast: dict[str, Any]) -> list[dict[str, str]]:
    flags = []
    for entry in blast["newly_public"]:
        via = ", ".join(entry["via"])
        flags.append(flag("GO-EXPOSE-001", "HIGH", entry["address"],
                          f"{entry['address']} becomes reachable from the internet (0.0.0.0/0 or ::/0) via {via}."))
    for entry in blast["iam_widened"]:
        if entry["unknown"]:
            flags.append(flag("GO-IAMW-001", "HIGH", entry["address"],
                              f"{entry['address']} has an IAM policy only known after apply, so it cannot be checked."))
        elif entry["admin"]:
            flags.append(flag("GO-IAMW-001", "CRITICAL", entry["address"],
                              f"{entry['address']} widens IAM permissions to full admin (Action * on Resource *)."))
        else:
            added = len(entry["added_grants"]) + len(entry["removed_denies"])
            flags.append(flag("GO-IAMW-001", "MEDIUM", entry["address"],
                              f"{entry['address']} grants {added} new IAM permission(s) or removes deny rules."))
    return flags


def _not_run(error: str) -> dict[str, Any]:
    return {"applied": False, "resources_created": 0, "error": error, "resources": [], "inventory_error": None}


def shadow_section(tf_dir: str | Path | None, result: ShadowResult | None) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """shadow_run: applied / resources_created (Terraform state) / error, plus `resources`:
    what boto3 actually found in MiniStack before teardown ({type, id}), and inventory_error."""
    if result is None:
        if tf_dir is None:
            error = "Shadow run not performed: no Terraform directory was provided."
            return _not_run(error), [flag("GO-SHADOW-001", "HIGH", "(shadow run)", error + " The change is unverified.")]
        try:
            result = run_shadow(tf_dir)
        except ShadowError as exc:
            error = f"Shadow run could not start: {exc}"
            return _not_run(error), [flag("GO-SHADOW-001", "HIGH", "(shadow run)", error)]
    section = {"applied": result.success, "resources_created": len(result.resources), "error": result.error,
               "resources": list(result.inventory), "inventory_error": result.inventory_error}
    flags = [flag(f["rule_id"], f["severity"], f["address"], f["message"]) for f in result.findings]
    return section, flags


def cost_section(plan: dict[str, Any], result: dict[str, Any] | None = None, *, generated=None
                 ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """(cost_delta, cost_breakdown). Usage inputs of a generated architecture go to Infracost."""
    if result is None:
        try:
            if generated is not None:
                result = plan_cost(plan, usage_file=generated.usage_file(), usage_inputs=generated.usage_inputs())
            else:
                result = plan_cost(plan)
        except InfracostAuthError as exc:
            if hosted():  # no interactive login on a server: say so instead of giving login steps
                return {"monthly_usd": None, "note": "Cost not estimated: Infracost is not available on "
                        "a hosted SimulaCrum (it has only an interactive browser login)."}, []
            return {"monthly_usd": None, "note": f"Cost not estimated: {exc}"}, []
        except CostError as exc:
            return {"monthly_usd": None, "note": f"Cost not estimated: {exc}"}, []
    notes = []
    if not result["complete"]:
        notes.append(f"Not priced by Infracost (excluded from the total): {', '.join(result['unpriced'])}.")
    usage = [r["address"] for r in result["resources"] if r.get("note") and "zero usage" in r["note"]
             and not r.get("usage_assumptions")]
    if usage:
        notes.append(f"Usage-based costs priced at zero usage, so the real cost may be higher: {', '.join(usage)}.")
    breakdown = [
        {"resource": r["address"], "type": r.get("type"), "action": r.get("action"),
         "monthly_usd": r.get("monthly_usd"), "delta_usd": r.get("delta_usd"),
         "usage_assumptions": r.get("usage_assumptions") or {}, "note": r.get("note")}
        for r in result["resources"]
    ]
    return {"monthly_usd": result["monthly_delta_usd"], "note": " ".join(notes) or None}, breakdown


def architecture_section(generated) -> dict[str, Any] | None:
    """Per-service analysis mode: static_only services were left out of the shadow apply."""
    if generated is None:
        return None
    return {"services": [
        {"type": s.type, "name": s.slug, "shadow_supported": s.shadow_supported,
         "analysis": "shadow_and_static" if s.shadow_supported else "static_only",
         "config": s.config, "usage": s.usage}
        for s in generated.services
    ]}


def decide(flags: list[dict[str, str]], shadow: dict[str, Any]) -> str:
    if not shadow["applied"] or any(blocks(f) for f in flags):
        return BLOCKED
    return AUTO_APPROVED


# --- explanation ------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA)[A-Z0-9]{16}\b"),
    re.compile(r"\barn:aws[\w-]*:[^\s\"',]+"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*\S+"),
    re.compile(r"\b(?:gsk|sk|ghp|gho|xox[abp])[_-][A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b\d{12}\b"),  # AWS account id
    re.compile(r"\b(?=[A-Za-z0-9+/=-]*\d)(?=[A-Za-z0-9+/=-]*[A-Za-z])[A-Za-z0-9+/=-]{32,}\b"),  # long tokens
]
_RESOURCE_TYPE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


def sanitize_text(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def resource_type(address: str) -> str:
    """aws_s3_bucket.logs -> aws_s3_bucket; module.x.aws_y.z[0] -> aws_y. Never the name."""
    parts = [p.split("[")[0] for p in address.split(".")]
    while len(parts) >= 2 and parts[0] == "module":
        parts = parts[2:]
    candidate = parts[0] if parts else ""
    return candidate if _RESOURCE_TYPE.match(candidate) else "resource"


def explainer_facts(flags: list[dict[str, str]], shadow: dict[str, Any], verdict: str, change_count: int) -> dict[str, Any]:
    """The only data that may leave the machine for the LLM: structure, no values."""
    return {
        "verdict": verdict,
        "resource_change_count": change_count,
        "shadow_apply_succeeded": bool(shadow["applied"]),
        "findings": [
            {
                "rule": sanitize_text(f["rule"]),
                "title": RULE_TITLES.get(f["rule"], "Policy finding"),
                "severity": f["severity"] if f["severity"] in SEVERITY_ORDER else "UNKNOWN",
                "resource_type": resource_type(f["resource"]),
                "pillar": f.get("pillar", "security") if f.get("pillar", "security") in PILLARS else "security",
                "blocks_change": blocks(f),
            }
            for f in flags
        ],
    }


def _post_json(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "ghostops", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def groq_explain(facts: dict[str, Any], *, timeout: float = 30) -> str | None:
    """2-3 sentences from Groq, or None on any failure (no key, network, 429, bad output)."""
    key = setting("GROQ_API_KEY")
    if not key:
        return None
    body = {
        "model": setting("GROQ_MODEL", "openai/gpt-oss-120b"),
        "temperature": 0.2,
        "max_tokens": 600,
        "messages": [
            {"role": "system", "content": (
                "You summarize infrastructure change risk reviews for non-experts. Write exactly 2 or 3 plain "
                "English sentences. Use only the facts provided: state the verdict, the most severe findings and "
                "what they mean, and whether the emulator test apply succeeded. Only findings with blocks_change true "
                "can block (high/critical security findings and the monthly budget); the others are advisory. Do not invent resources, names, "
                "numbers or remediation steps. No markdown, no lists.")},
            {"role": "user", "content": json.dumps(facts, sort_keys=True)},
        ],
    }
    try:
        reply = _post_json(GROQ_URL, body, {"Authorization": f"Bearer {key}"}, timeout)
        text = reply["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError, TypeError):
        return None
    if not isinstance(text, str):
        return None
    text = " ".join(sanitize_text(text).split())
    return text[:800] if len(text) >= 20 else None


def template_explain(flags: list[dict[str, str]], shadow: dict[str, Any], cost: dict[str, Any],
                     verdict: str, change_count: int) -> str:
    blocking = [f for f in flags if blocks(f)]
    titles = list(dict.fromkeys(RULE_TITLES.get(f["rule"], f["rule"]) for f in blocking or flags))
    named = "; ".join(titles[:3]) + ("; and others" if len(titles) > 3 else "")
    if verdict == BLOCKED:
        counts = {s: sum(f["severity"] == s for f in blocking) for s in ("CRITICAL", "HIGH")}
        first = (f"SimulaCrum blocked this change for human review: it has {counts['CRITICAL']} critical and "
                 f"{counts['HIGH']} high-severity blocking findings ({named})." if blocking else
                 "SimulaCrum blocked this change for human review because it could not be verified.")
    else:
        warns = [f for f in flags if not blocks(f)]
        first = (f"SimulaCrum auto-approved this change of {change_count} resource(s): no critical or high-severity "
                 "security findings" + (f", only {len(warns)} advisory finding(s) ({named})." if warns else "."))
    second = (f"It applied cleanly on the MiniStack emulator ({shadow['resources_created']} resources)."
              if shadow["applied"] else
              "The test apply on the MiniStack emulator did not succeed, so the change is unverified.")
    if cost["monthly_usd"] is None:
        third = "The monthly cost change could not be estimated."
    else:
        third = f"Estimated monthly cost change: {'+' if cost['monthly_usd'] >= 0 else '-'}${abs(cost['monthly_usd']):.2f}."
    return f"{first} {second} {third}"


# --- assembly ----------------------------------------------------------------------------


def build_certificate(
    plan: dict[str, Any],
    tf_dir: str | Path | None = None,
    *,
    shadow_result: ShadowResult | None = None,
    cost_result: dict[str, Any] | None = None,
    use_groq: bool = True,
    secret: str | None = None,
    signing_key: str | Ed25519PrivateKey | None = None,
    now: datetime | None = None,
    generated=None,
) -> dict[str, Any]:
    """generated: the GeneratedTerraform when the plan came from a catalog architecture
    (adds generated_terraform, architecture, usage-based pricing, config-level remediations)."""
    from app.remediation import remediate

    changes = parse_plan(plan)  # PlanParseError for anything malformed
    alg, key = _signer(secret, signing_key)  # fail before doing slow work if we cannot sign
    blast = analyze_blast_radius(plan)
    shadow, shadow_flags = shadow_section(tf_dir, shadow_result)
    cost, cost_breakdown = cost_section(plan, cost_result, generated=generated)
    flags = policy_flags(plan) + graph_flags(blast) + shadow_flags + budget_flags(cost)
    flags.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["rule"], f["resource"], f["message"]))
    for f, remediation in zip(flags, remediate(flags, generated, use_groq=use_groq)):
        f["remediation"] = remediation
    verdict = decide(flags, shadow)

    explanation = groq_explain(explainer_facts(flags, shadow, verdict, len(changes))) if use_groq else None
    generated_by = "groq" if explanation else "template"
    if not explanation:
        explanation = template_explain(flags, shadow, cost, verdict, len(changes))

    cert = {
        "plan_id": compute_plan_id(plan),
        "timestamp": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "resource_changes": resource_changes_section(changes),
        "blast_radius": {
            "newly_public": blast["newly_public"],
            "iam_widened": blast["iam_widened"],
            "risk_flags": flags,
            "graph": blast["graph"],
        },
        "shadow_run": shadow,
        "cost_delta": cost,
        "verdict": verdict,
        "risk_explanation": explanation,
        "generated_by": generated_by,
        "cost_breakdown": cost_breakdown,
        "generated_terraform": generated.main_tf if generated is not None else None,
        "architecture": architecture_section(generated),
        "pillars": pillars_section(flags),
        "signature_alg": alg,
    }
    cert["signature"] = sign(cert, **({"signing_key": key} if alg == ED25519 else {"secret": key}))
    return cert


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.certificate")
    parser.add_argument("--plan", required=True, help="plan JSON from terraform show -json")
    parser.add_argument("--tf", help="Terraform directory for the shadow run on MiniStack")
    parser.add_argument("--no-groq", action="store_true", help="use the template explanation")
    parser.add_argument("--out", help="also write the certificate to this file")
    args = parser.parse_args(argv)
    try:
        plan = json.loads(Path(args.plan).read_bytes())
    except (OSError, ValueError) as exc:
        raise PlanParseError(f"cannot read plan: {exc}") from None
    cert = build_certificate(plan, args.tf, use_groq=not args.no_groq)
    text = json.dumps(cert, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if cert["verdict"] == AUTO_APPROVED else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
