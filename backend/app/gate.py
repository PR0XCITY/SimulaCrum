"""GhostOps as an enforced gate: for CI jobs, AI agents and a pre-apply wrapper.

  python -m app.gate ci --tf DIR [--summary FILE] [--github-output FILE] [--out-dir DIR]
                        [--no-groq] [--expect VERDICT]
      Plan DIR against MiniStack (scrubbed env, forced endpoints), write the plan JSON,
      run `ghostops analyze` on it and write a Markdown job summary.
      Exit: the CLI's code (0 AUTO_APPROVED, 1 BLOCKED_PENDING_REVIEW, 2 error), or with
      --expect, 0 only if the verdict is the expected one (self-tests of demo/bad).

  python -m app.gate prepare-apply --tf DIR
      Safety checks for scripts/safe-apply.ps1 (DIR inside this repo's demo/, MiniStack on
      loopback) and write the MiniStack override file into DIR. Exit 0 or 2.

  python -m app.gate decide --plan PLAN.json --tf DIR [--no-groq]
      Get the certificate for exactly this plan (reuse a stored one, so a reviewer's
      decision still applies; otherwise analyse it), then decide whether it may be applied.
      Exit: 0 apply allowed, 1 refused, 2 error.

Apply is allowed only for a signature-valid certificate of this exact plan that is
AUTO_APPROVED, or BLOCKED_PENDING_REVIEW whose latest decision on this certificate
version (same signature) is "approve". GhostOps itself never applies anything.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from app.certificate import blocks, compute_plan_id

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = REPO_ROOT / "demo"
APPROVED, BLOCKED = "AUTO_APPROVED", "BLOCKED_PENDING_REVIEW"
EXIT_ALLOW, EXIT_REFUSE, EXIT_ERROR = 0, 1, 2
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_API_URL = "http://127.0.0.1:8000"
DASHBOARD_URL = "http://localhost:3000"


class GateError(RuntimeError):
    """The gate could not reach a decision (fail closed: nothing may be applied)."""


# --- what a certificate says ---------------------------------------------------------


def blocking_findings(cert: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {k: f.get(k) for k in ("rule", "severity", "resource", "message")}
        for f in cert["blast_radius"]["risk_flags"] if blocks(f)
    ]


def pillar_scores(cert: dict[str, Any]) -> dict[str, int] | None:
    pillars = cert.get("pillars")
    return {name: p["score"] for name, p in pillars.items()} if pillars else None


def latest_decision(cert: dict[str, Any], decisions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Latest decision on this version of the certificate. A decision recorded on an earlier
    analysis of the same plan (a different signature) does not count."""
    current = [d for d in decisions if d.get("certificate_signature") == cert.get("signature")]
    return max(current, key=lambda d: d["id"]) if current else None


def apply_decision(cert: dict[str, Any], decisions: list[dict[str, Any]], signature_valid: bool,
                   plan: dict[str, Any] | None = None) -> tuple[bool, str]:
    """(allowed, reason). Everything that is not clearly allowed is refused."""
    if not signature_valid:
        return False, "certificate signature is INVALID; refusing"
    if plan is not None and cert.get("plan_id") != compute_plan_id(plan):
        return False, "certificate is for a different plan; refusing"
    if cert.get("verdict") == APPROVED:
        return True, "AUTO_APPROVED by policy"
    if cert.get("verdict") != BLOCKED:
        return False, f"unknown verdict {cert.get('verdict')!r}; refusing"
    decision = latest_decision(cert, decisions)
    if decision is None:
        return False, "BLOCKED_PENDING_REVIEW and no reviewer has approved it"
    if decision["decision"] == "approve":
        return True, f"BLOCKED_PENDING_REVIEW, approved by {decision['reviewer']} at {decision['decided_at']}"
    return False, f"BLOCKED_PENDING_REVIEW, denied by {decision['reviewer']} at {decision['decided_at']}"


def summarize(cert: dict[str, Any], decisions: list[dict[str, Any]], signature_valid: bool,
              plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """The short answer an agent or a script needs (the full certificate stays in GhostOps)."""
    allowed, reason = apply_decision(cert, decisions, signature_valid, plan)
    decision = latest_decision(cert, decisions)
    cost = cert["cost_delta"]
    return {
        "certificate_id": cert["plan_id"],
        "plan_id": cert["plan_id"],
        "verdict": cert["verdict"],
        "signature_valid": signature_valid,
        "apply_allowed": allowed,
        "reason": reason,
        "blocking_findings": blocking_findings(cert),
        "advisory_findings": len(cert["blast_radius"]["risk_flags"]) - len(blocking_findings(cert)),
        "pillar_scores": pillar_scores(cert),
        "cost_delta_monthly_usd": cost["monthly_usd"],
        "cost_note": cost.get("note"),
        "shadow_applied": cert["shadow_run"]["applied"],
        "review": {k: decision[k] for k in ("decision", "reviewer", "decided_at")} if decision else None,
        "dashboard_url": f"{DASHBOARD_URL}/certificates/{cert['plan_id']}",
    }


# --- where certificates come from: the local API, or the pipeline in-process ----------


class ApiClient:
    """The local GhostOps API (python -m app.server)."""

    def __init__(self, base_url: str, timeout: float = 1800):
        self.base_url, self.timeout = base_url.rstrip("/"), timeout

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise GateError(f"GhostOps API {method} {path} failed ({exc.code}): {detail}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise GateError(f"GhostOps API not reachable at {self.base_url}: {exc}") from None

    def healthy(self) -> bool:
        try:
            return (self._request("GET", "/health") or {}).get("status") == "ok"
        except GateError:
            return False

    def get_certificate(self, plan_id: str) -> dict[str, Any] | None:
        return self._request("GET", f"/certificates/{plan_id}")

    def decisions(self, plan_id: str) -> list[dict[str, Any]]:
        return self._request("GET", f"/certificates/{plan_id}/decisions") or []

    def signature_valid(self, plan_id: str) -> bool:
        return bool((self._request("GET", f"/verify/{plan_id}") or {}).get("valid"))

    def analyze(self, plan_path: str, tf_dir: str | None, use_groq: bool) -> dict[str, Any]:
        cert = self._request("POST", "/analyze", {"plan_path": plan_path, "tf_dir": tf_dir, "use_groq": use_groq})
        if cert is None:
            raise GateError("GhostOps API returned 404 for /analyze")
        return cert


class LocalClient:
    """The same pipeline and database, in this process (when the API is not running)."""

    def __init__(self, store: Any = None):
        from app.store import open_store  # SQLite, or Postgres with GHOSTOPS_DATABASE_URL

        self.store = store or open_store()

    def get_certificate(self, plan_id: str) -> dict[str, Any] | None:
        return self.store.get_certificate(plan_id)

    def decisions(self, plan_id: str) -> list[dict[str, Any]]:
        return self.store.decisions(plan_id)

    def signature_valid(self, plan_id: str) -> bool:
        from app.certificate import verify

        cert = self.store.get_certificate(plan_id)
        return cert is not None and verify(cert)

    def analyze(self, plan_path: str, tf_dir: str | None, use_groq: bool) -> dict[str, Any]:
        from app.certificate import build_certificate

        cert = build_certificate(load_plan(plan_path), tf_dir, use_groq=use_groq)
        self.store.save_certificate(cert)
        return cert


def default_client() -> ApiClient | LocalClient:
    """GHOSTOPS_API_URL (default http://127.0.0.1:8000) if it answers, else in-process."""
    from app.config import check_required, setting

    api = ApiClient(setting("GHOSTOPS_API_URL") or DEFAULT_API_URL)
    if api.healthy():
        return api
    check_required()  # in-process signing needs the secret
    return LocalClient()


def load_plan(path: str | Path) -> dict[str, Any]:
    try:
        plan = json.loads(Path(path).read_bytes())  # bytes: a UTF-8 BOM is accepted
    except OSError as exc:
        raise GateError(f"cannot read plan {path}: {exc}") from None
    except ValueError as exc:
        raise GateError(f"plan {path} is not valid JSON: {exc}") from None
    if not isinstance(plan, dict):
        raise GateError(f"plan {path} is not a terraform show -json object")
    return plan


def check_plan(client: Any, plan_path: str | Path, tf_dir: str | Path | None, *, use_groq: bool = True) -> dict[str, Any]:
    """Certificate summary for exactly this plan. A stored certificate for the same plan id is
    reused, not re-analysed: re-analysis would sign a new version and orphan its review."""
    plan_path = Path(plan_path).resolve()
    plan = load_plan(plan_path)
    if tf_dir is not None and not Path(tf_dir).is_dir():
        raise GateError(f"tf_dir must be an existing directory: {tf_dir}")
    plan_id = compute_plan_id(plan)
    cert = client.get_certificate(plan_id)
    if cert is None:
        cert = client.analyze(str(plan_path), str(Path(tf_dir).resolve()) if tf_dir else None, use_groq)
    return summarize(cert, client.decisions(cert["plan_id"]), client.signature_valid(cert["plan_id"]), plan)


def get_certificate(client: Any, plan_id: str) -> dict[str, Any]:
    if not isinstance(plan_id, str) or len(plan_id) != 64 or any(c not in "0123456789abcdef" for c in plan_id):
        raise GateError("plan_id must be a 64-character lowercase sha256 hex string")
    cert = client.get_certificate(plan_id)
    if cert is None:
        raise GateError(f"no certificate for plan {plan_id}")
    return summarize(cert, client.decisions(plan_id), client.signature_valid(plan_id))


# --- safe-apply guards ---------------------------------------------------------------


def guard_apply_target(tf_dir: str | Path, ministack_url: str | None = None) -> Path:
    """The wrapper only ever applies this repo's demos, and only to a loopback MiniStack."""
    from app.shadow import MINISTACK_URL

    target = Path(tf_dir).resolve()
    demo_root = DEMO_ROOT.resolve()
    if target == demo_root or demo_root not in target.parents:
        raise GateError(f"refusing: {target} is not inside {demo_root}. safe-apply only targets this "
                        "repo's MiniStack demos; real infrastructure needs your own review and tooling.")
    if not target.is_dir() or not any(target.glob("*.tf")):
        raise GateError(f"refusing: {target} has no *.tf files")
    host = urllib.parse.urlparse(ministack_url or MINISTACK_URL).hostname
    if host not in LOOPBACK_HOSTS:
        raise GateError(f"refusing: MINISTACK_ENDPOINT_URL host {host!r} is not loopback; "
                        "safe-apply only targets a local MiniStack")
    return target


def write_override(tf_dir: Path) -> Path:
    """The shadow run's override file: every AWS endpoint forced onto MiniStack, fake keys."""
    from app.shadow import OVERRIDE_FILE, override_hcl

    path = tf_dir / OVERRIDE_FILE
    path.write_text(override_hcl(), encoding="utf-8")
    return path


# --- CI job summary ------------------------------------------------------------------


def _cell(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def step_summary(cert: dict[str, Any] | None, tf_dir: str, error: str | None = None) -> str:
    lines = [f"## GhostOps gate: `{tf_dir}`", ""]
    if cert is None:
        lines += ["**Verdict: ERROR** (fail closed, the job fails)", "", "```text", _cell(error)[:3000], "```", ""]
        return "\n".join(lines)
    blocking = blocking_findings(cert)
    word = "BLOCKED_PENDING_REVIEW (needs human review)" if cert["verdict"] == BLOCKED else "AUTO_APPROVED"
    lines += [f"**Verdict: {word}**", "", f"- Plan id: `{cert['plan_id']}`"]
    cost = cert["cost_delta"]
    if cost["monthly_usd"] is None:
        lines.append(f"- Monthly cost delta: unknown ({_cell(cost.get('note'))})")
    else:
        sign = "+" if cost["monthly_usd"] >= 0 else "-"
        lines.append(f"- Monthly cost delta: {sign}${abs(cost['monthly_usd']):.2f}"
                     + (f" ({_cell(cost['note'])})" if cost.get("note") else ""))
    shadow = cert["shadow_run"]
    lines.append(f"- Shadow apply on MiniStack: {'applied, ' + str(shadow['resources_created']) + ' resources' if shadow['applied'] else 'NOT applied: ' + _cell(shadow.get('error'))[:300]}")
    lines += ["", f"### Blocking findings ({len(blocking)})", ""]
    if blocking:
        lines += ["| Severity | Rule | Resource | Finding |", "|---|---|---|---|"]
        lines += [f"| {f['severity']} | {f['rule']} | `{_cell(f['resource'])}` | {_cell(f['message'])} |" for f in blocking]
    else:
        lines.append("None.")
    scores = pillar_scores(cert)
    if scores:
        lines += ["", "### Pillar scores", "", "| " + " | ".join(p.title() for p in scores) + " |",
                  "|" + "---|" * len(scores), "| " + " | ".join(str(s) for s in scores.values()) + " |"]
    advisory = len(cert["blast_radius"]["risk_flags"]) - len(blocking)
    lines += ["", f"{advisory} advisory finding(s) (reliability, cost, performance, low/medium security) do not block.",
              "", f"> {_cell(cert['risk_explanation'])}", ""]
    return "\n".join(lines)


def run_ci(tf_dir: str, *, out_dir: Path, use_groq: bool, summary_file: str | None,
           output_file: str | None, expect: str | None) -> int:
    """Plan (forced onto MiniStack), analyse with the ghostops CLI, report. Fail closed."""
    from app.shadow import ShadowError, plan_json

    out_dir.mkdir(parents=True, exist_ok=True)
    plan_path, cert_path = out_dir / "plan.json", out_dir / "certificate.json"
    cert, error, code = None, None, EXIT_ERROR
    try:
        plan_path.write_text(json.dumps(plan_json(tf_dir)), encoding="utf-8")
        cmd = [sys.executable, "-m", "app.cli", "analyze", str(plan_path), "--tf", tf_dir, "--json", "--no-store"]
        proc = subprocess.run(cmd + ([] if use_groq else ["--no-groq"]), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", cwd=Path(__file__).resolve().parents[1])
        sys.stderr.write(proc.stderr)
        code = proc.returncode
        try:
            parsed = json.loads(proc.stdout) if code in (EXIT_ALLOW, EXIT_REFUSE) else None
        except ValueError:
            parsed = None  # e.g. a crash: Python also exits 1, with a traceback instead of JSON
        if isinstance(parsed, dict) and parsed.get("verdict") in (APPROVED, BLOCKED):
            cert = parsed
            cert_path.write_text(json.dumps(cert, indent=2), encoding="utf-8")
        else:
            error = (proc.stderr or proc.stdout).strip()[-3000:] or f"ghostops exited with {code}"
            code = EXIT_ERROR
    except (ShadowError, OSError, ValueError, subprocess.SubprocessError) as exc:
        error, code = f"{type(exc).__name__}: {exc}", EXIT_ERROR

    report = step_summary(cert, tf_dir, error)
    print(report)
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    verdict = cert["verdict"] if cert else "ERROR"
    if output_file:
        with open(output_file, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={verdict}\nplan-id={cert['plan_id'] if cert else ''}\n"
                     f"certificate={cert_path if cert else ''}\n")
    if expect:
        ok = verdict == expect
        print(f"ghostops gate: expected {expect}, got {verdict}: {'ok' if ok else 'MISMATCH'}")
        return EXIT_ALLOW if ok else (EXIT_ERROR if cert is None else EXIT_REFUSE)
    return code


# --- command line --------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.gate", description="GhostOps as an enforced gate.")
    sub = parser.add_subparsers(dest="command", required=True)
    ci = sub.add_parser("ci", help="plan a Terraform dir on MiniStack, analyse it, write a job summary")
    ci.add_argument("--tf", required=True)
    ci.add_argument("--out-dir", default="ghostops-gate-out")
    ci.add_argument("--summary", help="append the Markdown report here ($GITHUB_STEP_SUMMARY)")
    ci.add_argument("--github-output", help="append verdict/plan-id outputs here ($GITHUB_OUTPUT)")
    ci.add_argument("--no-groq", action="store_true")
    ci.add_argument("--expect", choices=[APPROVED, BLOCKED], help="pass only if the verdict is this (self-tests)")
    prep = sub.add_parser("prepare-apply", help="safe-apply guards + MiniStack override file")
    prep.add_argument("--tf", required=True)
    decide = sub.add_parser("decide", help="may this exact plan be applied?")
    decide.add_argument("--plan", required=True)
    decide.add_argument("--tf", required=True)
    decide.add_argument("--no-groq", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "ci":
        from app.config import setting

        if not (setting("GHOSTOPS_SIGNING_KEY") or setting("GHOSTOPS_HMAC_SECRET")):
            os.environ["GHOSTOPS_HMAC_SECRET"] = secrets.token_hex(32)  # CI without a key: per-run secret
        return run_ci(args.tf, out_dir=Path(args.out_dir), use_groq=not args.no_groq,
                      summary_file=args.summary, output_file=args.github_output, expect=args.expect)
    try:
        target = guard_apply_target(args.tf)
        if args.command == "prepare-apply":
            print(write_override(target))
            return EXIT_ALLOW
        result = check_plan(default_client(), args.plan, target, use_groq=not args.no_groq)
    except GateError as exc:
        print(f"ghostops gate: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # fail closed on anything unexpected
        print(f"ghostops gate: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(result, indent=2))
    return EXIT_ALLOW if result["apply_allowed"] else EXIT_REFUSE


if __name__ == "__main__":
    sys.exit(main())
