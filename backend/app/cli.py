"""GhostOps command line.

  ghostops analyze <plan.json> [--tf DIR] [--no-groq] [--json] [--no-store]

Prints a readable verdict (or the certificate JSON with --json) and stores the
certificate in the GhostOps database so the dashboard shows it.
Exit codes: 0 AUTO_APPROVED, 1 BLOCKED_PENDING_REVIEW, 2 error.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

from app.config import ConfigError, check_required

EXIT_APPROVED, EXIT_BLOCKED, EXIT_ERROR = 0, 1, 2


def render(cert: dict[str, Any], valid: bool) -> str:
    def wrap(text: str, indent: str, hang: str = "  ") -> str:
        return textwrap.fill(text, width=100, initial_indent=indent, subsequent_indent=indent + hang)

    actions: dict[str, int] = {}
    for rc in cert["resource_changes"]:
        actions[rc["action"]] = actions.get(rc["action"], 0) + 1
    flags = cert["blast_radius"]["risk_flags"]
    shadow, cost = cert["shadow_run"], cert["cost_delta"]
    lines = [
        "GhostOps Risk Certificate",
        f"  plan       {cert['plan_id']}",
        f"  generated  {cert['timestamp']}",
        "",
        f"VERDICT: {cert['verdict']}",
        "",
        f"Changes: {len(cert['resource_changes'])} ("
        + ", ".join(f"{n} {a}" for a, n in sorted(actions.items())) + ")" if actions else "Changes: none",
        f"Risk flags: {len(flags)}" if flags else "Risk flags: none",
    ]
    lines += [wrap(f"{f['severity']:<8} {f['rule']:<13} {f['message']}", "  ", " " * 23) for f in flags]
    public = cert["blast_radius"]["newly_public"]
    if public:
        lines.append("Newly public: " + ", ".join(p["address"] for p in public))
    lines.append(
        f"Shadow run: applied on MiniStack, {shadow['resources_created']} resources" if shadow["applied"]
        else wrap(f"Shadow run: NOT applied - {shadow['error']}", "")
    )
    if cost["monthly_usd"] is None:
        lines.append(wrap(f"Cost delta: unknown - {cost['note']}", ""))
    else:
        sign = "+" if cost["monthly_usd"] >= 0 else "-"
        lines.append(f"Cost delta: {sign}${abs(cost['monthly_usd']):.2f}/month")
        if cost["note"]:
            lines.append(wrap(cost["note"], "  "))
    lines += ["", f"Explanation ({cert['generated_by']}):", wrap(cert["risk_explanation"], "  ", ""), "",
              f"Signature: {cert['signature']} ({'verified' if valid else 'INVALID'})"]
    return "\n".join(lines)


def cmd_analyze(args: argparse.Namespace) -> int:
    from app.certificate import CertificateError, build_certificate, verify
    from app.plan_parser import PlanParseError

    try:
        plan = json.loads(Path(args.plan).read_bytes())
    except OSError as exc:
        print(f"ghostops: cannot read {args.plan}: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"ghostops: {args.plan} is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.tf and not Path(args.tf).is_dir():
        print(f"ghostops: --tf must be a directory: {args.tf}", file=sys.stderr)
        return EXIT_ERROR
    try:
        cert = build_certificate(plan, args.tf, use_groq=not args.no_groq)
    except (PlanParseError, CertificateError) as exc:
        print(f"ghostops: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.no_store:
        from app.store import open_store
        try:
            open_store().save_certificate(cert)
        except ConfigError as exc:  # e.g. GHOSTOPS_DATABASE_URL unreachable; never prints the URL
            print(exc, file=sys.stderr)
            return EXIT_ERROR
    print(json.dumps(cert, indent=2) if args.json else render(cert, verify(cert)))
    return EXIT_APPROVED if cert["verdict"] == "AUTO_APPROVED" else EXIT_BLOCKED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ghostops", description="GhostOps: risk-check a Terraform plan.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyse a plan JSON (terraform show -json) and print the verdict")
    analyze.add_argument("plan", help="plan JSON file")
    analyze.add_argument("--tf", help="Terraform directory for the shadow run (without it: BLOCKED, unverified)")
    analyze.add_argument("--no-groq", action="store_true", help="template explanation, no Groq call")
    analyze.add_argument("--json", action="store_true", help="print the full certificate JSON")
    analyze.add_argument("--no-store", action="store_true", help="do not save to the GhostOps database")
    args = parser.parse_args(argv)

    try:
        check_required()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_ERROR
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
