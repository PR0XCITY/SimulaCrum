"""Verify a GhostOps Risk Certificate with the published Ed25519 public key. No secret needed.

    python scripts/verify_certificate.py cert.json PUBKEY [--plan plan.json]

PUBKEY is a file (PEM, or the base64 from GET /public-key) or the base64/hex text itself.
Get it from the GhostOps API:  curl http://localhost:8000/public-key
With --plan, also checks that the certificate belongs to that exact Terraform plan.

Exit 0: valid. 1: invalid (tampered, wrong key, other plan, or HMAC-signed, which only
holders of the HMAC secret can check via GET /verify/{plan_id}). 2: unreadable input.
Self-contained on purpose: needs only the `cryptography` package, not the GhostOps backend.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(obj) -> bytes:
    # Must match backend/app/certificate.py canonical().
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def signing_input(cert: dict) -> bytes:
    body = {k: v for k, v in cert.items() if k != "signature"}
    return str(cert.get("plan_id", "")).encode("utf-8") + b"\n" + canonical(body)


def load_public_key(arg: str) -> Ed25519PublicKey:
    path = Path(arg)
    text = (path.read_text(encoding="utf-8") if len(arg) < 260 and path.is_file() else arg).strip()
    if text.startswith("{"):  # the JSON body of GET /public-key saved to a file
        text = json.loads(text)["public_key"]
    if text.startswith("-----BEGIN"):
        key = serialization.load_pem_public_key(text.encode("ascii"))
    else:
        raw = bytes.fromhex(text) if len(text) == 64 else base64.b64decode(text, validate=True)
        key = Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32 else serialization.load_der_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def check(cert: dict, key: Ed25519PublicKey, plan: dict | None = None) -> tuple[bool, str]:
    alg = cert.get("signature_alg", "hmac-sha256")
    if alg != "ed25519":
        return False, (f"signed with {alg}: only holders of the HMAC secret can verify it "
                       "(GET /verify/{plan_id} on the GhostOps server)")
    if plan is not None and cert.get("plan_id") != hashlib.sha256(canonical(plan)).hexdigest():
        return False, "certificate is for a different plan"
    try:
        key.verify(bytes.fromhex(str(cert.get("signature", ""))), signing_input(cert))
    except (InvalidSignature, ValueError):
        return False, "signature does not match (tampered, or signed with a different key)"
    return True, "signature valid"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a GhostOps Risk Certificate with its Ed25519 public key.")
    parser.add_argument("certificate", help="certificate JSON file")
    parser.add_argument("public_key", help="public key file (PEM / base64 / GET /public-key JSON) or base64 text")
    parser.add_argument("--plan", help="Terraform plan JSON the certificate must belong to")
    args = parser.parse_args(argv)
    try:
        cert = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
        key = load_public_key(args.public_key)
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8")) if args.plan else None
    except (OSError, ValueError, KeyError, TypeError, binascii.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not isinstance(cert, dict):
        print("ERROR: the certificate is not a JSON object", file=sys.stderr)
        return 2
    ok, reason = check(cert, key, plan)
    print(f"{'VALID' if ok else 'INVALID'}: {reason} (plan {cert.get('plan_id')}, verdict {cert.get('verdict')})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
