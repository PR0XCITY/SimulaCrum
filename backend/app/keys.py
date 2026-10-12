"""Ed25519 signing keys for Risk Certificates.

GHOSTOPS_SIGNING_KEY holds the private key as base64: either PKCS#8 DER (what
`python -m app.keys generate` prints) or the raw 32-byte seed. Only GhostOps signs with
it; the matching public key is published at GET /public-key and is all anyone needs to
verify a certificate (scripts/verify_certificate.py).

CLI: python -m app.keys generate   print a NEW key for you to paste into .env yourself
     python -m app.keys public     print the public key of the configured key
Nothing here ever prints or logs a configured private key, and nothing writes files.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.config import setting

KEY_SETTING = "GHOSTOPS_SIGNING_KEY"


class SigningKeyError(ValueError):
    """A key cannot be parsed. The message never contains the key."""


def load_private_key(value: str | None = None) -> Ed25519PrivateKey | None:
    """The configured key (or `value`), None when unset; SigningKeyError if malformed."""
    text = (value if value is not None else setting(KEY_SETTING) or "").strip()
    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise SigningKeyError(f"{KEY_SETTING} is not valid base64.") from None
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    try:
        key = serialization.load_der_private_key(raw, password=None)
    except (ValueError, TypeError):
        raise SigningKeyError(f"{KEY_SETTING} is neither a 32-byte Ed25519 seed nor a PKCS#8 key.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyError(f"{KEY_SETTING} is a PKCS#8 key but not an Ed25519 one.")
    return key


def configured_public_key() -> Ed25519PublicKey | None:
    key = load_private_key()
    return key.public_key() if key else None


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(raw_public(key)).decode("ascii")


def public_key_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def key_id(key: Ed25519PublicKey) -> str:
    """Short fingerprint (first 16 hex chars of sha256 over the raw public key)."""
    return hashlib.sha256(raw_public(key)).hexdigest()[:16]


def load_public_key(text: str) -> Ed25519PublicKey:
    """PEM, base64 of the raw 32 bytes or of SubjectPublicKeyInfo DER, or 64 hex chars."""
    text = text.strip()
    try:
        if text.startswith("-----BEGIN"):
            key = serialization.load_pem_public_key(text.encode("ascii"))
        else:
            raw = bytes.fromhex(text) if len(text) == 64 else base64.b64decode(text, validate=True)
            key = (Ed25519PublicKey.from_public_bytes(raw) if len(raw) == 32
                   else serialization.load_der_public_key(raw))
    except (ValueError, TypeError, binascii.Error):
        raise SigningKeyError("not a readable Ed25519 public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError("the public key is not an Ed25519 key")
    return key


def generate() -> str:
    """A new private key as base64 PKCS#8 DER."""
    der = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return base64.b64encode(der).decode("ascii")


def main(argv: list[str]) -> int:
    command = argv[0] if argv else ""
    if command == "generate":
        value = generate()
        public = load_private_key(value).public_key()
        print("# New Ed25519 signing key. Paste the next line into .env yourself; never commit it.")
        print(f"{KEY_SETTING}={value}")
        print(f"# Public key (safe to share): {public_key_b64(public)}  key_id {key_id(public)}")
        return 0
    if command == "public":
        try:
            public = configured_public_key()
        except SigningKeyError as exc:
            print(exc, file=sys.stderr)
            return 2
        if public is None:
            print(f"{KEY_SETTING} is not set (run: python -m app.keys generate)", file=sys.stderr)
            return 2
        print(public_key_pem(public), end="")
        print(f"# base64: {public_key_b64(public)}  key_id {key_id(public)}")
        return 0
    print("usage: python -m app.keys generate | public", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
