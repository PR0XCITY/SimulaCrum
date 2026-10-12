"""Ed25519 certificate signatures: anyone verifies with the public key, only GhostOps signs.
HMAC-SHA256 certificates (including old ones without signature_alg) must keep verifying."""

import base64
import copy
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import keys
from app.api import create_app
from app.certificate import CertificateError, build_certificate, sign, verify
from app.config import ConfigError, SecretRedactingFilter, check_required
from app.store import Store
from test_certificate import NOW, SECRET, cost_result, leaf_paths, load, mutated, shadow_ok

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "verify_certificate.py"
FIXTURES = Path(__file__).parent / "fixtures"
KEY = keys.generate()
OTHER_KEY = keys.generate()


def public_b64(private_b64):
    return keys.public_key_b64(keys.load_private_key(private_b64).public_key())


def make(name="bad_plan.json", **kwargs):
    kwargs.setdefault("signing_key", KEY)
    return build_certificate(load(name), shadow_result=shadow_ok(8), cost_result=cost_result(23.832),
                             use_groq=False, now=NOW, **kwargs)


def legacy(cert):
    """The same certificate as GhostOps signed it before signature_alg existed."""
    old = {k: v for k, v in cert.items() if k not in ("signature", "signature_alg")}
    old["signature"] = sign(old, secret=SECRET)
    return old


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", KEY)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")


# --- sign / verify --------------------------------------------------------------------------


def test_ed25519_roundtrip():
    cert = make()
    assert cert["signature_alg"] == "ed25519"
    assert list(cert)[-2:] == ["signature_alg", "signature"]
    assert len(cert["signature"]) == 128 and int(cert["signature"], 16) >= 0
    public = keys.load_private_key(KEY).public_key()
    for form in (public, keys.public_key_b64(public), keys.public_key_pem(public), keys.raw_public(public).hex()):
        assert verify(cert, public_key=form)
    assert verify(cert)  # public key derived from GHOSTOPS_SIGNING_KEY
    assert verify(cert, plan=load("bad_plan.json"))
    assert not verify(cert, plan=load("good_plan.json"))
    assert verify(dict(reversed(list(cert.items()))))


def test_configured_key_is_preferred_over_hmac():
    cert = build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), cost_result=cost_result(0.1),
                             use_groq=False)
    assert cert["signature_alg"] == "ed25519" and verify(cert)


def test_without_signing_key_hmac_is_used(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "")
    cert = build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), cost_result=cost_result(0.1),
                             use_groq=False)
    assert cert["signature_alg"] == "hmac-sha256" and len(cert["signature"]) == 64
    assert verify(cert) and not verify(cert, secret="f" * 64)


def test_tampering_any_field_fails():
    cert = make()
    paths = [p for p in leaf_paths(cert) if p != ("signature",)]
    assert ("signature_alg",) in paths and len(paths) > 100
    for path in paths:
        tampered = copy.deepcopy(cert)
        target = tampered
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = mutated(target[path[-1]])
        assert not verify(tampered), f"edit at {path} was not detected"
    for key in cert:
        assert not verify({k: v for k, v in cert.items() if k != key}), key
    assert not verify({**cert, "approved_by": "attacker"})
    assert not verify({**cert, "verdict": "AUTO_APPROVED"})


def test_algorithm_cannot_be_swapped():
    cert = make()
    assert not verify({**cert, "signature_alg": "hmac-sha256"})
    assert not verify({k: v for k, v in cert.items() if k != "signature_alg"})  # looks like a legacy cert
    assert not verify({**cert, "signature_alg": "none"})
    with pytest.raises(CertificateError):
        sign({"plan_id": "x", "signature_alg": "none"})


def test_wrong_key_fails():
    cert = make()
    assert not verify(cert, public_key=public_b64(OTHER_KEY))
    resigned = make(signing_key=OTHER_KEY)
    assert not verify(resigned)  # configured key is KEY
    assert verify(resigned, public_key=public_b64(OTHER_KEY))
    assert not verify({**cert, "signature": "00" * 64})
    assert not verify({**cert, "signature": "not hex"})


def test_no_public_key_means_ed25519_cannot_verify(monkeypatch):
    cert = make()
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "")
    assert not verify(cert)
    assert verify(cert, public_key=public_b64(KEY))


def test_old_hmac_certificates_still_verify(monkeypatch):
    old = legacy(make())
    assert "signature_alg" not in old
    assert verify(old)  # Ed25519 key configured too: HMAC is still accepted for old certificates
    assert verify(old, secret=SECRET) and not verify(old, secret="f" * 64)
    assert not verify({**old, "verdict": "AUTO_APPROVED"})
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "")
    assert verify(old)
    explicit = build_certificate(load("good_plan.json"), shadow_result=shadow_ok(2), cost_result=cost_result(0.1),
                                 use_groq=False, secret=SECRET)
    assert explicit["signature_alg"] == "hmac-sha256" and verify(explicit, secret=SECRET)


def test_malformed_key_is_refused_without_echoing_it(monkeypatch):
    bad = "bm90LWEta2V5LWF0LWFsbC0wMTIzNDU2Nzg5"  # base64, wrong length, not PKCS#8
    with pytest.raises(CertificateError) as exc:
        make(signing_key=bad)
    assert bad not in str(exc.value)
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "!!not base64!!")
    with pytest.raises(ConfigError, match="GHOSTOPS_SIGNING_KEY") as exc:
        check_required()
    assert "!!not base64!!" not in str(exc.value)


def test_signing_key_alone_is_enough_to_start(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", "")
    check_required()
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "")
    with pytest.raises(ConfigError, match="GHOSTOPS_SIGNING_KEY"):
        check_required()


def test_log_filter_redacts_the_signing_key():
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "leak %s", (KEY,), None)
    SecretRedactingFilter().filter(record)
    assert record.getMessage() == "leak [redacted]"


# --- keys CLI ---------------------------------------------------------------------------------


def test_seed_and_pkcs8_forms_are_the_same_key():
    der = base64.b64decode(KEY)
    seed = keys.load_private_key(KEY).private_bytes_raw()
    assert len(seed) == 32 and len(der) > 32
    assert public_b64(base64.b64encode(seed).decode()) == public_b64(KEY)


def test_generate_prints_a_new_key_and_public_never_prints_the_private_one(capsys):
    assert keys.main(["generate"]) == 0
    out = capsys.readouterr().out
    line = next(l for l in out.splitlines() if l.startswith("GHOSTOPS_SIGNING_KEY="))
    new = line.split("=", 1)[1]
    assert new != KEY and keys.load_private_key(new) is not None
    assert keys.main(["public"]) == 0
    out = capsys.readouterr().out
    assert KEY not in out and "BEGIN PUBLIC KEY" in out and public_b64(KEY) in out
    assert keys.main([]) == 2


# --- standalone verify script (no secret, no backend import) ----------------------------------


def run_script(*args):
    env = {"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")}  # no GhostOps secrets
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)], capture_output=True, text=True,
                          timeout=60, env=env, cwd=REPO / "scripts")


def test_script_verifies_with_only_the_public_key(tmp_path):
    cert = make()
    path = tmp_path / "cert.json"
    path.write_text(json.dumps(cert, indent=2), encoding="utf-8")
    public = keys.load_private_key(KEY).public_key()
    pem = tmp_path / "ghostops.pub"
    pem.write_text(keys.public_key_pem(public), encoding="utf-8")
    for key_arg in (keys.public_key_b64(public), pem):
        proc = run_script(path, key_arg)
        assert proc.returncode == 0 and proc.stdout.startswith("VALID"), proc.stderr
    assert run_script(path, pem, "--plan", FIXTURES / "bad_plan.json").returncode == 0
    assert run_script(path, pem, "--plan", FIXTURES / "good_plan.json").returncode == 1


def test_script_rejects_tampered_wrong_key_and_hmac(tmp_path):
    cert = make()
    cases = {
        "tampered": ({**cert, "verdict": "AUTO_APPROVED"}, public_b64(KEY), 1),
        "wrong_key": (cert, public_b64(OTHER_KEY), 1),
        "hmac": (legacy(cert), public_b64(KEY), 1),
        "bad_key": (cert, "not-a-key", 2),
    }
    for name, (body, key_arg, code) in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        proc = run_script(path, key_arg)
        assert proc.returncode == code, (name, proc.stdout, proc.stderr)
    assert "HMAC" in run_script(tmp_path / "hmac.json", public_b64(KEY)).stdout


# --- API ----------------------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "ghostops.db")


@pytest.fixture
def client(store):
    def analyzer(plan, tf_dir=None, *, use_groq=True):
        return build_certificate(plan, tf_dir, shadow_result=shadow_ok(2), cost_result=cost_result(1.5),
                                 use_groq=False)
    with TestClient(create_app(store=store, analyzer=analyzer)) as c:
        yield c


def test_api_public_key_and_verify(client, tmp_path):
    r = client.get("/public-key")
    assert r.status_code == 200
    body = r.json()
    assert body["alg"] == "ed25519" and body["public_key"] == public_b64(KEY)
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"] and len(body["key_id"]) == 16
    assert KEY not in r.text

    cert = client.post("/analyze", json={"plan_path": str(FIXTURES / "bad_plan.json")}).json()
    v = client.get(f"/verify/{cert['plan_id']}").json()
    assert v["valid"] is True and v["signature_alg"] == "ed25519"

    # an outsider with only GET /public-key verifies the certificate offline
    (tmp_path / "cert.json").write_text(json.dumps(client.get(f"/certificates/{cert['plan_id']}").json()),
                                        encoding="utf-8")
    (tmp_path / "pub.json").write_text(r.text, encoding="utf-8")
    assert run_script(tmp_path / "cert.json", tmp_path / "pub.json").returncode == 0


def test_api_verifies_old_hmac_certificates(client, store):
    old = legacy(make())
    store.save_certificate(old)
    v = client.get(f"/verify/{old['plan_id']}").json()
    assert v["valid"] is True and v["signature_alg"] == "hmac-sha256"


def test_api_public_key_404_without_signing_key(monkeypatch, store):
    monkeypatch.setenv("GHOSTOPS_SIGNING_KEY", "")
    with TestClient(create_app(store=store)) as c:
        r = c.get("/public-key")
    assert r.status_code == 404 and "HMAC" in r.json()["detail"]
