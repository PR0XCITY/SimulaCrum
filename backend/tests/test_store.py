"""Store backends: SQLite always; Postgres too when TEST_DATABASE_URL is set (see conftest.py)."""

import logging

import pytest

from app import store as store_module
from app.config import ConfigError, SecretRedactingFilter, check_required
from app.store import PostgresStore, Store, open_store
from conftest import reopen

SECRET = "store-test-secret-" + "c0ffee" * 6
DB_PASSWORD = "npg_S3cretPassw0rdNeverLogged"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_HMAC_SECRET", SECRET)
    monkeypatch.setenv("GHOSTOPS_HOSTED", "0")
    monkeypatch.delenv("GHOSTOPS_DATABASE_URL", raising=False)


def cert(plan_id, timestamp, signature="s" * 64, verdict="BLOCKED_PENDING_REVIEW", severity="HIGH"):
    return {"plan_id": plan_id, "timestamp": timestamp, "verdict": verdict, "generated_by": "template",
            "signature": signature, "resource_changes": [{"address": "x.y"}],
            "blast_radius": {"risk_flags": [{"rule": "GO-SG-001", "severity": severity, "resource": "x.y",
                                             "message": "m"}]},
            "cost_delta": {"monthly_usd": 2.5}, "shadow_run": {"applied": True}, "architecture": None}


def test_round_trip_and_survives_a_restart(make_store):
    store = make_store()
    a, b = cert("a" * 64, "2026-10-01T00:00:00Z"), cert("b" * 64, "2026-10-02T00:00:00Z")
    store.save_certificate(a)
    store.save_certificate(b)
    assert store.get_certificate("a" * 64) == a and store.get_certificate("c" * 64) is None
    assert list(store.get_certificate("a" * 64)) == list(a)  # field order kept (signatures depend on it)

    first = store.add_decision(a, "deny", "ana", "no")
    second = store.add_decision(a, "approve", "lead", None)
    assert second["id"] > first["id"]
    assert [{k: d[k] for k in ("id", "decision", "reviewer", "comment")} for d in store.decisions("a" * 64)] == [
        {"id": first["id"], "decision": "deny", "reviewer": "ana", "comment": "no"},
        {"id": second["id"], "decision": "approve", "reviewer": "lead", "comment": None}]
    assert store.decisions("a" * 64)[0] == first

    store.save_design("B", {"services": [1]}, {"monthly_usd": 1})
    store.save_design("B", {"services": [2]}, {"monthly_usd": 2})  # replaces
    assert store.designs()["A"] is None and store.designs()["B"]["architecture"] == {"services": [2]}

    again = reopen(store)  # a restart: everything is still there
    summaries = again.list_certificates()
    assert [s["plan_id"] for s in summaries] == ["b" * 64, "a" * 64]  # newest first
    assert summaries[1]["latest_decision"]["decision"] == "approve"
    assert summaries[1]["risk_flag_counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0}
    assert again.designs()["B"]["snapshot"] == {"monthly_usd": 2}
    assert again.delete_design("B") is True and again.delete_design("B") is False


def test_reanalysis_replaces_the_certificate_but_keeps_the_log(make_store):
    store = make_store()
    old = cert("a" * 64, "2026-10-01T00:00:00Z", signature="1" * 64)
    store.save_certificate(old)
    store.add_decision(old, "deny", "ana", None)
    new = cert("a" * 64, "2026-10-03T00:00:00Z", signature="2" * 64, severity="LOW")
    store.save_certificate(new)
    [summary] = store.list_certificates()
    assert summary["timestamp"] == "2026-10-03T00:00:00Z" and summary["latest_decision"] is None
    assert store.get_certificate("a" * 64) == new and len(store.decisions("a" * 64)) == 1


def test_open_store_uses_sqlite_unless_a_database_url_is_set(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTOPS_DB_PATH", str(tmp_path / "x.db"))
    s = open_store()
    assert type(s) is Store and s.backend == "sqlite" and s.path == tmp_path / "x.db"

    seen = []
    monkeypatch.setattr(store_module, "PostgresStore", lambda url: seen.append(url) or "pg")
    monkeypatch.setenv("GHOSTOPS_DATABASE_URL", "postgresql://u:p@db.example/ghostops")
    assert open_store() == "pg" and seen == ["postgresql://u:p@db.example/ghostops"]


def test_a_non_postgres_url_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("GHOSTOPS_DATABASE_URL", f"mysql://u:{DB_PASSWORD}@h/db")
    with pytest.raises(ConfigError, match="postgresql://") as exc:
        check_required()
    assert DB_PASSWORD not in str(exc.value)


def test_unreachable_database_fails_clearly_without_the_password(monkeypatch):
    url = f"postgresql://ghostops:{DB_PASSWORD}@127.0.0.1:1/ghostops?connect_timeout=3"
    monkeypatch.setenv("GHOSTOPS_DATABASE_URL", url)  # port 1: nothing listens, nothing is started
    with pytest.raises(ConfigError, match="cannot use the database in GHOSTOPS_DATABASE_URL") as exc:
        PostgresStore(url)
    assert DB_PASSWORD not in str(exc.value) and url not in str(exc.value)
    with pytest.raises(ConfigError, match="not a valid Postgres connection URL") as exc:
        PostgresStore(f"postgresql://u:{DB_PASSWORD}@h/db?nonsense_option=1")
    assert DB_PASSWORD not in str(exc.value)


def test_logs_never_contain_the_database_url_or_password(monkeypatch):
    url = f"postgresql://ghostops:{DB_PASSWORD}@ep-x.neon.tech/ghostops?sslmode=require"
    monkeypatch.setenv("GHOSTOPS_DATABASE_URL", url)
    for message in (f"connecting to {url}", f"password={DB_PASSWORD} failed"):
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, message, None, None)
        SecretRedactingFilter().filter(record)
        assert DB_PASSWORD not in record.getMessage() and "[redacted]" in record.getMessage()
