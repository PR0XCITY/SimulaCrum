"""Storage for certificates and the reviewer audit log: SQLite by default, or Postgres when
GHOSTOPS_DATABASE_URL is set (a free hosted database survives Render's free-plan restarts).

certificates  latest certificate per plan_id (re-analysing a plan replaces it)
audit_log     every approve/deny decision, append-only: triggers reject UPDATE
              and DELETE, so recorded decisions cannot be rewritten.
designs       the Builder's compare slots A and B: architecture JSON + a snapshot
              of its static check (saving a slot again replaces it).
Decisions are records only; nothing here applies anything to any system.

Both backends run the same SQL (written with ? placeholders) and return the same results.
The database URL holds a password: it is never logged or put in an error message.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.config import ConfigError, db_path, redact, setting

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    plan_id      TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    signature    TEXT NOT NULL,
    body         TEXT NOT NULL,
    stored_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id               TEXT NOT NULL,
    decision              TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
    reviewer              TEXT NOT NULL,
    comment               TEXT,
    certificate_signature TEXT NOT NULL,
    verdict_at_decision   TEXT NOT NULL,
    decided_at            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS designs (
    slot         TEXT PRIMARY KEY CHECK (slot IN ('A', 'B')),
    architecture TEXT NOT NULL,
    snapshot     TEXT NOT NULL,
    saved_at     TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""

# The same tables in Postgres. COLLATE "C" keeps ORDER BY byte-wise, as in SQLite.
PG_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS certificates (
        plan_id      TEXT COLLATE "C" PRIMARY KEY,
        "timestamp"  TEXT COLLATE "C" NOT NULL,
        verdict      TEXT NOT NULL,
        generated_by TEXT NOT NULL,
        signature    TEXT NOT NULL,
        body         TEXT NOT NULL,
        stored_at    TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS audit_log (
        id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        plan_id               TEXT NOT NULL,
        decision              TEXT NOT NULL CHECK (decision IN ('approve', 'deny')),
        reviewer              TEXT NOT NULL,
        comment               TEXT,
        certificate_signature TEXT NOT NULL,
        verdict_at_decision   TEXT NOT NULL,
        decided_at            TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS designs (
        slot         TEXT COLLATE "C" PRIMARY KEY CHECK (slot IN ('A', 'B')),
        architecture TEXT NOT NULL,
        snapshot     TEXT NOT NULL,
        saved_at     TEXT NOT NULL)""",
    """CREATE OR REPLACE FUNCTION ghostops_audit_log_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit_log is append-only'; END $$""",
    """CREATE OR REPLACE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION ghostops_audit_log_append_only()""",
    """CREATE OR REPLACE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION ghostops_audit_log_append_only()""",
    """CREATE OR REPLACE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION ghostops_audit_log_append_only()""",
]


def _source(cert: dict[str, Any]) -> dict[str, Any]:
    """Where a certificate came from: a Builder design (with its services) or a Terraform plan."""
    arch = cert.get("architecture")
    if arch and arch.get("services"):
        return {"kind": "builder", "services": [{"name": s["name"], "type": s["type"]} for s in arch["services"]]}
    return {"kind": "plan", "services": []}


def _blocks(flag: dict[str, Any]) -> bool:
    from app.certificate import blocks  # late import: certificate imports nothing from here

    return blocks(flag)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def open_store() -> Store:
    """Postgres if GHOSTOPS_DATABASE_URL is set, else the SQLite file at GHOSTOPS_DB_PATH."""
    url = setting("GHOSTOPS_DATABASE_URL")
    return PostgresStore(url) if url else Store(db_path())


class Store:
    """SQLite store (the default). PostgresStore swaps only the connection and the schema."""

    backend = "sqlite"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:  # commit on success, roll back on error
                yield db
        finally:
            db.close()

    def save_certificate(self, cert: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute(
                'INSERT INTO certificates (plan_id, "timestamp", verdict, generated_by, signature, body, stored_at) '
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (plan_id) DO UPDATE SET "
                '"timestamp" = excluded."timestamp", verdict = excluded.verdict, '
                "generated_by = excluded.generated_by, signature = excluded.signature, "
                "body = excluded.body, stored_at = excluded.stored_at",
                (cert["plan_id"], cert["timestamp"], cert["verdict"], cert["generated_by"],
                 cert["signature"], json.dumps(cert), _now()),  # keeps the certificate's field order
            )

    def get_certificate(self, plan_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT body FROM certificates WHERE plan_id = ?", (plan_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def list_certificates(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute('SELECT body FROM certificates ORDER BY "timestamp" DESC, plan_id').fetchall()
            # Latest decision on the CURRENT version of each certificate (same signature);
            # decisions on an earlier analysis of the plan stay in the log but are not "the" decision.
            latest = {
                r["plan_id"]: dict(r) for r in db.execute(
                    "SELECT a.plan_id, a.decision, a.reviewer, a.decided_at FROM audit_log a "
                    "JOIN certificates c ON c.plan_id = a.plan_id AND c.signature = a.certificate_signature "
                    "WHERE a.id = (SELECT MAX(b.id) FROM audit_log b WHERE b.plan_id = a.plan_id "
                    "AND b.certificate_signature = c.signature)").fetchall()
            }
        out = []
        for row in rows:
            cert = json.loads(row["body"])
            flags = cert["blast_radius"]["risk_flags"]
            decision = latest.get(cert["plan_id"])
            out.append({
                "plan_id": cert["plan_id"],
                "timestamp": cert["timestamp"],
                "verdict": cert["verdict"],
                "generated_by": cert["generated_by"],
                "resource_change_count": len(cert["resource_changes"]),
                "risk_flag_counts": {s: sum(f["severity"] == s for f in flags)
                                     for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
                "monthly_usd": cert["cost_delta"]["monthly_usd"],
                "shadow_applied": cert["shadow_run"]["applied"],
                "latest_decision": {k: decision[k] for k in ("decision", "reviewer", "decided_at")} if decision else None,
                "source": _source(cert),
                "pillar_scores": {p: v["score"] for p, v in cert["pillars"].items()} if cert.get("pillars") else None,
                "blocking_count": sum(_blocks(f) for f in flags),
            })
        return out

    def add_decision(self, cert: dict[str, Any], decision: str, reviewer: str, comment: str | None) -> dict[str, Any]:
        decided_at = _now()
        with self._connect() as db:
            row_id = db.execute(
                "INSERT INTO audit_log (plan_id, decision, reviewer, comment, certificate_signature, "
                "verdict_at_decision, decided_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
                (cert["plan_id"], decision, reviewer, comment, cert["signature"], cert["verdict"], decided_at),
            ).fetchone()["id"]
        return {"id": row_id, "plan_id": cert["plan_id"], "decision": decision, "reviewer": reviewer,
                "comment": comment, "certificate_signature": cert["signature"],
                "verdict_at_decision": cert["verdict"], "decided_at": decided_at}

    def decisions(self, plan_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM audit_log WHERE plan_id = ? ORDER BY id", (plan_id,)).fetchall()
        return [dict(r) for r in rows]

    def save_design(self, slot: str, architecture: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
        saved_at = _now()
        with self._connect() as db:
            db.execute("INSERT INTO designs (slot, architecture, snapshot, saved_at) VALUES (?, ?, ?, ?) "
                       "ON CONFLICT (slot) DO UPDATE SET architecture = excluded.architecture, "
                       "snapshot = excluded.snapshot, saved_at = excluded.saved_at",
                       (slot, json.dumps(architecture), json.dumps(snapshot), saved_at))
        return {"slot": slot, "architecture": architecture, "snapshot": snapshot, "saved_at": saved_at}

    def designs(self) -> dict[str, dict[str, Any] | None]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM designs").fetchall()
        saved = {r["slot"]: {"slot": r["slot"], "architecture": json.loads(r["architecture"]),
                             "snapshot": json.loads(r["snapshot"]), "saved_at": r["saved_at"]} for r in rows}
        return {slot: saved.get(slot) for slot in ("A", "B")}

    def delete_design(self, slot: str) -> bool:
        with self._connect() as db:
            return db.execute("DELETE FROM designs WHERE slot = ?", (slot,)).rowcount > 0


class _PgConnection:
    """Runs the shared ?-placeholder SQL on a psycopg connection (dict rows, like sqlite3.Row)."""

    def __init__(self, conn: Any):
        self.conn = conn

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> Any:
        return self.conn.execute(query.replace("?", "%s"), params)


class PostgresStore(Store):
    """Postgres store, e.g. a free Neon database: certificates survive restarts and redeploys.

    `schema` (tests only) keeps the tables in a schema of their own instead of the default one.
    """

    backend = "postgres"

    def __init__(self, url: str, *, schema: str | None = None):
        try:
            import psycopg
            from psycopg.conninfo import conninfo_to_dict
        except ImportError:
            raise ConfigError('GHOSTOPS_DATABASE_URL is set but psycopg is not installed: '
                              'pip install "psycopg[binary]"') from None
        self._psycopg = psycopg
        try:
            params = conninfo_to_dict(url)
        except psycopg.Error:
            raise ConfigError("GHOSTOPS_DATABASE_URL is not a valid Postgres connection URL.") from None
        params.setdefault("connect_timeout", "20")  # a sleeping free database takes a few seconds to wake
        self._params = params
        self._schema = schema
        self.path = None  # no file
        try:
            with self._connect(create_schema=True) as db:
                for statement in PG_SCHEMA:
                    db.execute(statement)
        except psycopg.Error as exc:
            # psycopg names the host and user, never the password; redact anyway.
            raise ConfigError("GhostOps cannot start: cannot use the database in GHOSTOPS_DATABASE_URL "
                              f"({redact(str(exc)).strip()})") from None

    def __repr__(self) -> str:  # never show the URL
        return f"<PostgresStore schema={self._schema or 'default'}>"

    @contextmanager
    def _connect(self, create_schema: bool = False) -> Iterator[Any]:
        from psycopg.rows import dict_row

        # prepare_threshold=None: also works through Neon's pooled (PgBouncer) endpoint.
        conn = self._psycopg.connect(**self._params, row_factory=dict_row, prepare_threshold=None)
        try:
            with conn:  # commit on success, roll back on error
                if self._schema:
                    if create_schema:
                        conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{self._schema}"')
                    conn.execute(f'SET search_path TO "{self._schema}"')
                yield _PgConnection(conn)
        finally:
            conn.close()
