"""Store fixtures: every store test runs on SQLite, and on Postgres too when TEST_DATABASE_URL is set.

    $env:TEST_DATABASE_URL = "postgresql://user:password@host/db?sslmode=require"

Each Postgres test gets its own schema, dropped afterwards; nothing else in that database is touched.
Use a throwaway database: never the one a deployed GhostOps writes to.
"""

from __future__ import annotations

import os
import uuid

import pytest

from app.store import PostgresStore, Store

BACKENDS = ["sqlite", "postgres"]


def _drop_schema(store: PostgresStore) -> None:
    with store._connect() as db:
        db.execute(f'DROP SCHEMA IF EXISTS "{store._schema}" CASCADE')


@pytest.fixture(params=BACKENDS)
def store_backend(request):
    if request.param == "postgres" and not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("set TEST_DATABASE_URL to run the store tests on Postgres")
    return request.param


@pytest.fixture
def make_store(store_backend, tmp_path):
    """make_store() -> a fresh, empty Store on the backend under test."""
    made: list[Store] = []

    def make() -> Store:
        if store_backend == "sqlite":
            store = Store(tmp_path / f"ghostops-{len(made)}.db")
        else:
            store = PostgresStore(os.environ["TEST_DATABASE_URL"], schema=f"ghostops_test_{uuid.uuid4().hex[:12]}")
        made.append(store)
        return store

    yield make
    for store in made:
        if isinstance(store, PostgresStore):
            _drop_schema(store)


def raw_execute(store: Store, query: str, params: tuple = ()):
    """Run SQL directly on the store's database, bypassing its API (tamper and append-only tests)."""
    with store._connect() as db:
        cur = db.execute(query, params)
        return cur.fetchall() if cur.description else None


def reopen(store: Store) -> Store:
    """A new Store on the same database, as after a restart."""
    if isinstance(store, PostgresStore):
        return PostgresStore(os.environ["TEST_DATABASE_URL"], schema=store._schema)
    return Store(store.path)
