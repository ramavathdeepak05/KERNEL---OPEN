"""PostgresWrappedDekStore (W6-4) against a fake cursor — no real DB."""

from __future__ import annotations

from quaicu.adapters.erasure import PostgresWrappedDekStore


class _FakeCursor:
    def __init__(self, backend):
        self._b = backend

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._b.calls.append((sql, params))
        self._b.result = self._b.next_result

    def fetchone(self):
        return self._b.result


class _FakeConn:
    def __init__(self, backend):
        self._b = backend

    def cursor(self):
        return _FakeCursor(self._b)

    def commit(self):
        self._b.commits += 1

    def close(self):
        pass


class _Backend:
    def __init__(self):
        self.calls: list = []
        self.next_result = None
        self.result = None
        self.commits = 0


def _store(backend):
    return PostgresWrappedDekStore("dsn://x", connect=lambda: _FakeConn(backend))


def test_put_executes_upsert():
    b = _Backend()
    _store(b).put(("acme", "alice"), "dek_1", b"WRAP:xyz")
    sql, params = b.calls[-1]
    assert "INSERT INTO quaicu_shred_keys" in sql
    assert params == ("acme", "alice", "dek_1", b"WRAP:xyz")
    assert b.commits == 1


def test_get_returns_bytes_or_none():
    b = _Backend()
    b.next_result = (b"WRAP:abc",)
    assert _store(b).get("dek_1") == b"WRAP:abc"
    b.next_result = None
    assert _store(b).get("missing") is None


def test_key_id_for_and_delete_and_tombstone():
    b = _Backend()
    b.next_result = ("dek_1",)
    assert _store(b).key_id_for(("acme", "alice")) == "dek_1"

    b.next_result = ("dek_1",)
    assert _store(b).delete(("acme", "alice")) == "dek_1"
    assert "UPDATE quaicu_shred_keys SET wrapped_dek = NULL" in b.calls[-1][0]

    b.next_result = None
    _store(b).tombstone(("acme", "bob"))
    assert "tombstoned = TRUE" in b.calls[-1][0]


def test_is_tombstoned():
    b = _Backend()
    b.next_result = (True,)
    assert _store(b).is_tombstoned(("acme", "alice")) is True
    b.next_result = None
    assert _store(b).is_tombstoned(("acme", "ghost")) is False
