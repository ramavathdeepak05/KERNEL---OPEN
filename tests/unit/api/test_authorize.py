"""Unit tests for POST /v1/authorize — pure policy-decision endpoint."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}


def _app(decision: Decision = Decision.ALLOW, *, with_identity: bool = True):
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity() if with_identity else None,
    )
    return create_app(kernel)


def _body(record: bool | None = False) -> dict:
    return {"type": "payments.wire", "payload": {"amount": 100}, "record": record}


# ── Auth ──────────────────────────────────────────────────────────────────────


async def test_authorize_without_token_returns_401() -> None:
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body())
    assert resp.status_code == 401


async def test_authorize_without_identity_adapter_returns_503() -> None:
    app = _app(with_identity=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body(), headers=AUTH)
    assert resp.status_code == 503


# ── Pure PDP semantics: always 200 ────────────────────────────────────────────


async def test_authorize_allow_returns_200_allowed_true() -> None:
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body(), headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is True
    assert data["decision"] == "allow"


async def test_authorize_deny_returns_200_allowed_false() -> None:
    """Deny must be 200 + allowed:false — NOT a 403. The caller is the PEP."""
    app = _app(decision=Decision.DENY)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body(), headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["allowed"] is False
    assert data["decision"] == "deny"


# ── Response fields ────────────────────────────────────────────────────────────


async def test_authorize_response_contains_actor_and_layers() -> None:
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body(), headers=AUTH)
    data = resp.json()
    assert data["actor_id"] == "alice"  # FakeIdentity resolves to "alice"
    assert isinstance(data["enforced_layers"], list)
    assert "enforce_policy" in data["enforced_layers"]


async def test_authorize_record_false_does_not_seal() -> None:
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/authorize", json=_body(record=False), headers=AUTH)
    data = resp.json()
    assert data["sealed"] is False
    assert data["ledger_seq"] is None
