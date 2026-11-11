"""Unit tests for the FastAPI action routes."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import (
    FakeEvents,
    FakeHITL,
    FakeIdentity,
    FakeLedger,
    FakePolicy,
)

TENANT = TenantId("ciro-bank")
AUTH = {"Authorization": "Bearer test-token"}


def _app(decision: Decision = Decision.ALLOW, raise_ledger: bool = False):
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(raise_exc=raise_ledger),
        events=FakeEvents(),
        identity=FakeIdentity(),  # API requires a configured IdentityPort
    )
    return create_app(kernel)


def _body(idempotency_key: str = "ik-1") -> dict:
    # No actor_id / actor_roles: identity is resolved from the bearer token, never the body.
    return {
        "type": "ciro.ifrs9.stage_transition",
        "payload": {"loan_id": "4471", "from_stage": 1, "to_stage": 2},
        "idempotency_key": idempotency_key,
    }


@pytest.fixture
def allow_app():
    return _app(Decision.ALLOW)


@pytest.fixture
def deny_app():
    return _app(Decision.DENY)


# ── POST /v1/actions/propose ─────────────────────────────────────────────────────


async def test_propose_without_token_returns_401(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body())
    assert resp.status_code == 401


async def test_propose_allow_returns_202(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    assert resp.status_code == 202
    data = resp.json()
    assert data["state"] == "COMPLETED"
    assert data["type"] == "ciro.ifrs9.stage_transition"


async def test_propose_actor_comes_from_token_not_body(allow_app):
    """The resolved actor (from the IdentityPort) is authoritative — the body cannot set it."""
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    # FakeIdentity resolves to "alice" regardless of any request content.
    assert resp.json()["actor_id"] == "alice"


async def test_propose_deny_returns_403(deny_app):
    async with AsyncClient(transport=ASGITransport(app=deny_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    assert resp.status_code == 403


async def test_propose_missing_fields_returns_422(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json={"type": "x"}, headers=AUTH)  # missing idempotency_key
    assert resp.status_code == 422


async def test_propose_ledger_failure_returns_422():
    app = _app(raise_ledger=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    assert resp.status_code == 422


async def test_propose_response_has_action_id(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    assert "action_id" in resp.json()


async def test_propose_response_has_tenant(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.post("/v1/actions/propose", json=_body(), headers=AUTH)
    assert resp.json()["tenant"] == "ciro-bank"


# ── GET /v1/actions/{id} ──────────────────────────────────────────────────────────


async def test_get_action_not_found_returns_404(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.get("/v1/actions/nonexistent-id", headers=AUTH)
    assert resp.status_code == 404


async def test_get_action_without_token_returns_401(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        propose = await client.post("/v1/actions/propose", json=_body("ik-get-401"), headers=AUTH)
        resp = await client.get(f"/v1/actions/{propose.json()['action_id']}")
    assert resp.status_code == 401


async def test_get_action_after_propose(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        propose = await client.post("/v1/actions/propose", json=_body("ik-get-test"), headers=AUTH)
        action_id = propose.json()["action_id"]
        get_resp = await client.get(f"/v1/actions/{action_id}", headers=AUTH)
    assert get_resp.status_code == 200
    assert get_resp.json()["action_id"] == action_id


async def test_get_action_uses_the_repository_protocol_not_in_memory_internals():
    """Regression: the route used to scan `repo.by_key`, which only the in-memory repository has,
    so it returned 404 for every action on Postgres."""
    from quaicu.core.types import ActionId, TenantId

    class ProtocolOnlyRepository:
        """Only the ActionRepository protocol — no `by_key`."""

        def __init__(self) -> None:
            self.rows: dict[tuple[str, str], object] = {}
            self.lookups: list[tuple[str, str]] = []

        async def insert_if_absent(self, action):
            self.rows[(str(action.tenant), str(action.id))] = action
            return None

        async def update_state(self, action):
            self.rows[(str(action.tenant), str(action.id))] = action

        async def get_by_idempotency_key(self, tenant, key):
            return None

        async def get_by_id(self, tenant: TenantId, action_id: ActionId):
            self.lookups.append((str(tenant), str(action_id)))
            return self.rows.get((str(tenant), str(action_id)))

    repo = ProtocolOnlyRepository()
    kernel = Kernel.from_parts(
        tenant=TenantId("ciro-bank"),
        policy=FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(),
        repository=repo,
    )
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        proposed = await client.post("/v1/actions/propose", json=_body("ik-proto"), headers=AUTH)
        action_id = proposed.json()["action_id"]
        found = await client.get(f"/v1/actions/{action_id}", headers=AUTH)
        missing = await client.get("/v1/actions/does-not-exist", headers=AUTH)
    assert found.status_code == 200 and found.json()["state"] == "COMPLETED"
    assert missing.status_code == 404
    assert repo.lookups[0] == ("ciro-bank", action_id)  # scoped to this kernel's tenant


# ── GET /health ───────────────────────────────────────────────────────────────────


async def test_health_endpoint(allow_app):
    async with AsyncClient(transport=ASGITransport(app=allow_app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
