"""Unit tests for the HITL approvals API (/v1/approvals)."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    IdempotencyKey,
    TenantId,
)
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakeIdentity, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}


def _kernel(*, hitl=None, with_identity=True, identity_roles=("role:risk_head",)):
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(),
        hitl=hitl if hitl is not None else InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(roles=identity_roles) if with_identity else None,
    )


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _request_approval(hitl: InProcessHITLPort, *, approvers, proposer="bob"):
    """Create a PENDING approval record (proposed by ``proposer``) and return its handle id."""
    action = Action(
        id=ActionId(f"act-{proposer}"),
        type="payments.wire",
        payload={},
        actor=Actor(id=ActorId(proposer), tenant=TENANT),
        tenant=TENANT,
        idempotency_key=IdempotencyKey(f"k-{proposer}"),
        state=ActionState.PENDING_APPROVAL,
    )
    handle = await hitl.request_approval(
        action=action, approvers=[ApproverRef(a) for a in approvers], tenant=TENANT
    )
    return handle.id


# ── Auth ─────────────────────────────────────────────────────────────────────────


async def test_list_without_token_returns_401() -> None:
    async with _client(create_app(_kernel())) as c:
        resp = await c.get("/v1/approvals")
    assert resp.status_code == 401


async def test_list_without_identity_returns_503() -> None:
    async with _client(create_app(_kernel(with_identity=False))) as c:
        resp = await c.get("/v1/approvals", headers=AUTH)
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "IDENTITY_NOT_CONFIGURED"


async def test_non_inprocess_hitl_returns_503() -> None:
    async with _client(create_app(_kernel(hitl=FakeHITLNonListable()))) as c:
        resp = await c.get("/v1/approvals", headers=AUTH)
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "HITL_QUEUE_UNAVAILABLE"


class FakeHITLNonListable:
    """A HITL port that is not an InProcessHITLPort (external/webhook-style)."""

    async def request_approval(self, **_):  # pragma: no cover - not exercised
        raise NotImplementedError

    async def poll(self, _):  # pragma: no cover
        raise NotImplementedError


# ── List ─────────────────────────────────────────────────────────────────────────


async def test_list_pending_returns_records() -> None:
    hitl = InProcessHITLPort()
    kernel = _kernel(hitl=hitl)
    await _request_approval(hitl, approvers=["role:risk_head"])
    async with _client(create_app(kernel)) as c:
        resp = await c.get("/v1/approvals", headers=AUTH)
    data = resp.json()
    assert resp.status_code == 200
    assert data["count"] == 1
    assert data["approvals"][0]["decision"] == "PENDING"
    assert data["approvals"][0]["required_approvers"] == ["role:risk_head"]


async def test_list_empty() -> None:
    async with _client(create_app(_kernel())) as c:
        resp = await c.get("/v1/approvals", headers=AUTH)
    assert resp.json() == {"approvals": [], "count": 0}


# ── Approve / reject ───────────────────────────────────────────────────────────────


async def test_approve_updates_record() -> None:
    hitl = InProcessHITLPort()
    # FakeIdentity resolves the actor to id 'alice' with role:risk_head; make the proposer someone
    # else so the self-approval guard does not trip.
    handle = await _request_approval(hitl, approvers=["role:risk_head"], proposer="carol")
    kernel = _kernel(hitl=hitl, identity_roles=("role:risk_head",))
    async with _client(create_app(kernel)) as c:
        resp = await c.post(f"/v1/approvals/{handle}/approve", headers=AUTH)
    data = resp.json()
    assert resp.status_code == 200
    assert data["decision"] == "APPROVED"
    assert data["decided_by"] == "alice"


async def test_reject_updates_record() -> None:
    hitl = InProcessHITLPort()
    handle = await _request_approval(hitl, approvers=["role:risk_head"], proposer="carol")
    async with _client(create_app(_kernel(hitl=hitl))) as c:
        resp = await c.post(f"/v1/approvals/{handle}/reject", headers=AUTH)
    assert resp.json()["decision"] == "REJECTED"


async def test_approve_missing_returns_404() -> None:
    async with _client(create_app(_kernel())) as c:
        resp = await c.post("/v1/approvals/nope/approve", headers=AUTH)
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "APPROVAL_NOT_FOUND"


async def test_unauthorized_approver_returns_409() -> None:
    hitl = InProcessHITLPort()
    # Required approver is a role the resolved actor (role:risk_head) does NOT hold.
    handle = await _request_approval(hitl, approvers=["role:board"], proposer="carol")
    async with _client(create_app(_kernel(hitl=hitl, identity_roles=("role:risk_head",)))) as c:
        resp = await c.post(f"/v1/approvals/{handle}/approve", headers=AUTH)
    assert resp.status_code == 409


async def test_self_approval_blocked_returns_409() -> None:
    hitl = InProcessHITLPort()
    # Proposer is 'alice' (== the resolved actor) → separation-of-duties guard trips.
    handle = await _request_approval(hitl, approvers=["role:risk_head"], proposer="alice")
    async with _client(create_app(_kernel(hitl=hitl))) as c:
        resp = await c.post(f"/v1/approvals/{handle}/approve", headers=AUTH)
    assert resp.status_code == 409


async def test_already_decided_returns_409() -> None:
    hitl = InProcessHITLPort()
    handle = await _request_approval(hitl, approvers=["role:risk_head"], proposer="carol")
    async with _client(create_app(_kernel(hitl=hitl))) as c:
        first = await c.post(f"/v1/approvals/{handle}/approve", headers=AUTH)
        second = await c.post(f"/v1/approvals/{handle}/reject", headers=AUTH)
    assert first.status_code == 200
    assert second.status_code == 409
