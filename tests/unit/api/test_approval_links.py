"""Signed email-link approval round-trip through /v1/approvals/link/{token} (D1-2)."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from quaicu.adapters.hitl.email import EmailHITLAdapter
from quaicu.core.errors import LifecyclePendingApprovalError
from quaicu.core.hitl.links import ApprovalLinkSigner
from quaicu.core.types import (
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    TenantId,
)
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy

SECRET = "link-secret"
MAKER = Actor(id=ActorId("maker"), tenant=TenantId("acme"), roles=())


class _Capture:
    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, message) -> None:
        self.sent.append(message)


def _app():
    adapter = EmailHITLAdapter(
        sender=_Capture(),
        signer=ApprovalLinkSigner(SECRET),
        link_base_url="http://test",
        approver_email="compliance@x.io",
        approver_id="checker",
        approver_roles=("role:approver",),
    )
    kernel = Kernel.from_parts(
        tenant="acme",
        policy=FakePolicy(
            decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
        ),
        hitl=adapter,
        ledger=FakeLedger(),
        events=FakeEvents(),
    )
    return create_app(kernel), kernel


async def _make_pending(kernel) -> tuple[str, str]:
    """Drive a require_approval guarded call to durable PENDING; return (handle_id, action_id)."""

    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str) -> dict:
        return {"ok": loan_id}

    with pytest.raises(LifecyclePendingApprovalError) as ei:
        async with kernel.actor_context(MAKER):
            await approve_loan(loan_id="L1")
    return ei.value.detail["handle_id"], ei.value.detail["action_id"]


def _token(handle_id: str, decision: str) -> str:
    return ApprovalLinkSigner(SECRET).sign(
        handle_id=handle_id,
        tenant="acme",
        decision=decision,
        approver_id="checker",
        approver_roles=("role:approver",),
    )


async def _state(kernel, action_id: str) -> ActionState:
    action = await kernel.engine._repo.get_by_id(TenantId("acme"), ActionId(action_id))
    assert action is not None
    return action.state


async def test_approve_link_resumes_and_seals(monkeypatch) -> None:
    monkeypatch.setenv("QUAICU_APPROVAL_LINK_SECRET", SECRET)
    app, kernel = _app()
    handle_id, action_id = await _make_pending(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        # GET renders a confirm page (prefetch-safe); POST commits.
        page = await c.get(f"/v1/approvals/link/{_token(handle_id, 'approve')}")
        assert page.status_code == 200 and "Confirm approve" in page.text
        resp = await c.post(f"/v1/approvals/link/{_token(handle_id, 'approve')}")
    assert resp.status_code == 200
    assert await _state(kernel, action_id) is ActionState.COMPLETED


async def test_reject_link_denies(monkeypatch) -> None:
    monkeypatch.setenv("QUAICU_APPROVAL_LINK_SECRET", SECRET)
    app, kernel = _app()
    handle_id, action_id = await _make_pending(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post(f"/v1/approvals/link/{_token(handle_id, 'reject')}")
    assert resp.status_code == 200
    assert await _state(kernel, action_id) is ActionState.DENIED


async def test_reused_link_is_single_use(monkeypatch) -> None:
    monkeypatch.setenv("QUAICU_APPROVAL_LINK_SECRET", SECRET)
    app, kernel = _app()
    handle_id, _ = await _make_pending(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        first = await c.post(f"/v1/approvals/link/{_token(handle_id, 'approve')}")
        second = await c.post(f"/v1/approvals/link/{_token(handle_id, 'approve')}")
    assert first.status_code == 200
    assert second.status_code == 409  # already decided


async def test_tampered_token_rejected(monkeypatch) -> None:
    monkeypatch.setenv("QUAICU_APPROVAL_LINK_SECRET", SECRET)
    app, kernel = _app()
    await _make_pending(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post("/v1/approvals/link/not-a-valid-token")
    assert resp.status_code == 400


async def test_links_disabled_without_secret(monkeypatch) -> None:
    monkeypatch.delenv("QUAICU_APPROVAL_LINK_SECRET", raising=False)
    app, kernel = _app()
    handle_id, _ = await _make_pending(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post(f"/v1/approvals/link/{_token(handle_id, 'approve')}")
    assert resp.status_code == 503  # QUAICU_APPROVAL_LINK_SECRET unset
