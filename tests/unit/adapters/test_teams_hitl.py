"""MicrosoftTeamsHITLAdapter (D1-3) — posts an approval Adaptive Card with signed links."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.adapters.hitl.teams import MicrosoftTeamsHITLAdapter
from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.links import ApprovalLinkSigner
from quaicu.core.types import (
    Action,
    ActionId,
    Actor,
    ActorId,
    ApproverRef,
    IdempotencyKey,
    TenantId,
)

WEBHOOK = "https://outlook.office.com/webhook/abc"


def _action() -> Action:
    return Action(
        id=ActionId("a1"),
        type="loan.approve",
        payload={"amount": 5000},
        actor=Actor(id=ActorId("maker"), tenant=TenantId("acme"), roles=()),
        tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("k1"),
        proposed_at=datetime.now(timezone.utc),
    )


def _adapter(http_post) -> MicrosoftTeamsHITLAdapter:
    return MicrosoftTeamsHITLAdapter(
        webhook_url=WEBHOOK,
        signer=ApprovalLinkSigner("s3cret"),
        link_base_url="http://test",
        approver_id="checker",
        approver_roles=("role:approver",),
        http_post=http_post,
    )


async def test_request_approval_posts_card_with_signed_links() -> None:
    captured: list[tuple] = []

    async def _post(url, body):
        captured.append((url, body))
        return 200

    handle = await _adapter(_post).request_approval(
        action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
    )

    assert len(captured) == 1
    url, body = captured[0]
    assert url == WEBHOOK
    card = body["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    actions = card["actions"]
    assert [a["type"] for a in actions] == ["Action.OpenUrl", "Action.OpenUrl"]

    signer = ApprovalLinkSigner("s3cret")
    payloads = []
    for a in actions:
        token = a["url"].rsplit("/", 1)[-1]
        p = signer.verify(token)
        assert p is not None
        payloads.append(p)
    assert {p["d"] for p in payloads} == {"approve", "reject"}
    assert all(p["h"] == handle.id and p["t"] == "acme" and p["aid"] == "checker" for p in payloads)


async def test_request_approval_persists_routing_metadata() -> None:
    async def _post(url, body):
        return 200

    adapter = _adapter(_post)
    handle = await adapter.request_approval(
        action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
    )
    rec = adapter.get_record(handle.id)
    assert rec is not None
    assert rec.notify_channel == "teams"
    assert rec.notify_target == WEBHOOK
    assert rec.resume_link and "/v1/approvals/link/" in rec.resume_link
    assert rec.expires_at is None  # pending until a human decides


async def test_non_2xx_response_is_fail_closed_with_no_orphan() -> None:
    async def _post(url, body):
        return 500

    adapter = _adapter(_post)
    with pytest.raises(HITLPortError):
        await adapter.request_approval(
            action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
        )
    assert adapter.list_pending() == []  # send-then-persist → no orphan on failure


async def test_transport_error_is_fail_closed() -> None:
    async def _post(url, body):
        raise ConnectionError("teams unreachable")

    with pytest.raises(HITLPortError):
        await _adapter(_post).request_approval(
            action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
        )


def test_requires_webhook_url() -> None:
    with pytest.raises(ValueError):
        MicrosoftTeamsHITLAdapter(
            webhook_url="",
            signer=ApprovalLinkSigner("s3cret"),
            link_base_url="http://test",
            approver_id="checker",
        )
