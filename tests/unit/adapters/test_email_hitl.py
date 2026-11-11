"""EmailHITLAdapter + ApprovalLinkSigner (D1-2)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from quaicu.adapters.hitl.email import EmailHITLAdapter
from quaicu.core.errors import EmailPortError, HITLPortError
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


class _CaptureSender:
    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, message) -> None:
        self.sent.append(message)


class _RaisingSender:
    async def send(self, message) -> None:
        raise EmailPortError("provider down")


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


def _adapter(sender) -> EmailHITLAdapter:
    return EmailHITLAdapter(
        sender=sender,
        signer=ApprovalLinkSigner("s3cret"),
        link_base_url="http://test",
        approver_email="compliance@x.io",
        approver_id="checker",
        approver_roles=("role:approver",),
    )


async def test_request_approval_sends_signed_approve_and_reject_links() -> None:
    cap = _CaptureSender()
    handle = await _adapter(cap).request_approval(
        action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
    )
    assert len(cap.sent) == 1
    msg = cap.sent[0]
    assert msg.to == "compliance@x.io"

    signer = ApprovalLinkSigner("s3cret")
    tokens = re.findall(r"/v1/approvals/link/([\w\-.]+)", msg.text)
    assert len(tokens) == 2
    payloads = [signer.verify(t) for t in tokens]
    assert all(p is not None for p in payloads)
    assert {p["d"] for p in payloads} == {"approve", "reject"}
    assert all(p["h"] == handle.id for p in payloads)
    assert all(p["t"] == "acme" and p["aid"] == "checker" for p in payloads)


async def test_request_approval_persists_routing_metadata() -> None:
    adapter = _adapter(_CaptureSender())
    handle = await adapter.request_approval(
        action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
    )
    rec = adapter.get_record(handle.id)
    assert rec is not None
    assert rec.notify_channel == "email"
    assert rec.notify_target == "compliance@x.io"
    assert rec.resume_link and "/v1/approvals/link/" in rec.resume_link
    assert rec.expires_at is None  # pending until a human decides (no auto-expiry)
    # The stored resume_link is the signed approve link for this handle.
    token = rec.resume_link.rsplit("/", 1)[-1]
    payload = ApprovalLinkSigner("s3cret").verify(token)
    assert payload is not None and payload["d"] == "approve" and payload["h"] == handle.id


async def test_send_failure_is_fail_closed_with_no_orphan() -> None:
    adapter = _adapter(_RaisingSender())
    with pytest.raises(HITLPortError):
        await adapter.request_approval(
            action=_action(), approvers=[ApproverRef("role:approver")], tenant=TenantId("acme")
        )
    # send-then-persist: a failed send stores nothing (no orphan PENDING record).
    assert adapter.list_pending() == []


def test_signer_roundtrip_tamper_and_expiry() -> None:
    signer = ApprovalLinkSigner("key")
    tok = signer.sign(
        handle_id="h1", tenant="acme", decision="approve", approver_id="checker",
        approver_roles=("role:approver",),
    )
    payload = signer.verify(tok)
    assert payload is not None and payload["h"] == "h1" and payload["d"] == "approve"

    assert signer.verify(tok[:-3] + "AAA") is None          # tampered signature
    assert ApprovalLinkSigner("other").verify(tok) is None  # wrong secret
    assert signer.verify("not-a-token") is None             # malformed
    expired = signer.sign(
        handle_id="h1", tenant="acme", decision="approve", approver_id="c", ttl_seconds=-1
    )
    assert signer.verify(expired) is None                   # expired


def test_signer_rejects_empty_secret_and_bad_decision() -> None:
    with pytest.raises(ValueError):
        ApprovalLinkSigner("")
    with pytest.raises(ValueError):
        ApprovalLinkSigner("k").sign(
            handle_id="h", tenant="t", decision="maybe", approver_id="c"
        )
