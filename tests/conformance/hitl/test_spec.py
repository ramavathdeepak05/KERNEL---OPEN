"""Conformance: spec §6 K·03 DoD requirements."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApprovalDecision,
    ApproverRef,
    IdempotencyKey,
    TenantId,
)


def _action(action_id: str = "conf-action-1", tenant: str = "conf-tenant") -> Action:
    return Action(
        id=ActionId(action_id),
        type="conformance.test",
        payload={},
        actor=Actor(id=ActorId("conf-actor"), tenant=TenantId(tenant)),
        tenant=TenantId(tenant),
        idempotency_key=IdempotencyKey(f"idem-{action_id}"),
        state=ActionState.PROPOSED,
        proposed_at=datetime.now(UTC),
    )


def _approvers(*refs: str) -> list[ApproverRef]:
    return [ApproverRef(r) for r in refs]


@pytest.mark.conformance
async def test_require_approval_suspends_durably() -> None:
    """PENDING state persists across multiple poll calls without side effects."""
    port = InProcessHITLPort(timeout_seconds=86400)
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=TenantId("conf-tenant"),
    )
    for _ in range(5):
        outcome = await port.poll(handle)
        assert outcome.decision is ApprovalDecision.PENDING

    record = port.get_record(handle.id)
    assert record is not None
    assert record.decision is ApprovalDecision.PENDING
    assert record.decided_by is None
    assert record.decided_at is None


@pytest.mark.conformance
async def test_timeout_resolves_fail_closed() -> None:
    """Timeout → TIMED_OUT, and TIMED_OUT is treated as REJECTED (fail-closed)."""
    port = InProcessHITLPort(timeout_seconds=86400)
    handle = await port.request_approval(
        action=_action("conf-action-timeout"),
        approvers=_approvers("role:risk_head"),
        tenant=TenantId("conf-tenant"),
    )
    await port.force_expire(handle.id)
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.TIMED_OUT
    assert outcome.decision is not ApprovalDecision.APPROVED
    assert outcome.decision != ApprovalDecision.APPROVED


@pytest.mark.conformance
async def test_approver_identity_recorded() -> None:
    """The deciding actor's identity is captured in the approval record (resolves open ADR)."""
    port = InProcessHITLPort()
    approver_id = ActorId("risk-officer-99")
    handle = await port.request_approval(
        action=_action("conf-action-identity"),
        approvers=_approvers("user:risk-officer-99"),
        tenant=TenantId("conf-tenant"),
    )
    await port.approve(handle.id, approver_actor_id=approver_id)
    record = port.get_record(handle.id)
    assert record is not None
    assert record.decided_by == approver_id
    assert record.decided_at is not None
    assert record.decision is ApprovalDecision.APPROVED
