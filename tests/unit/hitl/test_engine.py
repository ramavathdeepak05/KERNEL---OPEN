from __future__ import annotations

from datetime import UTC, datetime

import pytest

from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApprovalDecision,
    ApprovalHandle,
    ApproverRef,
    IdempotencyKey,
    TenantId,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _tenant(name: str = "tenant-a") -> TenantId:
    return TenantId(name)


def _actor(uid: str = "actor-1", tenant: str = "tenant-a") -> Actor:
    return Actor(id=ActorId(uid), tenant=TenantId(tenant))


def _action(
    action_id: str = "action-1",
    tenant: str = "tenant-a",
    actor_uid: str = "actor-1",
) -> Action:
    return Action(
        id=ActionId(action_id),
        type="test.action",
        payload={},
        actor=_actor(actor_uid, tenant),
        tenant=TenantId(tenant),
        idempotency_key=IdempotencyKey(f"idem-{action_id}"),
        state=ActionState.PROPOSED,
        proposed_at=datetime.now(UTC),
    )


def _approvers(*refs: str) -> list[ApproverRef]:
    return [ApproverRef(r) for r in refs]


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_request_approval_returns_handle() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    assert isinstance(handle, ApprovalHandle)
    assert handle.id != ""


async def test_poll_returns_pending_initially() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.PENDING


async def test_approve_then_poll_returns_approved() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.approve(
        handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.APPROVED
    assert outcome.decided_by == ActorId("admin")  # ADR-0007: poll surfaces the decider


async def test_reject_then_poll_returns_rejected() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.reject(
        handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.REJECTED


async def test_force_expire_then_poll_returns_timed_out() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.force_expire(handle.id)
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.TIMED_OUT


async def test_zero_timeout_is_immediately_expired() -> None:
    port = InProcessHITLPort(timeout_seconds=0)
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.PENDING


async def test_double_approve_raises() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.approve(
        handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    with pytest.raises(HITLPortError):
        await port.approve(
            handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
        )


async def test_approve_after_reject_raises() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.reject(
        handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    with pytest.raises(HITLPortError):
        await port.approve(
            handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
        )


async def test_approve_nonexistent_handle_raises() -> None:
    port = InProcessHITLPort()
    with pytest.raises(HITLPortError):
        await port.approve("bad-id", approver_actor_id=ActorId("admin"))


async def test_poll_nonexistent_handle_raises() -> None:
    port = InProcessHITLPort()
    bad_handle = ApprovalHandle(id="no-such-handle", tenant=_tenant())
    with pytest.raises(HITLPortError):
        await port.poll(bad_handle)


async def test_unauthorized_user_ref_raises() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("user:alice"),
        tenant=_tenant(),
    )
    with pytest.raises(HITLPortError):
        await port.approve(handle.id, approver_actor_id=ActorId("bob"))


async def test_authorized_user_ref_passes() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("user:alice"),
        tenant=_tenant(),
    )
    await port.approve(handle.id, approver_actor_id=ActorId("alice"))
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.APPROVED


async def test_role_ref_requires_matching_role() -> None:
    """An actor holding the required role may approve a role-gated request."""
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.approve(
        handle.id, approver_actor_id=ActorId("carol"), approver_roles=("role:risk_head",)
    )
    outcome = await port.poll(handle)
    assert outcome.decision is ApprovalDecision.APPROVED


async def test_role_gate_rejects_actor_without_role() -> None:
    """Fail-closed: an actor lacking the required role cannot approve a role-gated request."""
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    with pytest.raises(HITLPortError):
        await port.approve(
            handle.id, approver_actor_id=ActorId("nobody"), approver_roles=("role:teller",)
        )


async def test_proposer_cannot_self_approve() -> None:
    """Separation of duties: the actor who proposed the action may never approve it."""
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(actor_uid="alice"),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    with pytest.raises(HITLPortError):
        await port.approve(
            handle.id, approver_actor_id=ActorId("alice"), approver_roles=("role:risk_head",)
        )


async def test_get_record_returns_full_record() -> None:
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    await port.approve(
        handle.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    record = port.get_record(handle.id)
    assert record is not None
    assert record.decided_by == ActorId("admin")
    assert record.decided_at is not None
    assert record.decision is ApprovalDecision.APPROVED


async def test_tenant_isolation() -> None:
    port = InProcessHITLPort()
    handle_a = await port.request_approval(
        action=_action("action-a", "tenant-a"),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant("tenant-a"),
    )
    handle_b = await port.request_approval(
        action=_action("action-b", "tenant-b"),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant("tenant-b"),
    )
    await port.approve(
        handle_a.id, approver_actor_id=ActorId("admin"), approver_roles=("role:risk_head",)
    )
    assert (await port.poll(handle_a)).decision is ApprovalDecision.APPROVED
    assert (await port.poll(handle_b)).decision is ApprovalDecision.PENDING


async def test_handle_id_is_unique_per_request() -> None:
    port = InProcessHITLPort()
    handle_1 = await port.request_approval(
        action=_action("action-1"),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    handle_2 = await port.request_approval(
        action=_action("action-2"),
        approvers=_approvers("role:risk_head"),
        tenant=_tenant(),
    )
    assert handle_1.id != handle_2.id


# ── One person is one actor across id forms ("member:<id>" vs "<id>") ────────────


async def test_named_user_approver_matches_either_member_id_form():
    for required, approver in [
        ("user:member:mem_1", "mem_1"),  # policy written with the prefixed id
        ("user:mem_1", "member:mem_1"),  # host sending the prefixed form
        ("user:mem_1", "mem_1"),
    ]:
        port = InProcessHITLPort()
        handle = await port.request_approval(
            action=_action(), approvers=[ApproverRef(required)], tenant=_tenant()
        )
        await port.approve(handle.id, approver_actor_id=ActorId(approver))
        assert (await port.poll(handle)).decision is ApprovalDecision.APPROVED


async def test_named_user_approver_still_rejects_a_different_user():
    port = InProcessHITLPort()
    handle = await port.request_approval(
        action=_action(), approvers=[ApproverRef("user:mem_1")], tenant=_tenant()
    )
    with pytest.raises(HITLPortError):
        await port.approve(handle.id, approver_actor_id=ActorId("mem_2"))
