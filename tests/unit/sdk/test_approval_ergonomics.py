"""D2-3: async-approval ergonomics — kernel.approve / kernel.reject over a caught pending error."""

from __future__ import annotations

import pytest

from quaicu.delivery.sdk import Kernel, LifecyclePendingApprovalError, QUAICUError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    TenantId,
)
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy

TENANT = TenantId("acme")
MAKER = Actor(id=ActorId("maker"), tenant=TENANT, roles=("role:approver",))
CHECKER = Actor(id=ActorId("checker"), tenant=TENANT, roles=("role:approver",))


def _kernel() -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(
            decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
        ),
        hitl=InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )


async def _state(kernel: Kernel, action_id: str) -> ActionState:
    action = await kernel.engine._repo.get_by_id(TENANT, ActionId(action_id))
    assert action is not None
    return action.state


def _guarded(kernel: Kernel):
    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str) -> dict:
        return {"ok": loan_id}

    return approve_loan


async def _suspend(kernel: Kernel, fn) -> tuple[str, str]:
    with pytest.raises(LifecyclePendingApprovalError) as ei:
        async with kernel.actor_context(MAKER):
            await fn(loan_id="L1")
    return ei.value.detail["handle_id"], ei.value.detail["action_id"]


async def test_approve_helper_resumes_and_seals():
    kernel = _kernel()
    handle_id, action_id = await _suspend(kernel, _guarded(kernel))

    record = await kernel.approve(handle_id, actor=CHECKER)

    assert await _state(kernel, action_id) is ActionState.COMPLETED
    assert str(record.decided_by) == "checker"
    assert len(kernel.engine._ledger.sealed) == 1  # type: ignore[attr-defined]


async def test_reject_helper_denies():
    kernel = _kernel()
    handle_id, action_id = await _suspend(kernel, _guarded(kernel))

    await kernel.reject(handle_id, actor=CHECKER)

    assert await _state(kernel, action_id) is ActionState.DENIED


async def test_self_approval_is_blocked():
    # The maker who proposed the action cannot approve it (separation of duties, fail-closed).
    kernel = _kernel()
    handle_id, action_id = await _suspend(kernel, _guarded(kernel))

    with pytest.raises(QUAICUError):
        await kernel.approve(handle_id, actor=MAKER)

    assert await _state(kernel, action_id) is ActionState.PENDING_APPROVAL
