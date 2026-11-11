"""Async-by-default approval on the SDK path (D1-1).

A `require_approval` policy must **suspend the action durably** on the SDK entry points
(`guard`/`generate`) instead of the old poll-once → TIMED_OUT → false DENY. The suspended action is
recorded + its approval registered; approving resumes (execute → seal), rejecting DENIES. Fail-closed is
preserved: a HITL-infra failure still HALTs.
"""

from __future__ import annotations

import pytest

from quaicu.core.errors import LifecycleHaltedError, LifecyclePendingApprovalError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    ModelRef,
    TenantId,
)
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy

TENANT = "acme"
MAKER = Actor(id=ActorId("maker"), tenant=TenantId(TENANT), roles=())
CHECKER = Actor(id=ActorId("checker"), tenant=TenantId(TENANT), roles=("role:approver",))


def _kernel(*, hitl=None, policy=None) -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=policy
        or FakePolicy(
            decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
        ),
        hitl=hitl or InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )


async def _action_state(kernel: Kernel, action_id: str) -> ActionState:
    action = await kernel.engine._repo.get_by_id(TenantId(TENANT), ActionId(action_id))
    assert action is not None
    return action.state


async def test_guard_require_approval_suspends_instead_of_denying() -> None:
    kernel = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str, amount: float) -> dict:
        return {"ok": loan_id}

    with pytest.raises(LifecyclePendingApprovalError) as ei:
        async with kernel.actor_context(MAKER):
            await approve_loan(loan_id="L1", amount=100.0)

    # Durably pending — not a false DENY — with a decidable handle.
    handle_id = ei.value.detail["handle_id"]
    assert handle_id is not None
    action_id = ei.value.detail["action_id"]
    assert await _action_state(kernel, action_id) is ActionState.PENDING_APPROVAL
    assert len(kernel.list_pending_approvals()) == 1


async def test_approval_resumes_and_seals() -> None:
    kernel = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str) -> dict:
        return {"ok": loan_id}

    with pytest.raises(LifecyclePendingApprovalError) as ei:
        async with kernel.actor_context(MAKER):
            await approve_loan(loan_id="L1")
    handle_id = ei.value.detail["handle_id"]
    action_id = ei.value.detail["action_id"]

    # An authorized, non-proposing approver resumes it → execute + seal → COMPLETED.
    await kernel.decide_approval(handle_id, decision="approved", actor=CHECKER)
    assert await _action_state(kernel, action_id) is ActionState.COMPLETED

    # Resume is idempotent: re-driving a resolved action is a no-op (no double-seal / re-execute).
    await kernel.resume_approved(handle_id, approver=CHECKER)
    assert await _action_state(kernel, action_id) is ActionState.COMPLETED


async def test_rejection_denies_the_pending_action() -> None:
    kernel = _kernel()

    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str) -> dict:
        return {"ok": loan_id}

    with pytest.raises(LifecyclePendingApprovalError) as ei:
        async with kernel.actor_context(MAKER):
            await approve_loan(loan_id="L1")
    handle_id = ei.value.detail["handle_id"]
    action_id = ei.value.detail["action_id"]

    await kernel.decide_approval(handle_id, decision="rejected", actor=CHECKER)
    assert await _action_state(kernel, action_id) is ActionState.DENIED


async def test_wrap_require_approval_suspends() -> None:
    # kernel.wrap must defer like kernel.guard (regression: it was missed by the original defer change).
    kernel = _kernel()

    async def transfer(amount: int) -> dict:
        return {"moved": amount}

    governed = kernel.wrap(transfer, policy="payments.transfer", actor=MAKER)
    with pytest.raises(LifecyclePendingApprovalError):
        await governed(amount=100)


async def test_generate_require_approval_suspends_without_calling_gateway() -> None:
    class _StubGateway:
        async def generate(self, **_: object):  # pragma: no cover - must not run when deferred
            raise AssertionError("gateway must not execute for a deferred (pending) action")

    kernel = _kernel()
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(
            decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
        ),
        hitl=InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        gateway=_StubGateway(),  # present but must not be called on the deferred path
    )

    with pytest.raises(LifecyclePendingApprovalError):
        await kernel.generate(
            prompt_text="hi", model_ref=ModelRef(id="m1", version="1"), actor=MAKER
        )


async def test_hitl_infra_failure_still_halts_fail_closed() -> None:
    class _RaisingHITL:
        async def request_approval(self, **_: object):
            from quaicu.core.errors import HITLPortError

            raise HITLPortError("injected HITL outage")

    kernel = _kernel(hitl=_RaisingHITL())

    @kernel.guard(policy="loans.approve")
    async def approve_loan(loan_id: str) -> dict:
        return {"ok": loan_id}

    # A real infra failure on the gate must HALT (fail-closed), not silently pend.
    with pytest.raises(LifecycleHaltedError):
        async with kernel.actor_context(MAKER):
            await approve_loan(loan_id="L1")
