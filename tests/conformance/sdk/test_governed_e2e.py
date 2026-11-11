"""Conformance tests — @governed decorator end-to-end contract.

These tests exercise the full SDK surface (Kernel + @governed) with fake adapters
and verify that the behaviour required by the spec is maintained.
"""

from __future__ import annotations

import pytest

from quaicu.delivery.sdk import SdkUsageError

from quaicu.core.errors import (
    LifecycleDeniedError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
)
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApprovalDecision,
    ApproverRef,
    Decision,
    TenantId,
)
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import (
    FakeEvents,
    FakeHITL,
    FakeLedger,
    FakePolicy,
)

TENANT = TenantId("spec-tenant")


def _actor(id: str = "alice") -> Actor:
    return Actor(id=ActorId(id), tenant=TENANT, roles=("role:analyst",))


def _kernel(
    *,
    decision: Decision = Decision.ALLOW,
    hitl_decision: ApprovalDecision = ApprovalDecision.APPROVED,
    raise_ledger: bool = False,
    require_approval: bool = False,
) -> Kernel:
    policy = FakePolicy(
        decision=Decision.REQUIRE_APPROVAL if require_approval else decision,
        approvers=("approver@spec",) if require_approval else (),
    )
    return Kernel.from_parts(
        tenant=TENANT,
        policy=policy,
        hitl=FakeHITL(decision=hitl_decision),
        ledger=FakeLedger(raise_exc=raise_ledger),
        events=FakeEvents(),
    )


# ── C-SDK-01 Allowed actions complete ────────────────────────────────────────────


async def test_c_sdk_01_allowed_action_completes():
    k = _kernel(decision=Decision.ALLOW)

    @k.governed(policy="spec.allowed_action")
    async def fn(*, actor: Actor):
        return "result"

    action = await fn(actor=_actor())
    assert action.state == ActionState.COMPLETED


# ── C-SDK-02 Denied actions raise LifecycleDeniedError ───────────────────────────


async def test_c_sdk_02_denied_action_raises():
    k = _kernel(decision=Decision.DENY)

    @k.governed(policy="spec.denied_action")
    async def fn(*, actor: Actor):
        return "result"

    with pytest.raises(LifecycleDeniedError) as exc_info:
        await fn(actor=_actor())
    assert "denied" in str(exc_info.value).lower()


# ── C-SDK-03 Execute body runs only on allow ─────────────────────────────────────


async def test_c_sdk_03_execute_body_runs_iff_allowed():
    calls = []

    k_allow = _kernel(decision=Decision.ALLOW)
    k_deny = _kernel(decision=Decision.DENY)

    @k_allow.governed(policy="spec.body_test")
    async def fn_allow(*, actor: Actor):
        calls.append("allow")
        return "ok"

    @k_deny.governed(policy="spec.body_test")
    async def fn_deny(*, actor: Actor):
        calls.append("deny")
        return "ok"

    await fn_allow(actor=_actor())
    with pytest.raises(LifecycleDeniedError):
        await fn_deny(actor=_actor())

    assert calls == ["allow"]


# ── C-SDK-04 Ledger sealed on COMPLETED ──────────────────────────────────────────


async def test_c_sdk_04_ledger_sealed_on_completed():
    ledger = FakeLedger()
    k = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=ledger,
        events=FakeEvents(),
    )

    @k.governed(policy="spec.seal_test")
    async def fn(*, actor: Actor):
        return "sealed"

    await fn(actor=_actor())
    assert len(ledger.sealed) == 1
    assert ledger.sealed[0].action_type == "spec.seal_test"


# ── C-SDK-05 Seal failure → LifecycleHaltedError ─────────────────────────────────


async def test_c_sdk_05_seal_failure_halts():
    k = _kernel(raise_ledger=True)

    @k.governed(policy="spec.seal_failure")
    async def fn(*, actor: Actor):
        return "ok"

    with pytest.raises(LifecycleHaltedError):
        await fn(actor=_actor())


# ── C-SDK-06/07 HITL: require_approval suspends durably, then resumes on the decision ─────
# (D1-1: the SDK path defers instead of poll-once → TIMED_OUT → DENY. The decorated call raises
# LifecyclePendingApprovalError; an authorized, non-proposing approver resolves it out-of-band.)

_CHECKER = Actor(id=ActorId("checker"), tenant=TENANT, roles=("role:approver",))


def _approval_kernel() -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(
            decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)
        ),
        hitl=InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )


async def _suspend(fn) -> tuple[str, str]:
    with pytest.raises(LifecyclePendingApprovalError) as ei:
        await fn(actor=_actor())
    return ei.value.detail["handle_id"], ei.value.detail["action_id"]


async def test_c_sdk_06_hitl_approval_completes():
    k = _approval_kernel()

    @k.governed(policy="spec.hitl_action")
    async def fn(*, actor: Actor):
        return "approved"

    handle_id, action_id = await _suspend(fn)
    await k.decide_approval(handle_id, decision="approved", actor=_CHECKER)
    action = await k.engine._repo.get_by_id(TENANT, ActionId(action_id))
    assert action is not None and action.state == ActionState.COMPLETED


async def test_c_sdk_07_hitl_rejection_denies():
    k = _approval_kernel()

    @k.governed(policy="spec.hitl_rejection")
    async def fn(*, actor: Actor):
        return "ok"

    handle_id, action_id = await _suspend(fn)
    await k.decide_approval(handle_id, decision="rejected", actor=_CHECKER)
    action = await k.engine._repo.get_by_id(TENANT, ActionId(action_id))
    assert action is not None and action.state == ActionState.DENIED


# ── C-SDK-08 Missing actor is a hard TypeError ───────────────────────────────────


async def test_c_sdk_08_missing_actor_is_type_error():
    k = _kernel()

    @k.governed(policy="spec.no_actor")
    async def fn(value: int, *, actor: Actor):
        return value

    with pytest.raises(SdkUsageError, match="actor"):
        await fn(42)
