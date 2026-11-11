"""Phase B — async resume-on-approval (deferred HITL gate).

A `require_approval` action proposed with `defer_gate=True` pauses at PENDING_APPROVAL (durably queued,
not sealed); an authorized approval then resumes it (execute → seal → emit). Covers the fail-closed +
idempotency + separation-of-duties invariants on this new lifecycle path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    IdempotencyKey,
    TenantId,
)
from quaicu.delivery.sdk.kernel import Kernel, _InMemoryActionRepository

from tests.unit.lifecycle.fakes import FakeEvents, FakeLedger, FakePolicy

TENANT = TenantId("acme")
# Both carry the required role; separation of duties keys on identity, not role.
PROPOSER = Actor(id=ActorId("agent:proposer"), tenant=TENANT, roles=("role:approver",))
APPROVER = Actor(id=ActorId("officer"), tenant=TENANT, roles=("role:approver",))


def _kernel() -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)),
        hitl=InProcessHITLPort(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        repository=_InMemoryActionRepository(),
    )


async def _propose_gated(kernel: Kernel, ikey: str = "ik-1") -> Action:
    action = Action(
        id=ActionId(str(uuid.uuid4())),
        type="credit.approve",
        payload={"amount": 1},
        actor=PROPOSER,
        tenant=TENANT,
        idempotency_key=IdempotencyKey(ikey),
        proposed_at=datetime.now(tz=timezone.utc),
    )

    async def _ex() -> dict:
        return {"payload": dict(action.payload)}

    return await kernel.engine.run(action, _ex, defer_gate=True)


def _ledger(kernel: Kernel) -> FakeLedger:
    return kernel.engine._ledger  # type: ignore[attr-defined]


async def test_gated_propose_pauses_without_sealing() -> None:
    k = _kernel()
    final = await _propose_gated(k)
    assert final.state is ActionState.PENDING_APPROVAL
    assert _ledger(k).sealed == []  # not executed/sealed yet
    pending = k.list_pending_approvals()
    assert len(pending) == 1 and str(pending[0].action_id) == str(final.id)


async def test_approve_resumes_executes_and_seals_with_approver() -> None:
    k = _kernel()
    pending = await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id

    await k.decide_approval(handle, decision="approved", actor=APPROVER)

    sealed = _ledger(k).sealed
    assert len(sealed) == 1
    assert sealed[0].approver is not None  # the approver identity is sealed (ADR-0007)
    resumed = await k.engine._repo.get_by_id(TENANT, pending.id)  # type: ignore[attr-defined]
    assert resumed.state is ActionState.COMPLETED


async def test_double_approve_is_idempotent_single_seal() -> None:
    k = _kernel()
    pending = await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id

    await k.decide_approval(handle, decision="approved", actor=APPROVER)
    # Re-driving resume after the action is COMPLETED must not execute/seal again.
    await k.resume_approved(handle, approver=APPROVER)

    assert len(_ledger(k).sealed) == 1
    _ = pending


async def test_self_approval_blocked_no_seal() -> None:
    k = _kernel()
    await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id

    with pytest.raises(HITLPortError):
        await k.decide_approval(handle, decision="approved", actor=PROPOSER)  # proposer == approver
    assert _ledger(k).sealed == []


async def test_reject_denies_pending_action_no_seal() -> None:
    k = _kernel()
    pending = await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id

    await k.decide_approval(handle, decision="rejected", actor=APPROVER)

    denied = await k.engine._repo.get_by_id(TENANT, pending.id)  # type: ignore[attr-defined]
    assert denied.state is ActionState.DENIED
    assert _ledger(k).sealed == []


async def test_resume_denies_when_policy_now_denies() -> None:
    k = _kernel()
    pending = await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id
    # Policy flips to DENY between propose and approve → resume must fail-closed deny, never execute.
    k.engine._policy.decision = Decision.DENY  # type: ignore[attr-defined]

    await k.decide_approval(handle, decision="approved", actor=APPROVER)

    resumed = await k.engine._repo.get_by_id(TENANT, pending.id)  # type: ignore[attr-defined]
    assert resumed.state is ActionState.DENIED
    assert _ledger(k).sealed == []


# ── Consent is re-checked when an approved action resumes ───────────────────────


class _ConsentPort:
    """A consent store whose single record the test can change while an action waits."""

    def __init__(self) -> None:
        from datetime import timedelta

        from quaicu.core.ports.consent import ConsentRecord

        now = datetime.now(tz=timezone.utc)
        self.record: ConsentRecord | None = ConsentRecord(
            consent_id="c-1",
            tenant_id=str(TENANT),
            subject_id=str(PROPOSER.id),
            purpose="ai_inference",
            data_categories=("general",),
            status="active",
            granted_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=30),
            withdrawn_at=None,
            policy_ref=None,
        )

    async def get_consent(self, *, tenant_id: str, subject_id: str, purpose: str):
        return self.record


class _CapturingLedger(FakeLedger):
    """Also records the evaluation metadata each seal was given."""

    def __init__(self) -> None:
        super().__init__()
        self.metadata: list[dict] = []

    async def seal(self, *, action, evaluation, recorded_result, approver=None):
        self.metadata.append(dict(evaluation.metadata))
        return await super().seal(
            action=action, evaluation=evaluation, recorded_result=recorded_result, approver=approver
        )


def _kernel_with_consent(consent: _ConsentPort) -> Kernel:
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=Decision.REQUIRE_APPROVAL, approvers=(ApproverRef("role:approver"),)),
        hitl=InProcessHITLPort(),
        ledger=_CapturingLedger(),
        events=FakeEvents(),
        repository=_InMemoryActionRepository(),
        consent=consent,
    )


async def test_resume_seals_the_consent_snapshot() -> None:
    k = _kernel_with_consent(_ConsentPort())
    pending = await _propose_gated(k)
    assert pending.state is ActionState.PENDING_APPROVAL
    handle = k.list_pending_approvals()[0].handle_id

    await k.decide_approval(handle, decision="approved", actor=APPROVER)

    ledger = _ledger(k)
    assert len(ledger.sealed) == 1
    assert ledger.metadata[0]["consent_state"]["consent_id"] == "c-1"
    resumed = await k.engine._repo.get_by_id(TENANT, pending.id)  # type: ignore[attr-defined]
    assert resumed.state is ActionState.COMPLETED


@pytest.mark.parametrize("change", ["withdrawn", "expired", "missing"])
async def test_consent_lost_while_waiting_denies_the_action_on_resume(change: str) -> None:
    import dataclasses
    from datetime import timedelta

    consent = _ConsentPort()
    k = _kernel_with_consent(consent)
    pending = await _propose_gated(k)
    handle = k.list_pending_approvals()[0].handle_id

    # Consent was valid at proposal time; it changes while the action waits for a human.
    assert consent.record is not None
    if change == "withdrawn":
        consent.record = dataclasses.replace(consent.record, status="withdrawn")
    elif change == "expired":
        consent.record = dataclasses.replace(
            consent.record, expires_at=datetime.now(tz=timezone.utc) - timedelta(seconds=1)
        )
    else:
        consent.record = None

    await k.decide_approval(handle, decision="approved", actor=APPROVER)

    assert _ledger(k).sealed == []  # never executed, never sealed
    resumed = await k.engine._repo.get_by_id(TENANT, pending.id)  # type: ignore[attr-defined]
    assert resumed.state is ActionState.DENIED
