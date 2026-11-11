"""Fail-closed fake collaborators for testing the lifecycle spine.

Per the `python-testing` skill contract, fakes default to safe/fail-closed behavior. Each fake is
configurable to inject the fault under test (raise, deny, reject, timeout) so fail-closed is *proven*,
not assumed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from quaicu.core.errors import (
    HITLPortError,
    IdentityPortError,
    LedgerSealError,
    PolicyEvaluationError,
    StoragePortError,
)
from quaicu.core.types import (
    Action,
    ActionId,
    Actor,
    ActorId,
    ApprovalDecision,
    ApprovalHandle,
    ApprovalOutcome,
    ApproverRef,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    LedgerEntry,
    TenantId,
)

TENANT = TenantId("ciro-bank")


def make_action(
    *,
    action_id: str = "act-1",
    idempotency_key: str = "key-1",
    type: str = "ciro.ifrs9.stage_transition",
) -> Action:
    return Action(
        id=ActionId(action_id),
        type=type,
        payload={"loan_id": "4471", "from_stage": 1, "to_stage": 2, "exposure": 7_500_000},
        actor=Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:risk_analyst",)),
        tenant=TENANT,
        idempotency_key=IdempotencyKey(idempotency_key),
        proposed_at=datetime(2026, 6, 5, tzinfo=timezone.utc),
    )


class FakeActionRepository:
    """In-memory action store with atomic-style insert_if_absent keyed by (tenant, idempotency_key).

    ``raise_on_insert`` / ``raise_on_update`` inject a StoragePortError so the engine's
    fail-closed storage handling (HALT, never raise out of run()) can be proven.
    """

    def __init__(
        self, *, raise_on_insert: bool = False, raise_on_update: bool = False
    ) -> None:
        self.by_key: dict[tuple[str, str], Action] = {}
        self.update_calls: list[Action] = []
        self.raise_on_insert = raise_on_insert
        self.raise_on_update = raise_on_update

    async def insert_if_absent(self, action: Action) -> Action | None:
        if self.raise_on_insert:
            raise StoragePortError("injected insert fault")
        k = (str(action.tenant), str(action.idempotency_key))
        if k in self.by_key:
            return self.by_key[k]
        self.by_key[k] = action
        return None

    async def update_state(self, action: Action) -> None:
        if self.raise_on_update:
            raise StoragePortError("injected update fault")
        self.update_calls.append(action)
        self.by_key[(str(action.tenant), str(action.idempotency_key))] = action

    async def get_by_idempotency_key(
        self, tenant: TenantId, key: IdempotencyKey
    ) -> Action | None:
        return self.by_key.get((str(tenant), str(key)))


class FakePolicy:
    """Returns a configured decision, or raises if `raise_exc` is set (fail-closed test)."""

    def __init__(
        self,
        *,
        decision: Decision = Decision.ALLOW,
        approvers: tuple[ApproverRef, ...] = (),
        return_none: bool = False,
        raise_exc: bool = False,
    ) -> None:
        self.decision = decision
        self.approvers = approvers
        self.return_none = return_none
        self.raise_exc = raise_exc
        self.calls = 0

    async def evaluate(self, action: Action) -> EvaluationResult:
        self.calls += 1
        if self.raise_exc:
            raise PolicyEvaluationError("injected policy fault")
        if self.return_none:
            return None  # type: ignore[return-value]  # deliberately violate the contract for the test
        return EvaluationResult(
            decision=self.decision, policy_versions=("v3",), approvers=self.approvers
        )


class FakeHITL:
    """Returns a configured approval decision; can raise to simulate a port outage.

    ``decided_by`` configures the approver identity surfaced on the outcome (defaults to a fixed
    actor) so the lifecycle's approver-capture (ADR-0007) can be exercised."""

    def __init__(
        self,
        *,
        decision: ApprovalDecision = ApprovalDecision.APPROVED,
        decided_by: ActorId | None = ActorId("approver-1"),
        raise_exc: bool = False,
    ) -> None:
        self.decision = decision
        self.decided_by = decided_by
        self.raise_exc = raise_exc
        self.requested = False

    async def request_approval(
        self, *, action: Action, approvers: list[ApproverRef], tenant: TenantId
    ) -> ApprovalHandle:
        if self.raise_exc:
            raise HITLPortError("injected HITL dispatch fault")
        self.requested = True
        return ApprovalHandle(id="appr-1", tenant=tenant)

    async def poll(self, handle: ApprovalHandle) -> ApprovalOutcome:
        return ApprovalOutcome(self.decision, decided_by=self.decided_by)


class FakeLedger:
    """Seals to an in-memory list; can raise to simulate a seal failure."""

    def __init__(self, *, raise_exc: bool = False) -> None:
        self.raise_exc = raise_exc
        self.sealed: list[LedgerEntry] = []

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        if self.raise_exc:
            raise LedgerSealError("injected seal fault")
        entry = LedgerEntry(
            ledger_seq=len(self.sealed) + 1,
            tenant=action.tenant,
            action_id=action.id,
            action_type=action.type,
            actor_id=action.actor.id,
            decision=evaluation.decision,
            policy_versions=evaluation.policy_versions,
            leaf_hash=b"\x00" * 32,
            sealed_at=datetime(2026, 6, 5, tzinfo=timezone.utc),
            approver=approver,
            recorded_result={"result": recorded_result},
        )
        self.sealed.append(entry)
        return entry

    def get_entries(self, tenant: TenantId) -> list[LedgerEntry]:
        return [e for e in self.sealed if str(e.tenant) == str(tenant)]


class FakeEvents:
    """Records emitted events; can raise to prove emit is best-effort."""

    def __init__(self, *, raise_exc: bool = False) -> None:
        self.raise_exc = raise_exc
        self.emitted: list[LedgerEntry] = []

    async def emit(self, *, action: Action, entry: LedgerEntry) -> None:
        if self.raise_exc:
            raise RuntimeError("injected emit fault")
        self.emitted.append(entry)


class FakeIdentity:
    """Resolves to a fixed actor, or raises to simulate an unresolvable identity.

    ``roles`` configures the resolved actor's roles so control-plane authz (e.g. the policy
    management API's policy-admin check) can be exercised with and without the required role.
    """

    def __init__(
        self, *, raise_exc: bool = False, roles: tuple[str, ...] = ("role:risk_analyst",)
    ) -> None:
        self.raise_exc = raise_exc
        self.roles = roles

    async def resolve_actor(self, *, context: Any, tenant: TenantId) -> Actor:
        if self.raise_exc:
            raise IdentityPortError("injected identity fault")
        return Actor(id=ActorId("alice"), tenant=tenant, roles=self.roles)


class Counter:
    """A one-shot execute body that records how many times it ran."""

    def __init__(self, *, raise_exc: bool = False) -> None:
        self.count = 0
        self.raise_exc = raise_exc

    async def __call__(self) -> str:
        self.count += 1
        if self.raise_exc:
            raise RuntimeError("injected execute fault")
        return "stage updated"
