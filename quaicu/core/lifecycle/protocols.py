"""Core-to-core collaborator contracts the lifecycle spine depends on.

The spine orchestrates K·01 (policy), K·02 (ledger), K·07 (events), and a storage-backed action
repository. So it does not start before they exist, it depends on these **interfaces**, which those
layers implement. Like the ports in `quaicu/core/ports/`, these are stable contracts — change them via the
orchestrator + an ADR (AGENTS.md §3). This lets the spine be built and unit-tested with fakes now,
and K·01/K·02/K·07 plug in later.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from quaicu.core.types import (
    Action,
    ActionId,
    ApproverRef,
    EvaluationResult,
    IdempotencyKey,
    LedgerEntry,
    TenantId,
)


@runtime_checkable
class PolicyEvaluator(Protocol):
    """K·01. Resolves an action against all applicable active policies.

    Fail-closed contract: the result is total (always a `Decision`, never undefined). On an internal
    error the implementation raises a `PolicyError` subtype; the engine maps that to DENY.
    """

    async def evaluate(self, action: Action) -> EvaluationResult: ...


@runtime_checkable
class Ledger(Protocol):
    """K·02. Seals a completed action to the per-tenant RFC 6962 transparency log.

    Fail-closed contract: on any failure it raises a `LedgerError` subtype; the engine HALTS the
    action (an executed-but-unsealed action is never marked COMPLETED).
    """

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry: ...


@runtime_checkable
class EventBus(Protocol):
    """K·07. Publishes the structured event after seal. Best-effort: a failure here never changes a
    sealed outcome."""

    async def emit(self, *, action: Action, entry: LedgerEntry) -> None: ...


@runtime_checkable
class ActionRepository(Protocol):
    """Storage-backed persistence for actions, used by the spine. Implemented by the storage adapter.

    `insert_if_absent` MUST be atomic (e.g. INSERT … ON CONFLICT) so concurrent submissions with the
    same idempotency key cannot both proceed — returning the existing action on conflict.
    """

    async def insert_if_absent(self, action: Action) -> Action | None:
        """Insert a freshly proposed action. Return None if inserted; return the EXISTING action if its
        `(tenant, idempotency_key)` is already present (idempotency hit — caller must not re-run)."""
        ...

    async def update_state(self, action: Action) -> None:
        """Persist the action's current state (called on every transition)."""
        ...

    async def get_by_idempotency_key(
        self, tenant: TenantId, key: IdempotencyKey
    ) -> Action | None:
        """Return the action for `(tenant, key)` if present, else None."""
        ...

    async def get_by_id(self, tenant: TenantId, action_id: ActionId) -> Action | None:
        """Return the `(tenant, action_id)` action if present, else None. Used to resume a
        PENDING_APPROVAL action on approval (the approval record carries the tenant + action id, not the
        idempotency key). `tenant` scopes the read under RLS."""
        ...
