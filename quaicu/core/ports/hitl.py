"""HITLPort (K·03) — FROZEN. Routes approval requests to humans. The gate step of the lifecycle."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.types import (
    Action,
    ApprovalHandle,
    ApprovalOutcome,
    ApproverRef,
    TenantId,
)


@runtime_checkable
class HITLPort(Protocol):
    """Human-in-the-loop gate. Implementations: webhook (default), email, slack, inapp.

    Fail-closed contract:
      - Timeout → the caller treats the outcome as REJECTED (never approved).
      - Approver unreachable / dispatch failed → raise `HITLPortError`; the caller HALTS. Durable
        channels (email/Teams) **send-then-persist**: they notify first and only record a PENDING
        approval on success, so a persisted PENDING record always implies a delivered notification (no
        orphan on failure). A pending approval then waits until a human decides (no auto-expiry).
      - The durable `ApprovalRecord` carries its routing metadata (channel + target) and the signed
        resume link, so a restarted process retains full context of a pending approval (D1-4).
      - The port does NOT decide who may approve — approver authority is enforced by the lifecycle,
        not the adapter.
    """

    async def request_approval(
        self,
        *,
        action: Action,
        approvers: list[ApproverRef],
        tenant: TenantId,
    ) -> ApprovalHandle:
        """Dispatch an approval request and return a handle for polling.

        Raises:
            HITLPortError: the request could not be dispatched.
        """
        ...

    async def poll(self, handle: ApprovalHandle) -> ApprovalOutcome:
        """Poll for a decision.

        Returns:
            ApprovalOutcome: the decision (PENDING | APPROVED | REJECTED | TIMED_OUT) plus
            `decided_by` — the approver's actor id when known, else None (PENDING, or a TIMED_OUT
            with no decider). TIMED_OUT is a valid terminal outcome the lifecycle treats as
            REJECTED (fail-closed). The approver is sealed onto the ledger entry (ADR-0007).

        Raises:
            HITLPortError: the poll backend is unreachable.
        """
        ...
