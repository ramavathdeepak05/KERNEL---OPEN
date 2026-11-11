from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import UTC, datetime

from quaicu.core.types import ActionId, ActorId, ApprovalDecision, ApproverRef, TenantId


@dataclass(frozen=True)
class ApprovalRecord:
    """Full record of a HITL approval request, including WHO decided (resolves the open ADR)."""

    handle_id: str
    action_id: ActionId
    tenant: TenantId
    required_approvers: tuple[ApproverRef, ...]
    requested_at: datetime
    decision: ApprovalDecision = ApprovalDecision.PENDING
    decided_by: ActorId | None = None
    decided_at: datetime | None = None
    expires_at: datetime | None = None
    # The actor who proposed the action — used to forbid self-approval (separation of duties).
    proposed_by: ActorId | None = None
    # Durable routing metadata (D1-4): how the approver was notified + the signed resume link, so a
    # restarted process retains full context of a pending approval. None for the bare in-process port.
    notify_channel: str | None = None      # "email" | "teams" | None
    notify_target: str | None = None       # recipient email / webhook URL
    resume_link: str | None = None         # the signed approve (resume) link the notification carried

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def with_decision(
        self,
        decision: ApprovalDecision,
        decided_by: ActorId | None = None,
        decided_at: datetime | None = None,
    ) -> ApprovalRecord:
        return dataclasses.replace(
            self,
            decision=decision,
            decided_by=decided_by,
            decided_at=decided_at or datetime.now(UTC),
        )
