from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.model import ApprovalRecord
from quaicu.core.hitl.store import ApprovalStore
from quaicu.core.types import (
    Action,
    ActorId,
    ApprovalDecision,
    ApprovalHandle,
    ApprovalOutcome,
    ApproverRef,
    TenantId,
)

log = logging.getLogger("quaicu.hitl")

# A host may name the same person in two forms: ``member:<id>`` and the bare ``<id>``. Separation
# of duties is about the person, not the spelling, so the self-approval guard and ``user:``
# approver matching compare canonical ids (the prefix removed).
_MEMBER_PREFIX = "member:"


def _canonical_actor_id(actor_id: ActorId | str) -> str:
    """``actor_id`` without a ``member:`` prefix."""
    return str(actor_id).removeprefix(_MEMBER_PREFIX)


def _same_actor(a: ActorId | str, b: ActorId | str) -> bool:
    """True if ``a`` and ``b`` name the same actor, ignoring a ``member:`` prefix."""
    return _canonical_actor_id(a) == _canonical_actor_id(b)


class InProcessHITLPort:
    """
    Programmatic HITL port for sovereign tier and testing.

    Usage:
        port = InProcessHITLPort(timeout_seconds=3600)
        handle = await port.request_approval(action=..., approvers=..., tenant=...)
        decision = await port.poll(handle)

        await port.approve(handle.id, approver_actor_id=ActorId("bob"))
        await port.reject(handle.id, approver_actor_id=ActorId("carol"))
    """

    def __init__(
        self,
        timeout_seconds: int = 86400,
        store: ApprovalStore | None = None,
    ) -> None:
        self._timeout_seconds = timeout_seconds
        self._store = store or ApprovalStore()

    # ── HITLPort protocol ────────────────────────────────────────────────────

    @staticmethod
    def _new_handle_id() -> str:
        return str(uuid.uuid4())

    def _build_record(
        self,
        *,
        handle_id: str,
        action: Action,
        approvers: list[ApproverRef],
        tenant: TenantId,
        notify_channel: str | None = None,
        notify_target: str | None = None,
        resume_link: str | None = None,
    ) -> ApprovalRecord:
        """Build (but do not store) the approval record. Subclasses (email/Teams) use this to attach
        routing metadata and control the send/persist ordering (D1-4). ``timeout_seconds = 0`` means no
        expiry — the approval stays pending until a human decides."""
        now = datetime.now(UTC)
        return ApprovalRecord(
            handle_id=handle_id,
            action_id=action.id,
            tenant=tenant,
            required_approvers=tuple(approvers),
            requested_at=now,
            expires_at=(
                now + timedelta(seconds=self._timeout_seconds) if self._timeout_seconds > 0 else None
            ),
            proposed_by=action.actor.id,
            notify_channel=notify_channel,
            notify_target=notify_target,
            resume_link=resume_link,
        )

    async def request_approval(
        self,
        *,
        action: Action,
        approvers: list[ApproverRef],
        tenant: TenantId,
    ) -> ApprovalHandle:
        handle_id = self._new_handle_id()
        record = self._build_record(
            handle_id=handle_id, action=action, approvers=approvers, tenant=tenant
        )
        self._store.put(record)
        log.info(
            "HITL request created: handle=%s action=%s approvers=%s",
            handle_id,
            action.id,
            approvers,
        )
        return ApprovalHandle(id=handle_id, tenant=tenant, created_at=record.requested_at)

    async def poll(self, handle: ApprovalHandle) -> ApprovalOutcome:
        record = self._store.get(handle.id)
        if record is None:
            raise HITLPortError(
                f"ApprovalHandle {handle.id!r} not found.",
                detail={"handle_id": handle.id},
            )
        if record.decision is not ApprovalDecision.PENDING:
            return ApprovalOutcome(record.decision, decided_by=record.decided_by)
        if record.is_expired(datetime.now(UTC)):
            timed_out = record.with_decision(ApprovalDecision.TIMED_OUT)
            self._store.update(timed_out)
            log.info("HITL timed out: handle=%s action=%s", handle.id, record.action_id)
            return ApprovalOutcome(ApprovalDecision.TIMED_OUT)
        return ApprovalOutcome(ApprovalDecision.PENDING)

    # ── External control (admin / test surface) ──────────────────────────────

    async def approve(
        self,
        handle_id: str,
        *,
        approver_actor_id: ActorId,
        approver_roles: tuple[str, ...] = (),
    ) -> None:
        record = self._store.get(handle_id)
        if record is None:
            raise HITLPortError(f"Handle {handle_id!r} not found.")
        if record.decision is not ApprovalDecision.PENDING:
            raise HITLPortError(
                f"Handle {handle_id!r} already decided: {record.decision.value}."
            )
        if record.is_expired(datetime.now(UTC)):
            raise HITLPortError(f"Handle {handle_id!r} has expired.")
        # Separation of duties: the proposer may never approve their own action.
        if record.proposed_by is not None and _same_actor(approver_actor_id, record.proposed_by):
            raise HITLPortError(
                f"Actor {approver_actor_id!r} proposed this action and cannot approve it "
                "(separation of duties).",
                detail={"actor_id": str(approver_actor_id), "handle_id": handle_id},
            )
        self._assert_authorized(approver_actor_id, approver_roles, record.required_approvers)
        approved = record.with_decision(
            ApprovalDecision.APPROVED, decided_by=approver_actor_id
        )
        self._store.update(approved)
        log.info("HITL approved: handle=%s by=%s", handle_id, approver_actor_id)

    async def reject(
        self,
        handle_id: str,
        *,
        approver_actor_id: ActorId,
        approver_roles: tuple[str, ...] = (),
    ) -> None:
        record = self._store.get(handle_id)
        if record is None:
            raise HITLPortError(f"Handle {handle_id!r} not found.")
        if record.decision is not ApprovalDecision.PENDING:
            raise HITLPortError(
                f"Handle {handle_id!r} already decided: {record.decision.value}."
            )
        self._assert_authorized(approver_actor_id, approver_roles, record.required_approvers)
        rejected = record.with_decision(
            ApprovalDecision.REJECTED, decided_by=approver_actor_id
        )
        self._store.update(rejected)
        log.info("HITL rejected: handle=%s by=%s", handle_id, approver_actor_id)

    async def force_expire(self, handle_id: str) -> None:
        record = self._store.get(handle_id)
        if record is None:
            raise HITLPortError(f"Handle {handle_id!r} not found.")
        if record.decision is ApprovalDecision.PENDING:
            timed_out = record.with_decision(ApprovalDecision.TIMED_OUT)
            self._store.update(timed_out)

    def get_record(self, handle_id: str) -> ApprovalRecord | None:
        return self._store.get(handle_id)

    def list_pending(self) -> list[ApprovalRecord]:
        """All approval records still awaiting a decision (operator queue surface)."""
        return self._store.list_pending()

    # ── Authority ────────────────────────────────────────────────────────────

    def _assert_authorized(
        self,
        actor_id: ActorId,
        actor_roles: tuple[str, ...],
        required: tuple[ApproverRef, ...],
    ) -> None:
        """Fail-closed authorization against required approver refs.

        The actor is authorized iff they satisfy at least one required ref:
          - a ``user:<id>`` ref matching their actor id, OR
          - a ``role:<role>`` ref matching one of their roles.

        If ``required`` is empty no approver was specified — treat as unauthorized (a gate with
        no eligible approver must never be approvable). Previously only ``user:`` refs were
        checked, so any actor could satisfy a purely role-based gate (the common case).
        """
        # Normalise the actor's roles to bare role names (strip an optional "role:" prefix).
        actor_role_refs = {
            ApproverRef(r if str(r).startswith("role:") else f"role:{r}") for r in actor_roles
        }
        # A policy may name an approver as ``user:member:<id>`` or ``user:<id>``; both name the
        # same person, so compare canonical ids.
        required_users = {
            _canonical_actor_id(str(r).removeprefix("user:"))
            for r in required
            if str(r).startswith("user:")
        }

        satisfied = _canonical_actor_id(actor_id) in required_users or bool(
            actor_role_refs & set(required)
        )
        if not satisfied:
            raise HITLPortError(
                f"Actor {actor_id!r} is not authorized to decide this approval. "
                f"Required one of: {[str(r) for r in required]}",
                detail={
                    "actor_id": str(actor_id),
                    "actor_roles": list(actor_roles),
                    "required": [str(r) for r in required],
                },
            )
