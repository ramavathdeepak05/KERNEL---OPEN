from __future__ import annotations

import threading

from quaicu.core.hitl.model import ApprovalRecord
from quaicu.core.types import ActionId, ApprovalDecision


class ApprovalStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_handle: dict[str, ApprovalRecord] = {}
        self._by_action: dict[ActionId, str] = {}

    def put(self, record: ApprovalRecord) -> None:
        with self._lock:
            self._by_handle[record.handle_id] = record
            self._by_action[record.action_id] = record.handle_id

    def get(self, handle_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._by_handle.get(handle_id)

    def update(self, record: ApprovalRecord) -> None:
        with self._lock:
            if record.handle_id not in self._by_handle:
                raise KeyError(f"Handle {record.handle_id!r} not in store.")
            self._by_handle[record.handle_id] = record

    def get_by_action(self, action_id: ActionId) -> ApprovalRecord | None:
        with self._lock:
            handle_id = self._by_action.get(action_id)
            if handle_id is None:
                return None
            return self._by_handle.get(handle_id)

    def pending_count(self) -> int:
        """Number of approval records still awaiting a decision (HITL queue depth)."""
        with self._lock:
            return sum(
                1
                for r in self._by_handle.values()
                if r.decision is ApprovalDecision.PENDING
            )

    def list_pending(self) -> list[ApprovalRecord]:
        """All approval records still awaiting a decision, oldest request first."""
        with self._lock:
            pending = [
                r for r in self._by_handle.values()
                if r.decision is ApprovalDecision.PENDING
            ]
        return sorted(pending, key=lambda r: r.requested_at)
