"""InMemoryLedgerAdapter — single-process in-memory ledger.

Registers as adapter key ``"memory_ledger"`` in the Kernel adapter registry.
Entries are stored in a list; the ledger seq is the 1-based list index.
Suitable for local development, single-process deployments, and integration
tests that need a real (non-fake) ledger without external dependencies.

Not suitable for multi-process or horizontally-scaled deployments — use a
Postgres-backed ledger adapter for those.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any

from quaicu.core.types import (
    Action,
    ApproverRef,
    EvaluationResult,
    LedgerEntry,
)


class InMemoryLedgerAdapter:
    """Thread-safe in-memory ledger. Leaf hash = SHA-256 of the action payload."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: list[LedgerEntry] = []

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        leaf_hash = hashlib.sha256(
            json.dumps(
                {"action_id": str(action.id), "result": str(recorded_result)},
                sort_keys=True,
            ).encode()
        ).digest()

        with self._lock:
            seq = len(self._entries) + 1
            entry = LedgerEntry(
                ledger_seq=seq,
                tenant=action.tenant,
                action_id=action.id,
                action_type=action.type,
                actor_id=action.actor.id,
                decision=evaluation.decision,
                policy_versions=evaluation.policy_versions,
                leaf_hash=leaf_hash,
                sealed_at=datetime.now(tz=timezone.utc),
                approver=approver,
                recorded_result={"result": recorded_result},
            )
            self._entries.append(entry)

        return entry

    @property
    def sealed(self) -> list[LedgerEntry]:
        with self._lock:
            return list(self._entries)

    def get_entries(self, tenant: Any) -> list[LedgerEntry]:
        """Return sealed entries for `tenant` only (F-07: tenant-scoped read)."""
        with self._lock:
            return [e for e in self._entries if str(e.tenant) == str(tenant)]
