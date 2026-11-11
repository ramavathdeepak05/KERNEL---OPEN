from __future__ import annotations

import dataclasses
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from quaicu.core.errors import GatewayLoggingError
from quaicu.core.types import ActionId, ModelRef, TenantId


@dataclass(frozen=True)
class PromptLogEntry:
    log_id: str
    action_id: ActionId | None
    tenant: TenantId
    model_ref: ModelRef
    prompt_hash: str
    logged_at: datetime
    response_hash: str | None = None


class InMemoryPromptLog:
    """Write-before-call prompt log. Fail-closed: write() must succeed before generate() runs."""

    def __init__(self) -> None:
        self._entries: dict[str, PromptLogEntry] = {}
        self._lock = threading.Lock()
        self._fail_next: bool = False

    def write(
        self,
        *,
        action_id: ActionId | None,
        tenant: TenantId,
        model_ref: ModelRef,
        prompt_hash: str,
    ) -> PromptLogEntry:
        """Write prompt log BEFORE the model call. Raises GatewayLoggingError on failure."""
        if self._fail_next:
            self._fail_next = False
            raise GatewayLoggingError(
                "Injected prompt log failure — call denied (fail-closed).",
                detail={"tenant": str(tenant)},
            )
        entry = PromptLogEntry(
            log_id=str(uuid.uuid4()),
            action_id=action_id,
            tenant=tenant,
            model_ref=model_ref,
            prompt_hash=prompt_hash,
            logged_at=datetime.now(UTC),
        )
        with self._lock:
            self._entries[entry.log_id] = entry
        return entry

    def record_response(self, log_id: str, response_hash: str) -> None:
        """Update the log entry with the response hash after the call returns."""
        with self._lock:
            e = self._entries.get(log_id)
            if e is not None:
                self._entries[log_id] = dataclasses.replace(e, response_hash=response_hash)

    def inject_failure(self) -> None:
        """Cause the next write() to raise GatewayLoggingError (test injection)."""
        self._fail_next = True

    @property
    def entries(self) -> list[PromptLogEntry]:
        with self._lock:
            return list(self._entries.values())
