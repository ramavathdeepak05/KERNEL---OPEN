"""WorkflowPort (K·06) — FROZEN. Durable workflow execution. Two adapters behind one interface."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.types import ProcessDef, ProcessState, Signal, TenantId, WorkflowHandle


@runtime_checkable
class WorkflowPort(Protocol):
    """Durable workflow execution engine. Implementations:
      - postgres_statemachine: sovereign / built-first — no extra server required.
      - temporal: dedicated / cloud — full durable execution with replay.

    Both adapters pass the same conformance suite; config selects which is active (never an
    `if adapter == ...` in core — F-11).

    Fail-closed contract:
      - `start()` failure → raise `WorkflowPortError`. The caller must not proceed.
      - `signal()` failure → raise `WorkflowPortError`. The gate cannot be considered applied.
      - `state()` failure / unreachable → raise `WorkflowPortError`. The caller treats the state as
        UNKNOWN → HALT (never assume completed/approved).
    """

    async def start(
        self,
        *,
        definition: ProcessDef,
        payload: dict,
        tenant: TenantId,
    ) -> WorkflowHandle:
        """Start a durable workflow. Returns a handle for subsequent operations."""
        ...

    async def signal(self, handle: WorkflowHandle, signal: Signal) -> None:
        """Send a signal to a running workflow (e.g. APPROVED / REJECTED)."""
        ...

    async def state(self, handle: WorkflowHandle) -> ProcessState:
        """Return the current process state. Raises on an unreachable backend."""
        ...
