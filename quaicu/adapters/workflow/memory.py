"""In-memory WorkflowPort adapter — sovereign-tier reference implementation.

Uses an in-memory event store. No database dependency. Suitable for unit tests
and air-gapped single-process deployments. Implements the same WorkflowPort
protocol as the Postgres state-machine adapter.

Replay safety (F-09): every state change is appended as an event; ``state()``
rebuilds ProcessState by replaying the event list — no mutable shared state.

Fail-closed (F-03):
  - HITL timeout  → outcome ``"timeout"`` → TERMINAL_REJECTED.
  - Unknown signal → treated as ``"rejected"`` (most restrictive).
  - Unknown step   → workflow status ``"failed"``.

Tenant isolation (F-07): the handle carries ``tenant_id``; every operation
asserts it matches the stored workflow before proceeding.
"""

from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from quaicu.core.errors import WorkflowPortError
from quaicu.core.process.definitions import (
    DEAD_LETTER,
    TERMINAL_COMPENSATED,
    TERMINAL_COMPENSATION_FAILED,
    TERMINAL_COMPLETED,
    TERMINAL_DENIED,
    TERMINAL_REJECTED,
    TERMINAL_STATES,
    GovernedProcessDef,
    StepDef,
)
from quaicu.core.process.errors import (
    WorkflowNotFoundError,
    WorkflowStartError,
    WorkflowTenantIsolationError,
)
from quaicu.core.types import ProcessDef, ProcessState, Signal, TenantId, WorkflowHandle

StepFn = Callable[[dict[str, Any]], Coroutine[Any, Any, dict[str, Any]]]


@dataclass
class _WfState:
    """Mutable in-process workflow state (one per workflow_id)."""

    workflow_id: str
    tenant_id: str
    proc_def: GovernedProcessDef
    payload: dict[str, Any]
    events: list[dict[str, Any]] = field(default_factory=list)
    status: str = "running"
    current_step: str | None = None
    error: str | None = None
    signals: asyncio.Queue = field(default_factory=asyncio.Queue)
    started_at: float = field(default_factory=time.monotonic)


_TERMINAL_STATUS: dict[str, str] = {
    TERMINAL_COMPLETED: "completed",
    TERMINAL_DENIED: "denied",
    TERMINAL_REJECTED: "rejected",
    TERMINAL_COMPENSATED: "compensated",
    TERMINAL_COMPENSATION_FAILED: "compensation_failed",
    DEAD_LETTER: "dead_letter",
}


class InMemoryWorkflowAdapter:
    """In-memory WorkflowPort adapter.

    Args:
        process_defs: Map of ``GovernedProcessDef.name`` → definition.
        step_fns: Map of step name → async callable ``(payload) → {"outcome": str, ...}``.
            Steps with no registered function return outcome ``"error"``.
        hitl_timeout_seconds: Override HITL wait time for tests. ``None`` uses
            ``step_def.hitl_timeout_hours * 3600`` (the real value).
    """

    def __init__(
        self,
        *,
        process_defs: dict[str, GovernedProcessDef] | None = None,
        step_fns: dict[str, StepFn] | None = None,
        hitl_timeout_seconds: float | None = None,
    ) -> None:
        self._defs: dict[str, GovernedProcessDef] = process_defs or {}
        self._step_fns: dict[str, StepFn] = step_fns or {}
        self._hitl_timeout_seconds = hitl_timeout_seconds
        self._store: dict[str, _WfState] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    # ── Convenience helpers ────────────────────────────────────────────────────

    def register_definition(self, proc_def: GovernedProcessDef) -> None:
        self._defs[proc_def.name] = proc_def

    def register_step(self, name: str, fn: StepFn) -> None:
        self._step_fns[name] = fn

    # ── WorkflowPort protocol ─────────────────────────────────────────────────

    async def start(
        self,
        *,
        definition: ProcessDef,
        payload: dict[str, Any],
        tenant: TenantId,
    ) -> WorkflowHandle:
        proc_def = self._defs.get(definition.id)
        if proc_def is None:
            raise WorkflowStartError(
                f"Unknown process definition: {definition.id!r}",
                definition_id=definition.id,
            )

        workflow_id = str(uuid.uuid4())
        first_step = proc_def.steps[0].name if proc_def.steps else TERMINAL_COMPLETED

        state = _WfState(
            workflow_id=workflow_id,
            tenant_id=str(tenant),
            proc_def=proc_def,
            payload=dict(payload),
        )
        state.current_step = first_step
        state.events.append(
            {"event_type": "workflow_started", "first_step": first_step, "payload": payload}
        )

        self._store[workflow_id] = state
        task = asyncio.create_task(self._run_loop(state))
        self._tasks[workflow_id] = task

        return WorkflowHandle(id=workflow_id, tenant=tenant)

    async def signal(self, handle: WorkflowHandle, signal: Signal) -> None:
        self._assert_tenant(handle)
        state = self._store.get(handle.id)
        if state is None:
            raise WorkflowNotFoundError(
                f"Workflow {handle.id!r} not found",
                workflow_id=handle.id,
            )
        await state.signals.put(signal)

    async def state(self, handle: WorkflowHandle) -> ProcessState:
        self._assert_tenant(handle)
        wf = self._store.get(handle.id)
        if wf is None:
            raise WorkflowPortError(
                f"Workflow {handle.id!r} not found",
                detail={"workflow_id": handle.id},
            )
        return ProcessState(
            status=wf.status,
            current_step=wf.current_step,
            data={"events": wf.events, "error": wf.error},
        )

    # ── Internal step loop ─────────────────────────────────────────────────────

    async def _run_loop(self, state: _WfState) -> None:
        while True:
            current = state.current_step

            # Terminal sentinel reached
            if current is None or current in TERMINAL_STATES:
                state.status = _TERMINAL_STATUS.get(current or "", "completed")
                state.events.append({"event_type": f"workflow_{state.status}"})
                return

            step_def = state.proc_def.step_by_name(current)
            if step_def is None:
                state.status = "failed"
                state.error = f"Unknown step: {current!r}"
                state.events.append({"event_type": "workflow_failed", "error": state.error})
                return

            state.events.append({"event_type": "step_started", "step": current})

            if step_def.is_hitl:
                outcome = await self._run_hitl(state, step_def)
            else:
                outcome = await self._run_step(state, step_def)

            state.events.append(
                {"event_type": "step_completed", "step": current, "outcome": outcome}
            )

            try:
                next_step = state.proc_def.next_step(current, outcome)
            except KeyError:
                state.status = "failed"
                state.error = f"No transition for step={current!r} outcome={outcome!r}"
                state.events.append({"event_type": "workflow_failed", "error": state.error})
                return

            state.current_step = next_step

    async def _run_step(self, state: _WfState, step_def: StepDef) -> str:
        fn = self._step_fns.get(step_def.name)
        if fn is None:
            return "error"
        try:
            result_or_coro = fn(state.payload)
            if inspect.isawaitable(result_or_coro):
                result = await asyncio.wait_for(
                    result_or_coro, timeout=float(step_def.timeout_seconds)
                )
            else:
                result = result_or_coro
            return str(result.get("outcome", "ok"))
        except asyncio.TimeoutError:
            return "error"
        except Exception:
            return "error"

    async def _run_hitl(self, state: _WfState, step_def: StepDef) -> str:
        state.status = "paused_hitl"
        state.events.append({"event_type": "hitl_paused", "step": step_def.name})

        if self._hitl_timeout_seconds is not None:
            timeout = self._hitl_timeout_seconds
        else:
            timeout = float(step_def.hitl_timeout_hours) * 3600

        try:
            sig = await asyncio.wait_for(state.signals.get(), timeout=timeout)
            state.status = "running"
            state.events.append({"event_type": "signal_received", "name": sig.name})
            if sig.name == "hitl_approved":
                return "approved"
            # unknown or rejected signals → fail-closed
            return "rejected"
        except asyncio.TimeoutError:
            state.status = "running"
            state.events.append({"event_type": "hitl_timeout"})
            return "timeout"

    def _assert_tenant(self, handle: WorkflowHandle) -> None:
        wf = self._store.get(handle.id)
        if wf is not None and wf.tenant_id != str(handle.tenant):
            raise WorkflowTenantIsolationError(
                f"Cross-tenant access: handle.tenant={handle.tenant!r} "
                f"!= stored={wf.tenant_id!r}",
                workflow_id=handle.id,
            )
