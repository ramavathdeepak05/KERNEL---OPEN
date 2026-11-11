"""AWS Step Functions WorkflowPort adapter (K·06) — the dedicated-cloud alternative to the in-memory /
Postgres state-machine adapters, for customers standardizing durable workflows on AWS Step Functions.

It **translates a `GovernedProcessDef` into Amazon States Language (ASL)** — each step becomes a Task
state, each step's `transitions[step][outcome]` becomes a Choice routing to the next step or a terminal
state, the HITL gate becomes a long-timeout Task backed by an SFN **Activity** (whose token-based
callback is the approval signal), and the `TERMINAL_*` sentinels become `Succeed`/`Fail` states. The
deployed state machine therefore enforces the same governed lifecycle SFN-natively.

Fail-closed (WorkflowPort contract): any SFN error → `WorkflowPortError`; an unreachable `state()` must
be treated as UNKNOWN→HALT by the caller. boto3 is lazily imported (``[aws]`` extra) and the client is
injectable for tests; all (blocking) boto3 calls run off the event loop.

NOTE (live-AWS plumbing, documented honestly): the HITL Activity's **task token** is delivered to the
approval worker when SFN schedules the activity (`get_activity_task`); the worker passes it back in the
`Signal.payload['task_token']` so `signal()` can `send_task_success/failure`. State-machine creation +
the activity workers are provisioned per deployment. The ASL translation + the start/signal/state wiring
are unit-tested against a fake SFN client; they are not validated against live AWS here.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from quaicu.core.errors import WorkflowPortError
from quaicu.core.process.definitions import (
    DEAD_LETTER,
    GOVERNED_ACTION_PROCESS,
    TERMINAL_COMPENSATED,
    TERMINAL_COMPLETED,
    TERMINAL_STATES,
    GovernedProcessDef,
)
from quaicu.core.types import ProcessDef, ProcessState, Signal, TenantId, WorkflowHandle

# Terminal sentinels that represent a *successful* end (ASL Succeed); the rest are ASL Fail.
_SUCCESS_TERMINALS = frozenset({TERMINAL_COMPLETED, TERMINAL_COMPENSATED})


# ── ASL translation (pure, fully unit-testable) ──────────────────────────────────


def governed_def_to_asl(pdef: GovernedProcessDef, *, activity_arn_prefix: str) -> dict[str, Any]:
    """Translate a `GovernedProcessDef` into an Amazon States Language state-machine definition.

    ``activity_arn_prefix`` is the ARN stem for the SFN Activities that back each step
    (e.g. ``arn:aws:states:us-east-1:123:activity:quaicu``); each step uses ``{prefix}-{step}``.
    """
    if not pdef.steps:
        raise ValueError("Cannot translate a process definition with no steps.")

    states: dict[str, Any] = {}

    def target(dest: str) -> str:
        # A transition destination is either another step or a TERMINAL_* sentinel (its own state).
        return dest

    for step in pdef.steps:
        routes = pdef.transitions.get(step.name, {})
        task: dict[str, Any] = {
            "Type": "Task",
            "Resource": f"{activity_arn_prefix}-{step.name}",
            "TimeoutSeconds": (step.hitl_timeout_hours * 3600) if step.is_hitl else step.timeout_seconds,
            "ResultPath": "$.step",
            "Next": f"{step.name}__route",
        }
        if not step.is_hitl and step.max_retries > 0:
            task["Retry"] = [
                {
                    "ErrorEquals": ["States.ALL"],
                    "MaxAttempts": step.max_retries,
                    "IntervalSeconds": max(1, int(step.retry_backoff_base_seconds)),
                    "BackoffRate": 2.0,
                }
            ]
        # Route runtime errors via the step's "error" outcome (fail-closed default: DEAD_LETTER).
        err_dest = target(routes.get("error", DEAD_LETTER))
        task["Catch"] = [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.error", "Next": err_dest}]
        # HITL: a States.Timeout maps to the "timeout" outcome (fail-closed → usually TERMINAL_REJECTED).
        if step.is_hitl and "timeout" in routes:
            task["Catch"].insert(
                0, {"ErrorEquals": ["States.Timeout"], "ResultPath": "$.error", "Next": target(routes["timeout"])}
            )
        states[step.name] = task

        # Choice state: route on the step's reported outcome ($.outcome).
        choices = [
            {"Variable": "$.outcome", "StringEquals": outcome, "Next": target(dest)}
            for outcome, dest in routes.items()
            if outcome not in ("error", "timeout")
        ]
        states[f"{step.name}__route"] = {
            "Type": "Choice",
            "Choices": choices,
            "Default": err_dest,  # an unmatched outcome is fail-closed
        }

    # Terminal sentinel states (Succeed for successful ends, Fail otherwise).
    referenced_terminals = {
        dest
        for routes in pdef.transitions.values()
        for dest in routes.values()
        if dest in TERMINAL_STATES
    }
    for term in referenced_terminals:
        if term in _SUCCESS_TERMINALS:
            states[term] = {"Type": "Succeed"}
        else:
            states[term] = {"Type": "Fail", "Error": term, "Cause": term}

    return {
        "Comment": f"{pdef.name} v{pdef.version} (QUAICU governed process)",
        "StartAt": pdef.steps[0].name,
        "States": states,
    }


# ── Adapter ───────────────────────────────────────────────────────────────────


class StepFunctionsWorkflowAdapter:
    """`WorkflowPort` backed by AWS Step Functions. ``client`` injectable for tests."""

    def __init__(
        self,
        *,
        role_arn: str,
        activity_arn_prefix: str,
        region: str | None = None,
        process_defs: dict[str, GovernedProcessDef] | None = None,
        client: Any | None = None,
    ) -> None:
        self._role_arn = role_arn
        self._activity_prefix = activity_arn_prefix
        self._region = region
        self._client = client
        # Keyed by GovernedProcessDef.name (== ProcessDef.id), mirroring the in-memory adapter.
        self._defs: dict[str, GovernedProcessDef] = process_defs or {
            GOVERNED_ACTION_PROCESS.name: GOVERNED_ACTION_PROCESS
        }
        self._arns: dict[str, str] = {}  # def name -> deployed state-machine ARN (cache)

    def register_definition(self, proc_def: GovernedProcessDef) -> None:
        self._defs[proc_def.name] = proc_def

    def _sfn(self) -> Any:
        if self._client is None:
            try:
                import boto3  # lazy ([aws] extra)
            except ImportError as exc:  # pragma: no cover - exercised via the no-SDK test
                raise WorkflowPortError(
                    "Step Functions workflow adapter requires the 'aws' extra: "
                    "pip install quaicu-kernel[aws]."
                ) from exc
            self._client = boto3.client("stepfunctions", region_name=self._region) if self._region else boto3.client("stepfunctions")
        return self._client

    def _ensure_state_machine(self, pdef: GovernedProcessDef) -> str:
        """Create (idempotently) the SFN state machine for ``pdef`` and return its ARN. Blocking."""
        if pdef.name in self._arns:
            return self._arns[pdef.name]
        asl = governed_def_to_asl(pdef, activity_arn_prefix=self._activity_prefix)
        client = self._sfn()
        try:
            resp = client.create_state_machine(
                name=f"quaicu-{pdef.name}-v{pdef.version}",
                definition=json.dumps(asl),
                roleArn=self._role_arn,
            )
            arn = resp["stateMachineArn"]
        except Exception as exc:  # noqa: BLE001 — already-exists / API error
            # If it already exists, recover the ARN from the message-free path: list + match by name.
            arn = self._find_existing_arn(client, f"quaicu-{pdef.name}-v{pdef.version}")
            if arn is None:
                raise WorkflowPortError(f"Step Functions state-machine create failed: {exc}") from exc
        self._arns[pdef.name] = arn
        return arn

    @staticmethod
    def _find_existing_arn(client: Any, name: str) -> str | None:
        try:
            for sm in client.list_state_machines().get("stateMachines", []):
                if sm.get("name") == name:
                    return sm.get("stateMachineArn")
        except Exception:  # noqa: BLE001
            return None
        return None

    async def start(self, *, definition: ProcessDef, payload: dict, tenant: TenantId) -> WorkflowHandle:
        pdef = self._defs.get(definition.id)
        if pdef is None:
            raise WorkflowPortError(f"No governed process definition registered for {definition.id!r}.")
        try:
            arn = await asyncio.to_thread(self._ensure_state_machine, pdef)
            client = self._sfn()
            resp = await asyncio.to_thread(
                lambda: client.start_execution(
                    stateMachineArn=arn,
                    name=f"{tenant}-{uuid.uuid4().hex}",
                    input=json.dumps({**payload, "_tenant": str(tenant)}),
                )
            )
        except WorkflowPortError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise WorkflowPortError(f"Step Functions start failed: {exc}") from exc
        return WorkflowHandle(id=resp["executionArn"], tenant=tenant)

    async def signal(self, handle: WorkflowHandle, signal: Signal) -> None:
        # The HITL gate is an Activity (token-based). The approval worker received the token via
        # get_activity_task and returns it in the signal payload so we can resolve the callback.
        token = signal.payload.get("task_token")
        if not token:
            raise WorkflowPortError("Step Functions signal requires 'task_token' in the signal payload.")
        client = self._sfn()
        try:
            if signal.name.lower() in ("approved", "ok", "completed"):
                await asyncio.to_thread(
                    lambda: client.send_task_success(
                        taskToken=token, output=json.dumps({"outcome": signal.name.lower()})
                    )
                )
            else:
                await asyncio.to_thread(
                    lambda: client.send_task_failure(
                        taskToken=token, error=signal.name, cause=json.dumps(dict(signal.payload))
                    )
                )
        except Exception as exc:  # noqa: BLE001
            raise WorkflowPortError(f"Step Functions signal failed: {exc}") from exc

    async def state(self, handle: WorkflowHandle) -> ProcessState:
        client = self._sfn()
        try:
            resp = await asyncio.to_thread(lambda: client.describe_execution(executionArn=handle.id))
        except Exception as exc:  # noqa: BLE001 — unreachable backend → caller HALTs (fail-closed)
            raise WorkflowPortError(f"Step Functions state failed: {exc}") from exc

        sfn_status = resp.get("status")
        if sfn_status == "RUNNING":
            return ProcessState(status="running")
        if sfn_status == "SUCCEEDED":
            return ProcessState(status=TERMINAL_COMPLETED)
        if sfn_status == "FAILED":
            # The Fail state's Error is the TERMINAL_* sentinel we encoded in the ASL.
            err = resp.get("error", "")
            return ProcessState(status=err if err in TERMINAL_STATES else "failed")
        if sfn_status in ("TIMED_OUT", "ABORTED"):
            from quaicu.core.process.definitions import TERMINAL_REJECTED

            return ProcessState(status=TERMINAL_REJECTED)  # fail-closed
        return ProcessState(status="failed")
