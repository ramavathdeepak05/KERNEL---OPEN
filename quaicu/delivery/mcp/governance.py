"""Reusable MCP tool-call governance core (D2-1) — no ``mcp`` dependency.

`govern_tool_call` maps one MCP tool invocation to a governed kernel action: it wraps the tool's real
execution (`execute`) with `kernel.wrap(...)` — the full lifecycle (identity → policy → HITL gate →
execute → K·02 seal) — and turns the lifecycle outcome into a small `ToolOutcome` the MCP server/proxy
render back to the agent. Fail-closed: a policy DENY (or an infra HALT) never runs the tool; a
`require_approval` policy suspends the action durably (D1) and returns PENDING with the approval handle.

This core is pure kernel (imports only `core`/`delivery.sdk`), so it is unit-testable without the MCP
SDK; `server.py`/`proxy.py` import `mcp` lazily.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any

from quaicu.core.errors import (
    LifecycleDeniedError,
    LifecycleHaltedError,
    LifecyclePendingApprovalError,
)
from quaicu.core.types import Actor
from quaicu.delivery.sdk.kernel import Kernel

# The real tool: given the tool's argument dict, produce its result (a registered handler, or a forward
# to a downstream MCP server in the proxy). Only reached when governance ALLOWS the call.
ToolExecutor = Callable[[dict[str, Any]], Awaitable[Any]]


class ToolStatus(str, Enum):
    ALLOWED = "ALLOWED"      # governed + executed + sealed; `result` carries the tool output
    DENIED = "DENIED"        # policy denied → the tool did NOT run (fail-closed)
    PENDING = "PENDING"      # require_approval → durably suspended; `handle_id` awaits a human decision
    HALTED = "HALTED"        # infra/execute failure → fail-closed halt


@dataclasses.dataclass(frozen=True)
class ToolOutcome:
    """The governed result of one tool call."""

    status: ToolStatus
    result: Any = None
    reason: str | None = None
    action_id: str | None = None
    handle_id: str | None = None

    @property
    def blocked(self) -> bool:
        """True if the tool must NOT be treated as having run (deny/halt/pending)."""
        return self.status is not ToolStatus.ALLOWED


async def govern_tool_call(
    kernel: Kernel,
    *,
    actor: Actor,
    tool_name: str,
    arguments: dict[str, Any] | None,
    policy: str | None = None,
    execute: ToolExecutor,
) -> ToolOutcome:
    """Govern one MCP tool call and return its `ToolOutcome`. Never raises for a governance/infra
    outcome — the status carries it.

    The call is governed as action type ``policy`` when given, else ``mcp.<tool_name>`` (the
    per-tool default). The tool's ``arguments`` become the action **payload** directly, so a CEL
    policy can condition on ``payload_<field>`` (e.g. ``payload_amount > 10000``). Point several
    tools at one ``policy`` (action type) to govern them with a single policy.
    """
    args = dict(arguments or {})
    action_type = policy or f"mcp.{tool_name}"

    try:
        result = await kernel.govern_action(
            action_type=action_type, actor=actor, payload=args, execute=lambda: execute(args)
        )
        return ToolOutcome(ToolStatus.ALLOWED, result=result)
    except LifecyclePendingApprovalError as exc:
        detail = exc.detail or {}
        return ToolOutcome(
            ToolStatus.PENDING,
            reason="pending human approval",
            action_id=detail.get("action_id"),
            handle_id=detail.get("handle_id"),
        )
    except LifecycleDeniedError as exc:
        detail = exc.detail or {}
        return ToolOutcome(
            ToolStatus.DENIED, reason="denied by governance policy", action_id=detail.get("action_id")
        )
    except LifecycleHaltedError as exc:
        detail = exc.detail or {}
        return ToolOutcome(
            ToolStatus.HALTED, reason="halted (fail-closed)", action_id=detail.get("action_id")
        )
