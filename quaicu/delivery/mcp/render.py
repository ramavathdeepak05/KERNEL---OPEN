"""Render a governed `ToolOutcome` into an MCP `CallToolResult` (lazy ``mcp`` import).

Shared by the governed server (registered tools) and the proxy (downstream forward) so the agent sees a
consistent result: ALLOW → the tool output; DENY/HALT/PENDING → an error result that blocks the call,
with the approval handle surfaced for the PENDING case.
"""

from __future__ import annotations

import json

from quaicu.delivery.mcp.governance import ToolOutcome, ToolStatus

_BLOCKED_MESSAGE = {
    ToolStatus.DENIED: "blocked by governance policy",
    ToolStatus.HALTED: "halted (fail-closed)",
    ToolStatus.PENDING: "pending human approval",
}


def to_call_result(outcome: ToolOutcome):
    """Build a `mcp.types.CallToolResult` from a governed outcome."""
    import mcp.types as types

    if outcome.status is ToolStatus.ALLOWED:
        structured = outcome.result if isinstance(outcome.result, dict) else None
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(outcome.result, default=str))],
            structuredContent=structured,
            isError=False,
        )
    text = _BLOCKED_MESSAGE[outcome.status]
    if outcome.action_id:
        text += f" (action {outcome.action_id})"
    if outcome.status is ToolStatus.PENDING and outcome.handle_id:
        text += f" — approve handle {outcome.handle_id} via /v1/approvals"
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        isError=True,
        _meta={
            "quaicu_status": outcome.status.value,
            "action_id": outcome.action_id,
            "handle_id": outcome.handle_id,
        },
    )
