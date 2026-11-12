"""``/v1/tools`` — view and change the tool gateway's guardrails while it runs.

Served by ``quaicu gateway --admin-port N`` (the gateway and this API share one kernel). Every route
needs a policy-admin role; every change is a governed ``kernel.tools.configure`` action, sealed in the
ledger with who made it. Changes last until the gateway restarts — export them with
``GET /v1/tools/rules?format=toml`` and paste them into kernel.toml to keep them.

The AI has no route here: it reaches the gateway only over MCP, which offers no admin tools.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from quaicu.core.toolgate import ToolConfigError, parse_rule
from quaicu.delivery.api.routes.policies import _require_policy_admin

router = APIRouter(prefix="/v1/tools", tags=["tools"])


async def _gateway(request: Request):
    kernel, actor = await _require_policy_admin(request)
    gateway = getattr(kernel, "toolgate", None)
    if gateway is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "No tool gateway runs in this process. Start one with `quaicu gateway --admin-port N`.",
                "code": "TOOL_GATEWAY_NOT_RUNNING",
            },
        )
    return gateway, actor


def _parse(gateway, body: dict[str, Any]):
    try:
        return parse_rule(body, default_approvers=gateway.config.approvers)
    except ToolConfigError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc), "code": "INVALID_TOOL_RULE"}) from exc


@router.get("", summary="The tool catalogue: servers, tools, effective decisions, session taint")
async def get_catalogue(request: Request) -> dict[str, Any]:
    gateway, _actor = await _gateway(request)
    return gateway.catalogue()


@router.get("/rules", summary="The live tool rules (JSON, or TOML to paste into kernel.toml)")
async def list_rules(request: Request, format: str = Query("json", pattern="^(json|toml)$")):
    gateway, _actor = await _gateway(request)
    if format == "toml":
        return PlainTextResponse(gateway.rules.to_toml(), media_type="application/toml")
    return {"version": gateway.rules.version, "rules": [r.as_dict() for r in gateway.rules.rules()]}


@router.get("/rules/{rule_id}", summary="One tool rule")
async def get_rule(request: Request, rule_id: str) -> dict[str, Any]:
    gateway, _actor = await _gateway(request)
    rule = gateway.rules.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail={"error": f"No tool rule {rule_id!r}", "code": "TOOL_RULE_NOT_FOUND"})
    return rule.as_dict()


@router.post("/rules", status_code=201, summary="Add a tool rule (applies to the next call)")
async def create_rule(request: Request, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    gateway, actor = await _gateway(request)
    rule = _parse(gateway, body)
    if gateway.rules.get_rule(rule.id) is not None:
        raise HTTPException(status_code=409, detail={"error": f"Tool rule {rule.id!r} exists; use PUT", "code": "TOOL_RULE_EXISTS"})
    await _apply(gateway.put_rule(actor, rule))
    return rule.as_dict()


@router.put("/rules/{rule_id}", summary="Replace a tool rule (applies to the next call)")
async def replace_rule(request: Request, rule_id: str, body: dict[str, Any] = Body(...)) -> dict[str, Any]:
    gateway, actor = await _gateway(request)
    if gateway.rules.get_rule(rule_id) is None:
        raise HTTPException(status_code=404, detail={"error": f"No tool rule {rule_id!r}", "code": "TOOL_RULE_NOT_FOUND"})
    rule = _parse(gateway, {**body, "id": rule_id})
    await _apply(gateway.put_rule(actor, rule))
    return rule.as_dict()


@router.delete("/rules/{rule_id}", status_code=204, summary="Remove a tool rule")
async def delete_rule(request: Request, rule_id: str) -> None:
    gateway, actor = await _gateway(request)
    if gateway.rules.get_rule(rule_id) is None:
        raise HTTPException(status_code=404, detail={"error": f"No tool rule {rule_id!r}", "code": "TOOL_RULE_NOT_FOUND"})
    await _apply(gateway.remove_rule(actor, rule_id))


@router.post("/servers/{server}/{state}", summary="Take a tool server out of service, or back in")
async def set_server(request: Request, server: str, state: str) -> dict[str, Any]:
    gateway, actor = await _gateway(request)
    if state not in ("enable", "disable"):
        raise HTTPException(status_code=404, detail={"error": "Use /enable or /disable", "code": "NOT_FOUND"})
    if server not in gateway.rules.servers:
        raise HTTPException(status_code=404, detail={"error": f"No tool server {server!r}", "code": "TOOL_SERVER_NOT_FOUND"})
    await _apply(gateway.set_server_enabled(actor, server, state == "enable"))
    return {"server": server, "enabled": state == "enable"}


@router.post("/session/reset", summary="Clear the session's taint (when the agent's conversation resets)")
async def reset_session(request: Request) -> dict[str, Any]:
    gateway, actor = await _gateway(request)
    await _apply(gateway.reset_session(actor))
    return {"tainted": False, "sources": []}


async def _apply(change) -> None:
    try:
        await change
    except ToolConfigError as exc:
        raise HTTPException(status_code=422, detail={"error": str(exc), "code": "INVALID_TOOL_RULE"}) from exc
