"""Action lifecycle routes — propose and look up.

POST /v1/actions/propose  →  202 ActionResponse
GET  /v1/actions/{id}     →  200 ActionResponse

These routes are thin adapters over LifecycleEngine. No business logic here. The caller is the
actor `delivery/api/deps.authenticate` resolved — never an identity taken from the request body.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from quaicu.core.errors import QUAICUError, StoragePortError
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    IdempotencyKey,
    TenantId,
)
from quaicu.delivery.api.deps import current_actor, enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import ActionResponse, ProposeRequest
from quaicu.delivery.api.scopes import ACTIONS_READ, ACTIONS_WRITE
from quaicu.delivery.sdk.kernel import Kernel

router = APIRouter(prefix="/v1/actions", tags=["actions"])


def _action_response(action: Action) -> ActionResponse:
    return ActionResponse(
        action_id=str(action.id),
        state=action.state.value,
        type=action.type,
        tenant=str(action.tenant),
        actor_id=str(action.actor.id),
    )


@router.post(
    "/propose",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ActionResponse,
    summary="Propose a governed action",
)
async def propose_action(body: ProposeRequest, request: Request) -> ActionResponse:
    """Drive an action through the full governance lifecycle.

    Returns 202 with the action in its resulting state: COMPLETED when allowed, or
    PENDING_APPROVAL when a policy requires approval (it completes later through the approvals
    API). A repeated ``idempotency_key`` returns the existing action. Returns 403 if policy denies;
    422 if a lifecycle halt occurs.
    """
    kernel: Kernel = get_kernel(request)
    tenant: TenantId = get_request_tenant(request)
    enforce_scope(request, ACTIONS_WRITE)

    action = Action(
        id=ActionId(str(uuid.uuid4())),
        type=body.type,
        payload=body.payload,
        actor=current_actor(request),
        tenant=tenant,
        idempotency_key=IdempotencyKey(body.idempotency_key),
        proposed_at=datetime.now(tz=timezone.utc),
    )

    async def execute_fn() -> dict[str, Any]:
        return {"payload": dict(action.payload)}

    try:
        # defer_gate: a require_approval action pauses at PENDING_APPROVAL (queued to HITL) and is
        # completed later via the approvals API — it does NOT block the request or fail-closed-deny
        # on a synchronous timeout. The actor is already authenticated, so no context is passed.
        final = await kernel.engine.run(action, execute_fn, defer_gate=True)
    except QUAICUError as exc:
        raise HTTPException(status_code=503, detail={"error": str(exc), "code": exc.code})

    if final.state is ActionState.DENIED:
        raise HTTPException(
            status_code=403,
            detail={"error": "Action denied by governance", "action_id": str(final.id)},
        )
    if final.state is ActionState.HALTED:
        raise HTTPException(
            status_code=422,
            detail={"error": "Action halted by governance", "action_id": str(final.id)},
        )

    # 202 ActionResponse — COMPLETED (allowed) or PENDING_APPROVAL (gated; awaiting an approver).
    return _action_response(final)


@router.get(
    "/{action_id}",
    response_model=ActionResponse,
    summary="Get action state",
)
async def get_action(action_id: str, request: Request) -> ActionResponse:
    """Look up an action by id, scoped to this kernel's tenant. 404 if it does not exist."""
    enforce_scope(request, ACTIONS_READ)
    kernel: Kernel = get_kernel(request)
    repo = kernel.engine._repo  # type: ignore[attr-defined]
    try:
        action = await repo.get_by_id(get_request_tenant(request), ActionId(action_id))
    except StoragePortError as exc:
        raise HTTPException(status_code=503, detail={"error": str(exc), "code": exc.code})
    if action is None:
        raise HTTPException(
            status_code=404, detail={"error": "Action not found", "action_id": action_id}
        )
    return _action_response(action)
