"""Inference route — a governed model call.

POST /v1/inference  →  200 InferenceResponse (or 403 denied / 422 halted)

Thin adapter over ``Kernel.generate``: the model call runs as an ``inference.generate`` action
under the resolved governance profile (allowlist / PII masking / prompt logging / budget, plus
policy / HITL / seal / emit if the profile enforces them). The caller is the authenticated actor —
never an identity taken from the body.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from quaicu.core.errors import LifecycleDeniedError, LifecycleHaltedError, QUAICUError
from quaicu.core.types import ModelRef
from quaicu.delivery.api.deps import current_actor, enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import InferenceRequest, InferenceResponse
from quaicu.delivery.api.scopes import INFERENCE_WRITE
from quaicu.delivery.sdk.kernel import Kernel

router = APIRouter(prefix="/v1", tags=["inference"])


@router.post(
    "/inference",
    response_model=InferenceResponse,
    summary="Make a governed model call",
)
async def inference(body: InferenceRequest, request: Request) -> InferenceResponse:
    """Run a governed model call through the AI Gateway + lifecycle.

    401 without a token; 503 if no inference adapter is configured; 403 if governance denies;
    422 if the call halts.
    """
    kernel: Kernel = get_kernel(request)
    tenant = get_request_tenant(request)

    enforce_scope(request, INFERENCE_WRITE)
    if not kernel.has_inference:
        raise HTTPException(
            status_code=503,
            detail={"error": "No inference adapter configured", "code": "INFERENCE_NOT_CONFIGURED"},
        )
    model_ref = ModelRef(id=body.model_id, version=body.model_version)

    try:
        response = await kernel.generate(
            prompt_text=body.prompt_text,
            model_ref=model_ref,
            actor=current_actor(request),
            payload=body.payload,
            idempotency_key=body.idempotency_key,
            tenant=tenant,
        )
    except LifecycleDeniedError as exc:
        raise HTTPException(
            status_code=403,
            detail={"error": "Inference denied by governance", "code": exc.code},
        )
    except LifecycleHaltedError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "Inference halted by governance", "code": exc.code},
        )
    except QUAICUError as exc:
        raise HTTPException(status_code=503, detail={"error": str(exc), "code": exc.code})

    return InferenceResponse(
        content=response.content,
        model_id=response.model_id,
        prompt_hash=str(response.recorded_output.get("prompt_hash", "")),
        response_hash=str(response.recorded_output.get("response_hash", "")),
        action_id=str(response.recorded_output.get("action_id", "")),
        state="COMPLETED",
    )
