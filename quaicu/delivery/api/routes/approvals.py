"""HITL approvals routes — the operator approval queue (K·03).

A reviewable queue over the in-process HITL port: list pending approvals and approve/reject them.
The caller is the actor the API authenticated; the HITL port itself enforces approver eligibility
and the self-approval guard on decide.

    GET  /v1/approvals                       → 200 list pending approval records
    POST /v1/approvals/{handle_id}/approve   → 200 approve (as the authenticated actor)
    POST /v1/approvals/{handle_id}/reject    → 200 reject  (as the authenticated actor)

Suspend-then-resume: a REQUIRE_APPROVAL action suspends at PENDING_APPROVAL — the SDK entry points
(`guard`/`wrap`/`generate`) and `/v1/actions/propose` run with `defer_gate=True`, so the action is
recorded and its approval registered without polling (no false timeout→DENY). Approving here drives
`kernel.decide_approval` → `resume_approved` (execute → seal → emit); rejecting DENIES it. With the
Postgres approval store and action repository a pending action resumes across restarts. (A webhook
adapter keeps its queue in an external system → not listable here → 503; that path resumes via its
own callback.)

The signed email-link routes live on `link_router`: they authenticate with the HMAC-signed token in
the URL, not a bearer, so they are included without the API's authentication dependency.
"""

from __future__ import annotations

import html
import os

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from quaicu.core.errors import HITLPortError
from quaicu.core.hitl.links import ApprovalLinkSigner
from quaicu.core.hitl.model import ApprovalRecord
from quaicu.core.types import Actor, ActorId, ApprovalDecision, TenantId
from quaicu.delivery.api.deps import current_actor, enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import ApprovalListResponse, ApprovalRecordResponse
from quaicu.delivery.api.scopes import APPROVAL_DECIDE, APPROVAL_READ
from quaicu.delivery.sdk.kernel import Kernel

router = APIRouter(prefix="/v1/approvals", tags=["approvals"])
link_router = APIRouter(prefix="/v1/approvals", tags=["approvals"])


async def _authenticate(request: Request, *, scope: str) -> tuple[Kernel, Actor, TenantId]:
    """The serving kernel, the authenticated caller and the tenant.

    503 if the kernel has no in-process HITL port; 403 if a host principal lacks ``scope``.
    """
    enforce_scope(request, scope)
    kernel: Kernel = get_kernel(request)
    if kernel._in_process_hitl() is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Approvals require an in-process HITL port (an external/webhook queue "
                "is managed by its own system)",
                "code": "HITL_QUEUE_UNAVAILABLE",
            },
        )
    return kernel, current_actor(request), get_request_tenant(request)


def _to_response(record: ApprovalRecord) -> ApprovalRecordResponse:
    return ApprovalRecordResponse(
        handle_id=record.handle_id,
        action_id=str(record.action_id),
        tenant=str(record.tenant),
        required_approvers=[str(a) for a in record.required_approvers],
        requested_at=record.requested_at.isoformat(),
        decision=record.decision.value,
        decided_by=str(record.decided_by) if record.decided_by else None,
        decided_at=record.decided_at.isoformat() if record.decided_at else None,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        proposed_by=str(record.proposed_by) if record.proposed_by else None,
    )


@router.get("", response_model=ApprovalListResponse, summary="List pending HITL approvals")
async def list_approvals(request: Request) -> ApprovalListResponse:
    kernel, _, tenant = await _authenticate(request, scope=APPROVAL_READ)
    records = [r for r in kernel.list_pending_approvals() if str(r.tenant) == str(tenant)]
    return ApprovalListResponse(
        approvals=[_to_response(r) for r in records], count=len(records)
    )


@router.post(
    "/{handle_id}/approve",
    response_model=ApprovalRecordResponse,
    summary="Approve a pending HITL request",
)
async def approve(handle_id: str, request: Request) -> ApprovalRecordResponse:
    """Approve as the token-resolved actor. 404 if absent; 409 if already decided / not authorized /
    expired / self-approval."""
    return await _decide(request, handle_id, "approved")


@router.post(
    "/{handle_id}/reject",
    response_model=ApprovalRecordResponse,
    summary="Reject a pending HITL request",
)
async def reject(handle_id: str, request: Request) -> ApprovalRecordResponse:
    return await _decide(request, handle_id, "rejected")


async def _decide(request: Request, handle_id: str, decision: str) -> ApprovalRecordResponse:
    kernel, actor, tenant = await _authenticate(request, scope=APPROVAL_DECIDE)
    record = kernel._in_process_hitl().get_record(handle_id)  # type: ignore[union-attr]
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Approval {handle_id!r} not found", "code": "APPROVAL_NOT_FOUND"},
        )
    if str(record.tenant) != str(tenant):
        raise HTTPException(
            status_code=403,
            detail={"error": "Cannot decide another tenant's approval", "code": "TENANT_ISOLATION"},
        )
    try:
        updated = await kernel.decide_approval(handle_id, decision=decision, actor=actor)
    except HITLPortError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc), "code": exc.code})
    return _to_response(updated)


# ── Signed email-link approval (D1-2) ─────────────────────────────────────────────
# Authenticated by the HMAC-signed token in the URL (not a bearer). GET renders a confirm page so an
# email-scanner prefetch cannot auto-decide; POST commits. Single-use is enforced by the store.


def _link_signer() -> ApprovalLinkSigner:
    secret = os.getenv("QUAICU_APPROVAL_LINK_SECRET", "")
    if not secret:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Approval links are not configured (QUAICU_APPROVAL_LINK_SECRET unset)",
                "code": "APPROVAL_LINKS_DISABLED",
            },
        )
    return ApprovalLinkSigner(secret)


def _verify_link(token: str) -> dict:
    payload = _link_signer().verify(token)
    if payload is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "Invalid or expired approval link", "code": "APPROVAL_LINK_INVALID"},
        )
    return payload


def _kernel_for_tenant(request: Request, tenant: str) -> Kernel:
    """The kernel for a signed link. One kernel serves one tenant, so a link minted for a different
    tenant is refused outright."""
    kernel: Kernel = get_kernel(request)
    if tenant != str(kernel.tenant):
        raise HTTPException(
            status_code=403,
            detail={"error": "Approval link tenant mismatch", "code": "TENANT_ISOLATION"},
        )
    return kernel


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title>"
        f"<body style='font-family:system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem'>"
        f"{body}</body>",
        status_code=status_code,
    )


@link_router.get("/link/{token}", response_class=HTMLResponse, summary="Confirm an emailed approval link")
async def approval_link_page(token: str, request: Request) -> HTMLResponse:
    """Render a one-click confirmation page for an emailed approve/reject link. Committing is a POST to
    this same URL (so a link prefetch never decides)."""
    payload = _verify_link(token)
    verb = "approve" if payload["d"] == "approve" else "reject"
    kernel = _kernel_for_tenant(request, str(payload["t"]))
    hitl = kernel._in_process_hitl()
    record = hitl.get_record(str(payload["h"])) if hitl is not None else None
    if record is None or record.decision is not ApprovalDecision.PENDING:
        return _page(
            "Approval unavailable",
            "<p>This approval link is no longer valid — it may have already been decided or expired.</p>",
            status_code=409,
        )
    color = "#0a7d28" if verb == "approve" else "#b00020"
    return _page(
        f"Confirm {verb}",
        f"<h2>Confirm you want to <span style='color:{color}'>{verb}</span> this action</h2>"
        f"<ul><li><b>Action:</b> {html.escape(record.action_id)}</li>"
        f"<li><b>Requested by:</b> {html.escape(str(record.proposed_by))}</li></ul>"
        f"<form method='post' action='/v1/approvals/link/{html.escape(token)}'>"
        f"<button type='submit' style='padding:.6rem 1.2rem;background:{color};color:#fff;"
        f"border:0;border-radius:6px;font-size:1rem;cursor:pointer'>Confirm {verb}</button></form>",
    )


@link_router.post("/link/{token}", response_class=HTMLResponse, summary="Commit an emailed approval decision")
async def approval_link_commit(token: str, request: Request) -> HTMLResponse:
    """Verify the signed token and commit the decision as the approver it names. Single-use: an already
    decided approval → 409."""
    payload = _verify_link(token)
    tenant = str(payload["t"])
    kernel = _kernel_for_tenant(request, tenant)
    if kernel._in_process_hitl() is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "Approval queue unavailable for this deployment", "code": "HITL_QUEUE_UNAVAILABLE"},
        )
    record = kernel._in_process_hitl().get_record(str(payload["h"]))  # type: ignore[union-attr]
    if record is not None and str(record.tenant) != tenant:
        raise HTTPException(
            status_code=403,
            detail={"error": "Approval link tenant mismatch", "code": "TENANT_ISOLATION"},
        )
    actor = Actor(
        id=ActorId(str(payload["aid"])),
        tenant=TenantId(tenant),
        roles=tuple(str(r) for r in payload.get("ar", [])),
    )
    decision = "approved" if payload["d"] == "approve" else "rejected"
    try:
        await kernel.decide_approval(str(payload["h"]), decision=decision, actor=actor)
    except HITLPortError as exc:
        # Already decided (single-use), not authorized, expired, or self-approval.
        return _page("Approval not applied", f"<p>{html.escape(str(exc))}</p>", status_code=409)
    verb = "approved" if decision == "approved" else "rejected"
    return _page(f"Action {verb}", f"<h2>You have {verb} this action.</h2><p>You can close this page.</p>")
