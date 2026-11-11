"""Starter policy-pack routes — browse + import a ready-made regulatory baseline.

    GET  /v1/policy-packs                 → 200 list the shipped packs (DPDP, EU AI Act, …)
    POST /v1/policy-packs/{pack_id}/import → 200 register every pack policy as a DRAFT

Import reuses the same write-through primitive as ``POST /v1/policies`` (``kernel.register_policy``),
so imported policies enter as DRAFTs and go through the normal backtest → activate lifecycle — the
pack is a starting point, never silently activated. Auth is identical to policy authoring
(policy-admin role), since import writes policies.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from quaicu.core.errors import PolicyCompileError, PolicyTransitionError
from quaicu.core.policy import packs as packs_mod
from quaicu.core.policy.model import PolicyEnvelope, PolicyLifecycle
from quaicu.core.types import ApproverRef, Decision
from quaicu.delivery.api.deps import get_request_tenant
from quaicu.delivery.api.routes.policies import _require_policy_admin
from quaicu.delivery.api.schemas import (
    PolicyPackActionTypeResponse,
    PolicyPackImportResponse,
    PolicyPackListResponse,
    PolicyPackPolicyResponse,
    PolicyPackResponse,
)

router = APIRouter(prefix="/v1/policy-packs", tags=["policy-packs"])


def _pack_response(pack: packs_mod.PolicyPack) -> PolicyPackResponse:
    return PolicyPackResponse(
        id=pack.id,
        name=pack.name,
        regulation=pack.regulation,
        description=pack.description,
        summary=pack.summary,
        usage=pack.usage,
        action_types=list(pack.action_types),
        action_specs=[
            PolicyPackActionTypeResponse(
                name=a.name, use_case=a.use_case, payload=a.payload, example=a.example
            )
            for a in pack.action_specs
        ],
        policy_count=len(pack.policies),
        policies=[
            PolicyPackPolicyResponse(
                id=p.id,
                title=p.title,
                description=p.description,
                governs=p.governs,
                condition=p.condition,
                decision=p.decision,
                approvers=list(p.approvers),
                regulatory_refs=list(p.regulatory_refs),
            )
            for p in pack.policies
        ],
    )


@router.get(
    "",
    response_model=PolicyPackListResponse,
    summary="List the available starter policy packs",
)
async def list_policy_packs(request: Request) -> PolicyPackListResponse:
    await _require_policy_admin(request)
    packs = packs_mod.list_packs()
    return PolicyPackListResponse(
        packs=[_pack_response(p) for p in packs], count=len(packs)
    )


@router.post(
    "/{pack_id}/import",
    response_model=PolicyPackImportResponse,
    summary="Import a pack's policies as DRAFT versions",
)
async def import_policy_pack(pack_id: str, request: Request) -> PolicyPackImportResponse:
    """Register every policy in the pack as a DRAFT (version 1) for the caller's tenant.

    A policy whose id already exists (or is finalised) is skipped, not overwritten — re-importing is
    safe. The tenant then backtests + activates each DRAFT through the normal F-10 gate.

    Every imported policy is scoped to this kernel's tenant (``PolicyStore.lookup`` treats a missing
    tenant as *every* tenant) and ``scope.pack`` records which pack it came from.
    """
    kernel, _ = await _require_policy_admin(request)
    tenant = str(get_request_tenant(request))
    pack = packs_mod.get_pack(pack_id)
    if pack is None:
        raise HTTPException(
            status_code=404,
            detail={"error": f"Policy pack {pack_id!r} not found", "code": "POLICY_PACK_NOT_FOUND"},
        )

    imported: list[str] = []
    skipped: list[dict[str, str]] = []
    for p in pack.policies:
        envelope = PolicyEnvelope(
            id=p.id,
            version=1,
            governs=p.governs,
            scope={"tenant": tenant, "pack": pack_id},
            condition=p.condition,
            decision=Decision(p.decision),
            approvers=tuple(ApproverRef(a) for a in p.approvers),
            regulatory_refs=tuple(p.regulatory_refs),
            lifecycle=PolicyLifecycle.DRAFT,
        )
        try:
            await kernel.register_policy(envelope)
            imported.append(p.id)
        except PolicyTransitionError:
            skipped.append({"id": p.id, "reason": "already exists"})
        except PolicyCompileError as exc:
            skipped.append({"id": p.id, "reason": f"compile error: {exc}"})

    return PolicyPackImportResponse(
        pack_id=pack_id, imported=imported, skipped=skipped, count=len(imported)
    )
