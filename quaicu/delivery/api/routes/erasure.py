"""Crypto-shredding erasure routes (WS-G — GDPR / DPDP right to erasure).

  POST /v1/erasure/{tenant}/{subject}   → crypto-shred the data subject (destroy its key)
  GET  /v1/erasure/{tenant}/{subject}   → erasure status

Erasure does **not** delete ledger entries (the K·02 log is append-only / tamper-evident). It destroys
the per-subject encryption key so the PII ciphertext stored anywhere becomes irrecoverable, while every
Merkle proof still verifies. Same tenant-isolation guard as the audit trail; gated by the
``erasure:write`` scope. The erasure receipt is suitable for sealing into the ledger as proof the
right was honored.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from quaicu.delivery.api.deps import enforce_scope, get_request_tenant
from quaicu.delivery.api.scopes import ERASURE_WRITE

router = APIRouter(prefix="/v1/erasure", tags=["erasure"])


class ErasureReceiptResponse(BaseModel):
    tenant: str
    subject: str
    erased: bool
    key_destroyed: bool
    erased_at: str
    method: str


class ErasureStatusResponse(BaseModel):
    tenant: str
    subject: str
    erased: bool


def _engine(request: Request):
    engine = getattr(request.app.state, "erasure_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail={"error": "Erasure not enabled", "code": "ERASURE_DISABLED"},
        )
    return engine


def _guard_tenant(request: Request, tenant: str) -> None:
    if tenant != str(get_request_tenant(request)):
        raise HTTPException(
            status_code=403,
            detail={"error": "Cannot erase another tenant's subject", "code": "TENANT_ISOLATION"},
        )


@router.post(
    "/{tenant}/{subject}",
    response_model=ErasureReceiptResponse,
    summary="Crypto-shred a data subject (GDPR/DPDP right to erasure)",
)
async def erase_subject(tenant: str, subject: str, request: Request) -> ErasureReceiptResponse:
    _guard_tenant(request, tenant)
    enforce_scope(request, ERASURE_WRITE)
    receipt = _engine(request).erase(tenant=tenant, subject=subject)
    return ErasureReceiptResponse(
        tenant=receipt.tenant,
        subject=receipt.subject,
        erased=receipt.erased,
        key_destroyed=receipt.key_destroyed,
        erased_at=receipt.erased_at,
        method=receipt.method,
    )


@router.get(
    "/{tenant}/{subject}",
    response_model=ErasureStatusResponse,
    summary="Erasure status for a data subject",
)
async def erasure_status(tenant: str, subject: str, request: Request) -> ErasureStatusResponse:
    _guard_tenant(request, tenant)
    enforce_scope(request, ERASURE_WRITE)
    erased = _engine(request).is_erased(tenant=tenant, subject=subject)
    return ErasureStatusResponse(tenant=tenant, subject=subject, erased=erased)
