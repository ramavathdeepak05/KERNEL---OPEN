"""Ledger routes — trail, regulator export, and verify.

GET  /v1/ledger/{tenant}/trail   →  200 LedgerTrailResponse
GET  /v1/ledger/{tenant}/export  →  200 LedgerProofBundle (self-verifying regulator export, WS-F)
POST /v1/ledger/export/verify    →  200 { ok, errors } (stateless offline-equivalent verifier)
GET  /v1/ledger/health           →  200 { "ok": true }
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from quaicu.core.types import TenantId
from quaicu.delivery.api.deps import enforce_scope, get_kernel, get_request_tenant
from quaicu.delivery.api.schemas import LedgerEntryResponse, LedgerTrailResponse
from quaicu.delivery.api.scopes import LEDGER_READ

router = APIRouter(prefix="/v1/ledger", tags=["ledger"])


@router.get(
    "/{tenant}/trail",
    response_model=LedgerTrailResponse,
    summary="List sealed ledger entries for a tenant",
)
async def ledger_trail(tenant: str, request: Request) -> LedgerTrailResponse:
    """Return the sealed ledger entries for the requested tenant.

    The caller is authenticated by the API (401 otherwise). The audit trail is tenant-private: the path tenant
    must match this kernel instance's tenant (F-07) — any mismatch is 403, never a silent empty
    result. Entries are read via the ledger's tenant-scoped ``get_entries`` and projected to the
    API schema.
    """
    enforce_scope(request, LEDGER_READ)

    kernel = get_kernel(request)
    if tenant != str(get_request_tenant(request)):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Cannot read another tenant's audit trail",
                "code": "TENANT_ISOLATION",
            },
        )

    ledger = kernel.engine._ledger  # type: ignore[attr-defined]
    entries = ledger.get_entries(TenantId(tenant))

    projected = [
        LedgerEntryResponse(
            ledger_seq=e.ledger_seq,
            action_id=str(e.action_id),
            action_type=e.action_type,
            actor_id=str(e.actor_id),
            decision=e.decision.value,
            policy_versions=list(e.policy_versions),
            sealed_at=e.sealed_at.isoformat(),
            approver=str(e.approver) if e.approver else None,
        )
        for e in entries
    ]

    return LedgerTrailResponse(tenant=tenant, entries=projected, count=len(projected))


def _parse_window(value: str | None, field: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"error": f"{field} is not an ISO-8601 datetime", "code": "BAD_WINDOW"},
        )


@router.get(
    "/{tenant}/export",
    summary="Export a self-verifying ledger-proof bundle for a regulator (WS-F)",
)
async def ledger_export(tenant: str, request: Request) -> dict:
    """Build a regulator proof bundle of the tenant's sealed actions in an optional time window.

    Query params (all optional): ``from`` / ``to`` (ISO-8601 datetimes), ``regulations`` and
    ``policy_versions`` (comma-separated). Same tenant-isolation + scope guard as the audit trail —
    the bundle is tenant-private. The returned JSON is independently verifiable offline via
    ``POST /v1/ledger/export/verify`` or `core.regmap.export.verify_ledger_proof_bundle`.
    """
    enforce_scope(request, LEDGER_READ)

    kernel = get_kernel(request)
    if tenant != str(get_request_tenant(request)):
        raise HTTPException(
            status_code=403,
            detail={"error": "Cannot export another tenant's ledger", "code": "TENANT_ISOLATION"},
        )

    qp = request.query_params
    window_start = _parse_window(qp.get("from"), "from")
    window_end = _parse_window(qp.get("to"), "to")
    regulations = [s for s in (qp.get("regulations", "").split(",")) if s]
    policy_versions = [s for s in (qp.get("policy_versions", "").split(",")) if s]

    bundle = kernel.export_ledger_proof(
        TenantId(tenant),
        window_start=window_start,
        window_end=window_end,
        regulation_refs=regulations or None,
        policy_versions=policy_versions or None,
    )
    return bundle.to_dict()


def _ledger_signer(kernel: object) -> object | None:
    """The tenant kernel's STH signer (the source of the pinned trust anchor), or None."""
    ledger = getattr(getattr(kernel, "engine", None), "_ledger", None)
    return getattr(ledger, "_signer", None)


def _signing_algorithm(pem: str) -> str:
    """Human label for the signing algorithm, inferred from the public key type."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode())
    if isinstance(key, Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ecdsa-p256"
    return "unknown"


class SigningKeyResponse(BaseModel):
    key_id: str
    public_key_pem: str
    algorithm: str


@router.get(
    "/signing-key",
    response_model=SigningKeyResponse,
    summary="Publish this tenant's ledger signing key (pin it out-of-band to verify exports, D3-1)",
)
async def ledger_signing_key(request: Request) -> SigningKeyResponse:
    """Return the tenant's STH verification key ``{key_id, public_key_pem, algorithm}``.

    This is the trust anchor a regulator records **once at onboarding** and pins, then verifies every
    future export against it (``verify_ledger_proof_bundle(bundle, trusted_keys={key_id: pem})``) — so
    a later kernel-side key swap cannot pass. Tenant-private, like the trail/export.
    """
    enforce_scope(request, LEDGER_READ)
    signer = _ledger_signer(get_kernel(request))
    key_id = getattr(signer, "key_id", None)
    pem = getattr(signer, "public_key_pem", None)
    if not key_id or not pem:
        raise HTTPException(
            status_code=503,
            detail={"error": "This deployment's ledger signer does not expose a public key",
                    "code": "SIGNING_KEY_UNAVAILABLE"},
        )
    return SigningKeyResponse(key_id=str(key_id), public_key_pem=str(pem),
                              algorithm=_signing_algorithm(str(pem)))


class WitnessKeyResponse(BaseModel):
    witness_id: str
    public_key_pem: str
    algorithm: str


@router.get(
    "/witness-key",
    response_model=WitnessKeyResponse,
    summary="Publish this deployment's ledger witness key (pin it to verify anchor cosignatures, D3-2)",
)
async def ledger_witness_key(request: Request) -> WitnessKeyResponse:
    """Return the independent anchor witness's verification key ``{witness_id, public_key_pem,
    algorithm}``. Pin it out-of-band (like the signing key) and pass it as ``trusted_witnesses`` to
    verify a bundle's anchor cosignature — proof the log was externally attested (no split-view)."""
    enforce_scope(request, LEDGER_READ)
    witness = getattr(get_kernel(request), "witness", None)
    wid = getattr(witness, "witness_id", None)
    pem = getattr(witness, "public_key_pem", None)
    if not wid or not pem:
        raise HTTPException(
            status_code=503,
            detail={"error": "This deployment has no ledger anchor witness configured",
                    "code": "WITNESS_UNAVAILABLE"},
        )
    return WitnessKeyResponse(witness_id=str(wid), public_key_pem=str(pem),
                             algorithm=_signing_algorithm(str(pem)))


class VerifyResult(BaseModel):
    ok: bool
    errors: list[str]


@router.post(
    "/export/verify",
    response_model=VerifyResult,
    summary="Verify a ledger-proof bundle against this tenant's pinned signing key",
)
async def ledger_export_verify(bundle: dict, request: Request) -> VerifyResult:
    """Verify a posted export. Integrity is checked from the bundle; **authenticity is pinned against
    this tenant kernel's signing key** (D3-1) — so this answers "did we sign this?", not "is the
    bundle self-consistent?". A bundle carrying a forged/unknown key_id fails. For a fully independent
    check, a regulator runs `core.regmap.export.verify_ledger_proof_bundle` offline against the key
    they pinned from `GET /v1/ledger/signing-key`."""
    from quaicu.core.regmap.export import trusted_keys_from_signer, verify_ledger_proof_bundle

    enforce_scope(request, LEDGER_READ)
    kernel = get_kernel(request)
    signer = _ledger_signer(kernel)
    try:
        trusted_keys = trusted_keys_from_signer(signer) if signer is not None else None
    except ValueError:
        trusted_keys = None
    # If an anchor witness is wired, also pin it so the anchor cosignature is verified (D3-2).
    witness = getattr(kernel, "witness", None)
    wid = getattr(witness, "witness_id", None)
    wpem = getattr(witness, "public_key_pem", None)
    trusted_witnesses = {str(wid): str(wpem)} if wid and wpem else None
    ok, errors = verify_ledger_proof_bundle(
        bundle, trusted_keys=trusted_keys, trusted_witnesses=trusted_witnesses
    )
    return VerifyResult(ok=ok, errors=errors)


@router.get("/health", summary="Ledger health check")
async def ledger_health(request: Request) -> dict:
    return {"ok": True}
