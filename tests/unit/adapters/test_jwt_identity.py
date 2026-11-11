"""Unit tests for JWTIdentityAdapter."""

from __future__ import annotations

import jwt
import pytest

from quaicu.adapters.identity.jwt_adapter import JWTIdentityAdapter
from quaicu.core.errors import IdentityPortError, TenantIsolationError
from quaicu.core.types import RequestContext, TenantId

SECRET = "test-secret-key"
TENANT = TenantId("ciro-bank")


def _token(
    sub: str = "alice",
    tenant: str = "ciro-bank",
    roles: list[str] | None = None,
    extra: dict | None = None,
) -> str:
    payload = {"sub": sub, "tenant": tenant, "roles": roles or ["role:analyst"]}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def _ctx(token: str) -> RequestContext:
    return RequestContext(raw_token=token)


def _adapter() -> JWTIdentityAdapter:
    return JWTIdentityAdapter(secret_or_key=SECRET, algorithms=["HS256"])


# ── Happy path ────────────────────────────────────────────────────────────────────


async def test_valid_jwt_resolves_actor():
    actor = await _adapter().resolve_actor(context=_ctx(_token()), tenant=TENANT)
    assert actor.id == "alice"


async def test_roles_extracted():
    actor = await _adapter().resolve_actor(context=_ctx(_token(roles=["role:risk_head"])), tenant=TENANT)
    assert "role:risk_head" in actor.roles


async def test_tenant_preserved_in_actor():
    actor = await _adapter().resolve_actor(context=_ctx(_token()), tenant=TENANT)
    assert actor.tenant == TENANT


async def test_extra_claims_in_attributes():
    token = _token(extra={"department": "risk"})
    actor = await _adapter().resolve_actor(context=_ctx(token), tenant=TENANT)
    assert actor.attributes.get("department") == "risk"


# ── Fail-closed ───────────────────────────────────────────────────────────────────


async def test_missing_token_raises_identity_error():
    ctx = RequestContext(raw_token=None)
    with pytest.raises(IdentityPortError, match="No bearer token"):
        await _adapter().resolve_actor(context=ctx, tenant=TENANT)


async def test_invalid_token_raises_identity_error():
    ctx = RequestContext(raw_token="not-a-jwt")
    with pytest.raises(IdentityPortError):
        await _adapter().resolve_actor(context=ctx, tenant=TENANT)


async def test_wrong_secret_raises_identity_error():
    token = jwt.encode({"sub": "alice", "tenant": "ciro-bank"}, "wrong-secret", algorithm="HS256")
    with pytest.raises(IdentityPortError):
        await _adapter().resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_missing_sub_raises_identity_error():
    token = jwt.encode({"tenant": "ciro-bank"}, SECRET, algorithm="HS256")
    with pytest.raises(IdentityPortError, match="sub"):
        await _adapter().resolve_actor(context=_ctx(token), tenant=TENANT)


# ── Tenant isolation (F-07) ───────────────────────────────────────────────────────


async def test_jwt_tenant_mismatch_raises_isolation_error():
    token = _token(tenant="evil-bank")
    with pytest.raises(TenantIsolationError):
        await _adapter().resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_jwt_no_tenant_claim_does_not_raise():
    # If JWT has no tenant claim, we can't cross-check — allow it
    token = jwt.encode({"sub": "alice"}, SECRET, algorithm="HS256")
    actor = await _adapter().resolve_actor(context=_ctx(token), tenant=TENANT)
    assert actor.id == "alice"
