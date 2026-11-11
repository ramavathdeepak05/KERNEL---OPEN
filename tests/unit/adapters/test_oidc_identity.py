"""Unit tests for OIDCIdentityAdapter — JWKS verification, rotation, and fail-closed paths.

No network: the adapter's JWKS fetch is injected with a static key set built from a locally
generated RSA key pair, and tokens are signed with the matching private key.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from quaicu.adapters.identity.oidc import OIDCIdentityAdapter
from quaicu.core.errors import IdentityPortError, TenantIsolationError
from quaicu.core.types import RequestContext, TenantId

ISSUER = "https://idp.example.com/oauth2/default"
AUDIENCE = "quaicu-kernel"
TENANT = TenantId("ciro-bank")


# ── Key + token helpers ─────────────────────────────────────────────────────────


def _make_key(kid: str) -> tuple[str, dict]:
    """Return (PEM private key, public JWK dict) for ``kid``."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return pem, jwk


def _jwks(*jwks: dict) -> dict:
    return {"keys": list(jwks)}


def _token(
    pem: str,
    kid: str,
    *,
    sub: str = "alice",
    tenant: str | None = "ciro-bank",
    roles: list[str] | None = None,
    iss: str = ISSUER,
    aud: str = AUDIENCE,
    exp_delta: int = 3600,
    extra: dict | None = None,
) -> str:
    now = int(time.time())
    payload: dict = {"sub": sub, "iss": iss, "aud": aud, "iat": now, "exp": now + exp_delta}
    if tenant is not None:
        payload["tenant"] = tenant
    if roles is not None:
        payload["roles"] = roles
    if extra:
        payload.update(extra)
    return jwt.encode(payload, pem, algorithm="RS256", headers={"kid": kid})


def _fetcher(document: dict):
    async def fetch() -> dict:
        return document

    return fetch


def _adapter(document: dict, **kwargs) -> OIDCIdentityAdapter:
    return OIDCIdentityAdapter(
        issuer=ISSUER, audience=AUDIENCE, jwks_fetcher=_fetcher(document), **kwargs
    )


def _ctx(token: str) -> RequestContext:
    return RequestContext(raw_token=token)


# ── Happy path ────────────────────────────────────────────────────────────────────


async def test_valid_token_resolves_actor():
    pem, jwk = _make_key("k1")
    adapter = _adapter(_jwks(jwk))
    actor = await adapter.resolve_actor(context=_ctx(_token(pem, "k1")), tenant=TENANT)
    assert actor.id == "alice"
    assert actor.tenant == TENANT


async def test_roles_and_extra_claims_mapped():
    pem, jwk = _make_key("k1")
    adapter = _adapter(_jwks(jwk))
    token = _token(pem, "k1", roles=["role:risk_head"], extra={"department": "risk"})
    actor = await adapter.resolve_actor(context=_ctx(token), tenant=TENANT)
    assert "role:risk_head" in actor.roles
    assert actor.attributes.get("department") == "risk"
    # Verification claims must not leak into the attribute bag.
    assert "iss" not in actor.attributes
    assert "aud" not in actor.attributes


# ── Fail-closed ───────────────────────────────────────────────────────────────────


async def test_missing_token_raises():
    pem, jwk = _make_key("k1")
    with pytest.raises(IdentityPortError, match="No bearer token"):
        await _adapter(_jwks(jwk)).resolve_actor(context=RequestContext(raw_token=None), tenant=TENANT)


async def test_wrong_audience_raises():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1", aud="some-other-api")
    with pytest.raises(IdentityPortError):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_wrong_issuer_raises():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1", iss="https://evil.example.com/")
    with pytest.raises(IdentityPortError):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_expired_token_raises():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1", exp_delta=-10)
    with pytest.raises(IdentityPortError, match="expired"):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_token_signed_by_unknown_key_raises():
    # JWKS publishes k1, but the token is signed by an entirely different key also labelled k1.
    pem_published, jwk = _make_key("k1")
    pem_attacker, _ = _make_key("k1")
    token = _token(pem_attacker, "k1")
    with pytest.raises(IdentityPortError):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_unknown_kid_after_refresh_raises():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1")
    adapter = OIDCIdentityAdapter(
        issuer=ISSUER, audience=AUDIENCE, jwks_fetcher=_fetcher(_jwks())  # empty key set
    )
    with pytest.raises(IdentityPortError):
        await adapter.resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_token_without_kid_raises():
    pem, jwk = _make_key("k1")
    token = jwt.encode(
        {"sub": "alice", "iss": ISSUER, "aud": AUDIENCE, "exp": int(time.time()) + 60},
        pem,
        algorithm="RS256",
    )
    with pytest.raises(IdentityPortError, match="kid"):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


# ── Tenant isolation (F-07) ─────────────────────────────────────────────────────


async def test_tenant_mismatch_raises_isolation_error():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1", tenant="evil-bank")
    with pytest.raises(TenantIsolationError):
        await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)


async def test_no_tenant_claim_allowed():
    pem, jwk = _make_key("k1")
    token = _token(pem, "k1", tenant=None)
    actor = await _adapter(_jwks(jwk)).resolve_actor(context=_ctx(token), tenant=TENANT)
    assert actor.id == "alice"


# ── JWKS rotation ────────────────────────────────────────────────────────────────


async def test_key_rotation_triggers_refetch():
    # Cache starts with k1; the IdP rotates to k2; a token signed by k2 forces exactly one refetch.
    pem1, jwk1 = _make_key("k1")
    pem2, jwk2 = _make_key("k2")

    state = {"doc": _jwks(jwk1), "calls": 0}

    async def fetch() -> dict:
        state["calls"] += 1
        return state["doc"]

    adapter = OIDCIdentityAdapter(issuer=ISSUER, audience=AUDIENCE, jwks_fetcher=fetch)

    # First resolve with k1 populates the cache.
    actor1 = await adapter.resolve_actor(context=_ctx(_token(pem1, "k1")), tenant=TENANT)
    assert actor1.id == "alice"
    assert state["calls"] == 1

    # Rotate the published set, then present a k2 token: the unknown kid forces a refetch.
    state["doc"] = _jwks(jwk2)
    actor2 = await adapter.resolve_actor(
        context=_ctx(_token(pem2, "k2", sub="bob")), tenant=TENANT
    )
    assert actor2.id == "bob"
    assert state["calls"] == 2


async def test_cached_key_not_refetched_within_ttl():
    pem, jwk = _make_key("k1")
    state = {"calls": 0}

    async def fetch() -> dict:
        state["calls"] += 1
        return _jwks(jwk)

    adapter = OIDCIdentityAdapter(
        issuer=ISSUER, audience=AUDIENCE, jwks_fetcher=fetch, jwks_ttl=3600
    )
    await adapter.resolve_actor(context=_ctx(_token(pem, "k1")), tenant=TENANT)
    await adapter.resolve_actor(context=_ctx(_token(pem, "k1", sub="bob")), tenant=TENANT)
    assert state["calls"] == 1  # second call served from cache


# ── Provider presets ─────────────────────────────────────────────────────────────


def test_okta_preset_issuer():
    a = OIDCIdentityAdapter.okta(domain="dev-123.okta.com", audience="api://default")
    assert a._issuer == "https://dev-123.okta.com/oauth2/default"


def test_auth0_preset_issuer_keeps_trailing_slash():
    a = OIDCIdentityAdapter.auth0(domain="my.eu.auth0.com", audience="https://api")
    assert a._issuer == "https://my.eu.auth0.com/"


def test_keycloak_preset_issuer():
    a = OIDCIdentityAdapter.keycloak(
        base_url="https://kc.example.com/", realm="quaicu", audience="kernel"
    )
    assert a._issuer == "https://kc.example.com/realms/quaicu"


def test_missing_audience_rejected():
    with pytest.raises(ValueError):
        OIDCIdentityAdapter(issuer=ISSUER, audience="")
