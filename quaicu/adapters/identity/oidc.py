"""OIDC IdentityPort adapter — verify IdP-issued JWTs against a rotating JWKS (ADR-0011, WS-D).

Where `JWTIdentityAdapter` verifies a token against a single shared symmetric secret, this adapter
verifies an **asymmetrically-signed** access/ID token issued by a named identity provider (Okta,
Auth0, Keycloak, or any OIDC-compliant IdP) against the provider's published JWKS:

  1. **Discovery** — if no ``jwks_uri`` is given, fetch ``{issuer}/.well-known/openid-configuration``
     once and read ``jwks_uri`` from it.
  2. **JWKS fetch + cache** — fetch the JWK Set and index it by ``kid``. Cached for ``jwks_ttl``.
  3. **Rotation** — a token whose ``kid`` is not in the cache triggers exactly one re-fetch (the IdP
     rotated its signing key); still-missing → fail-closed.
  4. **Verify** — ``jwt.decode`` with the matched public key, the configured algorithms, and a
     **mandatory** ``issuer`` + ``audience`` check.
  5. **Map** — the verified claims become an `Actor` via the shared `actor_from_claims` mapper, which
     also enforces the F-07 tenant cross-check.

Fail-closed (F-03) at every step: no token, undiscoverable JWKS, unknown ``kid`` after rotation,
wrong issuer/audience, expired or malformed token → `IdentityPortError`. Tenant mismatch →
`TenantIsolationError`.

The HTTP fetch is injectable (``jwks_fetcher=``) so the adapter is testable without a live IdP.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

import jwt as _jwt
from jwt import PyJWK

from quaicu.adapters.identity._claims import actor_from_claims
from quaicu.core.errors import IdentityPortError
from quaicu.core.types import Actor, RequestContext, TenantId

# An injectable async fetch of a JWKS document (``{"keys": [...]}``).
JwksFetcher = Callable[[], Awaitable[dict[str, Any]]]


class OIDCIdentityAdapter:
    """IdentityPort adapter that verifies OIDC JWTs against a provider's rotating JWKS.

    Args:
        issuer: The exact ``iss`` value the IdP stamps (validated, not normalized). For Auth0 this
            includes a trailing slash; for Okta/Keycloak it does not.
        audience: The expected ``aud`` (this API's client/audience id). Validated on every token.
        jwks_uri: The JWK Set URL. If omitted, discovered from the issuer's well-known document.
        algorithms: Allowed signing algorithms (asymmetric only; default RS256 + ES256).
        roles_claim: Token claim carrying the actor's roles (default ``roles``).
        leeway: Clock-skew leeway in seconds for exp/nbf/iat.
        jwks_ttl: Seconds a fetched JWKS is trusted before a refresh.
        http_timeout: Per-request timeout for discovery / JWKS fetches.
        jwks_fetcher: Test/override hook — an async callable returning a JWKS document. When given,
            discovery and HTTP are bypassed entirely.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str | None = None,
        algorithms: list[str] | tuple[str, ...] = ("RS256", "ES256"),
        roles_claim: str = "roles",
        leeway: float = 0.0,
        jwks_ttl: float = 3600.0,
        http_timeout: float = 5.0,
        jwks_fetcher: JwksFetcher | None = None,
    ) -> None:
        if not issuer:
            raise ValueError("OIDCIdentityAdapter requires an issuer.")
        if not audience:
            raise ValueError("OIDCIdentityAdapter requires an audience (fail-closed: aud is checked).")
        self._issuer = issuer
        self._audience = audience
        self._configured_jwks_uri = jwks_uri
        self._algorithms = list(algorithms)
        self._roles_claim = roles_claim
        self._leeway = leeway
        self._ttl = jwks_ttl
        self._http_timeout = http_timeout
        self._fetcher = jwks_fetcher

        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()

    # ── Provider presets ────────────────────────────────────────────────────────
    # Named IdPs differ only in how their issuer URL is shaped; everything downstream is identical.

    @classmethod
    def okta(
        cls, *, domain: str, audience: str, auth_server_id: str = "default", **kwargs: Any
    ) -> "OIDCIdentityAdapter":
        """Okta org/custom authorization server: ``https://{domain}/oauth2/{auth_server_id}``."""
        return cls(issuer=f"https://{domain}/oauth2/{auth_server_id}", audience=audience, **kwargs)

    @classmethod
    def auth0(cls, *, domain: str, audience: str, **kwargs: Any) -> "OIDCIdentityAdapter":
        """Auth0 tenant: issuer is ``https://{domain}/`` (the trailing slash is significant)."""
        return cls(issuer=f"https://{domain}/", audience=audience, **kwargs)

    @classmethod
    def keycloak(
        cls, *, base_url: str, realm: str, audience: str, **kwargs: Any
    ) -> "OIDCIdentityAdapter":
        """Keycloak realm: ``{base_url}/realms/{realm}``."""
        return cls(issuer=f"{base_url.rstrip('/')}/realms/{realm}", audience=audience, **kwargs)

    # ── IdentityPort ──────────────────────────────────────────────────────────────

    async def resolve_actor(
        self,
        *,
        context: RequestContext,
        tenant: TenantId,
    ) -> Actor:
        token = context.raw_token
        if not token:
            raise IdentityPortError(
                "No bearer token in RequestContext.raw_token",
                detail={"tenant": str(tenant)},
            )

        try:
            header = _jwt.get_unverified_header(token)
        except _jwt.InvalidTokenError as exc:
            raise IdentityPortError(
                f"Malformed token header: {exc}",
                detail={"tenant": str(tenant)},
            ) from exc

        kid = header.get("kid")
        if not kid:
            raise IdentityPortError(
                "Token has no 'kid' header — cannot select a JWKS key",
                detail={"tenant": str(tenant)},
            )

        signing_key = await self._signing_key_for(str(kid))

        try:
            payload: dict[str, Any] = _jwt.decode(
                token,
                signing_key.key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iss", "aud"]},
            )
        except _jwt.ExpiredSignatureError as exc:
            raise IdentityPortError(
                "OIDC token is expired — fail-closed",
                detail={"tenant": str(tenant)},
            ) from exc
        except _jwt.InvalidTokenError as exc:
            raise IdentityPortError(
                f"Invalid OIDC token: {exc}",
                detail={"tenant": str(tenant)},
            ) from exc

        return actor_from_claims(payload, tenant, roles_claim=self._roles_claim)

    # ── JWKS cache + rotation ─────────────────────────────────────────────────────

    async def _signing_key_for(self, kid: str) -> PyJWK:
        """Return the cached `PyJWK` for ``kid``, refreshing once on a miss (key rotation)."""
        now = time.monotonic()
        if kid in self._keys and (now - self._fetched_at) < self._ttl:
            return self._keys[kid]

        async with self._lock:
            # Re-check inside the lock: a concurrent caller may have just refreshed.
            now = time.monotonic()
            fresh = (now - self._fetched_at) < self._ttl
            if kid in self._keys and fresh:
                return self._keys[kid]
            if kid not in self._keys or not fresh:
                await self._refresh()
            key = self._keys.get(kid)
            if key is None:
                raise IdentityPortError(
                    f"No JWKS key matches token kid {kid!r} after refresh — fail-closed",
                    detail={"issuer": self._issuer, "known_kids": sorted(self._keys)},
                )
            return key

    async def _refresh(self) -> None:
        """Fetch the JWKS and rebuild the ``kid → PyJWK`` index."""
        try:
            document = await (self._fetcher() if self._fetcher else self._default_fetch_jwks())
            keys = document.get("keys", [])
            index: dict[str, PyJWK] = {}
            for jwk in keys:
                kid = jwk.get("kid")
                if not kid:
                    continue
                index[str(kid)] = PyJWK.from_dict(jwk)
        except IdentityPortError:
            raise
        except Exception as exc:  # noqa: BLE001 — any fetch/parse failure is fail-closed
            raise IdentityPortError(
                f"Could not load JWKS for issuer {self._issuer!r}: {exc}",
                detail={"issuer": self._issuer},
            ) from exc

        if not index:
            raise IdentityPortError(
                f"JWKS for issuer {self._issuer!r} contained no usable keys",
                detail={"issuer": self._issuer},
            )
        self._keys = index
        self._fetched_at = time.monotonic()

    async def _default_fetch_jwks(self) -> dict[str, Any]:
        """Discover (if needed) and fetch the JWKS over HTTP. Used when no fetcher is injected."""
        import httpx

        async with httpx.AsyncClient(timeout=self._http_timeout) as client:
            jwks_uri = self._configured_jwks_uri or await self._discover_jwks_uri(client)
            response = await client.get(jwks_uri)
            response.raise_for_status()
            return response.json()

    async def _discover_jwks_uri(self, client: Any) -> str:
        """Read ``jwks_uri`` from the issuer's OIDC discovery document."""
        well_known = self._issuer.rstrip("/") + "/.well-known/openid-configuration"
        response = await client.get(well_known)
        response.raise_for_status()
        jwks_uri = response.json().get("jwks_uri")
        if not jwks_uri:
            raise IdentityPortError(
                f"OIDC discovery document for {self._issuer!r} has no 'jwks_uri'",
                detail={"discovery_url": well_known},
            )
        return str(jwks_uri)
