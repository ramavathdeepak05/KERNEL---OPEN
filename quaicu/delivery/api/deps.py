"""Request → kernel, tenant and caller resolution for the REST API.

One kernel serves the API (``app.state.kernel``) and its tenant is fixed (``kernel.tenant``).

**Every ``/v1`` route depends on `authenticate`.** The caller is resolved by the kernel's
IdentityPort from the request — its bearer token and headers — and never from the request body.
Which adapter does that is configuration:

- ``local_token`` — one shared token; the calling product names the acting user in headers. The
  default for a kernel run locally (no accounts, no signup).
- ``jwt`` / ``oidc`` — a signed token per user.

A route never decides for itself whether a request is authenticated: the dependency is attached
where the routers are included (``delivery/api/app.py``), so a new route is protected by default.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from quaicu.core.errors import IdentityPortError
from quaicu.core.types import Actor, RequestContext, TenantId
from quaicu.delivery.sdk.kernel import Kernel


def get_kernel(request: Request) -> Kernel:
    """The kernel serving this API."""
    return request.app.state.kernel


def get_request_tenant(request: Request) -> TenantId:
    """The tenant stamped on actions for this request: the kernel's own tenant."""
    return request.app.state.kernel.tenant


def bearer_token(request: Request) -> str:
    """The bearer token from the Authorization header, or 401."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail={"error": "Missing or malformed bearer token", "code": "UNAUTHENTICATED"},
        )
    return token.strip()


async def authenticate(request: Request) -> Actor:
    """Resolve the caller through the kernel's IdentityPort and remember it for the request.

    401 if there is no bearer token or the identity adapter rejects the request; 503 if the kernel
    has no identity adapter (an API that cannot tell who is calling must not serve). A token issued
    for another tenant raises `TenantIsolationError`, which the app maps to 403.
    """
    cached = getattr(request.state, "actor", None)
    if cached is not None:
        return cached
    kernel = get_kernel(request)
    token = bearer_token(request)
    if not kernel.has_identity:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "API requires an identity adapter to authenticate callers",
                "code": "IDENTITY_NOT_CONFIGURED",
            },
        )
    context = RequestContext(
        headers=dict(request.headers),
        source_ip=request.client.host if request.client else None,
        raw_token=token,
        tenant_hint=kernel.tenant,
    )
    try:
        actor = await kernel.resolve_actor(context, tenant=kernel.tenant)
    except IdentityPortError as exc:
        raise HTTPException(status_code=401, detail={"error": str(exc), "code": exc.code})
    request.state.actor = actor
    return actor


def current_actor(request: Request) -> Actor:
    """The actor `authenticate` resolved for this request (401 if the route was not protected)."""
    actor = getattr(request.state, "actor", None)
    if actor is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "Request is not authenticated", "code": "UNAUTHENTICATED"},
        )
    return actor


# ── Optional scope enforcement (a seam for a host's own auth layer) ───────────────


def current_principal(request: Request) -> Any | None:
    """A host-provided principal carrying ``scopes``, or None.

    The kernel itself does not issue scoped credentials. A host that puts its own auth middleware in
    front of the API can set ``request.state.principal`` (any object with ``has_scope(scope)`` and
    ``scopes``), and the routes will then require the scope each one names
    (``delivery/api/scopes.py``).
    """
    return getattr(request.state, "principal", None)


def enforce_scope(request: Request, scope: str) -> None:
    """Require ``scope`` when a host principal is present; a no-op otherwise."""
    principal = current_principal(request)
    if principal is None:
        return
    if not principal.has_scope(scope):
        raise HTTPException(
            status_code=403,
            detail={
                "error": f"Credential is missing the required scope {scope!r}",
                "code": "INSUFFICIENT_SCOPE",
                "detail": {"required": scope, "granted": sorted(principal.scopes)},
            },
        )
