"""GovernanceMiddleware — reference Policy Enforcement Point (PEP).

Demonstrates "every action reaches the kernel": for configured (method, path-prefix) pairs, this
middleware intercepts the request BEFORE the route handler, calls ``kernel.check(...)`` for a
policy verdict, and short-circuits with 403 if the action is denied (or requires approval without
a gate).

This is the **canonical example** a customer copies to put the kernel in front of their own
endpoints. Wire it via ``create_app(kernel, enforce_paths=[...])``; it is off by default so
existing API tests are unaffected.

``enforce_paths`` format::

    [
        ("POST",   "/v1/payments"),          # exact match or prefix
        ("DELETE", "/v1/resources"),
    ]

The ``action_type`` sent to ``kernel.check`` is derived as ``"{method}:{path}"`` (e.g.
``"POST:/v1/payments"``). Override by putting an ``X-Action-Type`` header on the request.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from quaicu.core.types import Actor, ActorId, RequestContext


class GovernanceMiddleware(BaseHTTPMiddleware):
    """Intercept configured paths, call ``kernel.check``, block denied requests before routing."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        kernel: Any,
        enforce_paths: list[tuple[str, str]],
    ) -> None:
        super().__init__(app)
        self._kernel = kernel
        # Normalise to uppercase method + stripped path prefix.
        self._enforce_paths = [(m.upper(), p.rstrip("/")) for m, p in enforce_paths]

    def _should_enforce(self, method: str, path: str) -> bool:
        for m, prefix in self._enforce_paths:
            if method.upper() == m and (path == prefix or path.startswith(prefix + "/")):
                return True
        return False

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if not self._should_enforce(request.method, request.url.path):
            return await call_next(request)

        # Derive action_type from header or method:path.
        action_type = request.headers.get("x-action-type") or f"{request.method}:{request.url.path}"

        # Build a RequestContext so the IdentityPort can resolve the actor from the token.
        raw_token = ""
        auth = request.headers.get("authorization", "")
        scheme, _, tok = auth.partition(" ")
        if scheme.lower() == "bearer" and tok.strip():
            raw_token = tok.strip()

        ctx = RequestContext(
            headers=dict(request.headers),
            source_ip=request.client.host if request.client else None,
            raw_token=raw_token or None,
            tenant_hint=self._kernel.tenant,
        )
        placeholder_actor = Actor(id=ActorId("unresolved"), tenant=self._kernel.tenant)

        result = await self._kernel.check(
            action_type=action_type,
            actor=placeholder_actor,
            context=ctx,
        )

        if not result.allowed:
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request denied by governance middleware",
                    "decision": result.decision.value,
                    "reason": result.reason,
                    "actor_id": str(result.actor_id),
                },
            )

        return await call_next(request)
