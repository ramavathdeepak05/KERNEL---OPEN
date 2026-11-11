"""Local-token IdentityPort adapter — one shared token, the caller names the acting user.

For a kernel a product runs for itself, on its own machine or network. There are no accounts and
nothing to sign up for: the product and the kernel share one secret token, and on each request the
product states which of *its* users is acting.

    Authorization: Bearer <the shared token>
    X-Actor-Id:    alice
    X-Actor-Roles: analyst, approver        (optional, comma-separated)

Trust model: the product is trusted to name its own users — exactly as it is when it embeds the
Python package and passes an ``Actor`` in directly. The token proves the request comes from that
product; it does not prove who the end user is. Use the ``jwt`` or ``oidc`` adapter instead when
the kernel must verify each user's identity itself.

Fail-closed: a missing or wrong token, or a missing actor header, raises `IdentityPortError`. The
adapter refuses to be constructed without a real token, so a kernel can never start in a state
where any caller is accepted.

Config::

    [adapters]
    identity = "local_token"

    [identity]
    token = "${QUAICU_TOKEN}"      # resolved from the environment; keep the token out of the file
"""

from __future__ import annotations

import hmac
import os

from quaicu.core.errors import IdentityPortError
from quaicu.core.types import Actor, ActorId, RequestContext, TenantId

TOKEN_ENV = "QUAICU_TOKEN"
MIN_TOKEN_LENGTH = 16
_ACTOR_HEADER = "x-actor-id"
_ROLES_HEADER = "x-actor-roles"
_MAX_ACTOR_ID_LENGTH = 256
_MAX_ROLES = 64


class LocalTokenIdentityAdapter:
    """IdentityPort adapter that authenticates a shared token and reads the actor from headers.

    Args:
        token: The shared secret. Empty (or an unexpanded ``${VAR}`` placeholder) falls back to the
            ``QUAICU_TOKEN`` environment variable. Must be at least 16 characters.
    """

    def __init__(self, token: str = "") -> None:
        resolved = (token or "").strip()
        if not resolved or resolved.startswith("${"):
            resolved = os.getenv(TOKEN_ENV, "").strip()
        if len(resolved) < MIN_TOKEN_LENGTH:
            raise ValueError(
                f"The local_token identity adapter needs a token of at least {MIN_TOKEN_LENGTH} "
                f"characters. Set {TOKEN_ENV} (for example: "
                f"export {TOKEN_ENV}=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')) "
                "or run the API with `quaicu serve`, which generates one."
            )
        self._token = resolved.encode("utf-8")

    async def resolve_actor(
        self,
        *,
        context: RequestContext,
        tenant: TenantId,
    ) -> Actor:
        presented = (context.raw_token or "").encode("utf-8")
        if not presented or not hmac.compare_digest(presented, self._token):
            raise IdentityPortError(
                "Invalid or missing local token", detail={"tenant": str(tenant)}
            )

        headers = {str(k).lower(): str(v) for k, v in context.headers.items()}
        actor_id = headers.get(_ACTOR_HEADER, "").strip()
        if not actor_id:
            raise IdentityPortError(
                "Missing X-Actor-Id header: name the user on whose behalf this request is made",
                detail={"tenant": str(tenant)},
            )
        if len(actor_id) > _MAX_ACTOR_ID_LENGTH or not actor_id.isprintable():
            raise IdentityPortError("X-Actor-Id is not a valid actor id", detail={"tenant": str(tenant)})

        roles = tuple(r.strip() for r in headers.get(_ROLES_HEADER, "").split(",") if r.strip())
        if len(roles) > _MAX_ROLES or any(not r.isprintable() for r in roles):
            raise IdentityPortError("X-Actor-Roles is not valid", detail={"tenant": str(tenant)})

        return Actor(id=ActorId(actor_id), tenant=tenant, roles=roles)
