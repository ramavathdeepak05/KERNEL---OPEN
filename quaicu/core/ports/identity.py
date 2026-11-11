"""IdentityPort — FROZEN. Resolves the authenticated identity. The kernel does NOT own auth."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from quaicu.core.types import Actor, RequestContext, TenantId


@runtime_checkable
class IdentityPort(Protocol):
    """Resolves the caller's identity from host-supplied context. The kernel takes identity FROM the
    host. Implementations: oidc, jwt, host_provided.

    Fail-closed contract:
      - Unresolvable identity → raise `IdentityPortError`. Never proceed with an anonymous actor.
      - Token expired or invalid → raise `IdentityPortError`.
      - Token's tenant ≠ requested tenant → raise `TenantIsolationError`.
    """

    async def resolve_actor(
        self,
        *,
        context: RequestContext,
        tenant: TenantId,
    ) -> Actor:
        """Resolve the caller's identity.

        Raises:
            IdentityPortError: identity cannot be resolved.
            TenantIsolationError: the token's tenant does not match the requested tenant.
        """
        ...
