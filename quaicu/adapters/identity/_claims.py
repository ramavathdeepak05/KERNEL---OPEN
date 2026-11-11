"""Shared claim → Actor mapping for identity adapters (JWT, OIDC).

Both the symmetric-secret `JWTIdentityAdapter` and the OIDC/JWKS `OIDCIdentityAdapter` resolve a
verified token into the *same* `Actor` shape and enforce the *same* F-07 tenant cross-check; the only
thing that differs between them is how the signature is verified. This module owns the
post-verification claim mapping so the two adapters cannot drift.

Fail-closed (F-03): a token with no ``sub`` is unresolvable. Tenant isolation (F-07): a token whose
tenant claim contradicts the requested tenant raises `TenantIsolationError`.
"""

from __future__ import annotations

from typing import Any

from quaicu.core.errors import IdentityPortError, TenantIsolationError
from quaicu.core.types import Actor, ActorId, TenantId

# Standard / verification claims that are not part of the actor's free-form attribute bag. Anything
# the IdP adds beyond these (department, email, ...) flows through to ``Actor.attributes``.
_RESERVED_CLAIMS = frozenset(
    {"sub", "tenant", "tid", "roles", "exp", "iat", "nbf", "iss", "aud", "azp", "scope"}
)


def actor_from_claims(
    payload: dict[str, Any],
    tenant: TenantId,
    *,
    roles_claim: str = "roles",
) -> Actor:
    """Map a verified token payload to an `Actor`, enforcing identity + tenant invariants.

    Args:
        payload: The *already signature-verified* token claims.
        tenant: The tenant the request is scoped to (the action tenant).
        roles_claim: Claim name carrying the actor's roles (default ``roles``).

    Raises:
        IdentityPortError: the token has no ``sub`` claim (anonymous → fail-closed).
        TenantIsolationError: the token's tenant claim contradicts ``tenant``.
    """
    actor_id = payload.get("sub")
    if not actor_id:
        raise IdentityPortError(
            "Token missing 'sub' claim — cannot resolve an identity",
            detail={"claims": sorted(payload.keys())},
        )

    token_tenant = str(payload.get("tenant") or payload.get("tid") or "")
    if token_tenant and token_tenant != str(tenant):
        raise TenantIsolationError(
            f"Token tenant {token_tenant!r} does not match action tenant {str(tenant)!r}",
            detail={"token_tenant": token_tenant, "action_tenant": str(tenant)},
        )

    roles_raw = payload.get(roles_claim, [])
    if isinstance(roles_raw, str):
        roles_raw = [roles_raw]

    return Actor(
        id=ActorId(str(actor_id)),
        tenant=tenant,
        roles=tuple(str(r) for r in roles_raw),
        attributes={k: v for k, v in payload.items() if k not in _RESERVED_CLAIMS},
    )
