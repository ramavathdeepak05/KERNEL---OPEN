"""JWT IdentityPort adapter.

Decodes a JWT from ``RequestContext.raw_token``. Claims map:
  - ``sub``   → actor_id
  - ``tenant`` or ``tid`` → tenant (cross-checked against ``tenant`` arg)
  - ``roles`` → roles tuple

Fail-closed (F-03): missing, expired, or invalid JWT → IdentityPortError.
Tenant isolation (F-07): if the JWT tenant claim does not match the action tenant,
the adapter raises TenantIsolationError.
"""

from __future__ import annotations

from typing import Any

import jwt as _jwt

from quaicu.adapters.identity._claims import actor_from_claims
from quaicu.core.errors import IdentityPortError
from quaicu.core.types import Actor, RequestContext, TenantId


class JWTIdentityAdapter:
    """IdentityPort adapter that resolves actors from JWT bearer tokens.

    Args:
        secret_or_key: HMAC secret (string) or RSA/EC public key for verification.
        algorithms: Allowed signing algorithms.
        verify: Set False to skip signature verification (tests only).
    """

    def __init__(
        self,
        secret_or_key: str | bytes = "changeme",
        algorithms: list[str] | None = None,
        verify: bool = True,
    ) -> None:
        self._key = secret_or_key
        self._algorithms = algorithms or ["HS256"]
        self._verify = verify

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
            options = {} if self._verify else {"verify_signature": False}
            payload: dict[str, Any] = _jwt.decode(
                token,
                self._key,
                algorithms=self._algorithms,
                options=options,
            )
        except _jwt.ExpiredSignatureError as exc:
            raise IdentityPortError(
                "JWT is expired — fail-closed",
                detail={"tenant": str(tenant)},
            ) from exc
        except _jwt.InvalidTokenError as exc:
            raise IdentityPortError(
                f"Invalid JWT: {exc}",
                detail={"tenant": str(tenant)},
            ) from exc

        # Shared claim → Actor mapping (sub/tenant/roles), incl. the F-07 tenant cross-check.
        return actor_from_claims(payload, tenant)
