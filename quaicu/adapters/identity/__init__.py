"""IdentityPort adapters — `local_token` (one shared token), `jwt` (shared secret) and `oidc`
(an identity provider's rotating keys).

The adapters are loaded on first use, not when this package is imported: `jwt` and `oidc` need
PyJWT (the ``server`` extra), while `local_token` needs nothing beyond the base install.
"""

from __future__ import annotations

from typing import Any

_LAZY = {
    "JWTIdentityAdapter": "quaicu.adapters.identity.jwt_adapter",
    "LocalTokenIdentityAdapter": "quaicu.adapters.identity.local_token",
    "OIDCIdentityAdapter": "quaicu.adapters.identity.oidc",
}

__all__ = ["JWTIdentityAdapter", "LocalTokenIdentityAdapter", "OIDCIdentityAdapter"]


def __getattr__(name: str) -> Any:
    if name in _LAZY:
        import importlib

        return getattr(importlib.import_module(_LAZY[name]), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
