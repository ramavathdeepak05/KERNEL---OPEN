"""Tenant isolation primitives — schema-per-tenant + RLS (WS-E, F-07).

The shipped Postgres adapters isolate tenants *logically* — every row carries ``tenant_id`` and every
query predicates on it. For the dedicated **Enterprise** tier we harden this to **physical**
isolation, exactly as the tenant-isolation invariant (F-07) prescribes:

  1. **schema-per-tenant** — each tenant's tables live in their own Postgres schema; a connection sets
     ``search_path`` to that schema so a query *cannot name* another tenant's table; and
  2. **row-level security (RLS)** — defense in depth: every kernel table has an RLS policy keyed on
     ``current_setting('app.current_tenant')``, so even a query that reaches a shared table only sees
     the current tenant's rows.

This module owns the *mechanism*: injection-safe schema-name derivation, the request-scoped tenant
`ContextVar` that carries the RLS tenant, and the SQL builders for both. The derivation is
**fail-closed** — a tenant id that is not a safe SQL identifier raises rather than being escaped into
a query, so a crafted tenant id can never become SQL.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar

from quaicu.core.errors import TenantIsolationError
from quaicu.core.types import TenantId

# A tenant id safe to map into a physical schema name: starts alphanumeric, then alphanumerics plus
# '-'/'_' (the shape AccountEngine mints, e.g. "acme-co-1a2b3c"), bounded so the prefixed schema name
# stays within Postgres's 63-byte identifier limit.
_SAFE_TENANT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,50}$")

#: The tenant whose rows the current DB transaction may touch (RLS). Set per request/transaction.
current_db_tenant: ContextVar[str | None] = ContextVar("current_db_tenant", default=None)


def assert_safe_tenant(tenant: TenantId | str) -> str:
    """Return the tenant id, having proven it is a safe SQL identifier. Fail-closed (F-07)."""
    raw = str(tenant)
    if not _SAFE_TENANT.match(raw):
        raise TenantIsolationError(
            f"Tenant id {raw!r} is not a safe identifier for physical isolation.",
            detail={"tenant": raw},
        )
    return raw


def safe_schema_name(tenant: TenantId | str, *, prefix: str = "tenant_") -> str:
    """Derive a tenant's physical Postgres schema name (injection-safe).

    ``-`` is mapped to ``_`` because schema identifiers do not allow hyphens unquoted; the input is
    validated first, so the result is always a bare ``[a-z0-9_]`` identifier.
    """
    return f"{prefix}{assert_safe_tenant(tenant).replace('-', '_')}"


def search_path_sql(tenant: TenantId | str, *, prefix: str = "tenant_") -> str:
    """``SET LOCAL search_path`` pinning a connection to the tenant's schema, then ``public``.

    Safe to interpolate: ``safe_schema_name`` has validated the identifier. ``SET LOCAL`` lasts only
    for the current transaction, so isolation is re-established per unit of work.
    """
    schema = safe_schema_name(tenant, prefix=prefix)
    return f'SET LOCAL search_path TO "{schema}", public'


def set_rls_tenant_sql() -> str:
    """Parameterized statement to bind the RLS tenant for the current transaction.

    Returns SQL expecting one bind parameter (the tenant id). Using ``set_config(..., true)`` keeps it
    transaction-local and parameter-bound — the tenant id is never string-interpolated into SQL.
    """
    return "SELECT set_config('app.current_tenant', $1, true)"


def create_tenant_schema_sql(tenant: TenantId | str, *, prefix: str = "tenant_") -> str:
    """DDL to create a tenant's isolated schema (idempotent)."""
    return f'CREATE SCHEMA IF NOT EXISTS "{safe_schema_name(tenant, prefix=prefix)}"'


def drop_tenant_schema_sql(tenant: TenantId | str, *, prefix: str = "tenant_") -> str:
    """DDL to drop a tenant's schema and everything in it (tenant offboarding / GDPR)."""
    return f'DROP SCHEMA IF EXISTS "{safe_schema_name(tenant, prefix=prefix)}" CASCADE'


@contextmanager
def db_tenant_scope(tenant: TenantId | str):
    """Bind ``current_db_tenant`` for the duration of a block (set RLS tenant before issuing SQL).

    Adapters read this to issue ``set_rls_tenant_sql`` on the connection. Restores the prior value on
    exit so nested/sequential scopes don't leak across tenants.
    """
    token = current_db_tenant.set(assert_safe_tenant(tenant))
    try:
        yield
    finally:
        current_db_tenant.reset(token)
