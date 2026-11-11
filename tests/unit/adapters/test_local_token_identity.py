"""LocalTokenIdentityAdapter — one shared token; the caller names the acting user in headers."""

from __future__ import annotations

import pytest

from quaicu.adapters.identity.local_token import (
    MIN_TOKEN_LENGTH,
    TOKEN_ENV,
    LocalTokenIdentityAdapter,
)
from quaicu.core.errors import IdentityPortError
from quaicu.core.types import RequestContext, TenantId

TOKEN = "local-token-0123456789abcdef"
TENANT = TenantId("local")


def _ctx(token: str | None = TOKEN, **headers: str) -> RequestContext:
    return RequestContext(headers=headers, raw_token=token)


# ── Construction: a kernel can never start accepting everyone ───────────────────


@pytest.mark.parametrize("token", ["", "   ", "${QUAICU_TOKEN}", "short"])
def test_refuses_to_start_without_a_real_token(token: str, monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    with pytest.raises(ValueError, match=TOKEN_ENV):
        LocalTokenIdentityAdapter(token)


def test_short_token_from_the_environment_is_refused(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "x" * (MIN_TOKEN_LENGTH - 1))
    with pytest.raises(ValueError):
        LocalTokenIdentityAdapter()


async def test_unexpanded_placeholder_falls_back_to_the_environment(monkeypatch):
    # kernel.toml says token = "${QUAICU_TOKEN}"; when the variable is set at load time the loader
    # expands it, and when the adapter is built directly the placeholder resolves from the env.
    monkeypatch.setenv(TOKEN_ENV, TOKEN)
    adapter = LocalTokenIdentityAdapter("${QUAICU_TOKEN}")
    actor = await adapter.resolve_actor(context=_ctx(**{"x-actor-id": "alice"}), tenant=TENANT)
    assert str(actor.id) == "alice"


# ── Resolution ───────────────────────────────────────────────────────────────────


async def test_valid_token_and_headers_resolve_the_named_actor():
    adapter = LocalTokenIdentityAdapter(TOKEN)
    actor = await adapter.resolve_actor(
        context=_ctx(**{"X-Actor-Id": " alice ", "X-Actor-Roles": "analyst, approver ,,"}),
        tenant=TENANT,
    )
    assert str(actor.id) == "alice"
    assert actor.tenant == TENANT
    assert actor.roles == ("analyst", "approver")


async def test_roles_are_optional():
    adapter = LocalTokenIdentityAdapter(TOKEN)
    actor = await adapter.resolve_actor(context=_ctx(**{"x-actor-id": "alice"}), tenant=TENANT)
    assert actor.roles == ()


@pytest.mark.parametrize("token", [None, "", "wrong-token-0123456789abcdef", TOKEN + "x", TOKEN[:-1]])
async def test_wrong_or_missing_token_is_rejected(token):
    adapter = LocalTokenIdentityAdapter(TOKEN)
    with pytest.raises(IdentityPortError):
        await adapter.resolve_actor(context=_ctx(token, **{"x-actor-id": "alice"}), tenant=TENANT)


async def test_missing_actor_header_is_rejected_even_with_the_right_token():
    adapter = LocalTokenIdentityAdapter(TOKEN)
    with pytest.raises(IdentityPortError, match="X-Actor-Id"):
        await adapter.resolve_actor(context=_ctx(), tenant=TENANT)
    with pytest.raises(IdentityPortError):
        await adapter.resolve_actor(context=_ctx(**{"x-actor-id": "   "}), tenant=TENANT)


@pytest.mark.parametrize("actor_id", ["a" * 257, "ali\x00ce", "ali\nce"])
async def test_malformed_actor_id_is_rejected(actor_id: str):
    adapter = LocalTokenIdentityAdapter(TOKEN)
    with pytest.raises(IdentityPortError):
        await adapter.resolve_actor(context=_ctx(**{"x-actor-id": actor_id}), tenant=TENANT)


async def test_the_actor_cannot_be_named_in_the_token():
    # The token only proves the caller is the trusted product; it never carries an identity.
    adapter = LocalTokenIdentityAdapter(TOKEN)
    with pytest.raises(IdentityPortError):
        await adapter.resolve_actor(context=_ctx(TOKEN + ":alice"), tenant=TENANT)
