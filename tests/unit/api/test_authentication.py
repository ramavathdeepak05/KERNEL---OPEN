"""Every /v1 route authenticates the caller; only the probes, the API docs and signed links are open.

Authentication is attached where routers are included (`create_app`), not inside each route, so
this test walks the app's own route table: a route added later is covered automatically.
"""

from __future__ import annotations

import re

import pytest
from fastapi import APIRouter, Request
from httpx import ASGITransport, AsyncClient

from quaicu import Kernel
from quaicu.adapters.identity.local_token import LocalTokenIdentityAdapter
from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.api.deps import current_actor
from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger, FakePolicy

TOKEN = "local-token-0123456789abcdef"
GOOD = {"Authorization": f"Bearer {TOKEN}", "X-Actor-Id": "alice"}
OPEN_PATHS = {"/health", "/readyz", "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}
SIGNED_LINK_PREFIX = "/v1/approvals/link/"

def _kernel(*, identity=True) -> Kernel:
    return Kernel.from_parts(
        tenant=TenantId("local"),
        policy=FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=LocalTokenIdentityAdapter(TOKEN) if identity else None,
    )


def _app(**kwargs):
    router = APIRouter(prefix="/v1/extra")

    @router.get("/whoami")
    async def _whoami(request: Request) -> dict:
        return {"actor": str(current_actor(request).id)}

    return create_app(_kernel(**kwargs), extra_routers=[router])


def _v1_calls(app) -> list[tuple[str, str]]:
    """(method, concrete path) for every /v1 operation the app publishes, read from its OpenAPI
    schema — the app's own public route table, independent of how the framework stores routes."""
    calls = []
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/v1") or path.startswith(SIGNED_LINK_PREFIX):
            continue
        concrete = re.sub(r"\{version\}", "1", path)
        concrete = re.sub(r"\{[^}]+\}", "x", concrete)
        calls.extend((method.upper(), concrete) for method in operations)
    return calls


def _client(app) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_route_table_is_non_trivial():
    calls = _v1_calls(_app())
    assert len(calls) >= 25  # actions, authorize, approvals, policies, packs, ledger, dashboard, ...
    assert ("GET", "/v1/extra/whoami") in calls


@pytest.mark.parametrize(
    "headers",
    [
        {},  # no credentials at all
        {"X-Actor-Id": "alice"},  # an actor name without the token
        {"Authorization": "Bearer wrong-token-0123456789abcdef", "X-Actor-Id": "alice"},
        {"Authorization": f"Basic {TOKEN}", "X-Actor-Id": "alice"},
        {"Authorization": f"Bearer {TOKEN}"},  # the token without naming the acting user
    ],
)
async def test_every_v1_route_rejects_an_unauthenticated_request(headers: dict):
    app = _app()
    async with _client(app) as client:
        for method, path in _v1_calls(app):
            resp = await client.request(method, path, headers=headers, json={})
            assert resp.status_code == 401, (method, path, resp.status_code, resp.text[:120])


async def test_authenticated_requests_get_past_authentication_on_every_route():
    app = _app()
    async with _client(app) as client:
        for method, path in _v1_calls(app):
            resp = await client.request(method, path, headers=GOOD, json={})
            assert resp.status_code != 401, (method, path)


async def test_extra_routers_are_protected_and_see_the_authenticated_actor():
    app = _app()
    async with _client(app) as client:
        anonymous = await client.get("/v1/extra/whoami")
        named = await client.get("/v1/extra/whoami", headers=GOOD)
    assert anonymous.status_code == 401
    assert named.json() == {"actor": "alice"}


async def test_probes_and_api_docs_are_open():
    app = _app()
    async with _client(app) as client:
        for path in ("/health", "/readyz", "/openapi.json"):
            assert (await client.get(path)).status_code in (200, 503), path  # readyz is 503 pre-startup
    # Nothing outside /v1 is published except the probes.
    published = set(app.openapi()["paths"])
    assert all(p.startswith("/v1") or p in OPEN_PATHS for p in published), published


async def test_a_kernel_without_an_identity_adapter_serves_no_v1_route():
    app = _app(identity=False)
    async with _client(app) as client:
        for method, path in _v1_calls(app):
            resp = await client.request(method, path, headers=GOOD, json={})
            assert resp.status_code == 503, (method, path, resp.status_code)
            assert resp.json()["detail"]["code"] == "IDENTITY_NOT_CONFIGURED"


async def test_signed_approval_links_do_not_take_a_bearer_but_reject_a_bad_token(monkeypatch):
    monkeypatch.setenv("QUAICU_APPROVAL_LINK_SECRET", "link-secret-0123456789")
    app = _app()
    async with _client(app) as client:
        page = await client.get("/v1/approvals/link/not-a-signed-token")
        commit = await client.post("/v1/approvals/link/not-a-signed-token")
    assert page.status_code == 400 and commit.status_code == 400
