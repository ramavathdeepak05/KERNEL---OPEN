"""Liveness (/health) + readiness (/readyz) probes (W4-1)."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import (
    FakeEvents,
    FakeHITL,
    FakeIdentity,
    FakeLedger,
    FakePolicy,
)


def _app():
    return create_app(
        Kernel.from_parts(
            tenant=TenantId("acme"),
            policy=FakePolicy(decision=Decision.ALLOW),
            hitl=FakeHITL(),
            ledger=FakeLedger(),
            events=FakeEvents(),
            identity=FakeIdentity(),
        )
    )


async def test_health_is_200_and_unauthenticated():
    # No lifespan needed: liveness must answer even before/without startup hydration.
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


async def test_readyz_is_503_before_startup_then_200_after():
    app = _app()
    transport = ASGITransport(app=app)

    # Before lifespan startup, readiness is not ready → 503.
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        not_ready = await client.get("/readyz")
    assert not_ready.status_code == 503
    assert not_ready.json()["status"] == "not-ready"

    # Run the lifespan (hydration) → readiness flips to ready → 200.
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            ready = await client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
