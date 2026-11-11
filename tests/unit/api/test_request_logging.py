"""Request-logging middleware: correlation ids (ADR-0011, WS-D)."""

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


async def test_response_carries_a_request_id():
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.headers.get("x-request-id")


async def test_inbound_request_id_is_echoed():
    async with AsyncClient(transport=ASGITransport(app=_app()), base_url="http://test") as client:
        resp = await client.get("/health", headers={"X-Request-ID": "trace-123"})
    assert resp.headers.get("x-request-id") == "trace-123"
