"""Unit tests for GovernanceMiddleware — the reference PEP."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}


def _app(decision: Decision = Decision.ALLOW, *, enforce_paths=None):
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(decision=decision),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(),
    )
    return create_app(kernel, enforce_paths=enforce_paths)


# ── Middleware not wired → paths pass through unchanged ───────────────────────


async def test_no_middleware_health_returns_200() -> None:
    app = _app()  # no enforce_paths
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


# ── Allowed request passes through the PEP ───────────────────────────────────


async def test_middleware_allow_passes_request_to_route() -> None:
    app = _app(enforce_paths=[("GET", "/health")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health", headers=AUTH)
    assert resp.status_code == 200


# ── Denied request short-circuits before the route ───────────────────────────


async def test_middleware_deny_returns_403_before_route() -> None:
    app = _app(decision=Decision.DENY, enforce_paths=[("GET", "/health")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health", headers=AUTH)
    assert resp.status_code == 403
    data = resp.json()
    assert data["decision"] == "deny"
    assert "governance middleware" in data["error"].lower()


# ── Unenforced paths bypass the PEP ──────────────────────────────────────────


async def test_middleware_unenforced_path_bypasses_check() -> None:
    # Only /v1/protected is enforced — /health must pass through even with DENY policy.
    app = _app(decision=Decision.DENY, enforce_paths=[("POST", "/v1/protected")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200


# ── Method matching ───────────────────────────────────────────────────────────


async def test_middleware_method_mismatch_bypasses() -> None:
    # Only POST /health is enforced — GET should bypass even with DENY policy.
    app = _app(decision=Decision.DENY, enforce_paths=[("POST", "/health")])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
