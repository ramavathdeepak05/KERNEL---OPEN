"""Crypto-shredding erasure routes (WS-G)."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.core.erasure import ErasureEngine
from quaicu.core.types import Decision, TenantId
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

AUTH = {"Authorization": "Bearer opaque"}


def _kernel(tenant: str = "ciro-bank") -> Kernel:
    return Kernel.from_parts(
        tenant=TenantId(tenant),
        policy=FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(),
    )


def _app(engine: ErasureEngine | None = None):
    return create_app(_kernel(), erasure_engine=engine or ErasureEngine())


async def test_erase_then_status_reports_erased():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        erased = await client.post("/v1/erasure/ciro-bank/subject-1", headers=AUTH)
        assert erased.status_code == 200, erased.text
        body = erased.json()
        assert body["erased"] is True
        assert body["method"].startswith("crypto-shredding")

        status = await client.get("/v1/erasure/ciro-bank/subject-1", headers=AUTH)
    assert status.status_code == 200
    assert status.json()["erased"] is True


async def test_status_before_erasure_is_false():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        status = await client.get("/v1/erasure/ciro-bank/fresh-subject", headers=AUTH)
    assert status.status_code == 200
    assert status.json()["erased"] is False


async def test_erase_requires_bearer_token():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/erasure/ciro-bank/subject-1")  # no token
    assert resp.status_code == 401


async def test_erase_tenant_isolation():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/erasure/other-bank/subject-1", headers=AUTH)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "TENANT_ISOLATION"


async def test_erasure_disabled_returns_503():
    app = create_app(_kernel())  # no erasure_engine wired
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/erasure/ciro-bank/subject-1", headers=AUTH)
    assert resp.status_code == 503


async def test_decrypt_after_erasure_returns_410():
    # Drive a SubjectErasedError through a route to confirm the 410 Gone handler is wired.
    engine = ErasureEngine()
    engine.encrypt(tenant="ciro-bank", subject="subject-1", plaintext="PII")
    app = _app(engine)

    @app.get("/_test/read/{subject}")
    async def _read(subject: str):  # pragma: no cover - test-only probe route
        token = engine.encrypt(tenant="ciro-bank", subject=subject, plaintext="PII")
        return {"value": engine.decrypt(token)}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/v1/erasure/ciro-bank/subject-1", headers=AUTH)
        resp = await client.get("/_test/read/subject-1")
    assert resp.status_code == 410
    assert resp.json()["code"] == "SUBJECT_ERASED"
