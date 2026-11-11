"""Regulator ledger-proof export route + verify endpoint (WS-F)."""

from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    TenantId,
)
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel
from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakePolicy

AUTH = {"Authorization": "Bearer opaque"}


def _action(tenant: TenantId, n: int) -> Action:
    return Action(
        id=ActionId(f"act-{n}"),
        type="loan.approve",
        payload={"amount": n},
        actor=Actor(id=ActorId("alice"), tenant=tenant),
        tenant=tenant,
        idempotency_key=IdempotencyKey(f"idem-{n}"),
        state=ActionState.SEALING,
    )


async def _kernel_with_sealed(tenant: str, n: int, *, witness: bool = False) -> Kernel:
    ledger = TrustLedger()
    t = TenantId(tenant)
    for i in range(n):
        await ledger.seal(
            action=_action(t, i),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1.0",)),
            recorded_result={},
        )
    return Kernel.from_parts(
        tenant=t,
        policy=FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=ledger,
        events=FakeEvents(),
        identity=FakeIdentity(),
        witness=SoftwareWitness() if witness else None,
    )


async def test_export_then_verify_roundtrip():
    kernel = await _kernel_with_sealed("ciro-bank", 4)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        exported = await client.get("/v1/ledger/ciro-bank/export", headers=AUTH)
        assert exported.status_code == 200, exported.text
        bundle = exported.json()
        assert bundle["format_version"].startswith("quaicu.ledger-proof")
        assert len(bundle["inclusion_proofs"]) == 4

        verified = await client.post("/v1/ledger/export/verify", json=bundle, headers=AUTH)
    assert verified.status_code == 200
    assert verified.json() == {"ok": True, "errors": []}


async def test_signing_key_published_for_pinning():
    kernel = await _kernel_with_sealed("ciro-bank", 1)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/ledger/signing-key", headers=AUTH)
    assert resp.status_code == 200
    body = resp.json()
    assert body["key_id"] and "BEGIN PUBLIC KEY" in body["public_key_pem"]
    assert body["algorithm"] == "ed25519"


async def test_verify_requires_bearer_token():
    kernel = await _kernel_with_sealed("ciro-bank", 1)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/v1/ledger/export/verify", json={"x": 1})  # no token
    assert resp.status_code == 401


async def test_witness_key_and_anchored_roundtrip():
    kernel = await _kernel_with_sealed("ciro-bank", 3, witness=True)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        wk = await client.get("/v1/ledger/witness-key", headers=AUTH)
        assert wk.status_code == 200
        assert wk.json()["witness_id"] and wk.json()["algorithm"] == "ed25519"

        bundle = (await client.get("/v1/ledger/ciro-bank/export", headers=AUTH)).json()
        assert bundle["anchor"] and bundle["anchor"]["tree_size"] == 3  # cosignature embedded
        # The hosted verify pins both the signer AND the witness → anchored bundle verifies.
        verified = await client.post("/v1/ledger/export/verify", json=bundle, headers=AUTH)
    assert verified.status_code == 200
    assert verified.json() == {"ok": True, "errors": []}


async def test_witness_key_unavailable_without_witness():
    kernel = await _kernel_with_sealed("ciro-bank", 1)  # no witness
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/ledger/witness-key", headers=AUTH)
    assert resp.status_code == 503


async def test_export_requires_bearer_token():
    kernel = await _kernel_with_sealed("ciro-bank", 1)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/ledger/ciro-bank/export")  # no token
    assert resp.status_code == 401


async def test_export_tenant_isolation():
    kernel = await _kernel_with_sealed("ciro-bank", 1)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/v1/ledger/other-bank/export", headers=AUTH)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "TENANT_ISOLATION"


async def test_verify_rejects_tampered_bundle():
    kernel = await _kernel_with_sealed("ciro-bank", 3)
    app = create_app(kernel)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        bundle = (await client.get("/v1/ledger/ciro-bank/export", headers=AUTH)).json()
        sig = bundle["signed_tree_head"]["signature_hex"]
        bundle["signed_tree_head"]["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        verified = await client.post("/v1/ledger/export/verify", json=bundle, headers=AUTH)
    assert verified.status_code == 200
    body = verified.json()
    assert body["ok"] is False
    assert body["errors"]


async def test_export_window_filters_entries():
    kernel = await _kernel_with_sealed("ciro-bank", 3)
    app = create_app(kernel)
    # A window far in the past selects nothing.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/v1/ledger/ciro-bank/export?from=2000-01-01T00:00:00&to=2000-01-02T00:00:00",
            headers=AUTH,
        )
    assert resp.status_code == 200
    assert resp.json()["inclusion_proofs"] == []
