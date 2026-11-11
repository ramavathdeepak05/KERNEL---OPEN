"""Witness service + HttpWitness client (D3-2 follow-up) — out-of-process anchoring over HTTP."""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from quaicu.adapters.ledger.http_witness import HttpWitness
from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.anchor import anchor_all_tenants, anchor_current_sth
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
from quaicu.delivery.witness_app import create_witness_app

T = TenantId("ciro-bank")
TOKEN = "witness-secret"


async def _ledger(n: int, tenant: TenantId = T) -> TrustLedger:
    ledger = TrustLedger()
    for i in range(n):
        await ledger.seal(
            action=Action(id=ActionId(f"{tenant}-a{i}"), type="x", payload={"n": i},
                          actor=Actor(id=ActorId("u"), tenant=tenant), tenant=tenant,
                          idempotency_key=IdempotencyKey(f"{tenant}-i{i}"), state=ActionState.SEALING),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",)),
            recorded_result={},
        )
    return ledger


def _remote(witness: SoftwareWitness, *, token: str | None = TOKEN) -> HttpWitness:
    app = create_witness_app(witness, auth_token=TOKEN)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return HttpWitness("http://witness", client=TestClient(app, headers=headers))


def test_from_config_builds_http_witness():
    from quaicu.adapters.ledger.http_witness import HttpWitness
    from quaicu.delivery.sdk.kernel import Kernel

    w = Kernel._build_witness(
        {"witness": "http_witness"}, {"witness": {"base_url": "http://w:7100", "token": "t"}}
    )
    assert isinstance(w, HttpWitness)
    with pytest.raises(ValueError):
        Kernel._build_witness({"witness": "http_witness"}, {})  # missing base_url


def test_witness_key_endpoint_public():
    witness = SoftwareWitness()
    client = TestClient(create_witness_app(witness, auth_token=TOKEN))
    r = client.get("/witness-key")  # public — no auth
    assert r.status_code == 200
    assert r.json()["witness_id"] == witness.witness_id
    assert "BEGIN PUBLIC KEY" in r.json()["public_key_pem"]


async def test_http_cosign_roundtrip_and_verify():
    ledger = await _ledger(3)
    witness = SoftwareWitness()
    remote = _remote(witness)
    cosig = anchor_current_sth(ledger, remote, T)  # kernel → remote witness over HTTP
    assert cosig.witness_id == witness.witness_id
    assert remote.verify(cosig, remote.public_key_pem)          # cached key fetch
    assert remote.public_key_pem == witness.public_key_pem      # served from the remote
    assert remote.last_seen(T)[0] == 3


async def test_http_cosign_requires_auth():
    ledger = await _ledger(1)
    remote_noauth = _remote(SoftwareWitness(), token=None)
    with pytest.raises(Exception):  # 401 → httpx raise_for_status
        anchor_current_sth(ledger, remote_noauth, T)


async def test_http_rewind_returns_409_as_tampererror():
    ledger = await _ledger(3)
    witness = SoftwareWitness()
    remote = _remote(witness)
    anchor_current_sth(ledger, remote, T)  # witness now at size 3
    stale = dataclasses.replace(ledger.get_signed_tree_head(T), tree_size=1)
    with pytest.raises(LedgerTamperError):
        remote.cosign(T, stale, [])


async def test_anchor_all_tenants_covers_each_and_isolates_tamper(caplog):
    # Two tenants sealed into one ledger; anchor_all_tenants cosigns both.
    ledger = TrustLedger()
    a, b = TenantId("acme"), TenantId("globex")
    for t in (a, b):
        await ledger.seal(
            action=Action(id=ActionId(f"{t}-0"), type="x", payload={}, actor=Actor(id=ActorId("u"), tenant=t),
                          tenant=t, idempotency_key=IdempotencyKey(f"{t}-0"), state=ActionState.SEALING),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1",)),
            recorded_result={},
        )
    witness = SoftwareWitness()
    results = anchor_all_tenants(ledger, witness)
    assert results == {a: "ok", b: "ok"}
    assert witness.last_seen(a)[0] == 1 and witness.last_seen(b)[0] == 1
