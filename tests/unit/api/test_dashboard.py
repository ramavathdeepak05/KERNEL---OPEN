"""Unit tests for the dashboard read-model routes (/v1/dashboard) — gap #5."""

from __future__ import annotations

from datetime import datetime, timezone

from httpx import ASGITransport, AsyncClient

from quaicu.core.hitl.engine import InProcessHITLPort
from quaicu.core.types import (
    ActionId,
    ActorId,
    ApproverRef,
    Decision,
    LedgerEntry,
    TenantId,
)
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import (
    FakeEvents,
    FakeHITL,
    FakeIdentity,
    FakeLedger,
    FakePolicy,
    make_action,
)

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}


def _entry(seq: int, *, decision: Decision, action_type="payments.wire", day=5) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=seq,
        tenant=TENANT,
        action_id=ActionId(f"act-{seq}"),
        action_type=action_type,
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=("p@v1",),
        leaf_hash=b"\x00" * 32,
        sealed_at=datetime(2026, 6, day, tzinfo=timezone.utc),
    )


def _kernel(*, entries=None, hitl=None, with_identity=True):
    ledger = FakeLedger()
    if entries:
        ledger.sealed.extend(entries)
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(),
        hitl=hitl or FakeHITL(),
        ledger=ledger,
        events=FakeEvents(),
        identity=FakeIdentity() if with_identity else None,
    )


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ── Auth / tenant isolation ──────────────────────────────────────────────────────


async def test_overview_without_token_returns_401():
    async with _client(create_app(_kernel())) as c:
        resp = await c.get("/v1/dashboard/acme/overview")
    assert resp.status_code == 401


async def test_cross_tenant_returns_403():
    async with _client(create_app(_kernel())) as c:
        resp = await c.get("/v1/dashboard/other-bank/overview", headers=AUTH)
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "TENANT_ISOLATION"


async def test_all_endpoints_require_token():
    app = create_app(_kernel())
    paths = [
        "/v1/dashboard/acme/overview",
        "/v1/dashboard/acme/decisions",
        "/v1/dashboard/acme/actions/top",
        "/v1/dashboard/acme/hitl/queue",
    ]
    async with _client(app) as c:
        for p in paths:
            assert (await c.get(p)).status_code == 401


# ── Overview ─────────────────────────────────────────────────────────────────────


async def test_overview_empty():
    async with _client(create_app(_kernel(entries=[]))) as c:
        resp = await c.get("/v1/dashboard/acme/overview", headers=AUTH)
    data = resp.json()
    assert data == {
        "tenant": "acme",
        "total_governed": 0,
        "decision_counts": {},
        "denial_rate": 0.0,
        "last_ledger_seq": None,
    }


async def test_overview_mixed_decisions():
    entries = [
        _entry(0, decision=Decision.ALLOW),
        _entry(1, decision=Decision.DENY),
        _entry(2, decision=Decision.DENY),
        _entry(3, decision=Decision.REQUIRE_APPROVAL),
    ]
    async with _client(create_app(_kernel(entries=entries))) as c:
        resp = await c.get("/v1/dashboard/acme/overview", headers=AUTH)
    data = resp.json()
    assert data["total_governed"] == 4
    assert data["decision_counts"]["deny"] == 2
    assert data["denial_rate"] == 0.5
    assert data["last_ledger_seq"] == 3


# ── Timeline ─────────────────────────────────────────────────────────────────────


async def test_decisions_timeline_buckets_by_day():
    entries = [
        _entry(0, decision=Decision.ALLOW, day=5),
        _entry(1, decision=Decision.DENY, day=5),
        _entry(2, decision=Decision.ALLOW, day=6),
    ]
    async with _client(create_app(_kernel(entries=entries))) as c:
        resp = await c.get(
            "/v1/dashboard/acme/decisions", params={"window_days": 365}, headers=AUTH
        )
    buckets = resp.json()["buckets"]
    assert len(buckets) == 2
    by_date = {b["date"]: b for b in buckets}
    assert by_date["2026-06-05"]["total"] == 2
    assert by_date["2026-06-05"]["decision_counts"]["deny"] == 1
    assert by_date["2026-06-06"]["total"] == 1


async def test_decisions_timeline_window_excludes_old():
    # An entry far in the past is excluded by a short window.
    old = _entry(0, decision=Decision.ALLOW)
    object.__setattr__(old, "sealed_at", datetime(2000, 1, 1, tzinfo=timezone.utc))
    async with _client(create_app(_kernel(entries=[old]))) as c:
        resp = await c.get("/v1/dashboard/acme/decisions", params={"window_days": 7}, headers=AUTH)
    assert resp.json()["buckets"] == []


async def test_decisions_timeline_invalid_window_returns_422():
    async with _client(create_app(_kernel())) as c:
        resp = await c.get("/v1/dashboard/acme/decisions", params={"window_days": 0}, headers=AUTH)
    assert resp.status_code == 422


# ── Top actions ──────────────────────────────────────────────────────────────────


async def test_top_actions_by_volume_and_denials():
    entries = [
        _entry(0, decision=Decision.ALLOW, action_type="payments.wire"),
        _entry(1, decision=Decision.DENY, action_type="payments.wire"),
        _entry(2, decision=Decision.DENY, action_type="loans.approve"),
        _entry(3, decision=Decision.ALLOW, action_type="loans.approve"),
        _entry(4, decision=Decision.ALLOW, action_type="loans.approve"),
    ]
    async with _client(create_app(_kernel(entries=entries))) as c:
        resp = await c.get("/v1/dashboard/acme/actions/top", headers=AUTH)
    data = resp.json()
    # loans.approve has 3 total (most volume); payments.wire has 2
    assert data["by_volume"][0]["action_type"] == "loans.approve"
    assert data["by_volume"][0]["total"] == 3
    # both have 1 denial; only types with denials appear in by_denials
    denial_types = {e["action_type"] for e in data["by_denials"]}
    assert denial_types == {"payments.wire", "loans.approve"}


async def test_top_actions_respects_limit():
    entries = [
        _entry(i, decision=Decision.ALLOW, action_type=f"type.{i}") for i in range(5)
    ]
    async with _client(create_app(_kernel(entries=entries))) as c:
        resp = await c.get("/v1/dashboard/acme/actions/top", params={"limit": 2}, headers=AUTH)
    assert len(resp.json()["by_volume"]) == 2


async def test_top_actions_empty_ledger():
    async with _client(create_app(_kernel(entries=[]))) as c:
        resp = await c.get("/v1/dashboard/acme/actions/top", headers=AUTH)
    data = resp.json()
    assert data["by_volume"] == [] and data["by_denials"] == []


# ── HITL queue ───────────────────────────────────────────────────────────────────


async def test_hitl_queue_zero_pending():
    async with _client(create_app(_kernel(hitl=InProcessHITLPort()))) as c:
        resp = await c.get("/v1/dashboard/acme/hitl/queue", headers=AUTH)
    assert resp.json() == {"tenant": "acme", "pending": 0}


async def test_hitl_queue_counts_pending():
    hitl = InProcessHITLPort()
    for i in range(2):
        await hitl.request_approval(
            action=make_action(action_id=f"a-{i}", idempotency_key=f"k-{i}"),
            approvers=[ApproverRef("role:risk_head")],
            tenant=TENANT,
        )
    async with _client(create_app(_kernel(hitl=hitl))) as c:
        resp = await c.get("/v1/dashboard/acme/hitl/queue", headers=AUTH)
    assert resp.json()["pending"] == 2


async def test_hitl_queue_non_inprocess_adapter_returns_zero():
    # FakeHITL is not an InProcessHITLPort → depth is reported as 0 (external queue).
    async with _client(create_app(_kernel(hitl=FakeHITL()))) as c:
        resp = await c.get("/v1/dashboard/acme/hitl/queue", headers=AUTH)
    assert resp.json()["pending"] == 0
