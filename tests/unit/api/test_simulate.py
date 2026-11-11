"""Unit tests for POST /v1/policies/{id}/versions/{v}/simulate (gap #4).

Covers control-plane authz, the backtest→ImpactReport assembly, the optional fairness sweep,
empty-ledger handling, auto_store, and the REVIEW-only lifecycle guard.
"""

from __future__ import annotations

from datetime import datetime, timezone

from httpx import ASGITransport, AsyncClient

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import (
    ActionId,
    ActorId,
    Decision,
    LedgerEntry,
    TenantId,
)
from quaicu.delivery.api.app import create_app
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeIdentity, FakeLedger, FakePolicy

TENANT = TenantId("acme")
AUTH = {"Authorization": "Bearer test-token"}
ADMIN_ROLES = ("role:policy_admin",)


def _entry(seq: int, *, decision: Decision, payload: dict, day: int = 5) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=seq,
        tenant=TENANT,
        action_id=ActionId(f"act-{seq}"),
        action_type="payments.wire",
        actor_id=ActorId("alice"),
        decision=decision,
        policy_versions=("p.wire@v1",),
        leaf_hash=b"\x00" * 32,
        sealed_at=datetime(2026, 6, day, tzinfo=timezone.utc),
        recorded_result=payload,
    )


def _kernel(*, entries: list[LedgerEntry] | None = None, identity_roles=ADMIN_ROLES, with_identity=True):
    repo = InMemoryPolicyRepository()
    store = PolicyStore(repository=repo)
    ledger = FakeLedger()
    if entries:
        ledger.sealed.extend(entries)
    return Kernel.from_parts(
        tenant=TENANT,
        policy=FakePolicy(),
        hitl=FakeHITL(),
        ledger=ledger,
        events=FakeEvents(),
        identity=FakeIdentity(roles=identity_roles) if with_identity else None,
        policy_store=store,
        policy_repository=repo,
    )


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _seed_review_policy(c, *, condition="payload_amount > 100", decision="deny"):
    """Register + submit a policy so it is in REVIEW, ready to simulate."""
    body = {
        "id": "p.wire",
        "version": 1,
        "governs": "payments.wire",
        "scope": {"tenant": "*"},
        "condition": condition,
        "decision": decision,
        "approvers": [],
        "regulatory_refs": [],
    }
    await c.post("/v1/policies", json=body, headers=AUTH)
    await c.post("/v1/policies/p.wire/versions/1/submit", headers=AUTH)


# ── Authorization ───────────────────────────────────────────────────────────────


async def test_simulate_without_token_returns_401():
    async with _client(create_app(_kernel())) as c:
        resp = await c.post("/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"})
    assert resp.status_code == 401


async def test_simulate_without_store_returns_503():
    k = Kernel.from_parts(
        tenant=TENANT, policy=FakePolicy(), hitl=FakeHITL(), ledger=FakeLedger(),
        events=FakeEvents(), identity=FakeIdentity(roles=ADMIN_ROLES), policy_store=None,
    )
    async with _client(create_app(k)) as c:
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.status_code == 503


async def test_simulate_wrong_role_returns_403():
    async with _client(create_app(_kernel(identity_roles=("role:risk_analyst",)))) as c:
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.status_code == 403


# ── Lifecycle guard ──────────────────────────────────────────────────────────────


async def test_simulate_missing_policy_returns_404():
    async with _client(create_app(_kernel())) as c:
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.status_code == 404


async def test_simulate_draft_policy_returns_409():
    app = create_app(_kernel())
    async with _client(app) as c:
        # register but do NOT submit → stays DRAFT
        await c.post(
            "/v1/policies",
            json={
                "id": "p.wire", "version": 1, "governs": "payments.wire",
                "scope": {"tenant": "*"}, "condition": "true", "decision": "allow",
                "approvers": [], "regulatory_refs": [],
            },
            headers=AUTH,
        )
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "POLICY_NOT_IN_REVIEW"


# ── Backtest assembly ────────────────────────────────────────────────────────────


async def test_simulate_empty_ledger():
    app = create_app(_kernel(entries=[]))
    async with _client(app) as c:
        await _seed_review_policy(c)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ledger_entries_evaluated"] == 0
    assert data["flip_rate"] == 0.0
    assert data["impact_report"]["acknowledged"] is False


async def test_simulate_counts_flips():
    # Active entries are all ALLOW; candidate denies when amount > 100.
    entries = [
        _entry(0, decision=Decision.ALLOW, payload={"amount": 200}),  # candidate=deny → flip
        _entry(1, decision=Decision.ALLOW, payload={"amount": 50}),   # candidate=deny (no match→deny) → flip
    ]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c, condition="payload_amount > 100", decision="deny")
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    data = resp.json()
    assert data["ledger_entries_evaluated"] == 2
    # both flip: entry0 matches→deny (was allow); entry1 no-match→deny (was allow)
    assert data["decisions_flipped"] == 2
    assert data["impact_report"]["flip_count"] == 2


async def test_simulate_no_flip_when_decisions_agree():
    # Active entries already DENY; candidate also denies (amount>100 matches) → no flip.
    entries = [_entry(0, decision=Decision.DENY, payload={"amount": 500})]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c, condition="payload_amount > 100", decision="deny")
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    data = resp.json()
    assert data["decisions_flipped"] == 0
    assert data["flip_rate"] == 0.0


# ── Fairness sweep ───────────────────────────────────────────────────────────────


async def test_simulate_with_group_key_populates_fairness():
    entries = [
        _entry(0, decision=Decision.ALLOW, payload={"amount": 200, "band": "A"}),
        _entry(1, decision=Decision.ALLOW, payload={"amount": 50, "band": "B"}),
    ]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c, condition="payload_amount > 100", decision="deny")
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate",
            json={"reviewed_by": "u", "group_key": "band"},
            headers=AUTH,
        )
    data = resp.json()
    assert data["fairness_delta"] is not None
    assert data["impact_report"]["fairness_delta"] == data["fairness_delta"]


async def test_simulate_without_group_key_fairness_none():
    entries = [_entry(0, decision=Decision.ALLOW, payload={"amount": 200})]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.json()["fairness_delta"] is None


# ── auto_store ───────────────────────────────────────────────────────────────────


async def test_simulate_auto_store_persists_report():
    app = create_app(_kernel(entries=[]))
    async with _client(app) as c:
        await _seed_review_policy(c)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate",
            json={"reviewed_by": "u", "auto_store": True},
            headers=AUTH,
        )
        assert resp.json()["stored"] is True
        # The stored (unacknowledged) report alone must NOT let activation pass the F-10 gate.
        activate = await c.post("/v1/policies/p.wire/versions/1/activate", json={}, headers=AUTH)
    assert activate.status_code == 409  # not acknowledged


async def test_simulate_no_auto_store_by_default():
    app = create_app(_kernel(entries=[]))
    async with _client(app) as c:
        await _seed_review_policy(c)
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    assert resp.json()["stored"] is False


# ── Recorded actor identity in the backtest ──────────────────────────────────────


def _entry_actor(
    seq: int,
    *,
    decision: Decision,
    actor: str,
    roles: tuple[str, ...] = (),
    payload: dict | None = None,
) -> LedgerEntry:
    e = _entry(seq, decision=decision, payload=payload or {})
    return LedgerEntry(  # rebuild with the desired actor identity
        ledger_seq=e.ledger_seq,
        tenant=e.tenant,
        action_id=e.action_id,
        action_type=e.action_type,
        actor_id=ActorId(actor),
        decision=e.decision,
        policy_versions=e.policy_versions,
        leaf_hash=e.leaf_hash,
        sealed_at=e.sealed_at,
        recorded_result=e.recorded_result,
        actor_roles=roles,
    )


async def test_simulate_actor_id_condition_evaluates():
    # The recorded actor_id is threaded into the backtest: a condition gating on actor_id
    # re-evaluates faithfully instead of failing closed.
    entries = [
        _entry_actor(0, decision=Decision.ALLOW, actor="alice"),  # matches → candidate deny → flip
        _entry_actor(1, decision=Decision.ALLOW, actor="bob"),    # no match → candidate deny → flip
    ]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c, condition='actor_id == "alice"', decision="deny")
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    data = resp.json()
    # alice: condition true → deny (flips from allow); bob: condition false → no-match → deny (flips).
    # The point: the condition referencing actor_id did NOT raise — it was evaluated. Prove the
    # branch was actually taken by checking a non-matching actor with an ALLOW candidate decision.
    assert data["ledger_entries_evaluated"] == 2


async def test_simulate_actor_id_match_is_distinguishable():
    # With an ALLOW decision policy, only the matching actor's entry yields the policy decision;
    # the non-matching entry falls through to a fail-closed deny. This proves actor_id is read.
    entries = [
        _entry_actor(0, decision=Decision.ALLOW, actor="alice"),  # match → allow → no flip
        _entry_actor(1, decision=Decision.ALLOW, actor="bob"),    # no match → deny → flip
    ]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(c, condition='actor_id == "alice"', decision="allow")
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    data = resp.json()
    # alice unchanged (allow), bob flips (allow→deny) → exactly one flip.
    assert data["decisions_flipped"] == 1


async def test_simulate_actor_roles_condition_evaluates():
    # actor_roles is now sealed on the LedgerEntry (ADR-0006), so a role-referencing condition
    # replays faithfully: the actor holding the role yields the policy decision, one without it
    # falls through to a fail-closed deny.
    entries = [
        _entry_actor(0, decision=Decision.ALLOW, actor="alice", roles=("role:risk_head",)),  # match → allow → no flip
        _entry_actor(1, decision=Decision.ALLOW, actor="bob", roles=("role:clerk",)),         # no match → deny → flip
    ]
    app = create_app(_kernel(entries=entries))
    async with _client(app) as c:
        await _seed_review_policy(
            c, condition='"role:risk_head" in actor_roles', decision="allow"
        )
        resp = await c.post(
            "/v1/policies/p.wire/versions/1/simulate", json={"reviewed_by": "u"}, headers=AUTH
        )
    data = resp.json()
    # alice (has role) unchanged allow; bob (no role) flips allow→deny → exactly one flip.
    assert data["decisions_flipped"] == 1
