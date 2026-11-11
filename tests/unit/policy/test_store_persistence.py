"""PolicyStore write-through + hydrate — durability without a database.

Uses InMemoryPolicyRepository as the durable backend so the full
register → persist → fresh store → hydrate → lookup loop is exercised in-process. The critical
property: hydrate RECOMPILES the CEL condition (compiled programs are never persisted).
"""

from __future__ import annotations

from datetime import datetime, timezone

from celpy import celtypes

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import ApproverRef, Decision


def _envelope(
    policy_id: str = "p.wire",
    version: int = 1,
    condition: str = "payload_amount > 1000",
    decision: Decision = Decision.REQUIRE_APPROVAL,
    lifecycle: PolicyLifecycle = PolicyLifecycle.ACTIVATED,
) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=policy_id,
        version=version,
        governs="payments.wire",
        scope={"tenant": "*"},
        condition=condition,
        decision=decision,
        approvers=(ApproverRef("role:risk_head"),) if decision is Decision.REQUIRE_APPROVAL else (),
        regulatory_refs=(),
        lifecycle=lifecycle,
    )


def _impact(policy_id: str, version: int) -> ImpactReport:
    return ImpactReport(
        policy_id=policy_id,
        policy_version=version,
        reviewed_by="reviewer:alice",
        reviewed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        decision_distribution={"allow": 1.0},
        flip_count=0,
        fairness_delta=0.0,
        acknowledged=True,
    )


# ── register_persisted ──────────────────────────────────────────────────────


async def test_register_persisted_writes_cache_and_repo() -> None:
    repo = InMemoryPolicyRepository()
    store = PolicyStore(repository=repo)
    await store.register_persisted(_envelope())
    # Cache: lookup finds the ACTIVATED policy.
    assert len(store.lookup("payments.wire", "acme")) == 1
    # Repo: persisted too.
    assert len(await repo.load_all()) == 1


async def test_register_persisted_with_no_repo_is_cache_only() -> None:
    store = PolicyStore()  # no repository
    await store.register_persisted(_envelope())
    assert len(store.lookup("payments.wire", "acme")) == 1


# ── hydrate recompiles CEL ──────────────────────────────────────────────────


async def test_hydrate_repopulates_and_recompiles_cel() -> None:
    repo = InMemoryPolicyRepository()
    # Seed the durable repo directly (lifecycle ACTIVATED so lookup will return it).
    await repo.save_envelope(_envelope())

    # A brand-new store over the same repo: empty until hydrate.
    fresh = PolicyStore(repository=repo)
    assert fresh.lookup("payments.wire", "acme") == []

    await fresh.hydrate()
    found = fresh.lookup("payments.wire", "acme")
    assert len(found) == 1
    # The condition was recompiled on hydrate → the compiled program is usable.
    env = found[0]
    assert env.compiled_condition is not None
    assert bool(env.compiled_condition.evaluate({"payload_amount": celtypes.IntType(5000)}))


async def test_hydrate_no_repo_is_noop() -> None:
    store = PolicyStore()
    await store.hydrate()  # must not raise
    assert store.lookup("payments.wire", "acme") == []


# ── activate_persisted / deprecate_persisted ─────────────────────────────────


async def test_activate_persisted_runs_f10_and_persists() -> None:
    repo = InMemoryPolicyRepository()
    store = PolicyStore(repository=repo)
    await store.register_persisted(_envelope(lifecycle=PolicyLifecycle.REVIEW))
    await store.activate_persisted("p.wire", 1, _impact("p.wire", 1))

    # Cache: now ACTIVATED → visible to lookup.
    assert len(store.lookup("payments.wire", "acme")) == 1
    # Repo: lifecycle persisted + impact report stored.
    loaded = await repo.load_all()
    assert loaded[0].lifecycle is PolicyLifecycle.ACTIVATED
    assert len(await repo.load_impact_reports()) == 1


async def test_deprecate_persisted_removes_from_lookup() -> None:
    repo = InMemoryPolicyRepository()
    store = PolicyStore(repository=repo)
    await store.register_persisted(_envelope())  # ACTIVATED
    assert len(store.lookup("payments.wire", "acme")) == 1

    await store.deprecate_persisted("p.wire", 1)
    assert store.lookup("payments.wire", "acme") == []  # DEPRECATED no longer matches
    loaded = await repo.load_all()
    assert loaded[0].lifecycle is PolicyLifecycle.DEPRECATED


# ── full durability round-trip ───────────────────────────────────────────────


async def test_durability_round_trip_survives_new_store() -> None:
    repo = InMemoryPolicyRepository()

    store1 = PolicyStore(repository=repo)
    await store1.register_persisted(_envelope(condition="payload_amount > 2000"))

    # Simulate a restart: a fresh store over the same durable repo.
    store2 = PolicyStore(repository=repo)
    await store2.hydrate()

    found = store2.lookup("payments.wire", "acme")
    assert len(found) == 1
    assert found[0].condition == "payload_amount > 2000"
