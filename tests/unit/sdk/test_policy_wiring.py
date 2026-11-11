"""End-to-end: the real CEL PolicyEngine wired into a Kernel via from_parts.

Proves the gap is closed — a Kernel can run on the real K·01 engine, an empty store fail-closed
DENYs, and authoring a policy through the SDK write-through primitive makes the action enforceable.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.adapters.policy.memory import InMemoryPolicyRepository
from quaicu.core.errors import LifecycleDeniedError
from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Actor, ActorId, Decision, TenantId
from quaicu.delivery.sdk.kernel import Kernel

from tests.unit.lifecycle.fakes import FakeEvents, FakeHITL, FakeLedger

TENANT = TenantId("acme")
ACTOR = Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:analyst",))


def _kernel(repo=None):
    store = PolicyStore(repository=repo)
    engine = PolicyEngine(store)
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=engine,
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        policy_store=store,
        policy_repository=repo,
    )
    return kernel, store


def _allow_envelope() -> PolicyEnvelope:
    return PolicyEnvelope(
        id="p.allow-wire",
        version=1,
        governs="payments.wire",
        scope={"tenant": "*"},
        condition="true",
        decision=Decision.ALLOW,
        approvers=(),
        regulatory_refs=(),
        lifecycle=PolicyLifecycle.ACTIVATED,
    )


# ── Wiring ─────────────────────────────────────────────────────────────────────


def test_kernel_exposes_policy_store() -> None:
    kernel, _ = _kernel()
    assert kernel.has_policy_store is True
    assert kernel.policy_store is not None


async def test_empty_store_denies_governed_action() -> None:
    """The secure default: no policies → fail-closed DENY (PolicyNotFoundError → DENY)."""
    kernel, _ = _kernel()

    @kernel.guard(policy="payments.wire", action_type="payments.wire")
    async def wire(amount: int) -> str:
        return "sent"

    with pytest.raises(LifecycleDeniedError):
        async with kernel.actor_context(ACTOR):
            await wire(amount=100)


async def test_register_policy_then_action_completes() -> None:
    kernel, _ = _kernel()
    await kernel.register_policy(_allow_envelope())

    @kernel.guard(policy="payments.wire", action_type="payments.wire")
    async def wire(amount: int) -> str:
        return "sent"

    async with kernel.actor_context(ACTOR):
        result = await wire(amount=100)
    assert result == "sent"


# ── Durability via startup() hydrate ─────────────────────────────────────────


async def test_startup_hydrates_from_repository() -> None:
    repo = InMemoryPolicyRepository()
    await repo.save_envelope(_allow_envelope())  # persisted, ACTIVATED

    kernel, store = _kernel(repo=repo)
    # Before startup the fresh store is empty.
    assert store.lookup("payments.wire", "acme") == []

    await kernel.startup()  # hydrates + recompiles
    assert len(store.lookup("payments.wire", "acme")) == 1


async def test_register_policy_without_store_raises() -> None:
    from quaicu.adapters.policy.always_allow import AlwaysAllowPolicyAdapter

    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=AlwaysAllowPolicyAdapter(),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )
    assert kernel.has_policy_store is False
    with pytest.raises(RuntimeError, match="No policy store"):
        await kernel.register_policy(_allow_envelope())


# ── Management passthroughs ──────────────────────────────────────────────────


def _draft_envelope() -> PolicyEnvelope:
    import dataclasses

    return dataclasses.replace(_allow_envelope(), lifecycle=PolicyLifecycle.DRAFT)


async def test_submit_policy_for_review_passthrough() -> None:
    kernel, store = _kernel()
    await kernel.register_policy(_draft_envelope())
    env = await kernel.submit_policy_for_review("p.allow-wire", 1)
    assert env.lifecycle is PolicyLifecycle.REVIEW


async def test_submit_policy_for_review_without_store_raises() -> None:
    from quaicu.adapters.policy.always_allow import AlwaysAllowPolicyAdapter

    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=AlwaysAllowPolicyAdapter(),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
    )
    with pytest.raises(RuntimeError, match="No policy store"):
        await kernel.submit_policy_for_review("x", 1)


async def test_store_policy_impact_report_passthrough() -> None:
    kernel, store = _kernel()
    report = ImpactReport(
        policy_id="p.allow-wire",
        policy_version=1,
        reviewed_by="user:reviewer",
        reviewed_at=datetime(2026, 6, 5, tzinfo=timezone.utc),
        decision_distribution={"allow": 1.0},
        flip_count=0,
        fairness_delta=0.0,
        acknowledged=True,
    )
    await kernel.store_policy_impact_report(report)
    assert store.get_impact_report("p.allow-wire", 1) is not None


# ── resolve_actor ─────────────────────────────────────────────────────────────


async def test_resolve_actor_resolves_via_identity_port() -> None:
    from quaicu.core.types import RequestContext

    from tests.unit.lifecycle.fakes import FakeIdentity

    store = PolicyStore()
    kernel = Kernel.from_parts(
        tenant=TENANT,
        policy=PolicyEngine(store),
        hitl=FakeHITL(),
        ledger=FakeLedger(),
        events=FakeEvents(),
        identity=FakeIdentity(roles=("role:policy_admin",)),
        policy_store=store,
    )
    actor = await kernel.resolve_actor(RequestContext(raw_token="t"))
    assert actor.roles == ("role:policy_admin",)


async def test_resolve_actor_without_identity_raises() -> None:
    from quaicu.core.types import RequestContext

    kernel, _ = _kernel()  # no identity wired
    with pytest.raises(RuntimeError, match="No identity adapter"):
        await kernel.resolve_actor(RequestContext(raw_token="t"))


# ── from_config: policy_admin_roles parsing ──────────────────────────────────


def test_from_config_default_policy_admin_roles(tmp_path) -> None:
    cfg = tmp_path / "kernel.toml"
    cfg.write_text(
        "[tenant]\nid = \"acme\"\n"
        "[adapters]\npolicy = \"cel_policy\"\nhitl = \"webhook\"\n"
        "ledger = \"memory_ledger\"\nevents = \"memory_events\"\n",
        encoding="utf-8",
    )
    kernel = Kernel.from_config(cfg)
    assert kernel.policy_admin_roles == ("role:policy_admin",)


def test_from_config_normalizes_bare_policy_admin_roles(tmp_path) -> None:
    cfg = tmp_path / "kernel.toml"
    cfg.write_text(
        "[tenant]\nid = \"acme\"\n"
        "[adapters]\npolicy = \"cel_policy\"\nhitl = \"webhook\"\n"
        "ledger = \"memory_ledger\"\nevents = \"memory_events\"\n"
        "[governance]\npolicy_admin_roles = [\"policy_admin\", \"role:governance_lead\"]\n",
        encoding="utf-8",
    )
    kernel = Kernel.from_config(cfg)
    assert kernel.policy_admin_roles == ("role:policy_admin", "role:governance_lead")
