"""Unit tests for the K·01 Policy Engine.

Each test proves one behavioral guarantee of the engine. The fail-closed contract means any error
path (empty policy set, CEL fault, all conditions false) must raise a typed `PolicyError` subtype
— never succeed silently — because the `LifecycleEngine` maps those exceptions to DENY.

Tests that verify "returns DENY" do so by asserting the raised exception type (proving the
lifecycle engine would map it to DENY); tests that verify a concrete decision assert the
`EvaluationResult.decision` directly.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.errors import PolicyActivationError, PolicyCompileError, PolicyEvaluationError, PolicyNotFoundError
from quaicu.core.policy.evaluator import PolicyEngine
from quaicu.core.policy.model import ImpactReport, PolicyEnvelope, PolicyLifecycle
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ActionId, Actor, ActorId, ApproverRef, Decision, IdempotencyKey, TenantId

# ── Fixtures / helpers ────────────────────────────────────────────────────────

TENANT_A = TenantId("alpha")
TENANT_B = TenantId("beta")

_IMPACT_REPORT_COUNTER = 0


def _make_impact_report(policy_id: str, version: int) -> ImpactReport:
    return ImpactReport(
        policy_id=policy_id,
        policy_version=version,
        reviewed_by="reviewer:alice",
        reviewed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        decision_distribution={"allow": 0.6, "deny": 0.3, "require_approval": 0.1},
        flip_count=12,
        fairness_delta=0.02,
        acknowledged=True,
    )


def _make_action(
    *,
    tenant: TenantId = TENANT_A,
    action_type: str = "test.action",
    payload: dict | None = None,
) -> Action:
    return Action(
        id=ActionId("act-1"),
        type=action_type,
        payload=payload or {"amount": 100},
        actor=Actor(id=ActorId("alice"), tenant=tenant, roles=("role:analyst",)),
        tenant=tenant,
        idempotency_key=IdempotencyKey("key-1"),
    )


def _make_policy(
    *,
    policy_id: str = "test.policy",
    version: int = 1,
    governs: str = "test.action",
    scope: dict | None = None,
    condition: str = "true",
    decision: Decision = Decision.ALLOW,
    approvers: tuple[ApproverRef, ...] = (),
    lifecycle: PolicyLifecycle = PolicyLifecycle.REVIEW,
) -> PolicyEnvelope:
    return PolicyEnvelope(
        id=policy_id,
        version=version,
        governs=governs,
        scope=scope or {"tenant": "*"},
        condition=condition,
        decision=decision,
        approvers=approvers,
        regulatory_refs=(),
        lifecycle=lifecycle,
    )


def _activated_store(*policies: PolicyEnvelope) -> PolicyStore:
    """Register and activate each policy, returning a populated store."""
    store = PolicyStore()
    for policy in policies:
        stored = store.register(policy)
        report = _make_impact_report(stored.id, stored.version)
        store.activate(stored.id, stored.version, report)
    return store


# ── Tests ─────────────────────────────────────────────────────────────────────


async def test_empty_policy_set_returns_deny() -> None:
    """No registered policies → PolicyNotFoundError (maps to DENY at lifecycle level)."""
    engine = PolicyEngine(PolicyStore())
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_make_action())


async def test_allow_policy_returns_allow() -> None:
    """One ACTIVATED allow policy with condition=true → ALLOW."""
    policy = _make_policy(condition="true", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(policy))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.ALLOW


async def test_deny_policy_returns_deny() -> None:
    """One ACTIVATED deny policy with condition=true → DENY result (not an exception)."""
    policy = _make_policy(condition="true", decision=Decision.DENY)
    engine = PolicyEngine(_activated_store(policy))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.DENY


async def test_require_approval_returns_require_approval() -> None:
    """One ACTIVATED require_approval policy → REQUIRE_APPROVAL with approvers in result."""
    approvers: tuple[ApproverRef, ...] = (ApproverRef("role:risk_head"),)
    policy = _make_policy(
        condition="true",
        decision=Decision.REQUIRE_APPROVAL,
        approvers=approvers,
    )
    engine = PolicyEngine(_activated_store(policy))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert ApproverRef("role:risk_head") in result.approvers


async def test_deny_overrides_allow() -> None:
    """Conflict resolution: deny beats allow when both conditions are true."""
    allow_p = _make_policy(policy_id="p.allow", condition="true", decision=Decision.ALLOW)
    deny_p = _make_policy(policy_id="p.deny", condition="true", decision=Decision.DENY)
    engine = PolicyEngine(_activated_store(allow_p, deny_p))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.DENY


async def test_deny_overrides_require_approval() -> None:
    """Conflict resolution: deny beats require_approval."""
    req_p = _make_policy(
        policy_id="p.req",
        condition="true",
        decision=Decision.REQUIRE_APPROVAL,
        approvers=(ApproverRef("role:risk_head"),),
    )
    deny_p = _make_policy(policy_id="p.deny", condition="true", decision=Decision.DENY)
    engine = PolicyEngine(_activated_store(req_p, deny_p))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.DENY


async def test_require_approval_overrides_allow() -> None:
    """Conflict resolution: require_approval beats allow."""
    allow_p = _make_policy(policy_id="p.allow", condition="true", decision=Decision.ALLOW)
    req_p = _make_policy(
        policy_id="p.req",
        condition="true",
        decision=Decision.REQUIRE_APPROVAL,
        approvers=(ApproverRef("role:risk_head"),),
    )
    engine = PolicyEngine(_activated_store(allow_p, req_p))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.REQUIRE_APPROVAL


async def test_condition_false_policy_is_skipped() -> None:
    """A policy whose CEL condition evaluates to false is not applied; no match → DENY."""
    policy = _make_policy(condition="false", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(policy))
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_make_action())


async def test_cel_error_is_fail_closed_deny() -> None:
    """A runtime CEL error on a valid-but-failing expression raises PolicyEvaluationError (→ DENY)."""
    # Referencing an undefined variable causes a runtime CEL error.
    policy = _make_policy(condition="undefined_variable == 42", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(policy))
    with pytest.raises(PolicyEvaluationError):
        await engine.evaluate(_make_action(payload={}))


async def test_cel_condition_uses_action_payload() -> None:
    """CEL condition can access payload fields via the flat namespace (payload_<key>)."""
    policy = _make_policy(
        condition="payload_exposure > 5000000",
        decision=Decision.ALLOW,
    )
    engine = PolicyEngine(_activated_store(policy))
    action_above = _make_action(payload={"exposure": 7_500_000})
    result = await engine.evaluate(action_above)
    assert result.decision is Decision.ALLOW

    action_below = _make_action(payload={"exposure": 3_000_000})
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(action_below)


async def test_determinism() -> None:
    """Same action evaluated twice returns the same decision both times."""
    policy = _make_policy(condition="true", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(policy))
    action = _make_action()
    r1 = await engine.evaluate(action)
    r2 = await engine.evaluate(action)
    assert r1.decision is r2.decision
    assert r1.policy_versions == r2.policy_versions


async def test_tenant_isolation() -> None:
    """Policy scoped to tenant 'alpha' does not apply to tenant 'beta'."""
    policy = _make_policy(
        scope={"tenant": str(TENANT_A)},
        condition="true",
        decision=Decision.ALLOW,
    )
    engine = PolicyEngine(_activated_store(policy))

    # Alpha action → policy matches → ALLOW
    result = await engine.evaluate(_make_action(tenant=TENANT_A))
    assert result.decision is Decision.ALLOW

    # Beta action → no policy matches → DENY (PolicyNotFoundError)
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_make_action(tenant=TENANT_B))


async def test_wildcard_tenant_scope_matches_all() -> None:
    """Policy with tenant '*' applies to actions from any tenant."""
    policy = _make_policy(scope={"tenant": "*"}, condition="true", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(policy))
    for tenant in (TENANT_A, TENANT_B, TenantId("gamma")):
        result = await engine.evaluate(_make_action(tenant=tenant))
        assert result.decision is Decision.ALLOW, f"expected ALLOW for tenant {tenant}"


async def test_draft_policy_not_evaluated() -> None:
    """DRAFT policies are never returned by lookup → effectively no matching policy → DENY."""
    store = PolicyStore()
    draft = _make_policy(lifecycle=PolicyLifecycle.DRAFT)
    store.register(draft)  # registered but NOT activated
    engine = PolicyEngine(store)
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_make_action())


async def test_deprecated_policy_not_evaluated() -> None:
    """DEPRECATED policies are not returned by lookup → no matching policy → DENY."""
    store = PolicyStore()
    # Register as REVIEW, activate, then manually simulate DEPRECATED by registering another
    # envelope with DEPRECATED lifecycle (store will not activate it through the normal gate).
    dep_policy = _make_policy(lifecycle=PolicyLifecycle.DEPRECATED)
    store.register(dep_policy)
    # Since it's DEPRECATED (not REVIEW), activating it should be blocked.
    # But even if someone inserted it, lookup filters by ACTIVATED only.
    engine = PolicyEngine(store)
    with pytest.raises(PolicyNotFoundError):
        await engine.evaluate(_make_action())


async def test_policy_versions_in_result() -> None:
    """EvaluationResult.policy_versions contains version strings for all evaluated policies."""
    p1 = _make_policy(policy_id="p.one", version=1, condition="true", decision=Decision.ALLOW)
    p2 = _make_policy(policy_id="p.two", version=2, condition="true", decision=Decision.ALLOW)
    engine = PolicyEngine(_activated_store(p1, p2))
    result = await engine.evaluate(_make_action())
    assert "p.one@v1" in result.policy_versions
    assert "p.two@v2" in result.policy_versions


async def test_approvers_populated_on_require_approval() -> None:
    """Approvers from the require_approval policy appear in EvaluationResult.approvers."""
    approvers: tuple[ApproverRef, ...] = (
        ApproverRef("role:risk_head"),
        ApproverRef("user:compliance_officer"),
    )
    policy = _make_policy(
        condition="true",
        decision=Decision.REQUIRE_APPROVAL,
        approvers=approvers,
    )
    engine = PolicyEngine(_activated_store(policy))
    result = await engine.evaluate(_make_action())
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert ApproverRef("role:risk_head") in result.approvers
    assert ApproverRef("user:compliance_officer") in result.approvers


async def test_activation_requires_impact_report() -> None:
    """Activating without an acknowledged impact report raises PolicyActivationError."""
    store = PolicyStore()
    policy = _make_policy(lifecycle=PolicyLifecycle.REVIEW)
    stored = store.register(policy)

    unacknowledged = ImpactReport(
        policy_id=stored.id,
        policy_version=stored.version,
        reviewed_by="reviewer:bob",
        reviewed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        decision_distribution={"allow": 1.0},
        flip_count=0,
        fairness_delta=0.0,
        acknowledged=False,  # not acknowledged
    )
    with pytest.raises(PolicyActivationError):
        store.activate(stored.id, stored.version, unacknowledged)


async def test_cel_compile_error_raises_policy_compile_error() -> None:
    """Registering a policy with syntactically invalid CEL raises PolicyCompileError."""
    store = PolicyStore()
    bad_policy = _make_policy(condition="this is not valid CEL !!! @@@")
    with pytest.raises(PolicyCompileError):
        store.register(bad_policy)
