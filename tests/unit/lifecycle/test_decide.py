"""LifecycleEngine.decide() — side-effect-free policy-decision tests.

Key invariants under test:
- Returns AuthorizationResult on all outcomes (never raises).
- Never inserts a row into the action repository.
- Never transitions any action state.
- Mirrors run()'s decision logic for identity / consent / policy layers.
- Seals to ledger iff seal_to_ledger is True (or record=True override).
- Seal failure is best-effort: the verdict is unchanged even when sealing fails.
"""

from __future__ import annotations

from datetime import datetime, timezone


from quaicu.core.lifecycle.decision import AuthorizationResult
from quaicu.core.lifecycle.engine import LifecycleEngine
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.ports.consent import ConsentRecord
from quaicu.core.types import ActionState, Decision, RequestContext, TenantId

from tests.unit.lifecycle.fakes import (
    FakeActionRepository,
    FakeEvents,
    FakeHITL,
    FakeLedger,
    FakePolicy,
    make_action,
)

TENANT = TenantId("acme")


def _engine(
    *,
    policy=None,
    ledger=None,
    events=None,
    identity=None,
    consent=None,
    default_profile=None,
):
    repo = FakeActionRepository()
    ledger = ledger or FakeLedger()
    events = events or FakeEvents()
    engine = LifecycleEngine(
        repository=repo,
        policy=policy or FakePolicy(decision=Decision.ALLOW),
        hitl=FakeHITL(),
        ledger=ledger,
        events=events,
        identity=identity,
        consent=consent,
        default_profile=default_profile,
    )
    return engine, repo, ledger, events


# ── Basic verdicts ─────────────────────────────────────────────────────────────


async def test_decide_allow_returns_allowed_true() -> None:
    engine, repo, _, _ = _engine()
    result = await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert isinstance(result, AuthorizationResult)
    assert result.allowed is True
    assert result.decision is Decision.ALLOW


async def test_decide_deny_returns_allowed_false() -> None:
    engine, repo, _, _ = _engine(policy=FakePolicy(decision=Decision.DENY))
    result = await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert result.allowed is False
    assert result.decision is Decision.DENY


async def test_decide_require_approval_returned_verbatim() -> None:
    engine, _, _, _ = _engine(policy=FakePolicy(decision=Decision.REQUIRE_APPROVAL))
    result = await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert result.decision is Decision.REQUIRE_APPROVAL
    # decide() never gates — the verdict is returned; the caller routes it.
    assert result.allowed is False


# ── Side-effect freedom ────────────────────────────────────────────────────────


async def test_decide_never_inserts_action_row() -> None:
    engine, repo, _, _ = _engine()
    await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert len(repo.by_key) == 0


async def test_decide_action_state_unchanged() -> None:
    engine, _, _, _ = _engine()
    action = make_action()
    assert action.state is ActionState.PROPOSED
    await engine.decide(action, profile=GovernanceProfile(seal_to_ledger=False))
    assert action.state is ActionState.PROPOSED  # immutable; decide never mutates it


async def test_decide_never_emits_events() -> None:
    engine, _, _, events = _engine()
    await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert events.emitted == []


# ── Policy layer skipping ──────────────────────────────────────────────────────


async def test_decide_policy_off_auto_allows_without_consulting_evaluator() -> None:
    policy = FakePolicy(decision=Decision.DENY)
    engine, _, _, _ = _engine(policy=policy)
    result = await engine.decide(
        make_action(), profile=GovernanceProfile(enforce_policy=False, seal_to_ledger=False)
    )
    assert result.allowed is True
    assert policy.calls == 0


async def test_decide_policy_exception_denies_fail_closed() -> None:
    class _RaisingPolicy:
        calls = 0
        async def evaluate(self, action):
            self.calls += 1
            raise RuntimeError("policy exploded")

    engine, _, _, _ = _engine(policy=_RaisingPolicy())
    result = await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert result.allowed is False
    assert result.reason is not None and "fail-closed" in result.reason


async def test_decide_policy_returns_none_denies_fail_closed() -> None:
    class _NonePolicy:
        async def evaluate(self, action):
            return None

    engine, _, _, _ = _engine(policy=_NonePolicy())
    result = await engine.decide(make_action(), profile=GovernanceProfile(seal_to_ledger=False))
    assert result.allowed is False


# ── Identity layer ─────────────────────────────────────────────────────────────


class _FaultIdentity:
    async def resolve_actor(self, *, context, tenant):
        raise Exception("identity fault")


async def test_decide_identity_fault_denies_fail_closed() -> None:
    engine, repo, _, _ = _engine(identity=_FaultIdentity())
    ctx = RequestContext(raw_token="tok")
    result = await engine.decide(
        make_action(), context=ctx, profile=GovernanceProfile(seal_to_ledger=False)
    )
    assert result.allowed is False
    assert "identity" in (result.reason or "").lower()
    assert len(repo.by_key) == 0  # still no insert


# ── Consent layer ──────────────────────────────────────────────────────────────


class _MissingConsent:
    async def get_consent(self, *, tenant_id, subject_id, purpose):
        return None


class _WithdrawnConsent:
    async def get_consent(self, *, tenant_id, subject_id, purpose):
        return ConsentRecord(
            consent_id="c-1",
            tenant_id=tenant_id,
            subject_id=subject_id,
            purpose=purpose,
            data_categories=("general",),
            status="withdrawn",
            granted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            withdrawn_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
            policy_ref="dpdp",
        )


async def test_decide_consent_missing_denies() -> None:
    engine, _, _, _ = _engine(consent=_MissingConsent())
    result = await engine.decide(
        make_action(),
        profile=GovernanceProfile(enforce_consent=True, seal_to_ledger=False),
    )
    assert result.allowed is False
    assert "consent" in (result.reason or "").lower()


async def test_decide_consent_withdrawn_denies() -> None:
    engine, _, _, _ = _engine(consent=_WithdrawnConsent())
    result = await engine.decide(
        make_action(),
        profile=GovernanceProfile(enforce_consent=True, seal_to_ledger=False),
    )
    assert result.allowed is False


async def test_decide_consent_off_ignores_missing() -> None:
    engine, _, _, _ = _engine(consent=_MissingConsent())
    result = await engine.decide(
        make_action(),
        profile=GovernanceProfile(enforce_consent=False, seal_to_ledger=False),
    )
    assert result.allowed is True


# ── Monitoring seal ────────────────────────────────────────────────────────────


async def test_decide_seals_monitoring_leaf_under_all_profile() -> None:
    engine, _, ledger, _ = _engine()
    result = await engine.decide(make_action())  # default all() → seal_to_ledger=True
    assert result.sealed is True
    assert result.ledger_seq is not None
    assert len(ledger.sealed) == 1
    entry = ledger.sealed[0]
    # FakeLedger wraps the recorded_result in {"result": ...} — the key content is what matters.
    assert entry.recorded_result.get("result") == {"decision_only": True} or entry.recorded_result == {"decision_only": True}


async def test_decide_no_seal_under_gateway_only_profile() -> None:
    engine, _, ledger, _ = _engine()
    result = await engine.decide(make_action(), profile=GovernanceProfile.gateway_only())
    assert result.sealed is False
    assert len(ledger.sealed) == 0


async def test_decide_record_false_suppresses_seal_regardless_of_profile() -> None:
    engine, _, ledger, _ = _engine()
    result = await engine.decide(make_action(), record=False)  # all() but record override
    assert result.sealed is False
    assert len(ledger.sealed) == 0


async def test_decide_record_true_forces_seal_even_on_gateway_only() -> None:
    engine, _, ledger, _ = _engine()
    result = await engine.decide(
        make_action(), profile=GovernanceProfile.gateway_only(), record=True
    )
    assert result.sealed is True
    assert len(ledger.sealed) == 1


async def test_decide_seal_failure_is_best_effort_verdict_unchanged() -> None:
    class _FailingLedger:
        sealed = []
        async def seal(self, **kwargs):
            raise RuntimeError("storage down")
        def get_entries(self, tenant):
            return []

    engine, _, _, _ = _engine(ledger=_FailingLedger())
    result = await engine.decide(make_action())  # seal attempted but fails
    assert result.allowed is True    # verdict unchanged
    assert result.sealed is False    # seal failed → False, not an exception


# ── enforced_layers populated ──────────────────────────────────────────────────


async def test_decide_enforced_layers_reflect_profile() -> None:
    profile = GovernanceProfile(
        verify_identity=False,
        enforce_consent=False,
        seal_to_ledger=False,
        emit_events=False,
    )
    engine, _, _, _ = _engine()
    result = await engine.decide(make_action(), profile=profile)
    assert "enforce_policy" in result.enforced_layers
    assert "verify_identity" not in result.enforced_layers
    assert "seal_to_ledger" not in result.enforced_layers
