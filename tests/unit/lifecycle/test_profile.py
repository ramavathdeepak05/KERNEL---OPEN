"""Composable governance — GovernanceProfile presets and the engine honoring each layer toggle.

Each test proves a single layer can be enforced or skipped independently, while every *enabled*
layer stays fail-closed.
"""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.core.lifecycle.engine import LifecycleEngine
from quaicu.core.lifecycle.profile import GovernanceProfile
from quaicu.core.ports.consent import ConsentRecord
from quaicu.core.types import ActionState, Actor, ActorId, Decision, RequestContext, TenantId

from tests.unit.lifecycle.fakes import (
    Counter,
    FakeActionRepository,
    FakeEvents,
    FakeHITL,
    FakeLedger,
    FakePolicy,
    make_action,
)

TENANT = TenantId("ciro-bank")


def _engine(*, policy, ledger=None, events=None, identity=None, consent=None, default_profile=None):
    ledger = ledger or FakeLedger()
    events = events or FakeEvents()
    engine = LifecycleEngine(
        repository=FakeActionRepository(),
        policy=policy,
        hitl=FakeHITL(),
        ledger=ledger,
        events=events,
        identity=identity,
        consent=consent,
        default_profile=default_profile,
    )
    return engine, ledger, events


# ── Consent fakes ───────────────────────────────────────────────────────────────


class _GrantingConsent:
    async def get_consent(self, *, tenant_id, subject_id, purpose):
        return ConsentRecord(
            consent_id="c-1",
            tenant_id=tenant_id,
            subject_id=subject_id,
            purpose=purpose,
            data_categories=("general",),
            status="active",
            granted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=None,
            withdrawn_at=None,
            policy_ref="dpdp",
        )


class _MissingConsent:
    async def get_consent(self, *, tenant_id, subject_id, purpose):
        return None


class _Identity:
    """Resolves to a fixed, distinct actor so identity-verification is observable."""

    def __init__(self, actor_id: str) -> None:
        self._actor_id = actor_id

    async def resolve_actor(self, *, context, tenant):
        return Actor(id=ActorId(self._actor_id), tenant=tenant, roles=())


# ── Preset shape ──────────────────────────────────────────────────────────────


def test_all_preset_enables_every_layer() -> None:
    layers = GovernanceProfile.all().enabled_layers()
    assert "enforce_policy" in layers
    assert "seal_to_ledger" in layers
    assert "mask_pii" in layers
    assert len(layers) == 10


def test_gateway_only_disables_engine_layers() -> None:
    p = GovernanceProfile.gateway_only()
    assert not p.enforce_policy and not p.seal_to_ledger and not p.emit_events
    assert p.enforce_model_allowlist and p.mask_pii  # gateway protections stay on


# ── Engine honors each toggle ───────────────────────────────────────────────────


async def test_policy_off_allows_without_calling_evaluator() -> None:
    policy = FakePolicy(decision=Decision.DENY)  # would DENY if consulted
    engine, ledger, _ = _engine(policy=policy)
    result = await engine.run(
        make_action(), Counter(), profile=GovernanceProfile(enforce_policy=False)
    )
    assert result.state is ActionState.COMPLETED
    assert policy.calls == 0  # evaluator never consulted


async def test_seal_off_completes_without_ledger_entry() -> None:
    engine, ledger, _ = _engine(policy=FakePolicy(decision=Decision.ALLOW))
    result = await engine.run(
        make_action(), Counter(), profile=GovernanceProfile(seal_to_ledger=False)
    )
    assert result.state is ActionState.COMPLETED
    assert len(ledger.sealed) == 0


async def test_emit_off_completes_without_event() -> None:
    engine, _ledger, events = _engine(policy=FakePolicy(decision=Decision.ALLOW))
    result = await engine.run(
        make_action(), Counter(), profile=GovernanceProfile(emit_events=False)
    )
    assert result.state is ActionState.COMPLETED
    assert events.emitted == []


async def test_identity_off_keeps_supplied_actor() -> None:
    engine, ledger, _ = _engine(
        policy=FakePolicy(decision=Decision.ALLOW), identity=_Identity("imposter")
    )
    result = await engine.run(
        make_action(),
        Counter(),
        context=RequestContext(),
        profile=GovernanceProfile(verify_identity=False),
    )
    assert result.state is ActionState.COMPLETED
    assert ledger.sealed[0].actor_id == ActorId("alice")  # not replaced by the identity port


async def test_identity_on_replaces_actor() -> None:
    engine, ledger, _ = _engine(
        policy=FakePolicy(decision=Decision.ALLOW), identity=_Identity("imposter")
    )
    await engine.run(make_action(), Counter(), context=RequestContext())  # default all() → verify
    assert ledger.sealed[0].actor_id == ActorId("imposter")


async def test_consent_off_skips_check() -> None:
    engine, _ledger, _ = _engine(
        policy=FakePolicy(decision=Decision.ALLOW), consent=_MissingConsent()
    )
    result = await engine.run(
        make_action(), Counter(), profile=GovernanceProfile(enforce_consent=False)
    )
    assert result.state is ActionState.COMPLETED  # consent missing but layer disabled


async def test_consent_on_denies_when_missing() -> None:
    engine, _ledger, _ = _engine(
        policy=FakePolicy(decision=Decision.ALLOW), consent=_MissingConsent()
    )
    result = await engine.run(make_action(), Counter())  # default all() → consent enforced
    assert result.state is ActionState.DENIED


async def test_consent_on_grants_when_active() -> None:
    engine, _ledger, _ = _engine(
        policy=FakePolicy(decision=Decision.ALLOW), consent=_GrantingConsent()
    )
    result = await engine.run(make_action(), Counter())
    assert result.state is ActionState.COMPLETED


async def test_require_approval_with_gate_disabled_denies() -> None:
    engine, _ledger, _ = _engine(policy=FakePolicy(decision=Decision.REQUIRE_APPROVAL))
    result = await engine.run(
        make_action(), Counter(), profile=GovernanceProfile(enforce_hitl_gate=False)
    )
    assert result.state is ActionState.DENIED  # approval required but gate disabled → fail-closed


# ── monitor() preset ──────────────────────────────────────────────────────────────


def test_monitor_preset_enforces_all_except_hitl_gate() -> None:
    p = GovernanceProfile.monitor()
    assert p.verify_identity
    assert p.enforce_consent
    assert p.enforce_policy
    assert not p.enforce_hitl_gate
    assert p.seal_to_ledger
    assert p.emit_events
    assert p.mask_pii
    assert p.enforce_model_allowlist


def test_monitor_preset_registered_in_presets() -> None:
    from quaicu.core.lifecycle.profile import resolve_preset
    p = resolve_preset("monitor")
    assert p == GovernanceProfile.monitor()
