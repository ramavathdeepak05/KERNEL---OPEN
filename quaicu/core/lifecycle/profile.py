"""GovernanceProfile — composable, per-call enforcement of governance layers.

Each governed action (including a model call) runs through a configurable set of layers. A
profile declares which layers are enforced. The same action type can run under different profiles
in different deployments — "full lifecycle" and "gateway-only" are simply two presets, not a fork.

Design rules:
- Fail-closed *within* an enabled layer is unchanged (e.g. if policy is enforced and errors → DENY).
- Disabling a layer is an explicit, recorded configuration decision — the set of enabled layers is
  sealed into the ledger leaf (when sealing is itself enabled) so an auditor can see what ran.
- The default is ``all()`` — everything on — so omitting a profile preserves maximal governance.

Offline assurance sweeps (drift K·10, fairness K·09, sandbox K·13) are NOT per-call layers and are
intentionally absent here.
"""

from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True)
class GovernanceProfile:
    """Declares which governance layers are enforced for an action.

    Engine-owned layers run inside ``LifecycleEngine.run``; gateway sub-layers run inside
    ``AIGateway.generate`` for inference actions. A field set to ``False`` skips that layer.
    """

    # ── Engine-owned layers ───────────────────────────────────────────────────
    verify_identity: bool = True
    enforce_consent: bool = True
    enforce_policy: bool = True
    enforce_hitl_gate: bool = True
    seal_to_ledger: bool = True
    emit_events: bool = True

    # ── Gateway sub-layers (apply to inference actions) ───────────────────────
    enforce_model_allowlist: bool = True
    mask_pii: bool = True
    log_prompts: bool = True
    enforce_budget: bool = True

    def enabled_layers(self) -> tuple[str, ...]:
        """The names of the enabled layers, in declaration order — recorded in the sealed leaf."""
        return tuple(f.name for f in fields(self) if getattr(self, f.name))

    # ── Presets ────────────────────────────────────────────────────────────────

    @classmethod
    def all(cls) -> "GovernanceProfile":
        """Every layer on — the default, maximal-governance posture."""
        return cls()

    @classmethod
    def standard(cls) -> "GovernanceProfile":
        """Identity + policy + HITL + seal + emit + all gateway protections; consent off."""
        return cls(enforce_consent=False)

    @classmethod
    def gateway_only(cls) -> "GovernanceProfile":
        """Gateway protections only (allowlist/mask/log/budget). No policy, HITL, seal, or emit.

        Identity is still verified when a port/context is available. This is the lightweight
        inference posture: protect the call without policy-gating or sealing it to the ledger.
        """
        return cls(
            enforce_consent=False,
            enforce_policy=False,
            enforce_hitl_gate=False,
            seal_to_ledger=False,
            emit_events=False,
        )

    @classmethod
    def audit_only(cls) -> "GovernanceProfile":
        """Record without gating: no policy/consent/HITL, but seal + emit are on."""
        return cls(
            enforce_consent=False,
            enforce_policy=False,
            enforce_hitl_gate=False,
        )

    @classmethod
    def monitor(cls) -> "GovernanceProfile":
        """Evaluate + record every decision, but never block on a HITL gate.

        Designed for ``LifecycleEngine.decide`` / ``Kernel.check``: full identity + consent +
        policy evaluation, sealed to the ledger (tamper-evident monitoring), but no HITL gating
        (gating is meaningless for a pure decision query). Gateway sub-layers are on so model-call
        authorizations also have allowlist/PII/budget checks.
        """
        return cls(enforce_hitl_gate=False)


# Module-level preset lookup used by config (`[governance].default`, action_profiles).
PRESETS: dict[str, GovernanceProfile] = {
    "all": GovernanceProfile.all(),
    "standard": GovernanceProfile.standard(),
    "gateway_only": GovernanceProfile.gateway_only(),
    "audit_only": GovernanceProfile.audit_only(),
    "monitor": GovernanceProfile.monitor(),
}


def resolve_preset(name: str) -> GovernanceProfile:
    """Return a named preset, or raise ValueError listing the valid names."""
    try:
        return PRESETS[name]
    except KeyError:
        raise ValueError(
            f"Unknown governance profile {name!r}. Available: {sorted(PRESETS)}"
        ) from None
