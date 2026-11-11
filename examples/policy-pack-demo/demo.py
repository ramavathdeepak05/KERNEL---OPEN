#!/usr/bin/env python3
"""QUAICU regulated-FS demo — the SHIPPED policy packs governing a demo tenant.

Unlike the underwriting demo (which ships a bespoke `credit.approve` policy), this loads the **real,
in-the-box** policy packs an India FS customer would adopt — **RBI FREE-AI · DPDP · EU AI Act** — into a
demo tenant ("demo-nbfc"), then runs realistic governed actions through the kernel exactly as they would
flow in production:

  • RBI   — store / transfer regulated data, engage an outsourcer, grant access
  • DPDP  — process / transfer personal data
  • EU AI Act — invoke an AI system, generate content

Each action is decided by the **actual pack CEL** (allow / deny / require-approval), high-risk ones wait
for a human approver, and every executed decision is sealed to the K·02 ledger → exported → **verified
offline**. Zero external services.

    python examples/policy-pack-demo/demo.py

The packs are loaded straight from `quaicu/policy_packs/{rbi,dpdp,eu-ai-act}/` via `quaicu.core.policy.packs`
(the same loader the live `POST /v1/policy-packs/{id}/import` uses) — so what you see enforced here is
the same content `POST /v1/policy-packs/<id>/import` registers.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from quaicu.adapters.events.memory import InMemoryEventBusAdapter  # noqa: E402
from quaicu.adapters.ledger.memory_signed import MemorySignedLedgerAdapter  # noqa: E402
from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.lifecycle.engine import LifecycleEngine  # noqa: E402
from quaicu.core.lifecycle.profile import GovernanceProfile  # noqa: E402
from quaicu.core.policy import PolicyEngine, PolicyEnvelope, PolicyStore  # noqa: E402
from quaicu.core.policy import packs as packs_mod  # noqa: E402
from quaicu.core.policy.model import PolicyLifecycle  # noqa: E402
from quaicu.core.regmap.export import (  # noqa: E402
    trusted_keys_from_signer,
    verify_ledger_proof_bundle,
)
from quaicu.core.types import (  # noqa: E402
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    IdempotencyKey,
    TenantId,
)
from quaicu.delivery.sdk.kernel import Kernel, _InMemoryActionRepository  # noqa: E402

TENANT = TenantId("demo-nbfc")
PACKS = ("rbi", "dpdp", "eu-ai-act")

# A single officer who can clear any of the packs' approval gates (compliance / CRO / DPO /
# compliance_officer). The proposing agent is a different actor, so separation-of-duties holds.
APPROVER = Actor(
    id=ActorId("compliance-officer"),
    tenant=TENANT,
    roles=("role:compliance", "role:cro", "role:dpo", "role:compliance_officer"),
)
AGENT = Actor(id=ActorId("agent:ops-assistant"), tenant=TENANT, roles=("role:agent",))


def _load_packs_into_store() -> tuple[PolicyStore, int]:
    """Register every policy from the shipped RBI/DPDP/EU-AI-Act packs as an ACTIVATED policy.

    Uses `core.policy.packs.get_pack` — the same loader behind the live `/v1/policy-packs` API — so the
    demo enforces the real, in-the-box pack content (not a hand-written copy).
    """
    store = PolicyStore()
    count = 0
    for pack_id in PACKS:
        pack = packs_mod.get_pack(pack_id)
        if pack is None:
            raise SystemExit(f"pack {pack_id!r} not found under quaicu/policy_packs/")
        for p in pack.policies:
            store.register(
                PolicyEnvelope(
                    id=p.id,
                    version=1,
                    governs=p.governs,
                    scope={"tenant": "*"},
                    condition=p.condition,
                    decision=Decision(p.decision.lower()),
                    approvers=tuple(ApproverRef(a) for a in p.approvers),
                    regulatory_refs=tuple(p.regulatory_refs),
                    lifecycle=PolicyLifecycle.ACTIVATED,
                )
            )
            count += 1
    return store, count


def _build_kernel(store: PolicyStore, hitl: InProcessHITLPort, ledger: MemorySignedLedgerAdapter) -> Kernel:
    async def approve_pending() -> None:
        for record in hitl.list_pending():
            await hitl.approve(
                record.handle_id,
                approver_actor_id=APPROVER.id,
                approver_roles=APPROVER.roles,
            )

    engine = LifecycleEngine(
        repository=_InMemoryActionRepository(),
        policy=PolicyEngine(store),
        hitl=hitl,
        ledger=ledger,
        events=InMemoryEventBusAdapter(),
        default_profile=GovernanceProfile.all(),
        max_poll_attempts=2,
        poll_wait=approve_pending,
    )
    return Kernel(engine=engine, tenant=TENANT, policy_store=store)


# (regime, action_type, label, payload, expected outcome) — payloads honor each pack's payload contract.
_SCENARIOS: list[tuple[str, str, str, dict, ActionState]] = [
    # ── RBI FREE-AI ──────────────────────────────────────────────────────────
    ("RBI", "data.store", "store KYC data in India, encrypted",
     {"data_class": "kyc", "storage_region": "IN", "encryption_at_rest": True}, ActionState.COMPLETED),
    ("RBI", "data.store", "store PAYMENT data outside India",
     {"data_class": "payment", "storage_region": "SG", "encryption_at_rest": True}, ActionState.DENIED),
    ("RBI", "data.transfer", "transfer regulated data cross-border (→ SG)",
     {"destination_country": "SG"}, ActionState.COMPLETED),  # require_approval → approved → sealed
    ("RBI", "outsourcing.engage", "engage a MATERIAL outsourcer (audit rights + exit plan)",
     {"material": True, "audit_rights": True, "exit_plan": True}, ActionState.COMPLETED),
    ("RBI", "outsourcing.engage", "engage an outsourcer with NO right-to-audit",
     {"material": True, "audit_rights": False, "exit_plan": True}, ActionState.DENIED),
    ("RBI", "access.grant", "grant access with NO audit logging",
     {"access_logged": False}, ActionState.DENIED),
    # ── DPDP ─────────────────────────────────────────────────────────────────
    ("DPDP", "personal_data.process", "process personal data (consent ✓, purpose=kyc)",
     {"consent_obtained": True, "purpose": "kyc", "subject_erased": False}, ActionState.COMPLETED),
    ("DPDP", "personal_data.process", "process personal data with NO consent",
     {"consent_obtained": False, "purpose": "kyc", "subject_erased": False}, ActionState.DENIED),
    ("DPDP", "personal_data.transfer", "transfer personal data cross-border (→ US)",
     {"destination_country": "US"}, ActionState.COMPLETED),  # require_approval → approved → sealed
    # ── EU AI Act ────────────────────────────────────────────────────────────
    ("EU-AI-Act", "ai_system.invoke", "invoke a limited-risk AI (oversight ✓, discloses ✓)",
     {"risk_category": "limited", "use_case": "fraud_detection", "human_oversight": True,
      "discloses_ai": True}, ActionState.COMPLETED),
    ("EU-AI-Act", "ai_system.invoke", "invoke a PROHIBITED-risk AI",
     {"risk_category": "prohibited", "use_case": "social_scoring", "human_oversight": True,
      "discloses_ai": True}, ActionState.DENIED),
    ("EU-AI-Act", "ai_system.invoke", "invoke a HIGH-risk AI with NO human oversight",
     {"risk_category": "high", "use_case": "credit_scoring", "human_oversight": False,
      "discloses_ai": True}, ActionState.COMPLETED),  # require_approval → approved → sealed
]

_ICON = {ActionState.COMPLETED: "✅ sealed", ActionState.DENIED: "⛔ DENIED (fail-closed)"}


async def _govern(kernel: Kernel, action_type: str, payload: dict) -> ActionState:
    action = Action(
        id=ActionId(str(uuid.uuid4())),
        type=action_type,
        payload=payload,
        actor=AGENT,
        tenant=TENANT,
        idempotency_key=IdempotencyKey(str(uuid.uuid4())),
        proposed_at=datetime.now(tz=timezone.utc),
    )

    async def execute_fn() -> dict:
        return {"executed": True, "action_type": action_type}

    final = await kernel.engine.run(action, execute_fn)
    return final.state


async def main() -> int:
    print("=" * 88)
    print("QUAICU — regulated-FS demo · SHIPPED packs (RBI FREE-AI · DPDP · EU AI Act) on tenant 'demo-nbfc'")
    print("=" * 88)

    store, n = _load_packs_into_store()
    print(f"\nLoaded {n} policies from the shipped packs {list(PACKS)} (ACTIVATED for this demo).\n")

    hitl = InProcessHITLPort()
    ledger = MemorySignedLedgerAdapter()
    kernel = _build_kernel(store, hitl, ledger)

    ok = True
    current = ""
    for regime, action_type, label, payload, expected in _SCENARIOS:
        if regime != current:
            print(f"── {regime} " + "─" * (84 - len(regime)))
            current = regime
        state = await _govern(kernel, action_type, payload)
        verdict = _ICON.get(state, state.value)
        note = "" if state == expected else f"  ⚠️ EXPECTED {expected.value}"
        if state != expected:
            ok = False
        print(f"  {action_type:<22} {label:<48} → {verdict}{note}")

    print("\n── Regulator proof bundle " + "─" * 62)
    bundle = kernel.export_ledger_proof(TENANT)
    bundle = bundle.to_dict() if hasattr(bundle, "to_dict") else bundle
    seals = len(bundle.get("inclusion_proofs", []))
    # The verifier trusts only a signing key it pinned beforehand, never the key carried in the
    # bundle. A regulator records the key once; here we pin it directly from the ledger's signer.
    verified, errors = verify_ledger_proof_bundle(
        bundle, trusted_keys=trusted_keys_from_signer(ledger._signer)
    )
    print(f"  📦 {seals} sealed action(s) exported (denials are blocked, not sealed).")
    if verified:
        print("  🔍 verify_ledger_proof_bundle() → ✅ VERIFIED offline, independent of QUAICU.")
    else:
        print(f"  ❌ verification FAILED: {errors}")
        ok = False

    print("\n" + "=" * 88)
    print("Done. The shipped RBI/DPDP/EU-AI-Act packs governed a real action stream — allowed, denied,")
    print("routed to a human, and sealed to an offline-verifiable ledger. No code per policy; just config.")
    print("=" * 88)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
