#!/usr/bin/env python3
"""QUAICU underwriting demo — the 10-minute "governed → gated → sealed → verify" story.

Runs a credit-underwriting assistant with a human approval gate end-to-end, in one process, with
ZERO external services:

  1. a low-risk credit draft           → policy ALLOWS  → executed → sealed to the K·02 ledger
  2. a high-risk credit draft          → policy REQUIRES APPROVAL → routed to the HITL queue →
                                          a human (role:risk_head) approves → executed → sealed
                                          (the approver's identity is sealed into the entry)
  3. an over-limit credit draft        → policy DENIES (fail-closed) → NOT executed
  4. export a regulator proof bundle of the sealed actions and **verify it offline** — the exact
     check a regulator runs, independent of QUAICU (RFC-6962 inclusion proofs + an Ed25519-signed
     tree head).

Everything below is *assembly of already-built kernel surfaces* — the CEL policy engine (K·01), the
in-process HITL gate (K·03), the RFC-6962 TrustLedger (K·02) with a software Ed25519 signer, and the
WS-F proof export + offline verifier. No new core logic.

    python examples/underwriting-demo/demo.py
"""

from __future__ import annotations

import asyncio
import sys
import tomllib
from pathlib import Path

# Emojis/arrows in the narrative need a UTF-8 stream (Windows consoles default to cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

# Make the kernel importable when run directly (repo root = two levels up from this file).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from quaicu.adapters.events.memory import InMemoryEventBusAdapter  # noqa: E402
from quaicu.adapters.ledger.memory_signed import MemorySignedLedgerAdapter  # noqa: E402
from quaicu.core.errors import LifecycleDeniedError, LifecyclePendingApprovalError  # noqa: E402
from quaicu.core.hitl.engine import InProcessHITLPort  # noqa: E402
from quaicu.core.lifecycle.engine import LifecycleEngine  # noqa: E402
from quaicu.core.lifecycle.profile import GovernanceProfile  # noqa: E402
from quaicu.core.policy import PolicyEngine, PolicyEnvelope, PolicyStore  # noqa: E402
from quaicu.core.policy.model import PolicyLifecycle  # noqa: E402
from quaicu.core.types import Actor, ActorId, ApproverRef, Decision, TenantId  # noqa: E402
from quaicu.delivery.sdk.kernel import Kernel, _InMemoryActionRepository  # noqa: E402

_CONFIG = Path(__file__).resolve().parent / "kernel.demo.toml"

# The human approver who clears the HITL queue (distinct from the proposing agent — separation of
# duties is enforced by the kernel, which forbids self-approval).
APPROVER = Actor(id=ActorId("risk_head"), tenant=TenantId("demo-bank"), roles=("role:risk_head",))


def _rupees(paise_or_amount: int) -> str:
    return f"INR {paise_or_amount:,}"


def _load_seeds(cfg_path: Path) -> list[PolicyEnvelope]:
    """Build ACTIVATED PolicyEnvelopes from the [[policy.seed]] entries in the demo config.

    Mirrors `Kernel._seed_policies` so the script and the config-driven console path enforce the
    identical policy set from a single source of truth (kernel.demo.toml).
    """
    with open(cfg_path, "rb") as f:
        cfg = tomllib.load(f)
    envelopes: list[PolicyEnvelope] = []
    for s in cfg.get("policy", {}).get("seed", []):
        envelopes.append(
            PolicyEnvelope(
                id=str(s["id"]),
                version=int(s.get("version", 1)),
                governs=str(s.get("governs", "*")),
                scope={"tenant": str(s.get("tenant", "*"))},
                condition=str(s["condition"]),
                decision=Decision(str(s["decision"]).lower()),
                approvers=tuple(ApproverRef(str(a)) for a in s.get("approvers", [])),
                regulatory_refs=tuple(str(r) for r in s.get("regulatory_refs", [])),
                lifecycle=PolicyLifecycle.ACTIVATED,
            )
        )
    return envelopes


def _build_kernel(hitl: InProcessHITLPort, ledger: MemorySignedLedgerAdapter) -> Kernel:
    """Assemble a demo kernel whose HITL gate is cleared by an automatic 'human' approval.

    The `poll_wait` callback models the real product flow: the action pauses in PENDING_APPROVAL, the
    risk officer reviews the queue and approves, and the lifecycle then resumes to execute + seal.
    """
    store = PolicyStore()
    for env in _load_seeds(_CONFIG):
        store.register(env)

    async def approve_pending() -> None:
        # Called by the lifecycle's bounded poll loop while an action waits for a human. In this demo
        # there is exactly one pending request at a time.
        for record in hitl.list_pending():
            print(f"      👤 risk officer reviews the queue → APPROVES {record.handle_id}")
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
        max_poll_attempts=2,          # poll → (approve in poll_wait) → poll again → APPROVED
        poll_wait=approve_pending,
    )
    return Kernel(engine=engine, tenant=TenantId("demo-bank"), policy_store=store)


async def main() -> int:
    print("=" * 78)
    print("QUAICU — credit-underwriting assist (HITL-gated)  ·  governed → gated → sealed → verify")
    print("=" * 78)

    hitl = InProcessHITLPort()
    ledger = MemorySignedLedgerAdapter()
    kernel = _build_kernel(hitl, ledger)
    tenant = kernel.tenant

    # The "agent": an internal underwriting assistant that drafts a credit decision. Each call is a
    # governed `credit.approve` action; the kernel decides allow / require-approval / deny.
    @kernel.guard(policy="credit.approve")
    async def draft_credit_decision(*, applicant: str, amount: int) -> dict:
        return {"applicant": applicant, "amount": amount, "decision": "approved", "by": "ai-underwriter"}

    async with kernel.actor_context("agent:underwriter"):
        # 1 ─ low-risk draft → auto-approved by policy → sealed.
        print(f"\n[1] Low-risk draft  · {_rupees(250_000)}  (applicant: A. Sharma)")
        result = await draft_credit_decision(applicant="A. Sharma", amount=250_000)
        print(f"      ✅ ALLOWED by policy → executed → sealed.  result={result['decision']}")

        # 2 ─ high-risk draft → require_approval → HITL queue → human approves → sealed.
        print(f"\n[2] High-risk draft · {_rupees(7_500_000)}  (applicant: K. Rao)")
        print("      ⏸  policy → REQUIRE_APPROVAL — routed to the HITL queue (fail-closed gate)…")
        try:
            await draft_credit_decision(applicant="K. Rao", amount=7_500_000)
            print("      ⚠️  UNEXPECTED: high-risk draft executed without approval")
            return 1
        except LifecyclePendingApprovalError as pending:
            # Not a failure: the action is suspended, waiting for a human. Nothing has executed.
            handle_id = pending.detail["handle_id"]
        print(f"      👤 risk officer reviews the queue → APPROVES {handle_id}")
        await kernel.approve(handle_id, actor=APPROVER)
        print("      ▶  approved → executed → sealed, with the approver's identity.")

        # 3 ─ over-limit draft → hard DENY → never executes.
        print(f"\n[3] Over-limit draft · {_rupees(60_000_000)}  (applicant: Acme Corp)")
        try:
            await draft_credit_decision(applicant="Acme Corp", amount=60_000_000)
            print("      ⚠️  UNEXPECTED: over-limit draft was not denied")
            return 1
        except LifecycleDeniedError:
            print("      ⛔ DENIED by policy (fail-closed) — the AI's decision did NOT execute.")

    # 4 ─ export the regulator proof bundle and verify it OFFLINE.
    print("\n[4] Regulator proof bundle")
    bundle = kernel.export_ledger_proof(tenant)
    bundle_dict = bundle.to_dict() if hasattr(bundle, "to_dict") else bundle
    seals = len(bundle_dict.get("inclusion_proofs", []))
    print(f"      📦 exported {seals} sealed action(s) with RFC-6962 inclusion proofs + a signed STH.")

    from quaicu.core.regmap.export import trusted_keys_from_signer, verify_ledger_proof_bundle

    # The verifier trusts only a signing key it pinned beforehand, never the key carried in the
    # bundle. A regulator records the key once (GET /v1/ledger/signing-key); here we pin it directly.
    pinned = trusted_keys_from_signer(ledger._signer)
    ok, errors = verify_ledger_proof_bundle(bundle_dict, trusted_keys=pinned)
    if ok:
        print("      🔍 verify_ledger_proof_bundle() → ✅ VERIFIED offline, independent of QUAICU.")
        print("\n" + "=" * 78)
        print("Done. Mathematical proof of what the AI did, under which policy, approved by whom.")
        print("=" * 78)
        return 0
    print(f"      ❌ verification FAILED: {errors}")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
