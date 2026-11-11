"""Unit tests for the WS-F regulator ledger-proof export + its independent verifier."""

from __future__ import annotations

from datetime import datetime, timezone

from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.ledger.anchor import anchor_current_sth
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.signer import InMemoryEd25519Signer
from quaicu.core.regmap.export import (
    build_ledger_proof_bundle,
    trusted_keys_from_signer,
    verify_ledger_proof_bundle,
)
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    TenantId,
)

TENANT = TenantId("ciro-bank")


def _action(n: int) -> Action:
    return Action(
        id=ActionId(f"act-{n}"),
        type="loan.approve",
        payload={"amount": n},
        actor=Actor(id=ActorId("alice"), tenant=TENANT, roles=("role:maker",)),
        tenant=TENANT,
        idempotency_key=IdempotencyKey(f"idem-{n}"),
        state=ActionState.SEALING,
    )


async def _ledger_with(n: int) -> TrustLedger:
    ledger = TrustLedger()
    for i in range(n):
        await ledger.seal(
            action=_action(i),
            evaluation=EvaluationResult(decision=Decision.ALLOW, policy_versions=("v1.0",)),
            recorded_result={},
        )
    return ledger


def _export(ledger: TrustLedger, **kwargs) -> dict:
    entries = ledger.get_entries(TENANT)
    entries_with_paths = [(e, ledger.get_inclusion_proof(TENANT, e.ledger_seq)[1]) for e in entries]
    bundle = build_ledger_proof_bundle(
        tenant_id=str(TENANT),
        window_start=entries[0].sealed_at,
        window_end=entries[-1].sealed_at,
        entries_with_paths=entries_with_paths,
        sth=ledger.get_signed_tree_head(TENANT),
        public_key_pem=ledger._signer.public_key_pem,  # type: ignore[attr-defined]
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v1.0"],
        **kwargs,
    )
    return bundle.to_dict()


def _pin(ledger: TrustLedger) -> dict[str, str]:
    """The pinned trust anchor (key_id → PEM) for this ledger's signer."""
    return trusted_keys_from_signer(ledger._signer)  # type: ignore[attr-defined]


# ── Happy path ──────────────────────────────────────────────────────────────────


async def test_export_verifies_clean():
    ledger = await _ledger_with(5)
    bundle = _export(ledger)
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert ok, errors
    assert len(bundle["inclusion_proofs"]) == 5
    assert bundle["evidence"]["verifiable"] is True
    assert bundle["evidence"]["manifest"]["action_count"] == 5


async def test_single_entry_export_verifies():
    ledger = await _ledger_with(1)
    ok, errors = verify_ledger_proof_bundle(_export(ledger), trusted_keys=_pin(ledger))
    assert ok, errors


# ── Key pinning (D3-1) ───────────────────────────────────────────────────────────


async def test_no_trust_anchor_fails_closed():
    ledger = await _ledger_with(2)
    ok, errors = verify_ledger_proof_bundle(_export(ledger))  # no trusted_keys
    assert not ok
    assert any("no pinned trust anchor" in e for e in errors)


async def test_forged_key_is_rejected():
    # Re-sign the same root with an attacker key and swap in its key_id + embedded PEM. The bundle is
    # self-consistent, but its key_id is not in the pinned anchor → rejected.
    ledger = await _ledger_with(3)
    bundle = _export(ledger)
    forger = InMemoryEd25519Signer()
    sth = bundle["signed_tree_head"]
    fsth = forger.sign(int(sth["tree_size"]), bytes.fromhex(sth["root_hash_hex"]),
                       datetime.now(tz=timezone.utc))
    sth["signature_hex"] = fsth.signature.hex()
    sth["key_id"] = forger.key_id
    sth["public_key_pem"] = forger.public_key_pem

    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert not ok
    assert any("not in the pinned trust anchor" in e for e in errors)


async def test_swapped_embedded_key_is_rejected():
    # Keep the genuine key_id + signature but swap the embedded PEM to another key — a tamper signal.
    ledger = await _ledger_with(2)
    bundle = _export(ledger)
    bundle["signed_tree_head"]["public_key_pem"] = InMemoryEd25519Signer().public_key_pem
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert not ok
    assert any("does not match the pinned key" in e for e in errors)


async def test_wrong_pinned_pem_fails_signature():
    # Correct key_id pinned, but to the WRONG public key (and no embedded key to short-circuit) →
    # the signature does not verify against the pinned key.
    ledger = await _ledger_with(2)
    bundle = _export(ledger)
    bundle["signed_tree_head"]["public_key_pem"] = None
    wrong = {ledger._signer.key_id: InMemoryEd25519Signer().public_key_pem}  # type: ignore[attr-defined]
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=wrong)
    assert not ok
    assert any("signature does not verify against the pinned key" in e for e in errors)


async def test_missing_embedded_key_still_verifies_against_pin():
    # Authenticity now comes from the pinned key, not the embedded one — so an omitted embedded key
    # is fine as long as the pinned key verifies the signature.
    ledger = await _ledger_with(2)
    bundle = _export(ledger)
    bundle["signed_tree_head"]["public_key_pem"] = None
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert ok, errors


# ── Anchoring / witness (D3-2) ────────────────────────────────────────────────────


async def _anchored_export(ledger: TrustLedger, witness: SoftwareWitness) -> dict:
    entries = ledger.get_entries(TENANT)
    ewp = [(e, ledger.get_inclusion_proof(TENANT, e.ledger_seq)[1]) for e in entries]
    cosig = anchor_current_sth(ledger, witness, TENANT)
    bundle = build_ledger_proof_bundle(
        tenant_id=str(TENANT),
        window_start=entries[0].sealed_at,
        window_end=entries[-1].sealed_at,
        entries_with_paths=ewp,
        sth=ledger.get_signed_tree_head(TENANT),
        public_key_pem=ledger._signer.public_key_pem,  # type: ignore[attr-defined]
        witness_cosignature=cosig,
    )
    return bundle.to_dict()


async def test_anchored_bundle_verifies_with_pinned_witness():
    ledger = await _ledger_with(3)
    witness = SoftwareWitness()
    bundle = await _anchored_export(ledger, witness)
    pins = {witness.witness_id: witness.public_key_pem}
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger), trusted_witnesses=pins)
    assert ok, errors


async def test_anchoring_skipped_when_no_witness_pinned():
    # Without trusted_witnesses, integrity+authenticity still verify (anchoring simply not checked).
    ledger = await _ledger_with(2)
    bundle = await _anchored_export(ledger, SoftwareWitness())
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert ok, errors


async def test_unpinned_witness_rejected():
    ledger = await _ledger_with(2)
    bundle = await _anchored_export(ledger, SoftwareWitness())
    other = {SoftwareWitness().witness_id: SoftwareWitness().public_key_pem}
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger), trusted_witnesses=other)
    assert not ok
    assert any("not in the pinned witness set" in e for e in errors)


async def test_anchor_attesting_wrong_head_rejected():
    ledger = await _ledger_with(2)
    witness = SoftwareWitness()
    bundle = await _anchored_export(ledger, witness)
    bundle["anchor"]["root_hash_hex"] = "00" * 32  # cosig now attests a different root
    pins = {witness.witness_id: witness.public_key_pem}
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger), trusted_witnesses=pins)
    assert not ok
    assert any("different tree head" in e or "does not verify" in e for e in errors)


async def test_missing_anchor_fails_when_witness_pinned():
    ledger = await _ledger_with(2)
    bundle = _export(ledger)  # no witness cosignature
    ok, errors = verify_ledger_proof_bundle(
        bundle, trusted_keys=_pin(ledger), trusted_witnesses={"witness:x": "pem"}
    )
    assert not ok
    assert any("no witness cosignature" in e for e in errors)


# ── Tamper detection ─────────────────────────────────────────────────────────────


async def test_tampered_leaf_fails_verification():
    ledger = await _ledger_with(4)
    bundle = _export(ledger)
    # Flip a byte in one leaf hash — the recomputed root no longer matches the signed root.
    bad = bundle["inclusion_proofs"][1]["leaf_hash_hex"]
    bundle["inclusion_proofs"][1]["leaf_hash_hex"] = ("f" if bad[0] != "f" else "0") + bad[1:]
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert not ok
    assert any("does not match the signed root" in e for e in errors)


async def test_tampered_signature_fails_verification():
    ledger = await _ledger_with(3)
    bundle = _export(ledger)
    sig = bundle["signed_tree_head"]["signature_hex"]
    bundle["signed_tree_head"]["signature_hex"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert not ok
    assert any("signature does not verify" in e for e in errors)


async def test_tampered_root_fails_verification():
    ledger = await _ledger_with(3)
    bundle = _export(ledger)
    root = bundle["signed_tree_head"]["root_hash_hex"]
    bundle["signed_tree_head"]["root_hash_hex"] = ("0" if root[0] != "0" else "1") + root[1:]
    ok, _ = verify_ledger_proof_bundle(bundle, trusted_keys=_pin(ledger))
    assert not ok  # both the proofs and the signature now disagree with the altered root


async def test_malformed_bundle_fails_gracefully():
    ok, errors = verify_ledger_proof_bundle({"nonsense": True})
    assert not ok
    assert errors
