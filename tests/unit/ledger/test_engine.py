"""Unit tests for TrustLedger (K·02 / quaicu/core/ledger/engine.py).

Covers: seal happy path, sequential seq numbers, tenant isolation, cross-tenant tree
independence, inclusion/consistency proof verification, failure wrapping, STH signing,
result/approver storage, leaf hash correctness, and concurrent safety.
"""

from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from quaicu.core.errors import LedgerSealError
from quaicu.core.ledger.engine import TrustLedger, _canonical_bytes
from quaicu.core.ledger.merkle import leaf_hash
from quaicu.core.ledger.signer import InMemoryEd25519Signer, SignedTreeHead
from quaicu.core.types import (
    Action,
    ActionId,
    ActionState,
    Actor,
    ActorId,
    ApproverRef,
    Decision,
    EvaluationResult,
    IdempotencyKey,
    LedgerEntry,
    TenantId,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _tenant(name: str = "alpha") -> TenantId:
    return TenantId(name)


def _actor(tenant: TenantId) -> Actor:
    return Actor(id=ActorId("actor-1"), tenant=tenant)


def _action(tenant: TenantId | None = None, action_type: str = "test.action") -> Action:
    t = tenant or _tenant()
    return Action(
        id=ActionId("act-001"),
        type=action_type,
        payload={},
        actor=_actor(t),
        tenant=t,
        idempotency_key=IdempotencyKey("idem-001"),
        state=ActionState.SEALING,
    )


def _evaluation(decision: Decision = Decision.ALLOW) -> EvaluationResult:
    return EvaluationResult(
        decision=decision,
        policy_versions=("v1.0",),
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


async def test_seal_returns_ledger_entry() -> None:
    ledger = TrustLedger()
    action = _action()
    evaluation = _evaluation()
    entry = await ledger.seal(action=action, evaluation=evaluation, recorded_result={})

    assert isinstance(entry, LedgerEntry)
    assert entry.ledger_seq == 0
    assert entry.leaf_hash != b""
    assert isinstance(entry.sealed_at, datetime)


async def test_seal_records_actor_roles() -> None:
    # ADR-0006: the actor's roles are sealed on the entry (and into the leaf) so role-gated
    # policies are point-in-time replayable.
    ledger = TrustLedger()
    t = _tenant()
    action = Action(
        id=ActionId("act-roles"),
        type="test.action",
        payload={},
        actor=Actor(id=ActorId("actor-1"), tenant=t, roles=("role:risk_head", "role:maker")),
        tenant=t,
        idempotency_key=IdempotencyKey("idem-roles"),
        state=ActionState.SEALING,
    )
    entry = await ledger.seal(action=action, evaluation=_evaluation(), recorded_result={})
    assert entry.actor_roles == ("role:risk_head", "role:maker")


async def test_sequential_seals_increment_seq() -> None:
    ledger = TrustLedger()
    t = _tenant()

    def _act(n: int) -> Action:
        return Action(
            id=ActionId(f"act-{n}"),
            type="test",
            payload={},
            actor=_actor(t),
            tenant=t,
            idempotency_key=IdempotencyKey(f"k{n}"),
        )

    e0 = await ledger.seal(action=_act(0), evaluation=_evaluation(), recorded_result={})
    e1 = await ledger.seal(action=_act(1), evaluation=_evaluation(), recorded_result={})
    assert e0.ledger_seq == 0
    assert e1.ledger_seq == 1


async def test_tenant_isolation() -> None:
    ledger = TrustLedger()
    alpha = _tenant("alpha")
    beta = _tenant("beta")

    action_alpha = _action(alpha)
    await ledger.seal(action=action_alpha, evaluation=_evaluation(), recorded_result={})

    # beta has no entries yet
    assert ledger._entries.get(beta) is None or len(ledger._entries[beta]) == 0

    # beta gets its own sequence starting at 0
    action_beta = Action(
        id=ActionId("beta-act-1"),
        type="test",
        payload={},
        actor=Actor(id=ActorId("actor-b"), tenant=beta),
        tenant=beta,
        idempotency_key=IdempotencyKey("b-k1"),
    )
    e_beta = await ledger.seal(action=action_beta, evaluation=_evaluation(), recorded_result={})
    assert e_beta.ledger_seq == 0


async def test_cross_tenant_tree_independence() -> None:
    """alpha's inclusion proof must not verify in beta's tree."""
    ledger = TrustLedger()
    alpha = _tenant("alpha")
    beta = _tenant("beta")

    a_act = _action(alpha)
    await ledger.seal(action=a_act, evaluation=_evaluation(), recorded_result={})

    b_act = Action(
        id=ActionId("b-act"),
        type="test",
        payload={},
        actor=Actor(id=ActorId("b-actor"), tenant=beta),
        tenant=beta,
        idempotency_key=IdempotencyKey("b-k"),
    )
    await ledger.seal(action=b_act, evaluation=_evaluation(), recorded_result={})

    # alpha's leaf hash and proof should not verify against beta's root
    alpha_lh, alpha_proof = ledger.get_inclusion_proof(alpha, 0)
    beta_sth = ledger.get_signed_tree_head(beta)

    beta_tree = ledger._trees[beta]
    # Trying to verify alpha's proof against beta's root should fail
    assert not beta_tree.verify_inclusion(0, alpha_lh, alpha_proof, beta_sth.root_hash)


async def test_inclusion_proof_verifies() -> None:
    ledger = TrustLedger()
    t = _tenant()
    action = _action(t)
    await ledger.seal(action=action, evaluation=_evaluation(), recorded_result={})

    sth = ledger.get_signed_tree_head(t)
    assert ledger.verify_inclusion(t, 0, sth)


async def test_consistency_proof_verifies() -> None:
    ledger = TrustLedger()
    t = _tenant()

    def _act(n: int) -> Action:
        return Action(
            id=ActionId(f"act-{n}"),
            type="test",
            payload={},
            actor=_actor(t),
            tenant=t,
            idempotency_key=IdempotencyKey(f"k{n}"),
        )

    for i in range(5):
        await ledger.seal(action=_act(i), evaluation=_evaluation(), recorded_result={})

    from quaicu.core.ledger.merkle import compute_root

    tree = ledger._trees[t]
    old_root = compute_root(list(tree._leaves[:3]))
    current_sth = ledger.get_signed_tree_head(t)

    from quaicu.core.ledger.signer import SignedTreeHead as STH

    old_sth = STH(
        tree_size=3,
        timestamp=current_sth.timestamp,
        root_hash=old_root,
        signature=b"",
        key_id="",
    )
    assert ledger.verify_consistency(t, old_sth, current_sth)


async def test_seal_failure_raises_ledger_seal_error() -> None:
    class _BrokenSigner:
        @property
        def key_id(self) -> str:
            return "broken"

        def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
            raise RuntimeError("vault unavailable")

        def verify(self, sth: SignedTreeHead) -> bool:
            return False

    ledger = TrustLedger(signer=_BrokenSigner())  # type: ignore[arg-type]
    action = _action()

    with pytest.raises(LedgerSealError):
        await ledger.seal(action=action, evaluation=_evaluation(), recorded_result={})


async def test_sth_is_signed() -> None:
    signer = InMemoryEd25519Signer()
    ledger = TrustLedger(signer=signer)
    t = _tenant()
    await ledger.seal(action=_action(t), evaluation=_evaluation(), recorded_result={})

    sth = ledger.get_signed_tree_head(t)
    assert signer.verify(sth)


async def test_recorded_result_stored_in_entry() -> None:
    ledger = TrustLedger()
    t = _tenant()
    result = {"status": "ok", "rows_affected": 5}
    entry = await ledger.seal(
        action=_action(t), evaluation=_evaluation(), recorded_result=result
    )
    assert entry.recorded_result == result


async def test_approver_stored_in_entry() -> None:
    ledger = TrustLedger()
    t = _tenant()
    approver = ApproverRef("role:risk_head")
    entry = await ledger.seal(
        action=_action(t),
        evaluation=_evaluation(Decision.REQUIRE_APPROVAL),
        recorded_result={},
        approver=approver,
    )
    assert entry.approver == approver


async def test_leaf_hash_in_entry() -> None:
    ledger = TrustLedger()
    t = _tenant()
    action = _action(t)
    evaluation = _evaluation()
    entry = await ledger.seal(
        action=action, evaluation=evaluation, recorded_result={}, approver=None
    )

    expected_bytes = _canonical_bytes(action, evaluation, {}, None)
    expected_lh = leaf_hash(expected_bytes)
    assert entry.leaf_hash == expected_lh


async def test_payload_is_covered_by_leaf_hash() -> None:
    """Two actions identical except for payload must produce different leaf hashes (#8)."""
    t = _tenant()
    evaluation = _evaluation()

    def _act(payload: dict) -> Action:
        return Action(
            id=ActionId("act-same"),
            type="test.action",
            payload=payload,
            actor=_actor(t),
            tenant=t,
            idempotency_key=IdempotencyKey("idem-same"),
            state=ActionState.SEALING,
        )

    lh_a = leaf_hash(_canonical_bytes(_act({"amount": 100}), evaluation, {}, None))
    lh_b = leaf_hash(_canonical_bytes(_act({"amount": 999}), evaluation, {}, None))
    assert lh_a != lh_b, "payload tampering must change the Merkle leaf"


async def test_non_dict_recorded_result_is_covered_by_leaf_hash() -> None:
    """A non-dict recorded_result must still be sealed (not coerced to {}) (#8)."""
    t = _tenant()
    evaluation = _evaluation()
    action = _action(t)

    lh_x = leaf_hash(_canonical_bytes(action, evaluation, "result-x", None))
    lh_y = leaf_hash(_canonical_bytes(action, evaluation, "result-y", None))
    assert lh_x != lh_y, "non-dict results must be covered by the leaf hash"


def test_governance_profile_is_covered_by_leaf_hash() -> None:
    """The enforced-layer list is sealed, so the same action under different profiles differs."""
    action = _action()
    eval_all = EvaluationResult(decision=Decision.ALLOW, metadata={"governance_profile": ["enforce_policy", "seal_to_ledger"]})
    eval_audit = EvaluationResult(decision=Decision.ALLOW, metadata={"governance_profile": ["seal_to_ledger"]})

    lh_a = leaf_hash(_canonical_bytes(action, eval_all, {}, None, None, ["enforce_policy", "seal_to_ledger"]))
    lh_b = leaf_hash(_canonical_bytes(action, eval_audit, {}, None, None, ["seal_to_ledger"]))
    assert lh_a != lh_b, "the enforced governance layers must be covered by the leaf"


async def test_concurrent_seals_are_safe() -> None:
    ledger = TrustLedger()
    t = _tenant()

    async def _seal(n: int) -> LedgerEntry:
        act = Action(
            id=ActionId(f"act-{n}"),
            type="test",
            payload={},
            actor=_actor(t),
            tenant=t,
            idempotency_key=IdempotencyKey(f"k{n}"),
        )
        return await ledger.seal(action=act, evaluation=_evaluation(), recorded_result={})

    entries = await asyncio.gather(*[_seal(i) for i in range(20)])

    seq_numbers = [e.ledger_seq for e in entries]
    assert sorted(seq_numbers) == list(range(20)), "all 20 entries must have distinct seq numbers"

    # Final tree must verify all entries.
    sth = ledger.get_signed_tree_head(t)
    for i in range(20):
        assert ledger.verify_inclusion(t, i, sth), f"entry {i} does not verify in final tree"
