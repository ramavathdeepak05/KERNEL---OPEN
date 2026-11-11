"""Proof-only RFC 6962 §2.1.4 consistency verifier (D3-2) — verifies from STHs alone (no leaves)."""

from __future__ import annotations

import os

from quaicu.core.ledger.merkle import (
    _consistency_proof,
    compute_root,
    leaf_hash,
    verify_consistency_proof,
)


def _leaves(n: int) -> list[bytes]:
    return [leaf_hash(bytes([i % 256]) + os.urandom(4)) for i in range(n)]


def test_roundtrip_all_sizes_verify():
    # Every (old_size m ≤ new_size n) with a genuine proof must verify from roots alone.
    for n in range(1, 33):
        leaves = _leaves(n)
        new_root = compute_root(leaves)
        for m in range(1, n + 1):
            proof = _consistency_proof(m, leaves)
            old_root = compute_root(leaves[:m])
            assert verify_consistency_proof(m, old_root, n, new_root, proof), f"n={n} m={m}"


def test_edge_cases():
    leaves = _leaves(5)
    root = compute_root(leaves)
    # equal sizes: proof empty, roots equal
    assert verify_consistency_proof(5, root, 5, root, [])
    assert not verify_consistency_proof(5, root, 5, compute_root(_leaves(5)), [])
    # empty old tree is consistent with anything (empty proof)
    assert verify_consistency_proof(0, b"", 5, root, [])
    # old_size > new_size is impossible (a rewind) → reject
    assert not verify_consistency_proof(5, root, 3, compute_root(leaves[:3]), _consistency_proof(3, leaves))


def test_tampered_new_root_rejected():
    leaves = _leaves(8)
    new_root = compute_root(leaves)
    for m in range(1, 8):
        proof = _consistency_proof(m, leaves)
        old_root = compute_root(leaves[:m])
        bad = bytes([new_root[0] ^ 0xFF]) + new_root[1:]
        assert not verify_consistency_proof(m, old_root, 8, bad, proof)


def test_forked_history_rejected():
    # Two size-5 trees that share only a 3-leaf prefix: a proof for the shared prefix must NOT verify
    # the fork as an extension of the OTHER tree (split-view detection).
    base = _leaves(3)
    a = base + _leaves(2)
    b = base + _leaves(2)  # different tail
    proof_for_b = _consistency_proof(3, b)
    # b genuinely extends base[:3]:
    assert verify_consistency_proof(3, compute_root(base), 5, compute_root(b), proof_for_b)
    # but the same proof must not verify `a` (a divergent size-5 tree) as an extension of base:
    assert not verify_consistency_proof(3, compute_root(base), 5, compute_root(a), proof_for_b)
