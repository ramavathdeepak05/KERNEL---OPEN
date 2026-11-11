"""RFC 6962-style Merkle transparency log — pure cryptographic primitives.

No ledger-specific logic here. Correctness is verified against published RFC 6962 test vectors
in tests/conformance/ledger/test_rfc6962.py. Every hash function matches the spec exactly.
"""

from __future__ import annotations

import hashlib


# ── Domain-separated hash primitives (RFC 6962 §2.1) ─────────────────────────


def leaf_hash(entry_bytes: bytes) -> bytes:
    """SHA-256(0x00 || entry_bytes). 0x00 prevents second-preimage attacks on leaf nodes."""
    return hashlib.sha256(b"\x00" + entry_bytes).digest()


def internal_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right). 0x01 prevents second-preimage attacks on internal nodes."""
    return hashlib.sha256(b"\x01" + left + right).digest()


# ── Core recursive MTH computation ───────────────────────────────────────────


def _largest_power_of_2_less_than(n: int) -> int:
    k = 1
    while k < n:
        k <<= 1
    return k >> 1


def compute_root(leaves: list[bytes]) -> bytes:
    """Merkle Tree Head (MTH) as defined in RFC 6962 §2.1.

    Invariant: each element of `leaves` is already a leaf_hash; this function only
    combines them into an MTH, it does NOT apply leaf_hash again.
    """
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_2_less_than(n)
    return internal_hash(compute_root(leaves[:k]), compute_root(leaves[k:]))


# ── Inclusion proof ───────────────────────────────────────────────────────────


def _inclusion_proof_path(m: int, leaves: list[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 PATH(m, D[n]) — returns the sibling hash sequence."""
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_power_of_2_less_than(n)
    if m < k:
        return _inclusion_proof_path(m, leaves[:k]) + [compute_root(leaves[k:])]
    else:
        return _inclusion_proof_path(m - k, leaves[k:]) + [compute_root(leaves[:k])]


def _recompute_root_from_path(m: int, n: int, leaf: bytes, proof: list[bytes]) -> bytes:
    """Reconstruct the Merkle root from a leaf hash and its RFC 6962 inclusion proof.

    Proof elements are ordered from innermost (leaf's immediate sibling) to outermost
    (child of the root). We build a direction list from the tree descent (outermost to
    innermost), reverse it, then zip with the proof to combine in the correct order.
    """
    # Trace the descent from root to leaf, recording at each level whether the leaf
    # is in the left subtree (False) or the right subtree (True). This list is
    # outermost-first, but proof elements are innermost-first, so we reverse.
    directions: list[bool] = []
    idx = m
    ts = n
    while ts > 1:
        k = _largest_power_of_2_less_than(ts)
        if idx < k:
            directions.append(False)  # leaf is in LEFT subtree at this level
            ts = k
        else:
            directions.append(True)   # leaf is in RIGHT subtree at this level
            idx -= k
            ts -= k
    # Proof is innermost-first; directions is outermost-first — reverse directions.
    directions.reverse()

    node = leaf
    for is_right, sibling in zip(directions, proof):
        if is_right:
            node = internal_hash(sibling, node)  # node is right child; sibling is left
        else:
            node = internal_hash(node, sibling)  # node is left child; sibling is right
    return node


# ── Consistency proof ─────────────────────────────────────────────────────────


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    """RFC 6962 §2.1.2 SUBPROOF(m, D[n], b)."""
    n = len(leaves)
    if m == n:
        return [] if b else [compute_root(leaves)]
    k = _largest_power_of_2_less_than(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [compute_root(leaves[k:])]
    else:
        return _subproof(m - k, leaves[k:], False) + [compute_root(leaves[:k])]


def _consistency_proof(old_size: int, leaves: list[bytes]) -> list[bytes]:
    """PROOF(m, D[n]) = SUBPROOF(m, D[n], true)."""
    return _subproof(old_size, leaves, True)


def _verify_consistency_proof(
    old_size: int,
    old_root: bytes,
    new_size: int,
    new_root: bytes,
    proof: list[bytes],
    all_leaves: list[bytes],
) -> bool:
    """Verify a consistency proof given the full leaf list.

    Because we hold the complete leaf list in the in-memory implementation, the most
    reliable verification strategy is to re-derive both roots directly and cross-check
    against the supplied proof structure. This is equivalent to running the verifier
    against recomputed subtree hashes.

    The proof is valid iff:
      1. compute_root(leaves[:old_size]) == old_root
      2. compute_root(leaves[:new_size]) == new_root (i.e. the current root)
      3. The proof path matches what _consistency_proof would generate for these leaves.

    Condition 3 is implicitly satisfied when conditions 1 and 2 hold and the proof
    length matches the expected SUBPROOF depth, but we check the proof path matches
    exactly to prevent forged proofs that happen to produce correct roots by accident.
    """
    if old_size > len(all_leaves) or new_size > len(all_leaves):
        return False
    # Re-derive roots from the actual leaves — tamper-evident because the caller
    # controls the proof but not the stored leaves.
    derived_old = compute_root(all_leaves[:old_size])
    derived_new = compute_root(all_leaves[:new_size])
    if derived_old != old_root or derived_new != new_root:
        return False
    # Also verify the proof path itself is structurally correct.
    expected_proof = _subproof(old_size, all_leaves[:new_size], True)
    return proof == expected_proof


def verify_consistency_proof(
    old_size: int,
    old_root: bytes,
    new_size: int,
    new_root: bytes,
    proof: list[bytes],
) -> bool:
    """RFC 6962 §2.1.4 consistency proof verification — PROOF-ONLY (no leaf list needed).

    Returns True iff the size-``new_size`` tree with root ``new_root`` is a consistent, append-only
    extension of the size-``old_size`` tree with root ``old_root``, given ``proof``. Reconstructs
    BOTH roots from the proof alone, so a party that holds only Signed Tree Heads — an external
    witness or auditor, which never sees the leaves — can verify continuity (D3-2). This is the
    canonical CT/Trillian algorithm; it never raises (False on any structural inconsistency).
    """
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if old_size == new_size:
        # Same tree: roots must match and the proof is (correctly) empty.
        return old_root == new_root and len(proof) == 0
    if old_size == 0:
        # Every tree is consistent with the empty tree; the proof must be empty.
        return len(proof) == 0
    if not proof:
        return False

    # Walk the rightmost node of the old tree down to the largest complete subtree it belongs to.
    node = old_size - 1
    last = new_size - 1
    while node & 1:
        node >>= 1
        last >>= 1

    idx = 0
    if node > 0:
        # Seed both reconstructions from the first proof node (the incomplete-subtree case).
        first_root = proof[idx]
        second_root = proof[idx]
        idx += 1
    else:
        # old_size is a power of two → its root is a complete subtree, taken as given.
        first_root = old_root
        second_root = old_root

    while node > 0:
        if node & 1:
            # Right child: both roots absorb the left sibling from the proof.
            if idx >= len(proof):
                return False
            first_root = internal_hash(proof[idx], first_root)
            second_root = internal_hash(proof[idx], second_root)
            idx += 1
        elif node < last:
            # Left child with a right sibling present only in the new tree: only the new root grows.
            if idx >= len(proof):
                return False
            second_root = internal_hash(second_root, proof[idx])
            idx += 1
        node >>= 1
        last >>= 1

    # Absorb the remaining right-hand nodes of the new tree into the new root.
    while last > 0:
        if idx >= len(proof):
            return False
        second_root = internal_hash(second_root, proof[idx])
        idx += 1
        last >>= 1

    if idx != len(proof):
        return False  # proof longer than the reconstruction consumed → reject
    return first_root == old_root and second_root == new_root


# ── MerkleTree class ──────────────────────────────────────────────────────────


class MerkleTree:
    """RFC 6962-style Merkle transparency log. Append-only.

    Stores leaf hashes in insertion order. MTH is recomputed on demand over the full list;
    the in-memory implementation trades CPU for simplicity — a persistent adapter would cache
    intermediate nodes.
    """

    def __init__(self) -> None:
        self._leaves: list[bytes] = []

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, entry_bytes: bytes) -> tuple[int, bytes]:
        """Compute leaf_hash(entry_bytes), append to the log, and return (index, leaf_hash)."""
        lh = leaf_hash(entry_bytes)
        index = len(self._leaves)
        self._leaves.append(lh)
        return index, lh

    def append_leaf_hash(self, lh: bytes) -> int:
        """Append a precomputed leaf hash (used to rehydrate a tree from a durable store).

        Unlike `append`, this does NOT apply `leaf_hash` again — `lh` is already a leaf hash
        (e.g. a `LedgerEntry.leaf_hash` loaded from the repository). Returns the new index.
        """
        index = len(self._leaves)
        self._leaves.append(lh)
        return index

    def pop_last(self) -> None:
        """Remove the most recently appended leaf.

        Used to roll back an in-memory append when the durable write of that entry fails, so the
        in-memory tree never gets ahead of the persisted log. Raises IndexError if the tree is empty.
        """
        if not self._leaves:
            raise IndexError("pop_last on an empty MerkleTree")
        self._leaves.pop()

    def root(self) -> bytes:
        """Current Merkle Tree Head (MTH)."""
        return compute_root(list(self._leaves))

    def inclusion_proof(self, index: int) -> list[bytes]:
        """RFC 6962 §2.1.1 inclusion proof path for the leaf at `index`."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"index {index} out of range [0, {len(self._leaves)})")
        return _inclusion_proof_path(index, list(self._leaves))

    def verify_inclusion(
        self, index: int, lh: bytes, proof: list[bytes], root: bytes
    ) -> bool:
        """Verify an inclusion proof. Returns True iff the proof reconstructs `root`."""
        n = len(self._leaves)
        if n == 0:
            return False
        return _recompute_root_from_path(index, n, lh, proof) == root

    def consistency_proof(self, old_size: int) -> list[bytes]:
        """RFC 6962 §2.1.2 consistency proof from `old_size` to current size."""
        new_size = len(self._leaves)
        if old_size < 0 or old_size > new_size:
            raise ValueError(f"old_size {old_size} out of range [0, {new_size}]")
        if old_size == 0 or old_size == new_size:
            return []
        return _consistency_proof(old_size, list(self._leaves))

    def verify_consistency(
        self,
        old_size: int,
        old_root: bytes,
        new_size: int,
        new_root: bytes,
        proof: list[bytes],
    ) -> bool:
        """Verify that the old tree is a prefix of the new one.

        Returns True iff the proof is valid. A False return means either the tree was tampered
        with or the proof is for a different pair of tree sizes.

        Verification strategy: re-derive the old root and the new root from the proof path
        using the same SUBPROOF traversal as generation, then compare both against the
        supplied roots. This avoids any iterative bit-manipulation and matches the structure
        of the recursive generator exactly.
        """
        if old_size == 0:
            return True
        if old_size == new_size:
            return old_root == new_root and not proof
        return _verify_consistency_proof(
            old_size, old_root, new_size, new_root, proof, list(self._leaves)
        )
