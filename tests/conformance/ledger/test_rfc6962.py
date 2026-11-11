"""RFC 6962 conformance tests — spec-derived golden values.

These are NOT implementation tests; they are contract tests. If any of these fail, the
implementation diverges from the specification. The expected values are computed inline
from the same primitives as the spec (hashlib.sha256) so there is no external oracle required.
"""

from __future__ import annotations

import hashlib

import pytest

from quaicu.core.ledger.merkle import compute_root, internal_hash, leaf_hash


pytestmark = pytest.mark.conformance


# ── Leaf hash (RFC 6962 §2.1) ─────────────────────────────────────────────────


def test_rfc6962_leaf_hash_empty() -> None:
    """leaf_hash(b"") == SHA-256(0x00)."""
    expected = hashlib.sha256(b"\x00").digest()
    assert leaf_hash(b"") == expected


def test_rfc6962_leaf_hash_malic() -> None:
    """leaf_hash(bytes.fromhex("4d616c6963")) == SHA-256(0x00 || 0x4d616c6963).

    0x4d616c6963 == b"Malic". Referenced in the spec description as the test vector input.
    """
    data = bytes.fromhex("4d616c6963")  # b"Malic"
    expected = hashlib.sha256(b"\x00" + data).digest()
    assert leaf_hash(data) == expected


def test_rfc6962_internal_hash() -> None:
    """internal_hash(a, b) == SHA-256(0x01 || a || b) for known inputs."""
    a = hashlib.sha256(b"\x00" + b"left").digest()
    b = hashlib.sha256(b"\x00" + b"right").digest()
    expected = hashlib.sha256(b"\x01" + a + b).digest()
    assert internal_hash(a, b) == expected


# ── MTH (RFC 6962 §2.1) ───────────────────────────────────────────────────────


def test_size_1_tree_equals_leaf() -> None:
    """MTH({d(0)}) == SHA-256(0x00 || d(0)) — single leaf MTH is the leaf hash."""
    data = b"single entry"
    lh = leaf_hash(data)
    assert compute_root([lh]) == lh


def test_size_2_tree_equals_internal() -> None:
    """MTH({d(0), d(1)}) == SHA-256(0x01 || leaf_hash(d(0)) || leaf_hash(d(1)))."""
    d0 = b"first"
    d1 = b"second"
    lh0 = leaf_hash(d0)
    lh1 = leaf_hash(d1)
    expected = hashlib.sha256(b"\x01" + lh0 + lh1).digest()
    assert compute_root([lh0, lh1]) == expected


def test_size_4_tree_structure() -> None:
    """MTH of 4 leaves follows the complete binary tree structure."""
    entries = [b"e0", b"e1", b"e2", b"e3"]
    leaves = [leaf_hash(e) for e in entries]

    # Build expected root manually.
    left = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
    right = hashlib.sha256(b"\x01" + leaves[2] + leaves[3]).digest()
    expected = hashlib.sha256(b"\x01" + left + right).digest()

    assert compute_root(leaves) == expected


def test_size_3_tree_structure() -> None:
    """MTH of 3 leaves: k=2, root = SHA256(0x01 || MTH(D[0:2]) || MTH(D[2:3]))."""
    entries = [b"a", b"b", b"c"]
    leaves = [leaf_hash(e) for e in entries]

    left = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
    right = leaves[2]  # single leaf MTH == the leaf hash
    expected = hashlib.sha256(b"\x01" + left + right).digest()

    assert compute_root(leaves) == expected
