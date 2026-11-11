"""K·02 TrustLedger — public surface.

Import these from `core.ledger`; do not reach into submodules directly.
"""

from __future__ import annotations

from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.merkle import MerkleTree
from quaicu.core.ledger.signer import InMemoryEd25519Signer, SignedTreeHead

# Inclusion and consistency proofs are ordered sequences of sibling hashes (RFC 6962 §2.1).
InclusionProof = list[bytes]
ConsistencyProof = list[bytes]

__all__ = [
    "TrustLedger",
    "SignedTreeHead",
    "MerkleTree",
    "InMemoryEd25519Signer",
    "InclusionProof",
    "ConsistencyProof",
]
