"""AnchorPort — external attestation of Signed Tree Heads (K·02 / D3-2).

An *anchor* is an independent party that attests to each STH the kernel produces, so a compromised
kernel cannot present a split view or silently rewind its log undetected. The shipped anchor is a
**witness** that cosigns an STH only after verifying it is a consistent append-only extension of the
last STH it cosigned (`core/ledger/merkle.verify_consistency_proof`) — a fork/rewind is refused.

The port is mechanism-agnostic: a witness cosignature today; an RFC-3161 TSA token or a public
append-only receipt could implement the same shape later. The cosignature is embedded in the K·14
export bundle and verified offline by pinning the witness key (the same trust model as D3-1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.types import TenantId


@dataclass(frozen=True)
class WitnessCosignature:
    """An independent witness's attestation that it saw ``root_hash`` at ``tree_size`` for a tenant."""

    witness_id: str
    tenant: str
    tree_size: int
    root_hash: bytes
    cosigned_at: datetime
    signature: bytes

    def signing_message(self) -> bytes:
        """The deterministic bytes the witness signs (domain-separated; no ambiguity)."""
        parts = [
            self.witness_id,
            self.tenant,
            str(self.tree_size),
            self.root_hash.hex(),
            self.cosigned_at.isoformat(),
        ]
        return b"quaicu.witness.v1\x00" + "\x00".join(parts).encode("utf-8")

    def to_dict(self) -> dict:
        return {
            "witness_id": self.witness_id,
            "tenant": self.tenant,
            "tree_size": self.tree_size,
            "root_hash_hex": self.root_hash.hex(),
            "cosigned_at": self.cosigned_at.isoformat(),
            "signature_hex": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WitnessCosignature":
        return cls(
            witness_id=str(d["witness_id"]),
            tenant=str(d["tenant"]),
            tree_size=int(d["tree_size"]),
            root_hash=bytes.fromhex(d["root_hash_hex"]),
            cosigned_at=datetime.fromisoformat(d["cosigned_at"]),
            signature=bytes.fromhex(d["signature_hex"]),
        )


class AnchorPort(Protocol):
    """An independent anchor for Signed Tree Heads. The witness implementation cosigns after a
    consistency check; other mechanisms (TSA, public log) can satisfy the same surface."""

    @property
    def witness_id(self) -> str: ...

    @property
    def public_key_pem(self) -> str:
        """The anchor's verification key — pinned out-of-band to verify cosignatures offline."""
        ...

    def last_seen(self, tenant: TenantId) -> tuple[int, bytes] | None:
        """The (tree_size, root_hash) of the last STH cosigned for ``tenant``, or None."""
        ...

    def cosign(
        self, tenant: TenantId, sth: SignedTreeHead, consistency_proof: list[bytes]
    ) -> WitnessCosignature:
        """Cosign ``sth`` iff it is a consistent extension of the last STH seen for ``tenant``.

        ``consistency_proof`` proves ``last_seen → sth`` (empty for the first STH or same size).
        Raises ``LedgerTamperError`` (fail-closed) if the proof does not verify — a fork/rewind.
        """
        ...

    def verify(self, cosig: WitnessCosignature, public_key_pem: str) -> bool:
        """Verify a cosignature against a pinned witness public key (offline)."""
        ...
