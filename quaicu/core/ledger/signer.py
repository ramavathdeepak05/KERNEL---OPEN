"""Tree signer protocol and the stub in-memory Ed25519 implementation.

The real OpenBao signer plugs in here as a drop-in replacement for `InMemoryEd25519Signer`
without changing any ledger logic (F-04 / no-bypass: the ledger depends only on `TreeSigner`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ── Value type ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SignedTreeHead:
    """An RFC 6962 Signed Tree Head (STH).

    `signature` is a signature over (tree_size as 8-byte big-endian || root_hash). The scheme depends
    on the `TreeSigner`: Ed25519 for the software/OpenBao signers, ECDSA P-256 for the Cloud KMS
    signer (GCP Cloud KMS has no Ed25519). The offline verifier infers the scheme from the public-key
    type, so no algorithm tag is carried on the wire.
    `key_id` identifies which signing key produced the signature.
    """

    tree_size: int
    timestamp: datetime
    root_hash: bytes
    signature: bytes
    key_id: str


# ── Protocol ──────────────────────────────────────────────────────────────────


class TreeSigner(Protocol):
    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead: ...

    def verify(self, sth: SignedTreeHead) -> bool: ...

    @property
    def key_id(self) -> str: ...

    @property
    def public_key_pem(self) -> str:
        """The verification key as an SPKI PEM — the trust anchor a regulator pins out-of-band (D3-1)."""
        ...


# ── Stub implementation ───────────────────────────────────────────────────────


def _signing_message(tree_size: int, root_hash: bytes) -> bytes:
    return tree_size.to_bytes(8, "big") + root_hash


class InMemoryEd25519Signer:
    """Ephemeral Ed25519 key, generated once at construction.

    Suitable for unit tests and single-process in-memory runs. The real production signer
    uses OpenBao and shares a stable key across nodes; it satisfies the same `TreeSigner`
    interface so no ledger code changes at that point.
    """

    def __init__(self) -> None:
        self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._key_id: str = str(uuid.uuid4())

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_pem(self) -> str:
        """The Ed25519 verification key as an SPKI PEM — embedded in regulator exports (WS-F) so an
        STH signature can be verified offline."""
        from cryptography.hazmat.primitives import serialization

        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
        msg = _signing_message(tree_size, root_hash)
        signature = self._private_key.sign(msg)
        return SignedTreeHead(
            tree_size=tree_size,
            timestamp=timestamp,
            root_hash=root_hash,
            signature=signature,
            key_id=self._key_id,
        )

    def verify(self, sth: SignedTreeHead) -> bool:
        msg = _signing_message(sth.tree_size, sth.root_hash)
        try:
            self._public_key.verify(sth.signature, msg)
            return True
        except Exception:
            return False
