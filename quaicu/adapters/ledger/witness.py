"""Software witness — an independent Ed25519 cosigner for Signed Tree Heads (K·02 / D3-2).

Implements `AnchorPort`. Keeps, per tenant, the last STH it cosigned; a new STH is cosigned only if a
supplied consistency proof shows it is an append-only extension of that last STH — otherwise the
witness raises `LedgerTamperError` (a fork / silent rewind / split view). The cosignature is an
independent, pinnable attestation of what root existed at what size.

For real independence, run this as a separate process/service with its own key (a remote HTTP witness
adapter is a follow-up); the in-process instance proves the mechanism and is used in tests + sovereign
single-node deployments. The key never leaves this object (same posture as the ledger signer).
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.anchor import InMemoryWitnessStateStore, WitnessStateStore
from quaicu.core.ledger.merkle import verify_consistency_proof
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.ports.anchor import WitnessCosignature
from quaicu.core.types import TenantId


class SoftwareWitness:
    """An independent Ed25519 witness. Satisfies `AnchorPort`.

    ``private_key_pem`` loads a **stable** key (so the pinned witness key survives restarts and cross
    replicas); omit it only for dev/tests, where an ephemeral key is generated. ``state_store`` is the
    witness's durable memory of the last STH it cosigned per tenant — pass a `PostgresWitnessStateStore`
    in production so a rewind after a restart is still caught (an in-memory default forgets on restart).
    """

    def __init__(
        self,
        *,
        private_key_pem: str | None = None,
        witness_id: str | None = None,
        state_store: WitnessStateStore | None = None,
    ) -> None:
        if private_key_pem:
            key = load_pem_private_key(private_key_pem.encode(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError("witness private key must be Ed25519")
            self._private_key = key
        else:
            self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._witness_id = witness_id or f"witness:{uuid.uuid4()}"
        self._store: WitnessStateStore = state_store or InMemoryWitnessStateStore()

    @property
    def witness_id(self) -> str:
        return self._witness_id

    @property
    def public_key_pem(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def last_seen(self, tenant: TenantId) -> tuple[int, bytes] | None:
        return self._store.get(tenant)

    def cosign(
        self, tenant: TenantId, sth: SignedTreeHead, consistency_proof: list[bytes]
    ) -> WitnessCosignature:
        last = self._store.get(tenant)
        if last is not None:
            old_size, old_root = last
            if not verify_consistency_proof(
                old_size, old_root, sth.tree_size, sth.root_hash, list(consistency_proof or [])
            ):
                raise LedgerTamperError(
                    f"witness refuses to cosign: STH size={sth.tree_size} for tenant {tenant} is not a "
                    f"consistent extension of the last cosigned size={old_size} (fork / rewind detected)",
                    detail={"tenant": str(tenant), "old_size": old_size, "new_size": sth.tree_size},
                )

        cosig = WitnessCosignature(
            witness_id=self._witness_id,
            tenant=str(tenant),
            tree_size=sth.tree_size,
            root_hash=sth.root_hash,
            cosigned_at=datetime.now(tz=timezone.utc),
            signature=b"",
        )
        cosig = dataclasses.replace(cosig, signature=self._private_key.sign(cosig.signing_message()))
        self._store.advance(tenant, sth.tree_size, sth.root_hash)
        return cosig

    def verify(self, cosig: WitnessCosignature, public_key_pem: str) -> bool:
        try:
            key = load_pem_public_key(public_key_pem.encode())
            if not isinstance(key, Ed25519PublicKey):
                return False
            key.verify(cosig.signature, cosig.signing_message())
            return True
        except Exception:  # noqa: BLE001 — any failure is a verification failure
            return False
