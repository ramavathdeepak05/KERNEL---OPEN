"""AWS KMS-backed TreeSigner + LedgerAdapter (the AWS counterpart to adapters/ledger/gcp_kms.py).

``AwsKmsTreeSigner`` implements the ``TreeSigner`` protocol using an AWS KMS asymmetric signing key.
The private key lives in KMS — never in process memory — backed by FIPS 140-2 validated HSMs, so it
survives restarts and is shared across nodes in a horizontally-scaled deployment. This is the AWS
managed-service alternative to OpenBao / GCP Cloud KMS for regulated deployments.

**Signature scheme — ECDSA P-256, not Ed25519.** AWS KMS asymmetric keys sign with ECDSA (or RSA), not
Ed25519. This signer uses a ``ECC_NIST_P256`` key with ``ECDSA_SHA_256``: it signs SHA-256 of the
RFC 6962 signing message and stores the DER-encoded ECDSA signature in ``SignedTreeHead.signature`` —
identical on the wire to the GCP Cloud KMS signer, so KMS-signed bundles verify with the same offline
regulator code (``core/regmap/export.py`` infers the scheme from the public-key type).

Authentication uses the runtime's AWS credentials (instance/role / env) — no static keys in config. The
KMS client and the ``boto3`` import are lazy (constructor-time) so the kernel core carries no cloud
dependency; install with the ``[aws]`` extra.

Prerequisites (run once):
    aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY
    # then reference the key id / ARN / alias as [ledger].key
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from quaicu.core.errors import LedgerSealError
from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.repository import LedgerRepository
from quaicu.core.ledger.signer import SignedTreeHead, _signing_message
from quaicu.core.types import Action, ApproverRef, EvaluationResult, LedgerEntry


# ── AWS KMS TreeSigner ────────────────────────────────────────────────────────


class AwsKmsTreeSigner:
    """ECDSA-P256 ``TreeSigner`` backed by AWS KMS.

    ``key_id`` is the KMS key id, ARN, or alias of an ``ECC_NIST_P256`` SIGN_VERIFY key that must
    already exist before this adapter is used.
    """

    def __init__(self, key_id: str, *, region: str | None = None, client: Any | None = None) -> None:
        if not key_id:
            raise ValueError("AwsKmsTreeSigner requires a KMS key id / ARN / alias.")
        if client is None:
            import boto3  # lazy ([aws] extra)

            client = boto3.client("kms", region_name=region) if region else boto3.client("kms")
        self._client = client
        self._key_id = key_id
        self._cached_pem: str | None = None

    # ── TreeSigner protocol ───────────────────────────────────────────────────

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
        digest = hashlib.sha256(_signing_message(tree_size, root_hash)).digest()
        try:
            resp = self._client.sign(
                KeyId=self._key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )
            signature: bytes = resp["Signature"]
        except Exception as exc:
            raise LedgerSealError(
                f"AWS KMS sign failed for key {self._key_id!r}: {exc}",
                detail={"key_id": self._key_id},
            ) from exc

        return SignedTreeHead(
            tree_size=tree_size,
            timestamp=timestamp,
            root_hash=root_hash,
            signature=signature,  # DER-encoded ECDSA-P256 signature
            key_id=self._key_id,
        )

    def verify(self, sth: SignedTreeHead) -> bool:
        # Verify locally against the KMS public key. A cryptographically invalid signature returns
        # False; an inability to fetch the key (outage) raises — never a silent false-negative audit.
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        try:
            public_key = load_pem_public_key(self.public_key_pem.encode())
        except LedgerSealError:
            raise
        except Exception as exc:
            raise LedgerSealError(
                f"AWS KMS verify failed for key {self._key_id!r}: {exc}",
                detail={"key_id": self._key_id},
            ) from exc

        msg = _signing_message(sth.tree_size, sth.root_hash)
        try:
            public_key.verify(sth.signature, msg, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
            return True
        except InvalidSignature:
            return False

    @property
    def public_key_pem(self) -> str:
        """The signing key's public key as an SPKI PEM — embedded in regulator exports (WS-F) so an
        STH signature can be verified offline. KMS returns DER SPKI; we re-serialize to PEM (matching
        the GCP signer's output). Cached after the first fetch."""
        if self._cached_pem is None:
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

            try:
                der = self._client.get_public_key(KeyId=self._key_id)["PublicKey"]
                public_key = load_der_public_key(der)
                self._cached_pem = public_key.public_bytes(
                    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
                ).decode()
            except Exception as exc:
                raise LedgerSealError(
                    f"AWS KMS public-key fetch failed for {self._key_id!r}: {exc}",
                    detail={"key_id": self._key_id},
                ) from exc
        return self._cached_pem

    def close(self) -> None:
        # boto3 clients manage their own transport; nothing to close explicitly.
        return None


# ── AWS KMS Ledger Adapter ─────────────────────────────────────────────────────


class AwsKmsLedgerAdapter:
    """Production ledger: RFC 6962 TrustLedger + AWS KMS ECDSA-P256 signer.

    Satisfies the ``Ledger`` protocol structurally. Use in kernel.toml::

        [adapters]
        ledger       = "aws_kms_ledger"
        ledger_store = "postgres_ledger"

        [ledger]
        key    = "arn:aws:kms:us-east-1:123456789012:key/abcd-…"   # ECC_NIST_P256 SIGN_VERIFY
        region = "us-east-1"
    """

    def __init__(
        self,
        key: str,
        *,
        region: str | None = None,
        client: Any | None = None,
        repository: LedgerRepository | None = None,
    ) -> None:
        self._signer = AwsKmsTreeSigner(key, region=region, client=client)
        self._repository = repository
        self._ledger = TrustLedger(signer=self._signer, repository=repository)

    async def hydrate(self) -> None:
        """Rebuild the in-memory tree/entries/STHs from the durable repository (startup)."""
        await self._ledger.hydrate()

    # ── Ledger protocol ───────────────────────────────────────────────────────

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        return await self._ledger.seal(
            action=action,
            evaluation=evaluation,
            recorded_result=recorded_result,
            approver=approver,
        )

    # ── Read-side (pass-through to TrustLedger) ───────────────────────────────

    def get_entry(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_entry(tenant, seq)

    def get_entries(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_entries(tenant)

    def get_signed_tree_head(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_signed_tree_head(tenant)

    def get_inclusion_proof(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_inclusion_proof(tenant, seq)

    def verify_inclusion(self, tenant, seq, sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_inclusion(tenant, seq, sth)

    def get_consistency_proof(self, tenant, old_size):  # type: ignore[no-untyped-def]
        return self._ledger.get_consistency_proof(tenant, old_size)

    def verify_consistency(self, tenant, old_sth, new_sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_consistency(tenant, old_sth, new_sth)

    async def close(self) -> None:
        self._signer.close()
        if self._repository is not None:
            await self._repository.close()
