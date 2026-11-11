"""GCP Cloud KMS-backed TreeSigner + LedgerAdapter.

``GcpKmsTreeSigner`` implements the ``TreeSigner`` protocol using a Google Cloud KMS asymmetric
signing key. The private key lives in Cloud KMS — never in process memory — backed by FIPS 140-2
Level 3 HSMs (with the ``HSM`` protection level), so it survives restarts and is shared across nodes
in a horizontally-scaled deployment. This is the managed-service alternative to OpenBao for regulated
deployments (see docs/adr/0012-cloud-native-adapters.md).

**Signature scheme — ECDSA P-256, not Ed25519.** Google Cloud KMS does not support Ed25519 for
asymmetric signing; its EC signing algorithms are P-256 and P-384. This signer therefore uses
``EC_SIGN_P256_SHA256``: it signs SHA-256 of the RFC 6962 signing message and stores the DER-encoded
ECDSA signature in ``SignedTreeHead.signature``. The offline verifier in ``core/regmap/export.py``
infers the scheme from the public-key type, so KMS-signed bundles verify with the same regulator code
as the Ed25519 signers. ECDSA is itself RFC 6962-conformant (the RFC specifies ECDSA/RSA).

Authentication uses Application Default Credentials (ADC) / Workload Identity — no static keys in
config. The KMS client and the ``google-cloud-kms`` import are lazy (constructor-time) so the kernel
core carries no cloud dependency; install with the ``[gcp]`` extra.

Prerequisites (run once):
    gcloud kms keyrings create quaicu --location <loc>
    gcloud kms keys create ledger --location <loc> --keyring quaicu \
        --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256 \
        --protection-level hsm
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


# ── GCP Cloud KMS TreeSigner ──────────────────────────────────────────────────


class GcpKmsTreeSigner:
    """ECDSA-P256 ``TreeSigner`` backed by Google Cloud KMS.

    The key is identified by ``(project, location, key_ring, key, version)`` and must already exist
    as an ``EC_SIGN_P256_SHA256`` asymmetric-signing key before this adapter is used.
    """

    def __init__(
        self,
        project: str,
        location: str,
        key_ring: str,
        key: str,
        *,
        version: str = "1",
        client: Any | None = None,
    ) -> None:
        if client is None:
            # Lazy import: keeps google-cloud-kms an optional ([gcp]) dependency, out of core.
            from google.cloud import kms

            client = kms.KeyManagementServiceClient()
        self._client = client
        self._key_version_name = (
            f"projects/{project}/locations/{location}/keyRings/{key_ring}"
            f"/cryptoKeys/{key}/cryptoKeyVersions/{version}"
        )
        # A stable, human-readable key id for the STH (does not leak the full resource path's secrets).
        self._key_id = f"{key_ring}/{key}/v{version}"
        self._cached_pem: str | None = None

    # ── TreeSigner protocol ───────────────────────────────────────────────────

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, tree_size: int, root_hash: bytes, timestamp: datetime) -> SignedTreeHead:
        msg = _signing_message(tree_size, root_hash)
        digest = hashlib.sha256(msg).digest()
        try:
            resp = self._client.asymmetric_sign(
                request={
                    "name": self._key_version_name,
                    "digest": {"sha256": digest},
                }
            )
            signature: bytes = resp.signature
        except Exception as exc:
            raise LedgerSealError(
                f"GCP KMS sign failed for key {self._key_id!r}: {exc}",
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
                f"GCP KMS verify failed for key {self._key_id!r}: {exc}",
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
        STH signature can be verified offline. Cached after the first fetch."""
        if self._cached_pem is None:
            try:
                resp = self._client.get_public_key(request={"name": self._key_version_name})
                self._cached_pem = resp.pem
            except Exception as exc:
                raise LedgerSealError(
                    f"GCP KMS public-key fetch failed for {self._key_id!r}: {exc}",
                    detail={"key_id": self._key_id},
                ) from exc
        return self._cached_pem

    def close(self) -> None:
        # The KMS client manages its own transport; nothing to close explicitly.
        return None


# ── GCP Cloud KMS Ledger Adapter ──────────────────────────────────────────────


class GcpKmsLedgerAdapter:
    """Production ledger: RFC 6962 TrustLedger + GCP Cloud KMS ECDSA-P256 signer.

    Satisfies the ``Ledger`` protocol structurally. Use in kernel.toml::

        [adapters]
        ledger       = "gcp_kms_ledger"
        ledger_store = "postgres_ledger"

        [ledger]
        project   = "my-project"
        location  = "us-central1"
        key_ring  = "quaicu"
        key       = "ledger"
        version   = "1"
    """

    def __init__(
        self,
        project: str,
        location: str,
        key_ring: str,
        key: str,
        *,
        version: str = "1",
        client: Any | None = None,
        repository: LedgerRepository | None = None,
    ) -> None:
        self._signer = GcpKmsTreeSigner(
            project=project,
            location=location,
            key_ring=key_ring,
            key=key,
            version=version,
            client=client,
        )
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
