"""Unit tests for GcpKmsTreeSigner + GcpKmsLedgerAdapter.

The Cloud KMS client is faked with a local EC P-256 key (mimicking KMS's ECDSA_SHA_256 signing over a
prehashed digest), so no real GCP project or credentials are required.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from quaicu.adapters.ledger.gcp_kms import GcpKmsTreeSigner
from quaicu.core.errors import LedgerSealError
from quaicu.core.ledger.signer import SignedTreeHead, _signing_message
from quaicu.core.regmap.export import trusted_keys_from_signer, verify_ledger_proof_bundle

NOW = datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc)
TREE_SIZE = 5
ROOT_HASH = b"\xab" * 32


class _FakeKmsClient:
    """Mimics google.cloud.kms KeyManagementServiceClient over a local EC P-256 key."""

    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self._pub = self._priv.public_key()
        self.sign_error: Exception | None = None
        self.get_public_key_calls = 0

    def asymmetric_sign(self, request: dict) -> SimpleNamespace:
        if self.sign_error is not None:
            raise self.sign_error
        digest = request["digest"]["sha256"]
        # KMS signs the prehashed SHA-256 digest and returns a DER-encoded ECDSA signature.
        sig = self._priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return SimpleNamespace(signature=sig)

    def get_public_key(self, request: dict) -> SimpleNamespace:
        self.get_public_key_calls += 1
        pem = self._pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        return SimpleNamespace(pem=pem)


def _signer(client: _FakeKmsClient) -> GcpKmsTreeSigner:
    return GcpKmsTreeSigner(
        project="proj", location="us-central1", key_ring="quaicu", key="ledger", client=client
    )


def test_sign_returns_signed_tree_head():
    signer = _signer(_FakeKmsClient())
    sth = signer.sign(TREE_SIZE, ROOT_HASH, NOW)
    assert isinstance(sth, SignedTreeHead)
    assert sth.tree_size == TREE_SIZE
    assert sth.root_hash == ROOT_HASH
    assert sth.key_id == "quaicu/ledger/v1"
    assert sth.signature  # non-empty DER signature


def test_sign_signs_sha256_of_signing_message():
    client = _FakeKmsClient()
    signer = _signer(client)
    captured: dict = {}

    orig = client.asymmetric_sign

    def _spy(request):
        captured.update(request)
        return orig(request)

    client.asymmetric_sign = _spy  # type: ignore[method-assign]
    signer.sign(TREE_SIZE, ROOT_HASH, NOW)
    assert captured["digest"]["sha256"] == hashlib.sha256(
        _signing_message(TREE_SIZE, ROOT_HASH)
    ).digest()


def test_sign_then_verify_roundtrip_true():
    signer = _signer(_FakeKmsClient())
    sth = signer.sign(TREE_SIZE, ROOT_HASH, NOW)
    assert signer.verify(sth) is True


def test_verify_false_for_tampered_root():
    signer = _signer(_FakeKmsClient())
    sth = signer.sign(TREE_SIZE, ROOT_HASH, NOW)
    tampered = SignedTreeHead(
        tree_size=sth.tree_size,
        timestamp=sth.timestamp,
        root_hash=b"\xcd" * 32,  # different root → signature no longer matches
        signature=sth.signature,
        key_id=sth.key_id,
    )
    assert signer.verify(tampered) is False


def test_sign_raises_ledger_seal_error_on_kms_error():
    client = _FakeKmsClient()
    client.sign_error = RuntimeError("kms unavailable")
    signer = _signer(client)
    with pytest.raises(LedgerSealError, match="GCP KMS sign failed"):
        signer.sign(TREE_SIZE, ROOT_HASH, NOW)


def test_public_key_pem_is_cached():
    client = _FakeKmsClient()
    signer = _signer(client)
    _ = signer.public_key_pem
    _ = signer.public_key_pem
    assert client.get_public_key_calls == 1


def test_ecdsa_signed_bundle_verifies_through_offline_verifier():
    # End-to-end: an ECDSA-P256 (Cloud KMS) STH must verify with the same regulator-facing offline
    # code path that handles Ed25519 — the verifier infers the scheme from the public-key type.
    signer = _signer(_FakeKmsClient())
    sth = signer.sign(TREE_SIZE, ROOT_HASH, NOW)
    bundle = {
        "signed_tree_head": {
            "tree_size": TREE_SIZE,
            "root_hash_hex": ROOT_HASH.hex(),
            "signature_hex": sth.signature.hex(),
            "key_id": signer.key_id,
            "public_key_pem": signer.public_key_pem,
        },
        "inclusion_proofs": [],  # signature-only check
    }
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=trusted_keys_from_signer(signer))
    assert ok, errors
