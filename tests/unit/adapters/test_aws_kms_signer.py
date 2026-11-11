"""AWS KMS TreeSigner + ledger adapter (W6-7) — real-crypto fake KMS client, no boto3/AWS."""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from quaicu.adapters.ledger.aws_kms import AwsKmsLedgerAdapter, AwsKmsTreeSigner

NOW = datetime(2026, 6, 24, 12, 0, tzinfo=timezone.utc)


class _FakeKmsClient:
    """Backs the signer with a REAL EC P-256 key so sign→verify round-trips under actual crypto."""

    def __init__(self) -> None:
        self._priv = ec.generate_private_key(ec.SECP256R1())

    def sign(self, *, KeyId, Message, MessageType, SigningAlgorithm):  # noqa: N803 - boto3 kwarg names
        assert MessageType == "DIGEST" and SigningAlgorithm == "ECDSA_SHA_256"
        # AWS KMS signs the supplied digest; mirror that with a Prehashed ECDSA signature (DER).
        sig = self._priv.sign(Message, ec.ECDSA(Prehashed(hashes.SHA256())))
        return {"Signature": sig}

    def get_public_key(self, *, KeyId):  # noqa: N803
        der = self._priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der}


_KEY = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"


def test_signer_satisfies_protocol():
    # TreeSigner is a plain (non-runtime_checkable) Protocol — assert structurally.
    s = AwsKmsTreeSigner(_KEY, client=_FakeKmsClient())
    assert callable(s.sign) and callable(s.verify) and s.key_id == _KEY


def test_sign_then_verify_roundtrips():
    signer = AwsKmsTreeSigner(_KEY, client=_FakeKmsClient())
    sth = signer.sign(tree_size=5, root_hash=b"\x22" * 32, timestamp=NOW)
    assert sth.key_id == _KEY and sth.tree_size == 5 and sth.signature  # DER bytes present
    assert signer.verify(sth) is True


def test_tampered_sth_fails_verify():
    signer = AwsKmsTreeSigner(_KEY, client=_FakeKmsClient())
    sth = signer.sign(tree_size=5, root_hash=b"\x22" * 32, timestamp=NOW)
    tampered = dataclasses.replace(sth, root_hash=b"\x33" * 32)  # different head, same signature
    assert signer.verify(tampered) is False


def test_public_key_pem_is_spki_pem():
    signer = AwsKmsTreeSigner(_KEY, client=_FakeKmsClient())
    pem = signer.public_key_pem
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    # Cached: a second access doesn't re-fetch (no exception, same value).
    assert signer.public_key_pem == pem


def test_requires_key():
    import pytest

    with pytest.raises(ValueError):
        AwsKmsTreeSigner("", client=_FakeKmsClient())


async def test_ledger_adapter_seals_and_sth_verifies():
    from quaicu.core.types import Action, ActionId, ActionState, Actor, ActorId, Decision, EvaluationResult, IdempotencyKey, TenantId

    adapter = AwsKmsLedgerAdapter(_KEY, client=_FakeKmsClient())
    action = Action(
        id=ActionId("act-1"),
        type="loan.approve",
        payload={},
        actor=Actor(id=ActorId("alice"), tenant=TenantId("acme")),
        tenant=TenantId("acme"),
        idempotency_key=IdempotencyKey("ik-1"),
        state=ActionState.EXECUTING,
        proposed_at=NOW,
    )
    evaluation = EvaluationResult(decision=Decision.ALLOW, policy_versions=("pol:v1",))
    entry = await adapter.seal(action=action, evaluation=evaluation, recorded_result={"ok": True})
    assert entry.ledger_seq >= 0
    sth = adapter.get_signed_tree_head(TenantId("acme"))
    assert adapter._signer.verify(sth) is True  # noqa: SLF001 - the AWS-KMS-signed STH verifies
