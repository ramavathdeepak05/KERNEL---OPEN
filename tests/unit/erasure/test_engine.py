"""Unit tests for the crypto-shredding ErasureEngine (WS-G)."""

from __future__ import annotations

import pytest

from quaicu.core.erasure import ErasureEngine
from quaicu.core.erasure.engine import CipherToken
from quaicu.core.errors import CipherTokenError, SubjectErasedError
from quaicu.core.ledger.merkle import leaf_hash

TENANT = "ciro-bank"
SUBJECT = "data-principal-42"


def _engine() -> ErasureEngine:
    return ErasureEngine()


# ── Encrypt / decrypt round-trip ─────────────────────────────────────────────────


def test_encrypt_decrypt_roundtrip():
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="Aadhaar 1234-5678-9012")
    assert eng.decrypt(token) == "Aadhaar 1234-5678-9012"


def test_token_serialization_roundtrip():
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="secret")
    wire = token.serialize()
    assert eng.decrypt(wire) == "secret"  # decrypt accepts the string form too


def test_same_subject_reuses_key():
    eng = _engine()
    t1 = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="a")
    t2 = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="b")
    assert t1.key_id == t2.key_id


def test_distinct_subjects_get_distinct_keys():
    eng = _engine()
    t1 = eng.encrypt(tenant=TENANT, subject="alice", plaintext="x")
    t2 = eng.encrypt(tenant=TENANT, subject="bob", plaintext="x")
    assert t1.key_id != t2.key_id


def test_ciphertext_is_not_plaintext():
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="Aadhaar")
    assert "Aadhaar" not in token.ciphertext_b64


# ── Crypto-shredding ─────────────────────────────────────────────────────────────


def test_erase_makes_data_irrecoverable():
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="PII")
    receipt = eng.erase(tenant=TENANT, subject=SUBJECT)
    assert receipt.erased is True
    assert receipt.key_destroyed is True
    with pytest.raises(SubjectErasedError):
        eng.decrypt(token)


def test_erase_is_idempotent():
    eng = _engine()
    eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="PII")
    first = eng.erase(tenant=TENANT, subject=SUBJECT)
    second = eng.erase(tenant=TENANT, subject=SUBJECT)
    assert first.key_destroyed is True
    assert second.key_destroyed is False  # nothing left to destroy
    assert eng.is_erased(tenant=TENANT, subject=SUBJECT)


def test_no_resurrection_after_erase():
    eng = _engine()
    eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="PII")
    eng.erase(tenant=TENANT, subject=SUBJECT)
    # Encrypting again for an erased subject must fail — no silent new key.
    with pytest.raises(SubjectErasedError):
        eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="new")


def test_erase_one_subject_does_not_affect_another():
    eng = _engine()
    ta = eng.encrypt(tenant=TENANT, subject="alice", plaintext="alice-pii")
    tb = eng.encrypt(tenant=TENANT, subject="bob", plaintext="bob-pii")
    eng.erase(tenant=TENANT, subject="alice")
    with pytest.raises(SubjectErasedError):
        eng.decrypt(ta)
    assert eng.decrypt(tb) == "bob-pii"  # bob is untouched


def test_tenant_scopes_subjects():
    eng = _engine()
    eng.encrypt(tenant="tenant-a", subject="same-id", plaintext="a")
    tb = eng.encrypt(tenant="tenant-b", subject="same-id", plaintext="b")
    eng.erase(tenant="tenant-a", subject="same-id")
    # Erasing tenant-a's subject leaves tenant-b's same-named subject intact (F-07).
    assert eng.decrypt(tb) == "b"


# ── Tamper / fail-closed ─────────────────────────────────────────────────────────


def test_malformed_token_rejected():
    with pytest.raises(CipherTokenError):
        _engine().decrypt("not-a-token")


def test_tampered_ciphertext_rejected():
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="PII")
    import base64

    ct = bytearray(base64.b64decode(token.ciphertext_b64))
    ct[0] ^= 0xFF
    tampered = CipherToken(
        tenant=token.tenant, subject=token.subject, key_id=token.key_id,
        nonce_b64=token.nonce_b64, ciphertext_b64=base64.b64encode(bytes(ct)).decode(),
    )
    with pytest.raises(CipherTokenError):
        eng.decrypt(tampered)


# ── Ledger integrity survives erasure (the WS-G invariant) ───────────────────────


def test_merkle_leaf_over_token_is_stable_after_erasure():
    # A Merkle leaf computed over the cipher TOKEN does not change when the subject is erased —
    # the K·02 audit trail's hashes/proofs stay valid; only the plaintext behind them dies.
    eng = _engine()
    token = eng.encrypt(tenant=TENANT, subject=SUBJECT, plaintext="PII")
    wire = token.serialize().encode()
    leaf_before = leaf_hash(wire)
    eng.erase(tenant=TENANT, subject=SUBJECT)
    leaf_after = leaf_hash(wire)
    assert leaf_before == leaf_after  # the sealed bytes are unchanged
    with pytest.raises(SubjectErasedError):
        eng.decrypt(token)  # but the data is gone
