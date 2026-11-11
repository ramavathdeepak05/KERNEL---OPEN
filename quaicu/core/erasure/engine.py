"""ErasureEngine — encrypt PII under a per-subject key, decrypt, and crypto-shred (WS-G).

AES-256-GCM (AEAD) per data subject. A `CipherToken` is a self-describing envelope — version, tenant,
subject, key id, nonce, ciphertext — that travels with the stored record. Decryption looks the DEK up
by key id in the keyring; once the subject is crypto-shredded the DEK is gone, so `decrypt` raises
`SubjectErasedError` and the plaintext is unrecoverable by anyone, including the operator.

Crucially the token's nonce + ciphertext are stable bytes: a Merkle leaf computed over the *token*
stays valid after erasure (the proof still verifies), so the K·02 audit trail's integrity survives a
GDPR deletion — only the plaintext behind it dies.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quaicu.core.erasure.keyring import InMemoryShredKeyring, ShredKeyring, SubjectRef
from quaicu.core.errors import CipherTokenError, SubjectErasedError

_TOKEN_VERSION = "shred/1"


@dataclass(frozen=True)
class CipherToken:
    """A self-describing AES-GCM envelope for one PII value."""

    tenant: str
    subject: str
    key_id: str
    nonce_b64: str
    ciphertext_b64: str
    version: str = _TOKEN_VERSION

    def serialize(self) -> str:
        """Compact, URL-safe string form (base64 of the JSON envelope)."""
        raw = json.dumps(
            {
                "v": self.version,
                "t": self.tenant,
                "s": self.subject,
                "k": self.key_id,
                "n": self.nonce_b64,
                "c": self.ciphertext_b64,
            },
            sort_keys=True,
        ).encode()
        return base64.urlsafe_b64encode(raw).decode()

    @classmethod
    def deserialize(cls, token: str) -> "CipherToken":
        try:
            d = json.loads(base64.urlsafe_b64decode(token.encode()))
            return cls(
                tenant=d["t"], subject=d["s"], key_id=d["k"],
                nonce_b64=d["n"], ciphertext_b64=d["c"], version=d.get("v", _TOKEN_VERSION),
            )
        except Exception as exc:  # noqa: BLE001 — any parse failure is a bad token, fail-closed
            raise CipherTokenError(f"Malformed cipher token: {exc}") from exc


@dataclass(frozen=True)
class ErasureReceipt:
    """Proof that a subject was crypto-shredded — itself suitable for sealing into the ledger."""

    tenant: str
    subject: str
    erased: bool          # True if a key was destroyed; False if nothing existed to erase
    key_destroyed: bool
    erased_at: str
    method: str = "crypto-shredding/aes-256-gcm"


class ErasureEngine:
    """PII encryption + GDPR/DPDP crypto-shredding over a `ShredKeyring`."""

    def __init__(self, keyring: ShredKeyring | None = None) -> None:
        self._keyring = keyring or InMemoryShredKeyring()

    @staticmethod
    def _ref(tenant: str, subject: str) -> SubjectRef:
        return (str(tenant), str(subject))

    def encrypt(self, *, tenant: str, subject: str, plaintext: str, aad: str | None = None) -> CipherToken:
        """Encrypt ``plaintext`` under the subject's DEK. Raises `SubjectErasedError` if erased."""
        key_id, dek = self._keyring.get_or_create(self._ref(tenant, subject))
        import os

        nonce = os.urandom(12)
        associated = (aad or f"{tenant}:{subject}").encode()
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode(), associated)
        return CipherToken(
            tenant=str(tenant),
            subject=str(subject),
            key_id=key_id,
            nonce_b64=base64.b64encode(nonce).decode(),
            ciphertext_b64=base64.b64encode(ct).decode(),
        )

    def decrypt(self, token: CipherToken | str, *, aad: str | None = None) -> str:
        """Decrypt a cipher token. Raises `SubjectErasedError` if the subject was crypto-shredded."""
        tok = CipherToken.deserialize(token) if isinstance(token, str) else token
        ref = self._ref(tok.tenant, tok.subject)
        if self._keyring.is_erased(ref):
            raise SubjectErasedError(
                f"Subject {tok.subject!r} (tenant {tok.tenant!r}) was erased — data is irrecoverable.",
                detail={"tenant": tok.tenant, "subject": tok.subject},
            )
        dek = self._keyring.get(tok.key_id)
        if dek is None:
            # Key gone but no tombstone (e.g. unknown key id) — still fail-closed.
            raise SubjectErasedError(
                f"DEK {tok.key_id!r} is unavailable — data is irrecoverable.",
                detail={"tenant": tok.tenant, "subject": tok.subject, "key_id": tok.key_id},
            )
        associated = (aad or f"{tok.tenant}:{tok.subject}").encode()
        try:
            pt = AESGCM(dek).decrypt(
                base64.b64decode(tok.nonce_b64), base64.b64decode(tok.ciphertext_b64), associated
            )
        except InvalidTag as exc:
            raise CipherTokenError("Cipher token failed authentication (wrong key or tampered).") from exc
        return pt.decode()

    def erase(self, *, tenant: str, subject: str) -> ErasureReceipt:
        """Crypto-shred a data subject. Idempotent; returns a receipt suitable for the ledger."""
        destroyed = self._keyring.destroy(self._ref(tenant, subject))
        return ErasureReceipt(
            tenant=str(tenant),
            subject=str(subject),
            erased=True,
            key_destroyed=destroyed,
            erased_at=datetime.now(tz=timezone.utc).isoformat(),
        )

    def is_erased(self, *, tenant: str, subject: str) -> bool:
        return self._keyring.is_erased(self._ref(tenant, subject))
