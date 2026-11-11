"""Per-subject data-encryption keys + crypto-shredding (WS-G).

A `ShredKeyring` owns one 256-bit AES key (DEK) per data subject. Encryption fetches/creates the
subject's DEK; **erasure destroys it** and leaves a tombstone so the subject is permanently marked
erased (any later decrypt fails fail-closed; a new key is never silently minted for an erased
subject). Keys live per tenant — a subject id is scoped by tenant so two tenants' subjects never share
a key (F-07).

`InMemoryShredKeyring` is the single-process default. A production deployment swaps it for an
HSM/KMS-backed keyring (the DEK never leaves the HSM; "destroy" calls the KMS key-destruction API)
behind the same interface — the engine and call sites are unchanged.
"""

from __future__ import annotations

import secrets
import threading
from typing import Protocol, runtime_checkable

# A composite key identity: erasure operates on (tenant, subject).
SubjectRef = tuple[str, str]


@runtime_checkable
class ShredKeyring(Protocol):
    """Manages per-subject DEKs and their destruction."""

    def get_or_create(self, ref: SubjectRef) -> tuple[str, bytes]:
        """Return ``(key_id, dek)`` for a subject, creating one if absent.

        Raises `SubjectErasedError` if the subject was already crypto-shredded (no resurrection)."""
        ...

    def get(self, key_id: str) -> bytes | None:
        """Return the DEK for ``key_id``, or None if unknown/destroyed."""
        ...

    def destroy(self, ref: SubjectRef) -> bool:
        """Crypto-shred the subject: destroy the DEK and tombstone the subject. Idempotent.

        Returns True if a key was destroyed, False if there was nothing to destroy (already erased
        or never had data)."""
        ...

    def is_erased(self, ref: SubjectRef) -> bool:
        """True if the subject has been crypto-shredded."""
        ...


class InMemoryShredKeyring:
    """Process-local keyring. Thread-safe; tombstones erased subjects."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._dek_by_key_id: dict[str, bytes] = {}
        self._key_id_by_subject: dict[SubjectRef, str] = {}
        self._erased: set[SubjectRef] = set()

    def get_or_create(self, ref: SubjectRef) -> tuple[str, bytes]:
        from quaicu.core.errors import SubjectErasedError

        with self._lock:
            if ref in self._erased:
                raise SubjectErasedError(
                    f"Subject {ref[1]!r} (tenant {ref[0]!r}) is erased; cannot mint a new key.",
                    detail={"tenant": ref[0], "subject": ref[1]},
                )
            key_id = self._key_id_by_subject.get(ref)
            if key_id is not None:
                return key_id, self._dek_by_key_id[key_id]
            key_id = f"dek_{secrets.token_hex(8)}"
            dek = secrets.token_bytes(32)  # AES-256
            self._dek_by_key_id[key_id] = dek
            self._key_id_by_subject[ref] = key_id
            return key_id, dek

    def get(self, key_id: str) -> bytes | None:
        with self._lock:
            return self._dek_by_key_id.get(key_id)

    def destroy(self, ref: SubjectRef) -> bool:
        with self._lock:
            self._erased.add(ref)  # tombstone first (idempotent, no-resurrection)
            key_id = self._key_id_by_subject.pop(ref, None)
            if key_id is None:
                return False
            # Overwrite then drop the DEK bytes — best-effort scrub before release.
            existing = self._dek_by_key_id.get(key_id)
            if existing is not None:
                self._dek_by_key_id[key_id] = b"\x00" * len(existing)
            self._dek_by_key_id.pop(key_id, None)
            return True

    def is_erased(self, ref: SubjectRef) -> bool:
        with self._lock:
            return ref in self._erased
