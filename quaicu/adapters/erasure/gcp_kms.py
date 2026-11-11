"""HSM-backed crypto-shred keyring — DEKs wrapped by a Cloud KMS KEK (W6-4).

`InMemoryShredKeyring` keeps per-subject DEKs in process memory. This `GcpKmsShredKeyring` instead uses
**envelope encryption**: a per-subject 256-bit DEK is generated, immediately **wrapped** (encrypted) by
a Cloud KMS symmetric key (the KEK — FIPS 140-2 HSM-protected, non-extractable), and only the wrapped
blob is persisted (in a `WrappedDekStore`). The plaintext DEK exists in-process only transiently for the
AES-GCM call. **Erasure** deletes the wrapped DEK + tombstones the subject, so the DEK can never be
unwrapped again — provable crypto-shredding whose root of trust is the HSM.

Same `ShredKeyring` interface as the in-memory keyring, so `ErasureEngine` + call sites are unchanged.
The KMS client + ``google-cloud-kms`` import are lazy (``[gcp]`` extra) and the client is injectable.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any, Protocol, runtime_checkable

from quaicu.core.erasure.keyring import SubjectRef


class ErasureDependencyError(RuntimeError):
    """Raised when the Cloud KMS SDK (``google-cloud-kms``, ``[gcp]`` extra) isn't installed."""


@runtime_checkable
class WrappedDekStore(Protocol):
    """Durable home for wrapped DEKs + the subject→key_id map + tombstones."""

    def key_id_for(self, ref: SubjectRef) -> str | None: ...
    def get(self, key_id: str) -> bytes | None: ...
    def put(self, ref: SubjectRef, key_id: str, wrapped: bytes) -> None: ...
    def delete(self, ref: SubjectRef) -> str | None:
        """Remove the wrapped DEK for ``ref``; return its key_id, or None if absent."""
        ...
    def tombstone(self, ref: SubjectRef) -> None: ...
    def is_tombstoned(self, ref: SubjectRef) -> bool: ...


class InMemoryWrappedDekStore:
    """Process-local `WrappedDekStore` (default; thread-safe). Not durable across restarts."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._wrapped: dict[str, bytes] = {}              # key_id -> wrapped DEK
        self._key_id: dict[SubjectRef, str] = {}          # subject -> key_id
        self._erased: set[SubjectRef] = set()

    def key_id_for(self, ref: SubjectRef) -> str | None:
        with self._lock:
            return self._key_id.get(ref)

    def get(self, key_id: str) -> bytes | None:
        with self._lock:
            return self._wrapped.get(key_id)

    def put(self, ref: SubjectRef, key_id: str, wrapped: bytes) -> None:
        with self._lock:
            self._key_id[ref] = key_id
            self._wrapped[key_id] = wrapped

    def delete(self, ref: SubjectRef) -> str | None:
        with self._lock:
            key_id = self._key_id.pop(ref, None)
            if key_id is not None:
                self._wrapped.pop(key_id, None)
            return key_id

    def tombstone(self, ref: SubjectRef) -> None:
        with self._lock:
            self._erased.add(ref)

    def is_tombstoned(self, ref: SubjectRef) -> bool:
        with self._lock:
            return ref in self._erased


class GcpKmsShredKeyring:
    """`ShredKeyring` backed by Cloud KMS envelope encryption. ``store`` + ``kms_client`` injectable."""

    def __init__(
        self,
        kek_name: str,
        *,
        store: WrappedDekStore | None = None,
        kms_client: Any | None = None,
    ) -> None:
        if not kek_name:
            raise ValueError("GcpKmsShredKeyring requires a KMS key resource name (the KEK).")
        self._kek = kek_name
        self._store: WrappedDekStore = store or InMemoryWrappedDekStore()
        self._client = kms_client

    def _kms(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import kms  # lazy ([gcp] extra)
            except ImportError as exc:  # pragma: no cover - exercised via the no-SDK test
                raise ErasureDependencyError(
                    "KMS crypto-shred requires the 'gcp' extra: pip install quaicu-kernel[gcp]."
                ) from exc
            self._client = kms.KeyManagementServiceClient()
        return self._client

    def _wrap(self, dek: bytes) -> bytes:
        return self._kms().encrypt(request={"name": self._kek, "plaintext": dek}).ciphertext

    def _unwrap(self, wrapped: bytes) -> bytes:
        return self._kms().decrypt(request={"name": self._kek, "ciphertext": wrapped}).plaintext

    def get_or_create(self, ref: SubjectRef) -> tuple[str, bytes]:
        from quaicu.core.errors import SubjectErasedError

        if self._store.is_tombstoned(ref):
            raise SubjectErasedError(
                f"Subject {ref[1]!r} (tenant {ref[0]!r}) is erased; cannot mint a new key.",
                detail={"tenant": ref[0], "subject": ref[1]},
            )
        key_id = self._store.key_id_for(ref)
        if key_id is not None:
            wrapped = self._store.get(key_id)
            if wrapped is not None:
                return key_id, self._unwrap(wrapped)
        dek = secrets.token_bytes(32)  # AES-256, plaintext only in-process
        key_id = f"dek_{secrets.token_hex(8)}"
        self._store.put(ref, key_id, self._wrap(dek))
        return key_id, dek

    def get(self, key_id: str) -> bytes | None:
        wrapped = self._store.get(key_id)
        return self._unwrap(wrapped) if wrapped is not None else None

    def destroy(self, ref: SubjectRef) -> bool:
        self._store.tombstone(ref)  # tombstone first (idempotent, no resurrection)
        return self._store.delete(ref) is not None

    def is_erased(self, ref: SubjectRef) -> bool:
        return self._store.is_tombstoned(ref)
