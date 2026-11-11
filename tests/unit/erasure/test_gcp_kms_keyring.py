"""HSM-backed crypto-shred keyring (W6-4): GcpKmsShredKeyring envelope + erasure semantics."""

from __future__ import annotations

import pytest

from quaicu.adapters.erasure import GcpKmsShredKeyring, InMemoryWrappedDekStore
from quaicu.adapters.erasure.gcp_kms import ErasureDependencyError
from quaicu.core.erasure import ErasureEngine
from quaicu.core.errors import SubjectErasedError


class _Resp:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _FakeKms:
    """Reversible 'KMS': wrap = b'WRAP:' + dek; unwrap strips it. Records calls so a test can assert the
    DEK is only ever stored wrapped."""

    PREFIX = b"WRAP:"

    def encrypt(self, request=None):
        assert request["name"] == "projects/p/locations/global/keyRings/r/cryptoKeys/kek"
        return _Resp(ciphertext=self.PREFIX + request["plaintext"])

    def decrypt(self, request=None):
        ct = request["ciphertext"]
        assert ct.startswith(self.PREFIX)
        return _Resp(plaintext=ct[len(self.PREFIX):])


_KEK = "projects/p/locations/global/keyRings/r/cryptoKeys/kek"


def _keyring():
    return GcpKmsShredKeyring(_KEK, store=InMemoryWrappedDekStore(), kms_client=_FakeKms())


def test_full_cycle_encrypt_decrypt_then_erase():
    store = InMemoryWrappedDekStore()
    eng = ErasureEngine(GcpKmsShredKeyring(_KEK, store=store, kms_client=_FakeKms()))

    token = eng.encrypt(tenant="acme", subject="alice", plaintext="SSN 123-45-6789")
    assert eng.decrypt(token) == "SSN 123-45-6789"
    # The DEK is wrapped at rest — the store never holds raw key material, only WRAP:… blobs.
    wrapped_values = list(store._wrapped.values())  # noqa: SLF001 - test introspection
    assert wrapped_values and all(w.startswith(b"WRAP:") for w in wrapped_values)

    receipt = eng.erase(tenant="acme", subject="alice")
    assert receipt.erased and receipt.key_destroyed
    # After crypto-shred: decrypt fails closed, and the subject can't be resurrected.
    with pytest.raises(SubjectErasedError):
        eng.decrypt(token)
    assert eng.is_erased(tenant="acme", subject="alice")
    with pytest.raises(SubjectErasedError):
        eng.encrypt(tenant="acme", subject="alice", plaintext="again")


def test_get_or_create_is_stable_per_subject():
    kr = _keyring()
    kid1, dek1 = kr.get_or_create(("acme", "bob"))
    kid2, dek2 = kr.get_or_create(("acme", "bob"))
    assert kid1 == kid2 and dek1 == dek2  # unwrapped to the same DEK
    assert kr.get(kid1) == dek1


def test_destroy_is_idempotent_and_returns_false_when_nothing():
    kr = _keyring()
    assert kr.destroy(("acme", "ghost")) is False  # nothing to destroy, but now tombstoned
    assert kr.is_erased(("acme", "ghost")) is True
    assert kr.destroy(("acme", "ghost")) is False  # idempotent


def test_tenants_are_isolated():
    kr = _keyring()
    _, dek_a = kr.get_or_create(("acme", "alice"))
    _, dek_b = kr.get_or_create(("globex", "alice"))
    assert dek_a != dek_b  # same subject id, different tenant → different key


def test_requires_kek():
    with pytest.raises(ValueError):
        GcpKmsShredKeyring("")


def test_missing_kms_sdk_raises_dependency_error(monkeypatch):
    # Force the lazy `from google.cloud import kms` to fail, simulating no [gcp] extra.
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "google.cloud" and "kms" in (fromlist or ()):
            raise ImportError("no kms")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    kr = GcpKmsShredKeyring(_KEK)  # no injected client → must lazy-import
    with pytest.raises(ErasureDependencyError):
        kr.get_or_create(("acme", "x"))
