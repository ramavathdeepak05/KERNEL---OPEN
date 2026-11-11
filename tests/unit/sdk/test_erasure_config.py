"""build_erasure config wiring (W6-4)."""

from __future__ import annotations

from quaicu.adapters.erasure import GcpKmsShredKeyring
from quaicu.core.erasure import ErasureEngine, InMemoryShredKeyring
from quaicu.delivery.sdk.erasure_config import build_erasure


def test_disabled_returns_none():
    assert build_erasure({}) is None
    assert build_erasure({"erasure": {"enabled": False}}) is None


def test_memory_keyring():
    eng = build_erasure({"erasure": {"enabled": True, "keyring": "memory"}})
    assert isinstance(eng, ErasureEngine)
    assert isinstance(eng._keyring, InMemoryShredKeyring)  # noqa: SLF001


def test_gcp_kms_without_kek_falls_back_to_memory():
    eng = build_erasure({"erasure": {"enabled": True, "keyring": "gcp_kms"}})
    assert isinstance(eng._keyring, InMemoryShredKeyring)  # noqa: SLF001 - no KEK → safe fallback


def test_gcp_kms_with_kek_no_dsn_uses_inmemory_store():
    eng = build_erasure(
        {"erasure": {"enabled": True, "keyring": "gcp_kms", "kek": "projects/p/.../kek"}}
    )
    assert isinstance(eng._keyring, GcpKmsShredKeyring)  # noqa: SLF001
