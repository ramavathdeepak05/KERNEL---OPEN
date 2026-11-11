"""Config-driven erasure wiring (W6-4).

Returns an `ErasureEngine` when ``[erasure].enabled``, else ``None`` (the erasure routes stay 503).
The keyring is selectable: ``memory`` (process-local, default) or ``gcp_kms`` (HSM-backed crypto-shred —
DEKs wrapped by a Cloud KMS KEK, wrapped blobs persisted in Postgres). Secrets/resources resolve from
``${ENV}`` so they stay out of the file.

Config shape::

    [erasure]
    enabled = true
    keyring = "gcp_kms"                       # "memory" | "gcp_kms"
    kek     = "${QUAICU_ERASURE_KEK}"         # KMS symmetric key resource (gcp_kms)
    dsn     = "${ERASURE_DSN}"                 # Postgres DSN for the durable wrapped-DEK store (gcp_kms)
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from typing import Any

from quaicu.core.erasure import ErasureEngine, InMemoryShredKeyring

log = logging.getLogger("quaicu.erasure")


def build_erasure(config: Mapping[str, Any]) -> ErasureEngine | None:
    section = config.get("erasure", {}) or {}
    if not section.get("enabled"):
        return None

    keyring_kind = str(section.get("keyring", "memory")).lower()
    if keyring_kind != "gcp_kms":
        return ErasureEngine(InMemoryShredKeyring())

    kek = (os.path.expandvars(str(section.get("kek", ""))) or os.getenv("QUAICU_ERASURE_KEK", "")).strip()
    if not kek:
        log.warning("[erasure] keyring=gcp_kms but no 'kek' configured — falling back to in-memory keyring.")
        return ErasureEngine(InMemoryShredKeyring())

    from quaicu.adapters.erasure import (
        GcpKmsShredKeyring,
        InMemoryWrappedDekStore,
        PostgresWrappedDekStore,
    )

    dsn = (os.path.expandvars(str(section.get("dsn", ""))) or os.getenv("ERASURE_DSN", "")).strip()
    if dsn:
        store: Any = PostgresWrappedDekStore(dsn)
    else:
        log.warning("[erasure] keyring=gcp_kms but no 'dsn' — wrapped DEKs are in-memory (NOT durable).")
        store = InMemoryWrappedDekStore()

    return ErasureEngine(GcpKmsShredKeyring(kek, store=store))
