"""QUAICU ledger-witness service entrypoint (D3-2 follow-up; CLI: ``quaicu-kernel-witness``).

Runs the independent witness in its **own** process with its **own** key and durable state — the
out-of-process anchor the kernel calls via `HttpWitness`. Deploy separately from the kernel (ideally
different key custody) so a kernel compromise does not control the witness.

Environment:
    QUAICU_WITNESS_KEY_PEM   Ed25519 private-key PEM (the STABLE witness key; pin its public half).
                             Omit only in dev — an ephemeral key is generated and the pin changes on
                             every restart.
    QUAICU_WITNESS_ID        Stable witness id (default: derived from the key / a uuid).
    QUAICU_WITNESS_TOKEN     Shared bearer token the kernel presents on /cosign + /last-seen.
    QUAICU_WITNESS_DSN       Postgres DSN for durable last-seen state (run migration 016). Omit → an
                             in-memory store (loses rewind-detection memory on restart — dev only).
"""

from __future__ import annotations

import os

from quaicu.adapters.ledger.witness import SoftwareWitness
from quaicu.core.ledger.anchor import InMemoryWitnessStateStore
from quaicu.delivery.witness_app import create_witness_app


def _build_witness() -> SoftwareWitness:
    dsn = os.getenv("QUAICU_WITNESS_DSN", "").strip()
    if dsn:
        from quaicu.adapters.ledger.witness_store_postgres import PostgresWitnessStateStore

        store = PostgresWitnessStateStore(dsn)
    else:
        store = InMemoryWitnessStateStore()
    return SoftwareWitness(
        private_key_pem=os.getenv("QUAICU_WITNESS_KEY_PEM") or None,
        witness_id=os.getenv("QUAICU_WITNESS_ID") or None,
        state_store=store,
    )


app = create_witness_app(_build_witness(), auth_token=os.getenv("QUAICU_WITNESS_TOKEN") or None)


def main() -> None:
    """CLI entry point: ``quaicu-kernel-witness``."""
    import uvicorn

    host = os.getenv("WITNESS_HOST", "0.0.0.0")
    port = int(os.getenv("WITNESS_PORT", "7100"))
    uvicorn.run("quaicu.delivery.entrypoint_witness:app", host=host, port=port, workers=1)
