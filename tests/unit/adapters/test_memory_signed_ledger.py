"""MemorySignedLedgerAdapter — the no-external-deps signing ledger used by the underwriting demo.

Verifies the property that distinguishes it from the plain (unsigned) ``memory_ledger`` adapter: a
governed action sealed through it produces a proof bundle that **verifies offline** — RFC-6962
inclusion proofs against an Ed25519-signed tree head whose public key is embedded in the export.
Exercised end-to-end through ``Kernel.from_config`` on the shipped demo config, so it also covers the
``memory_signed_ledger`` + ``in_process`` registry wiring and the demo policy pack.
"""

from __future__ import annotations

from pathlib import Path

from quaicu.core.regmap.export import trusted_keys_from_signer, verify_ledger_proof_bundle
from quaicu.delivery.sdk.kernel import Kernel

_DEMO_CONFIG = Path(__file__).resolve().parents[3] / "examples" / "underwriting-demo" / "kernel.demo.toml"


def _as_dict(bundle: object) -> dict:
    return bundle.to_dict() if hasattr(bundle, "to_dict") else bundle  # type: ignore[return-value]


async def test_sealed_action_export_verifies_offline() -> None:
    kernel = Kernel.from_config(str(_DEMO_CONFIG))
    await kernel.startup()

    @kernel.guard(policy="credit.approve")
    async def draft(*, applicant: str, amount: int) -> dict:
        return {"applicant": applicant, "amount": amount}

    async with kernel.actor_context("agent:underwriter"):
        await draft(applicant="A. Sharma", amount=250_000)  # low-risk → allow → sealed

    bundle = _as_dict(kernel.export_ledger_proof(kernel.tenant))
    pin = trusted_keys_from_signer(kernel.engine._ledger._signer)  # type: ignore[attr-defined]
    ok, errors = verify_ledger_proof_bundle(bundle, trusted_keys=pin)

    assert ok, errors
    assert bundle["inclusion_proofs"], "expected at least one sealed action"
    # The signed STH carries a public key — the reason an export from this adapter verifies offline
    # whereas one from the unsigned `memory_ledger` adapter cannot.
    assert bundle["signed_tree_head"].get("public_key_pem")

    await kernel.shutdown()
