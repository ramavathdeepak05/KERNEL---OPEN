"""In-memory, Ed25519-signing ledger adapter.

``MemorySignedLedgerAdapter`` wraps the full RFC 6962 ``TrustLedger`` (K·02) with the software
``InMemoryEd25519Signer`` and an in-memory ``LedgerRepository``. Unlike the plain ``memory_ledger``
adapter (which does not sign), this one produces **signed tree heads with an embedded public key**, so
exported proof bundles verify offline via ``core.regmap.export.verify_ledger_proof_bundle`` — with zero
external dependencies (no OpenBao, no Cloud KMS).

Intended for **demos, the sovereign/air-gapped dev loop, and tests** — anywhere you want the real
transparency-log + offline-verifiable proof story without provisioning a signing backend. The signing
key is ephemeral (generated per process), so it is **not** durable across restarts; for production use
``openbao_ledger`` (sovereign), ``gcp_kms_ledger``, or ``aws_kms_ledger`` (HSM-rooted, stable key).

Use in kernel.toml::

    [adapters]
    ledger = "memory_signed_ledger"

Satisfies the ``Ledger`` protocol structurally (mirrors ``OpenBaoLedgerAdapter``).
"""

from __future__ import annotations

from typing import Any

from quaicu.core.ledger.engine import TrustLedger
from quaicu.core.ledger.repository import LedgerRepository
from quaicu.core.ledger.signer import InMemoryEd25519Signer
from quaicu.core.types import Action, ApproverRef, EvaluationResult, LedgerEntry


class MemorySignedLedgerAdapter:
    """RFC 6962 TrustLedger + ephemeral software Ed25519 signer + in-memory repository."""

    def __init__(self, repository: LedgerRepository | None = None) -> None:
        self._signer = InMemoryEd25519Signer()
        if repository is None:
            # Lazy import keeps the in-memory repo optional at module load.
            from quaicu.adapters.ledger.memory_repo import InMemoryLedgerRepository

            repository = InMemoryLedgerRepository()
        self._repository = repository
        self._ledger = TrustLedger(signer=self._signer, repository=repository)

    async def hydrate(self) -> None:
        """Rebuild the in-memory tree/entries/STHs from the repository (startup)."""
        await self._ledger.hydrate()

    # ── Ledger protocol ───────────────────────────────────────────────────────

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        return await self._ledger.seal(
            action=action,
            evaluation=evaluation,
            recorded_result=recorded_result,
            approver=approver,
        )

    # ── Read-side (pass-through to TrustLedger) ───────────────────────────────

    def get_entry(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_entry(tenant, seq)

    def get_entries(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_entries(tenant)

    def get_signed_tree_head(self, tenant):  # type: ignore[no-untyped-def]
        return self._ledger.get_signed_tree_head(tenant)

    def get_inclusion_proof(self, tenant, seq):  # type: ignore[no-untyped-def]
        return self._ledger.get_inclusion_proof(tenant, seq)

    def verify_inclusion(self, tenant, seq, sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_inclusion(tenant, seq, sth)

    def get_consistency_proof(self, tenant, old_size):  # type: ignore[no-untyped-def]
        return self._ledger.get_consistency_proof(tenant, old_size)

    def verify_consistency(self, tenant, old_sth, new_sth):  # type: ignore[no-untyped-def]
        return self._ledger.verify_consistency(tenant, old_sth, new_sth)

    async def close(self) -> None:
        if self._repository is not None:
            await self._repository.close()
