"""Consistency monitor / anchor orchestration (K·02 / D3-2).

Bridges the tenant's ledger and an independent `AnchorPort` (witness): it reads the current Signed
Tree Head, computes a consistency proof from the witness's last-seen size, and asks the witness to
cosign. If the current STH is not a consistent append-only extension of what the witness last saw —
a fork or silent rewind — the witness refuses and `LedgerTamperError` propagates (fail-closed).

Call at export time (so the bundle carries a fresh cosignature) and/or periodically from a scheduler.
"""

from __future__ import annotations

import logging
from typing import Protocol

from quaicu.core.errors import LedgerTamperError
from quaicu.core.ledger.signer import SignedTreeHead
from quaicu.core.ports.anchor import AnchorPort, WitnessCosignature
from quaicu.core.types import TenantId

log = logging.getLogger("quaicu.ledger.anchor")


class WitnessStateStore(Protocol):
    """The witness's durable memory of the last STH it cosigned per tenant (monotonic).

    Its integrity is the witness's security: it must survive restarts, or a replayed smaller STH
    after a restart would be treated as a fresh first STH and cosigned (a rewind slips through).
    """

    def get(self, tenant: TenantId) -> tuple[int, bytes] | None: ...

    def advance(self, tenant: TenantId, tree_size: int, root_hash: bytes) -> None:
        """Record (tree_size, root_hash) as the last seen. Advance-only — never regresses tree_size."""
        ...


class InMemoryWitnessStateStore:
    """Non-durable state store (dev / tests / single sovereign node). Advance-only."""

    def __init__(self) -> None:
        self._last: dict[TenantId, tuple[int, bytes]] = {}

    def get(self, tenant: TenantId) -> tuple[int, bytes] | None:
        return self._last.get(tenant)

    def advance(self, tenant: TenantId, tree_size: int, root_hash: bytes) -> None:
        cur = self._last.get(tenant)
        if cur is not None and tree_size < cur[0]:
            return  # never regress (the witness already verified consistency before calling)
        self._last[tenant] = (tree_size, root_hash)


class _LedgerView(Protocol):
    def get_signed_tree_head(self, tenant: TenantId) -> SignedTreeHead: ...
    def get_consistency_proof(
        self, tenant: TenantId, old_size: int
    ) -> tuple[bytes, bytes, list[bytes]]: ...
    def tenants(self) -> list[TenantId]: ...


def anchor_current_sth(
    ledger: _LedgerView, witness: AnchorPort, tenant: TenantId
) -> WitnessCosignature:
    """Anchor the tenant's current STH with an independent witness; return its cosignature.

    Raises ``LedgerTamperError`` (via the witness) if the current STH is not a consistent extension
    of the last one the witness cosigned — split-view / rewind detection.
    """
    sth = ledger.get_signed_tree_head(tenant)
    last = witness.last_seen(tenant)
    if last is None or last[0] >= sth.tree_size:
        # First STH, or same/smaller size — hand the witness an empty proof; it judges consistency
        # (a same-size fork or a smaller-size rewind both fail the witness's own check).
        proof: list[bytes] = []
    else:
        _, _, proof = ledger.get_consistency_proof(tenant, last[0])
    return witness.cosign(tenant, sth, proof)


def anchor_all_tenants(ledger: _LedgerView, witness: AnchorPort) -> dict[TenantId, str]:
    """Anchor every tenant that has an STH. Returns ``{tenant: "ok" | "<error>"}``.

    A tamper on one tenant is logged as a CRITICAL alert and does NOT stop anchoring the rest — the
    loop must keep observing every other tenant's log. Intended for a periodic scheduler.
    """
    results: dict[TenantId, str] = {}
    for tenant in ledger.tenants():
        try:
            anchor_current_sth(ledger, witness, tenant)
            results[tenant] = "ok"
        except LedgerTamperError as exc:
            log.critical("ledger anchor TAMPER for tenant=%s: %s", tenant, exc)
            results[tenant] = f"TAMPER: {exc.code}"
        except Exception as exc:  # noqa: BLE001 — an anchor outage must not crash the loop
            log.error("ledger anchor failed for tenant=%s: %s", tenant, exc)
            results[tenant] = f"error: {exc}"
    return results
