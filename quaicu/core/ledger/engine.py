"""K·02 TrustLedger — per-tenant RFC 6962 transparency log.

ADR invariants enforced here:
  F-06: RFC 6962 Merkle tree, no custom proof structures.
  F-07: Strict per-tenant isolation — each tenant owns a completely separate MerkleTree,
        sequence counter, and entry list. Cross-tenant contamination is structurally impossible.
  F-03: Fail-closed — any exception in `seal` raises LedgerSealError so the engine HALTS.
  F-09: Replay-safe — recorded_result is stored in the entry verbatim at original execution.
  F-04: No bypass — TrustLedger depends only on core.types, core.errors, and its own submodules.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from collections import defaultdict

from quaicu.core.errors import LedgerSealError, LedgerSequenceConflictError
from quaicu.core.ledger.merkle import MerkleTree
from quaicu.core.ledger.repository import LedgerRepository
from quaicu.core.ledger.signer import InMemoryEd25519Signer, SignedTreeHead, TreeSigner
from quaicu.core.types import (
    Action,
    ApproverRef,
    EvaluationResult,
    LedgerEntry,
    TenantId,
)

_log = logging.getLogger("quaicu.ledger")


# ── Canonical serialization ───────────────────────────────────────────────────


def _canonical_bytes(
    action: Action,
    evaluation: EvaluationResult,
    recorded_result: Any,
    approver: ApproverRef | None,
    consent_state: dict[str, Any] | None = None,
    governance_profile: list[str] | None = None,
) -> bytes:
    """Deterministic serialization of a seal request for hashing.

    sort_keys=True and ensure_ascii=True guarantee byte-identical output across Python versions
    and locales. `default=str` handles any non-JSON-native value without raising.
    consent_state is included so the K·04 state at evaluation time is covered by the Merkle leaf.
    """
    d = {
        "action_id": str(action.id),
        "action_type": action.type,
        "tenant": str(action.tenant),
        "actor_id": str(action.actor.id),
        # Actor roles are sealed alongside actor_id so role-gated policies are point-in-time
        # replayable (F-09) and the roles are tamper-evident (ADR-0006).
        "actor_roles": list(action.actor.roles),
        # payload is part of the sealed leaf so post-hoc payload tampering in storage is
        # detectable against the transparency log (F-09). default=str below handles any
        # non-JSON-native value the payload may carry.
        "payload": dict(action.payload),
        "decision": evaluation.decision.value,
        "policy_versions": list(evaluation.policy_versions),
        "approver": str(approver) if approver else None,
        "consent_state": consent_state or {},
        # The set of governance layers that were enforced for this action — sealed so an auditor
        # can verify which controls actually ran (composable enforcement).
        "governance_profile": governance_profile or [],
        # Seal the result verbatim (not only dicts) so strings/lists/scalars are covered by
        # the Merkle leaf; default=str serializes anything non-JSON-native.
        "recorded_result": recorded_result,
    }
    return json.dumps(d, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")


# ── TrustLedger ───────────────────────────────────────────────────────────────


class TrustLedger:
    """K·02. Per-tenant RFC 6962 transparency log.

    Tenant isolation: each tenant gets a completely separate MerkleTree and sequence counter.
    No tenant's entries ever appear in another tenant's tree.
    """

    def __init__(
        self,
        signer: TreeSigner | None = None,
        repository: LedgerRepository | None = None,
    ) -> None:
        self._signer: TreeSigner = signer or InMemoryEd25519Signer()
        self._trees: dict[TenantId, MerkleTree] = {}
        self._sequences: dict[TenantId, int] = {}
        self._entries: dict[TenantId, list[LedgerEntry]] = {}
        self._sths: dict[TenantId, SignedTreeHead] = {}
        # Optional durable backend. When set, `seal` persists each entry + STH write-through and
        # `hydrate()` rebuilds the in-memory trees/entries/STHs from it on startup. The read/proof
        # path never touches it — the in-memory trees stay the fast path (mirrors ADR-0005).
        self._repository = repository
        # Single asyncio lock — seals are serialized to keep sequence numbers monotonic.
        self._lock: asyncio.Lock = asyncio.Lock()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _ensure_tenant(self, tenant: TenantId) -> None:
        if tenant not in self._trees:
            self._trees[tenant] = MerkleTree()
            self._sequences[tenant] = 0
            self._entries[tenant] = []

    # ── Ledger protocol ───────────────────────────────────────────────────────

    # Bounded optimistic retries when another worker wins a sequence slot (multi-worker sealing).
    _MAX_SEAL_ATTEMPTS = 3

    async def seal(
        self,
        *,
        action: Action,
        evaluation: EvaluationResult,
        recorded_result: Any,
        approver: ApproverRef | None = None,
    ) -> LedgerEntry:
        """Seal an action into the per-tenant transparency log.

        Raises LedgerSealError on ANY failure so the lifecycle engine HALTS the action (F-03).
        An action is never marked COMPLETED without a successful seal.

        Multi-worker linearization (D4-1): the durable `append_entry` is the linearization point —
        a seal succeeds iff its row actually inserted at (tenant, ledger_seq). When a sibling
        worker wins the slot the repository raises `LedgerSequenceConflictError`; this method rolls
        back the in-memory append, rehydrates the tenant's tree from the durable log, and retries
        (bounded), then fails closed. Each worker's in-memory tree is therefore always a consistent
        PREFIX of the durable log — proofs served by a lagging worker are RFC 6962-consistent,
        never a fork.
        """
        try:
            async with self._lock:
                tenant = action.tenant
                self._ensure_tenant(tenant)

                # Extract K·04 consent state from evaluation metadata so it is
                # covered by the Merkle leaf hash and resolvable point-in-time.
                consent_state = dict(evaluation.metadata.get("consent_state", {}))
                # The enforced governance layers (composable enforcement) — sealed for audit.
                governance_profile = list(evaluation.metadata.get("governance_profile", []))

                # Leaf bytes are position-independent (no seq inside), so the same leaf is
                # re-appended at the fresh position on each retry.
                entry_bytes = _canonical_bytes(
                    action, evaluation, recorded_result, approver, consent_state, governance_profile
                )

                for attempt in range(1, self._MAX_SEAL_ATTEMPTS + 1):
                    seq = self._sequences[tenant]
                    idx, lh = self._trees[tenant].append(entry_bytes)
                    now = datetime.now(tz=timezone.utc)

                    # Build the entry, sign the new head, and (write-through) persist both BEFORE
                    # committing the rest of the in-memory state. If signing or the durable write
                    # fails, roll back the tree append so the in-memory tree never gets ahead of
                    # the durable log; the failure propagates → LedgerSealError → HALT (F-03).
                    try:
                        entry = LedgerEntry(
                            ledger_seq=seq,
                            tenant=tenant,
                            action_id=action.id,
                            action_type=action.type,
                            actor_id=action.actor.id,
                            decision=evaluation.decision,
                            policy_versions=evaluation.policy_versions,
                            leaf_hash=lh,
                            sealed_at=now,
                            approver=approver,
                            consent_state=consent_state,
                            recorded_result=recorded_result
                            if isinstance(recorded_result, dict)
                            else {},
                            actor_roles=tuple(action.actor.roles),
                        )
                        root = self._trees[tenant].root()
                        # Sign off the event loop: a durable signer (Cloud KMS / OpenBao) makes a
                        # blocking network call, and seal runs in the request path. The global lock
                        # above already serializes signs, so the (non-thread-safe) signer client is
                        # never used concurrently.
                        sth = await asyncio.to_thread(
                            self._signer.sign, self._trees[tenant].size, root, now
                        )
                        if self._repository is not None:
                            await self._repository.append_entry(entry)
                            await self._repository.save_sth(tenant, sth)
                    except LedgerSequenceConflictError:
                        # A sibling worker won this seq. Undo our speculative append, resync this
                        # tenant's tree from the durable log, and retry at the new position.
                        self._trees[tenant].pop_last()
                        if attempt >= self._MAX_SEAL_ATTEMPTS:
                            raise
                        _log.warning(
                            "ledger seq conflict — rehydrating tenant and retrying",
                            extra={"tenant": tenant, "seq": seq, "attempt": attempt},
                        )
                        await self._rehydrate_tenant(tenant)
                        continue
                    except Exception:
                        self._trees[tenant].pop_last()  # undo the append; nothing else committed
                        raise

                    # Durable write succeeded (or no repository) — commit the in-memory state.
                    self._entries[tenant].append(entry)
                    self._sequences[tenant] = seq + 1
                    self._sths[tenant] = sth

                    _log.debug(
                        "sealed action",
                        extra={
                            "tenant": tenant,
                            "seq": seq,
                            "action_id": str(action.id),
                            "tree_size": self._trees[tenant].size,
                        },
                    )
                    return entry

                raise LedgerSealError(  # pragma: no cover — loop exits via return or raise
                    f"seal retries exhausted for action {action.id}",
                    detail={"action_id": str(action.id), "tenant": str(action.tenant)},
                )

        except LedgerSealError:
            raise
        except Exception as exc:
            raise LedgerSealError(
                f"Failed to seal action {action.id} for tenant {action.tenant}: {exc}",
                detail={"action_id": str(action.id), "tenant": str(action.tenant)},
            ) from exc

    async def _rehydrate_tenant(self, tenant: TenantId) -> None:
        """Resync one tenant's in-memory tree/entries/sequence from the durable log.

        Called (under the seal lock) after a sequence conflict proved this worker's view stale.
        The STH is deliberately left to the retry that follows (it re-signs the new head).
        """
        if self._repository is None:  # pragma: no cover — conflicts only arise with a repository
            return
        tenant_entries = await self._repository.load_tenant_entries(tenant)
        tenant_entries.sort(key=lambda e: e.ledger_seq)
        tree = MerkleTree()
        for entry in tenant_entries:
            tree.append_leaf_hash(entry.leaf_hash)
        self._trees[tenant] = tree
        self._entries[tenant] = list(tenant_entries)
        self._sequences[tenant] = (
            tenant_entries[-1].ledger_seq + 1 if tenant_entries else 0
        )

    async def hydrate(self) -> None:
        """Rebuild the in-memory trees, entries, and STHs from the durable repository.

        Called once at startup (via the adapter / kernel). No-op when no repository is wired.
        Idempotent: it resets and reloads, so calling it twice yields the same state. Each tenant's
        Merkle tree is rebuilt from the stored leaf hashes (append-only, in seq order); the latest
        STH is restored, or recomputed and re-signed if a tenant has entries but no stored head.
        """
        if self._repository is None:
            return
        async with self._lock:
            entries = await self._repository.load_entries()
            sths = await self._repository.load_sths()

            self._trees.clear()
            self._sequences.clear()
            self._entries.clear()
            self._sths.clear()

            by_tenant: dict[TenantId, list[LedgerEntry]] = defaultdict(list)
            for entry in entries:
                by_tenant[entry.tenant].append(entry)

            for tenant, tenant_entries in by_tenant.items():
                tenant_entries.sort(key=lambda e: e.ledger_seq)
                tree = MerkleTree()
                for entry in tenant_entries:
                    tree.append_leaf_hash(entry.leaf_hash)
                self._trees[tenant] = tree
                self._entries[tenant] = list(tenant_entries)
                self._sequences[tenant] = tenant_entries[-1].ledger_seq + 1

                sth = sths.get(str(tenant))
                if sth is None:
                    # Entries exist but no stored head — recompute the root and re-sign (off-loop:
                    # hydrate runs in the startup path and a durable signer makes a blocking call).
                    sth = await asyncio.to_thread(
                        self._signer.sign, tree.size, tree.root(), datetime.now(tz=timezone.utc)
                    )
                self._sths[tenant] = sth

    # ── Read-side operations ──────────────────────────────────────────────────

    def get_entry(self, tenant: TenantId, seq: int) -> LedgerEntry:
        """Return the entry at sequence number `seq` for `tenant`."""
        entries = self._entries.get(tenant, [])
        if seq < 0 or seq >= len(entries):
            raise KeyError(f"No entry at seq={seq} for tenant={tenant}")
        return entries[seq]

    def get_entries(self, tenant: TenantId) -> list[LedgerEntry]:
        """Return all sealed entries for `tenant` in sequence order (F-07: tenant-scoped)."""
        return list(self._entries.get(tenant, []))

    def get_signed_tree_head(self, tenant: TenantId) -> SignedTreeHead:
        """Return the current Signed Tree Head for `tenant`."""
        if tenant not in self._sths:
            raise KeyError(f"No STH for tenant={tenant}")
        return self._sths[tenant]

    def tenants(self) -> list[TenantId]:
        """Tenants that have at least one sealed entry (i.e. a current STH) — for periodic anchoring."""
        return list(self._sths.keys())

    def get_inclusion_proof(
        self, tenant: TenantId, seq: int
    ) -> tuple[bytes, list[bytes]]:
        """Return (leaf_hash, proof_path) for the entry at `seq`."""
        entry = self.get_entry(tenant, seq)
        tree = self._trees[tenant]
        proof = tree.inclusion_proof(seq)
        return entry.leaf_hash, proof

    def verify_inclusion(
        self, tenant: TenantId, seq: int, sth: SignedTreeHead
    ) -> bool:
        """Verify that entry `seq` is included in the tree described by `sth`."""
        tree = self._trees.get(tenant)
        if tree is None:
            return False
        entry = self.get_entry(tenant, seq)
        proof = tree.inclusion_proof(seq)
        return tree.verify_inclusion(seq, entry.leaf_hash, proof, sth.root_hash)

    def get_consistency_proof(
        self, tenant: TenantId, old_size: int
    ) -> tuple[bytes, bytes, list[bytes]]:
        """Return (old_root, new_root, proof_path) from old_size to current size."""
        tree = self._trees.get(tenant)
        if tree is None:
            raise KeyError(f"No tree for tenant={tenant}")
        # Compute the old root from just the first old_size leaves.
        from quaicu.core.ledger.merkle import compute_root

        old_leaves = list(tree._leaves[:old_size])
        old_root = compute_root(old_leaves)
        new_root = tree.root()
        proof = tree.consistency_proof(old_size)
        return old_root, new_root, proof

    def verify_consistency(
        self,
        tenant: TenantId,
        old_sth: SignedTreeHead,
        new_sth: SignedTreeHead,
    ) -> bool:
        """Verify that old_sth and new_sth describe the same append-only prefix."""
        tree = self._trees.get(tenant)
        if tree is None:
            return False
        proof = tree.consistency_proof(old_sth.tree_size)
        return tree.verify_consistency(
            old_sth.tree_size,
            old_sth.root_hash,
            new_sth.tree_size,
            new_sth.root_hash,
            proof,
        )
