"""K·14 Regulatory Mapping — regulation catalog and evidence pack generation.

Rules:
- Evidence is ALWAYS point-in-time: built from the policy versions and regulation text
  in effect in the queried window, not the current versions.
- Regulation change → flag mapped policies review_required; NEVER auto-mutate a policy.
- Evidence pack MUST reference K·02 inclusion proofs + STH. A pack without proofs is
  not considered verifiable and must not be represented as such.
- Per-tenant scoping: never include another tenant's ledger entries in an evidence pack.
"""

from __future__ import annotations

import dataclasses
import threading
from datetime import datetime, timezone

from quaicu.core.regmap.model import (
    EvidenceManifest,
    EvidencePack,
    MappingStatus,
    PolicyMapping,
    RegulationRef,
)
from quaicu.core.types import LedgerEntry


class RegulationCatalog:
    """In-memory regulation registry and policy-mapping store.

    Thread-safe (threading.Lock). All updates return new frozen values.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._regulations: dict[str, RegulationRef] = {}
        self._mappings: dict[str, list[PolicyMapping]] = {}  # regulation_ref_id → [mapping]

    def register_regulation(self, regulation: RegulationRef) -> None:
        with self._lock:
            self._regulations[regulation.id] = regulation

    def get_regulation(self, ref_id: str) -> RegulationRef | None:
        with self._lock:
            return self._regulations.get(ref_id)

    def register_mapping(self, mapping: PolicyMapping) -> PolicyMapping:
        mapped = dataclasses.replace(mapping, mapped_at=mapping.mapped_at or datetime.now(tz=timezone.utc))
        with self._lock:
            self._mappings.setdefault(mapping.regulation_ref_id, []).append(mapped)
        return mapped

    def list_mappings(self, regulation_ref_id: str) -> list[PolicyMapping]:
        with self._lock:
            return list(self._mappings.get(regulation_ref_id, []))

    def flag_review_required(self, regulation_ref_id: str) -> list[PolicyMapping]:
        """Flag all active mappings for a regulation as review_required.

        Called when the regulation text changes. Returns the updated mapping list.
        NEVER mutates a policy — only updates the mapping status.
        """
        now = datetime.now(tz=timezone.utc)
        updated: list[PolicyMapping] = []
        with self._lock:
            current = self._mappings.get(regulation_ref_id, [])
            new_list: list[PolicyMapping] = []
            for m in current:
                if m.status == MappingStatus.ACTIVE:
                    m = dataclasses.replace(
                        m, status=MappingStatus.REVIEW_REQUIRED, flagged_at=now
                    )
                new_list.append(m)
                updated.append(m)
            self._mappings[regulation_ref_id] = new_list
        return updated

    def get_active_mappings_for_policy(self, policy_id: str) -> list[PolicyMapping]:
        with self._lock:
            result = []
            for mappings in self._mappings.values():
                for m in mappings:
                    if m.policy_id == policy_id and m.status == MappingStatus.ACTIVE:
                        result.append(m)
        return result


def generate_evidence_pack(
    *,
    tenant_id: str,
    regulation_refs: list[str],
    policy_versions: list[str],
    ledger_entries: list[LedgerEntry],
    window_start: datetime,
    window_end: datetime,
    ledger_proof_refs: list[str] | None = None,
) -> EvidencePack:
    """Build a three-part evidence pack for the given time window.

    Uses only the ledger entries provided (which should be the point-in-time
    subset for the window). The ``ledger_proof_refs`` are K·02 inclusion proof
    handles the caller supplies after running `verify` — leave empty only if
    proofs are unavailable (pack will be marked not verifiable).
    """
    tenant_entries = [e for e in ledger_entries if str(e.tenant) == tenant_id]
    proof_refs = tuple(ledger_proof_refs or [])
    now = datetime.now(tz=timezone.utc)

    manifest = EvidenceManifest(
        tenant_id=tenant_id,
        window_start=window_start,
        window_end=window_end,
        regulation_refs=tuple(regulation_refs),
        policy_versions=tuple(policy_versions),
        action_count=len(tenant_entries),
        ledger_proof_refs=proof_refs,
        generated_at=now,
    )

    narrative_lines = [
        f"Evidence pack for tenant '{tenant_id}'",
        f"Time window: {window_start.isoformat()} — {window_end.isoformat()}",
        f"Regulations covered: {', '.join(regulation_refs)}",
        f"Policy versions in effect: {', '.join(policy_versions)}",
        f"Governed actions in window: {len(tenant_entries)}",
    ]
    if proof_refs:
        narrative_lines.append(
            f"Ledger proof references: {len(proof_refs)} K·02 inclusion proof(s) attached."
        )
    else:
        narrative_lines.append(
            "WARNING: No K·02 ledger proof references attached — "
            "this pack is not independently verifiable."
        )

    return EvidencePack(
        tenant_id=tenant_id,
        manifest=manifest,
        narrative="\n".join(narrative_lines),
        verifiable=bool(proof_refs),
        generated_at=now,
    )
