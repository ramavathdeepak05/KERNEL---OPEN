"""K·14 Regulatory Mapping conformance tests — spec-derived golden cases.

Invariants tested:
  - Evidence is point-in-time: uses the policy versions provided, not current state.
  - Evidence pack verifiable via K·02 proofs when proof refs are attached.
  - Regulation change → flags mappings review_required, NEVER auto-mutates policy.
  - Per-tenant: evidence pack scoped to one tenant's ledger entries.
  - Pack without K·02 proof refs is not verifiable (must flag the gap).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quaicu.core.regmap.catalog import RegulationCatalog, generate_evidence_pack
from quaicu.core.regmap.model import MappingStatus, PolicyMapping
from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = "ciro-bank"


def _entry(tenant: str = TENANT) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=1, tenant=TenantId(tenant), action_id=ActionId("act-1"),
        action_type="ciro.ifrs9.stage_transition", actor_id=ActorId("alice"),
        decision=Decision.ALLOW, policy_versions=("ifrs9-v2",),
        leaf_hash=b"\x00" * 32, sealed_at=NOW,
    )


@pytest.mark.conformance
def test_regulation_change_flags_review_required_not_auto_mutates():
    """Regulation change must flag mappings review_required; must NOT change the policy."""
    cat = RegulationCatalog()
    cat.register_mapping(PolicyMapping(
        regulation_ref_id="rbi.ifrs9.staging",
        policy_id="ifrs9-policy", policy_version="v2", status=MappingStatus.ACTIVE,
    ))
    updated = cat.flag_review_required("rbi.ifrs9.staging")
    # Mapping is flagged — but the policy itself is never touched (that would violate the invariant)
    assert all(m.status == MappingStatus.REVIEW_REQUIRED for m in updated)
    # Policy id and version are unchanged (we only touched mapping status, not the policy)
    assert updated[0].policy_id == "ifrs9-policy"
    assert updated[0].policy_version == "v2"


@pytest.mark.conformance
def test_evidence_pack_verifiable_with_k02_proofs():
    """Pack must be verifiable when K·02 inclusion proof refs are attached."""
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["ifrs9-v2"],
        ledger_entries=[_entry()],
        window_start=NOW, window_end=NOW,
        ledger_proof_refs=["sha256-abc123"],
    )
    assert pack.verifiable is True
    assert "sha256-abc123" in pack.manifest.ledger_proof_refs


@pytest.mark.conformance
def test_evidence_pack_without_proofs_not_verifiable():
    """A pack with no K·02 proof refs must NOT claim to be verifiable — flag the gap."""
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v1"],
        ledger_entries=[],
        window_start=NOW, window_end=NOW,
    )
    assert pack.verifiable is False


@pytest.mark.conformance
def test_evidence_pack_scoped_to_tenant():
    """Evidence must only include the requesting tenant's governed actions."""
    entries = [_entry(tenant=TENANT), _entry(tenant="other-bank")]
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v1"],
        ledger_entries=entries,
        window_start=NOW, window_end=NOW,
        ledger_proof_refs=["proof-1"],
    )
    assert pack.manifest.action_count == 1


@pytest.mark.conformance
def test_evidence_pack_has_all_three_required_parts():
    """Evidence pack must have: human narrative + machine manifest + ledger proof refs."""
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["dpdp.consent.art.6"],
        policy_versions=["consent-v1"],
        ledger_entries=[_entry()],
        window_start=NOW, window_end=NOW,
        ledger_proof_refs=["proof-x"],
    )
    assert pack.narrative  # Part 1: human-readable
    assert pack.manifest.regulation_refs  # Part 2: machine manifest
    assert pack.manifest.ledger_proof_refs  # Part 3: K·02 proof refs
