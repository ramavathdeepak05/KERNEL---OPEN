"""Unit tests for K·14 Regulatory Mapping catalog and evidence pack generation."""

from __future__ import annotations

from datetime import datetime, timezone


from quaicu.core.regmap.catalog import RegulationCatalog, generate_evidence_pack
from quaicu.core.regmap.model import (
    EvidencePack,
    MappingStatus,
    PolicyMapping,
    Regime,
    RegulationRef,
)
from quaicu.core.types import ActionId, ActorId, Decision, LedgerEntry, TenantId

NOW = datetime(2026, 6, 9, 12, 0, tzinfo=timezone.utc)
TENANT = "ciro-bank"


def _reg(ref_id: str = "rbi.ifrs9.staging", regime: Regime = Regime.RBI_FREE_AI) -> RegulationRef:
    return RegulationRef(
        id=ref_id, name=f"Reg {ref_id}", description="Test regulation",
        regime=regime, version="2024-01",
    )


def _mapping(policy_id: str = "ifrs9-policy", ref_id: str = "rbi.ifrs9.staging") -> PolicyMapping:
    return PolicyMapping(
        regulation_ref_id=ref_id,
        policy_id=policy_id,
        policy_version="v2",
        status=MappingStatus.ACTIVE,
    )


def _ledger_entry(tenant: str = TENANT, seq: int = 1) -> LedgerEntry:
    return LedgerEntry(
        ledger_seq=seq,
        tenant=TenantId(tenant),
        action_id=ActionId(f"act-{seq}"),
        action_type="ciro.ifrs9.stage_transition",
        actor_id=ActorId("alice"),
        decision=Decision.ALLOW,
        policy_versions=("ifrs9-v2",),
        leaf_hash=b"\x00" * 32,
        sealed_at=NOW,
    )


# ── RegulationCatalog ─────────────────────────────────────────────────────────────


def test_register_and_get_regulation():
    cat = RegulationCatalog()
    reg = _reg()
    cat.register_regulation(reg)
    found = cat.get_regulation("rbi.ifrs9.staging")
    assert found is not None
    assert found.id == "rbi.ifrs9.staging"


def test_get_missing_regulation_returns_none():
    cat = RegulationCatalog()
    assert cat.get_regulation("nonexistent") is None


def test_register_mapping():
    cat = RegulationCatalog()
    m = cat.register_mapping(_mapping())
    assert m.status == MappingStatus.ACTIVE
    assert m.mapped_at is not None


def test_list_mappings():
    cat = RegulationCatalog()
    cat.register_mapping(_mapping("pol-1"))
    cat.register_mapping(_mapping("pol-2"))
    result = cat.list_mappings("rbi.ifrs9.staging")
    assert len(result) == 2


def test_list_mappings_returns_empty_for_unknown():
    cat = RegulationCatalog()
    assert cat.list_mappings("unknown.ref") == []


# ── flag_review_required ──────────────────────────────────────────────────────────


def test_regulation_change_flags_review_required():
    cat = RegulationCatalog()
    cat.register_mapping(_mapping("pol-1"))
    cat.register_mapping(_mapping("pol-2"))
    updated = cat.flag_review_required("rbi.ifrs9.staging")
    assert all(m.status == MappingStatus.REVIEW_REQUIRED for m in updated)


def test_regulation_change_sets_flagged_at():
    cat = RegulationCatalog()
    cat.register_mapping(_mapping())
    updated = cat.flag_review_required("rbi.ifrs9.staging")
    assert updated[0].flagged_at is not None


def test_regulation_change_does_not_touch_other_refs():
    cat = RegulationCatalog()
    cat.register_mapping(_mapping("pol-1", "rbi.ifrs9.staging"))
    cat.register_mapping(PolicyMapping(
        regulation_ref_id="eu.ai_act.art.9",
        policy_id="pol-2",
        policy_version="v1",
        status=MappingStatus.ACTIVE,
    ))
    cat.flag_review_required("rbi.ifrs9.staging")
    eu_mappings = cat.list_mappings("eu.ai_act.art.9")
    assert all(m.status == MappingStatus.ACTIVE for m in eu_mappings)


def test_already_review_required_not_changed():
    cat = RegulationCatalog()
    cat.register_mapping(PolicyMapping(
        regulation_ref_id="rbi.ifrs9.staging",
        policy_id="pol-1",
        policy_version="v1",
        status=MappingStatus.REVIEW_REQUIRED,
    ))
    # calling flag_review_required again should be harmless
    updated = cat.flag_review_required("rbi.ifrs9.staging")
    assert updated[0].status == MappingStatus.REVIEW_REQUIRED


def test_get_active_mappings_for_policy():
    cat = RegulationCatalog()
    cat.register_mapping(_mapping("pol-1", "rbi.ifrs9.staging"))
    cat.register_mapping(_mapping("pol-1", "eu.ai_act.art.9"))
    active = cat.get_active_mappings_for_policy("pol-1")
    assert len(active) == 2


# ── generate_evidence_pack ────────────────────────────────────────────────────────


def test_evidence_pack_with_proofs_is_verifiable():
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["ifrs9-v2"],
        ledger_entries=[_ledger_entry()],
        window_start=NOW,
        window_end=NOW,
        ledger_proof_refs=["leaf-hash-abc123"],
    )
    assert isinstance(pack, EvidencePack)
    assert pack.verifiable is True


def test_evidence_pack_without_proofs_not_verifiable():
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["ifrs9-v2"],
        ledger_entries=[_ledger_entry()],
        window_start=NOW,
        window_end=NOW,
    )
    assert pack.verifiable is False


def test_evidence_pack_scoped_to_tenant():
    entries = [
        _ledger_entry(tenant=TENANT),
        _ledger_entry(tenant="other-bank"),
    ]
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v1"],
        ledger_entries=entries,
        window_start=NOW,
        window_end=NOW,
    )
    assert pack.manifest.action_count == 1


def test_evidence_pack_narrative_warns_without_proofs():
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v1"],
        ledger_entries=[],
        window_start=NOW,
        window_end=NOW,
    )
    assert "WARNING" in pack.narrative or "not" in pack.narrative.lower()


def test_evidence_pack_manifest_has_all_three_parts():
    pack = generate_evidence_pack(
        tenant_id=TENANT,
        regulation_refs=["rbi.ifrs9.staging"],
        policy_versions=["v2"],
        ledger_entries=[_ledger_entry()],
        window_start=NOW,
        window_end=NOW,
        ledger_proof_refs=["proof-1"],
    )
    assert pack.narrative  # human-readable part
    assert pack.manifest   # machine-readable manifest
    assert pack.manifest.ledger_proof_refs  # K·02 proof references
