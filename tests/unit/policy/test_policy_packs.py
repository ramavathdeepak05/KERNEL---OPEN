"""Guards the policy-pack loader (quaicu/core/policy/packs.py) against the real shipped packs.

If a pack directory or its policies.toml is renamed/broken, or a seed loses a required field, these
fail — so the console's "Start from a pack" catalogue can't silently go empty.
"""

from __future__ import annotations

from quaicu.core.policy import packs


def test_lists_the_shipped_packs():
    ids = {p.id for p in packs.list_packs()}
    assert {"dpdp", "eu-ai-act"} <= ids


def test_eu_ai_act_pack_shape():
    pack = packs.get_pack("eu-ai-act")
    assert pack is not None
    assert pack.name == "EU AI Act"
    assert pack.regulation == "Regulation (EU) 2024/1689"
    assert len(pack.policies) == 7
    assert set(pack.action_types) == {"ai_system.invoke", "ai_content.generate"}


def test_packs_carry_human_metadata():
    """Each pack exposes a summary, usage, per-action-type contract, and per-policy descriptions."""
    for pack in packs.list_packs():
        assert pack.summary, f"{pack.id} has no summary"
        assert pack.usage, f"{pack.id} has no usage note"
        # one action-type spec per governed type, each with a payload contract + example
        assert {a.name for a in pack.action_specs} == set(pack.action_types)
        for a in pack.action_specs:
            assert a.use_case and a.payload and a.example
        for p in pack.policies:
            assert p.title and p.description, f"{pack.id}/{p.id} missing title/description"


def test_dpdp_pack_shape():
    pack = packs.get_pack("dpdp")
    assert pack is not None
    assert len(pack.policies) == 6
    assert "personal_data.process" in pack.action_types


def test_every_pack_policy_is_well_formed():
    for pack in packs.list_packs():
        assert pack.policies, f"{pack.id} has no policies"
        for p in pack.policies:
            assert p.id and p.governs and p.condition and p.decision
            assert p.decision in {"allow", "deny", "require_approval"}


def test_unknown_pack_is_none():
    assert packs.get_pack("does-not-exist") is None
