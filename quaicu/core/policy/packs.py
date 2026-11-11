"""Starter policy packs — ready-made CEL rule sets shipped inside the package (``quaicu/policy_packs/``).

Each pack is a directory with a ``policies.toml`` of ``[[policy.seed]]`` entries (the same format
the kernel seeds at boot) plus optional ``[pack]`` / ``[[pack.action_type]]`` metadata that the
console renders (the kernel seeder ignores those tables). The console lets a tenant *import* a pack:
every entry is registered as a DRAFT policy the tenant then backtests + activates — so adopting a
regulatory baseline is two clicks instead of hand-authoring CEL.

The packs ship as repo files (the runtime image bundles the tree), so this module discovers them at
the documented path. ``_META`` provides a name/regulation fallback for a pack whose TOML omits the
``[pack]`` table.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# quaicu/core/policy/packs.py → parents[2] is the `quaicu` package, which ships `policy_packs/` as
# package data, so the packs are found whether the kernel runs from a checkout or is pip-installed.
PACKS_DIR = Path(__file__).resolve().parents[2] / "policy_packs"

# pack id (directory name) → (display name, regulation, one-line description). Fallback only — a pack
# that declares [pack] in its TOML overrides these.
_META: dict[str, tuple[str, str, str]] = {
    "dpdp": (
        "India DPDP Act 2023",
        "Digital Personal Data Protection Act, 2023",
        "Consent, purpose-limitation, erasure, and cross-border transfer controls for personal data.",
    ),
    "eu-ai-act": (
        "EU AI Act",
        "Regulation (EU) 2024/1689",
        "Prohibited-practice, high-risk human-oversight, and AI transparency/disclosure controls.",
    ),
    "rbi": (
        "India RBI/SEBI Cloud & Outsourcing",
        "RBI Outsourcing of IT Services (2023) + SEBI Cloud Framework (2023)",
        "Data-localization, encryption, outsourcing-governance, and access-logging controls for RBI/SEBI regulated entities.",
    ),
}


@dataclass(frozen=True)
class PackPolicy:
    id: str
    title: str
    description: str
    governs: str
    condition: str
    decision: str
    approvers: tuple[str, ...]
    regulatory_refs: tuple[str, ...]


@dataclass(frozen=True)
class PackActionType:
    """How to actually invoke one of the governed action types — the payload contract + an example."""

    name: str
    use_case: str
    payload: str
    example: str


@dataclass(frozen=True)
class PolicyPack:
    id: str
    name: str
    regulation: str
    description: str
    summary: str
    usage: str
    policies: tuple[PackPolicy, ...]
    action_specs: tuple[PackActionType, ...] = field(default_factory=tuple)

    @property
    def action_types(self) -> tuple[str, ...]:
        """Distinct ``governs`` action types, in first-seen order."""
        seen: list[str] = []
        for p in self.policies:
            if p.governs not in seen:
                seen.append(p.governs)
        return tuple(seen)


def _load_dir(pack_id: str, path: Path) -> PolicyPack | None:
    toml_path = path / "policies.toml"
    if not toml_path.is_file():
        return None
    cfg = tomllib.loads(toml_path.read_text(encoding="utf-8"))

    seeds = cfg.get("policy", {}).get("seed", [])
    policies = tuple(
        PackPolicy(
            id=str(s["id"]),
            title=str(s.get("title", s["id"])),
            description=str(s.get("description", "")),
            governs=str(s["governs"]),
            condition=str(s["condition"]),
            decision=str(s["decision"]),
            approvers=tuple(str(a) for a in (s.get("approvers") or [])),
            regulatory_refs=tuple(str(r) for r in (s.get("regulatory_refs") or [])),
        )
        for s in seeds
        if "id" in s and "governs" in s and "condition" in s and "decision" in s
    )
    if not policies:
        return None

    meta = cfg.get("pack", {})
    fb_name, fb_reg, fb_desc = _META.get(pack_id, (pack_id, "", ""))
    action_specs = tuple(
        PackActionType(
            name=str(a.get("name", "")),
            use_case=str(a.get("use_case", "")),
            payload=str(a.get("payload", "")),
            example=str(a.get("example", "")),
        )
        for a in meta.get("action_type", [])
        if a.get("name")
    )
    return PolicyPack(
        id=pack_id,
        name=str(meta.get("name", fb_name)),
        regulation=str(meta.get("regulation", fb_reg)),
        description=fb_desc,
        summary=str(meta.get("summary", "")).strip(),
        usage=str(meta.get("usage", "")).strip(),
        policies=policies,
        action_specs=action_specs,
    )


def list_packs() -> list[PolicyPack]:
    """All packs discovered under ``PACKS_DIR``, sorted by id. Empty if the dir is absent."""
    if not PACKS_DIR.is_dir():
        return []
    packs: list[PolicyPack] = []
    for child in sorted(PACKS_DIR.iterdir()):
        if child.is_dir():
            pack = _load_dir(child.name, child)
            if pack is not None:
                packs.append(pack)
    return packs


def get_pack(pack_id: str) -> PolicyPack | None:
    """Load a single pack by id (directory name), or None if absent/empty."""
    path = PACKS_DIR / pack_id
    if not path.is_dir():
        return None
    return _load_dir(pack_id, path)
