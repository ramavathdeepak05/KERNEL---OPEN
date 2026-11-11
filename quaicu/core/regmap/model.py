"""K·14 Regulatory Mapping — domain models.

Evidence is point-in-time (policies/regulations as they were in the queried window).
The signed evidence pack verifies via K·02 `verify`. A regulation change flags affected
mappings `review_required` — never auto-mutates a policy.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Regime(str, Enum):
    RBI_FREE_AI = "RBI_FREE_AI"
    EU_AI_ACT = "EU_AI_ACT"
    DPDP_2023 = "DPDP_2023"
    NAAC = "NAAC"


@dataclass(frozen=True)
class RegulationRef:
    """A regulation article or requirement that a policy implements.

    ``id`` follows the ``<regime>.<domain>.<article>`` convention (e.g.
    ``rbi.ifrs9.staging``, ``eu.ai_act.art.9``, ``dpdp.consent.art.6``).
    """

    id: str  # e.g. "rbi.ifrs9.staging"
    name: str
    description: str
    regime: Regime
    version: str = "1.0"
    effective_from: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


class MappingStatus(str, Enum):
    ACTIVE = "active"
    REVIEW_REQUIRED = "review_required"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class PolicyMapping:
    """Links a policy (by id + version) to a regulation article.

    When the regulation text changes, all mappings that reference that regulation
    must be flagged ``review_required`` — a human re-activates through K·01 after review.
    """

    regulation_ref_id: str
    policy_id: str
    policy_version: str
    status: MappingStatus = MappingStatus.ACTIVE
    mapped_at: datetime | None = None
    flagged_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceManifest:
    """Machine-readable claims for one evidence pack.

    ``ledger_proof_refs`` holds K·02 inclusion-proof handles (leaf_hash hex strings or
    STH references) that a third party can verify without trusting us.
    """

    tenant_id: str
    window_start: datetime
    window_end: datetime
    regulation_refs: tuple[str, ...]
    policy_versions: tuple[str, ...]
    action_count: int
    ledger_proof_refs: tuple[str, ...]
    generated_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidencePack:
    """A complete evidence pack — three required parts (human doc + manifest + proofs).

    ``verifiable`` is True only when ``manifest.ledger_proof_refs`` is non-empty.
    An empty proof refs list means no K·02 proofs were attached — the pack must NOT
    be shipped as verified evidence; it must flag the gap.
    """

    tenant_id: str
    manifest: EvidenceManifest
    narrative: str
    verifiable: bool
    generated_at: datetime
    metadata: Mapping[str, Any] = field(default_factory=dict)
