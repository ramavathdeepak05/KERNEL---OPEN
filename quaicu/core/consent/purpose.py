"""K·04 DPDP Consent — canonical purpose constants and required data categories.

Purpose strings are the stable identifiers written into ConsentRecord.purpose. They are the
canonical cross-layer vocabulary — policy authors, adapter implementors, and the ConsentEngine
all use these constants. Never use ad-hoc strings for purposes in governed code.

Source of truth: DPDP Act 2023 §4 (purpose limitation) and the build spec §K·04.
"""

from __future__ import annotations


class ConsentPurpose:
    """Canonical DPDP purpose identifiers.

    Each constant is the string that appears in ConsentRecord.purpose and is matched
    against action.payload.get("consent_purpose", ConsentPurpose.AI_INFERENCE) by the
    ConsentEngine.
    """

    AI_INFERENCE: str = "ai_inference"
    """General AI inference over the subject's data (default purpose)."""

    LOAN_EVALUATION: str = "loan_evaluation"
    """Credit-underwriting and loan eligibility assessment."""

    CREDIT_SCORING: str = "credit_scoring"
    """Computation or update of a credit score."""

    DATA_SHARING: str = "data_sharing"
    """Transfer of subject data to a third-party processor."""

    PROFILING: str = "profiling"
    """Behavioural or financial profiling of the subject."""

    AUTOMATED_DECISION: str = "automated_decision"
    """Any automated decision with legal or significant personal effect (DPDP §6)."""


# Purpose → minimum required data categories that consent MUST cover.
# The ConsentEngine does NOT currently enforce category membership (that is a future
# K·04-ext enhancement); this mapping is published here as the authoritative reference
# so adapter tests and integration suites can validate category coverage.
REQUIRED_CATEGORIES: dict[str, frozenset[str]] = {
    ConsentPurpose.AI_INFERENCE: frozenset({"general"}),
    ConsentPurpose.LOAN_EVALUATION: frozenset({"financial", "identity"}),
    ConsentPurpose.CREDIT_SCORING: frozenset({"financial", "credit_history"}),
    ConsentPurpose.DATA_SHARING: frozenset({"general"}),
    ConsentPurpose.PROFILING: frozenset({"behavioral", "financial"}),
    ConsentPurpose.AUTOMATED_DECISION: frozenset({"general"}),
}

# The set of all known purpose strings. Used by adapters and validators.
ALL_PURPOSES: frozenset[str] = frozenset(REQUIRED_CATEGORIES.keys())
