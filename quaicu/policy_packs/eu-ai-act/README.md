# Starter policy pack — EU AI Act (Regulation (EU) 2024/1689)

> **DRAFT — not legal advice.** A worked starting point to adapt with your compliance/legal team, not
> a certified conformity artifact. The kernel *enforces* these rules; you own whether they correctly
> reflect your AI system's risk classification and obligations.

`policies.toml` contains [[policy.seed]] entries (see [`../../CEL_POLICY_GUIDE.md`](../../CEL_POLICY_GUIDE.md)
for the CEL schema). Seed them via a kernel config's `[policy]` section, or author them through
`POST /v1/policies` and the DRAFT→backtest→ACTIVATE flow. Deny-overrides applies: a prohibited-practice
violation beats the allow-baseline, and `require_approval` beats `allow`.

## Action types & required payload contract
Map your real actions onto these two types (edit `governs`). Because a CEL reference to an **absent**
variable fail-closes to DENY (intended here — an unclassified/undisclosed system ⇒ block), actions of
these types **must** carry these payload fields:

**`ai_system.invoke`** — `risk_category` (string: `prohibited` | `high` | `limited` | `minimal`),
`use_case` (string), `human_oversight` (bool), `discloses_ai` (bool).
**`ai_content.generate`** — `synthetic` (bool), `labeled` (bool).

## Policies → EU AI Act mapping
| Policy id | Rule | Decision | Article |
|---|---|---|---|
| `eu-ai-act-invoke-allow-baseline` | baseline: invocation allowed unless a guardrail fires | allow | `scope.art.6` |
| `eu-ai-act-prohibited-risk` | `risk_category == "prohibited"` → block | deny | `prohibited.art.5` |
| `eu-ai-act-prohibited-use` | use case is an enumerated banned practice → block | deny | `prohibited.art.5` |
| `eu-ai-act-high-risk-oversight` | high-risk system run without human oversight → route to a human | require_approval | `oversight.art.14` |
| `eu-ai-act-transparency-disclosure` | system doesn't disclose it's AI → review | require_approval | `transparency.art.50` |
| `eu-ai-act-content-allow-baseline` | baseline: content generation allowed unless unlabeled synthetic | allow | `transparency.art.50` |
| `eu-ai-act-deepfake-labeling` | synthetic content not marked as AI-generated → review | require_approval | `transparency.art.50` |

The banned-practice set (`eu-ai-act-prohibited-use`) covers `social_scoring`,
`subliminal_manipulation`, `emotion_recognition_workplace`, `biometric_categorization`, and
`untargeted_facial_scraping` — adapt to your own use-case taxonomy.

The `regulatory_refs` follow the K·14 convention (`<regime>.<domain>.<article>`), so K·14 evidence
packs can link each governed action back to the Article it satisfies.

## Behavior summary
- Compliant invoke (classified non-prohibited, permitted use, oversight present, AI disclosed) → **allow**.
- Prohibited risk class or banned use case → **deny** (Art. 5 — unacceptable risk).
- High-risk system without human oversight → **require_approval** by `role:compliance_officer` (Art. 14).
- System that doesn't disclose it is AI → **require_approval** (Art. 50).
- Synthetic/deepfake content not marked → **require_approval** (Art. 50); labeled synthetic → allow.

## Before relying on it
The Act's obligations turn on your system's **risk classification** (Annex III high-risk areas,
GPAI/systemic-risk thresholds). This pack encodes the *decision points*; you must supply the correct
`risk_category` and `use_case` for each action. Adapt the banned-practice set and the approver role,
then **backtest** against recorded history before activating (see CEL_POLICY_GUIDE).
