# Starter policy pack — India DPDP Act 2023

> **DRAFT — not legal advice.** A worked starting point to adapt with your DPO/counsel, not a
> certified compliance artifact. The kernel *enforces* these rules; you own whether they're correct
> for your processing.

`policies.toml` contains [[policy.seed]] entries (see [`../../CEL_POLICY_GUIDE.md`](../../CEL_POLICY_GUIDE.md)
for the CEL schema). Seed them via a kernel config's `[policy]` section, or author them through
`POST /v1/policies` and the DRAFT→backtest→ACTIVATE flow. Deny-overrides applies: a violation beats
the allow-baseline.

## Action types & required payload contract
Map your real actions onto these two types (edit `governs`). Because a CEL reference to an **absent**
variable fail-closes to DENY (intended here — undeclared consent/purpose ⇒ deny), actions of these
types **must** carry these payload fields:

**`personal_data.process`** — `consent_obtained` (bool), `purpose` (string), `subject_erased` (bool).
**`personal_data.transfer`** — `destination_country` (string, ISO code).

## Policies → DPDP mapping
| Policy id | Rule | Decision | DPDP ref |
|---|---|---|---|
| `dpdp-process-allow-baseline` | baseline: processing is allowed unless a guardrail fires | allow | `dpdp.process.art.4` |
| `dpdp-consent-required` | no consent obtained → block | deny | `dpdp.consent.art.6` |
| `dpdp-purpose-limitation` | purpose not in the permitted set → block | deny | `dpdp.purpose.art.6` |
| `dpdp-erased-subject` | subject has exercised erasure → block | deny | `dpdp.erasure.art.12` |
| `dpdp-transfer-allow-baseline` | baseline: transfers allowed unless reviewed | allow | `dpdp.transfer.art.16` |
| `dpdp-cross-border-review` | destination ≠ India → route to the DPO | require_approval | `dpdp.transfer.art.16` |

The `regulatory_refs` follow the K·14 convention (`<regime>.<domain>.<article>`), so K·14 evidence
packs can link each governed action back to the DPDP article it satisfies.

## Behavior summary
- Compliant process (consent=true, permitted purpose, not erased) → **allow**.
- Missing/false consent, disallowed purpose, or erased subject → **deny**.
- Cross-border transfer (destination ≠ `IN`) → **require_approval** by `role:dpo`.

## Before relying on it
Adapt the action types, the permitted-purpose set, and the approver role to your deployment; then
**backtest** against recorded history before activating (see CEL_POLICY_GUIDE). Consent is also a
first-class K·04 layer; these policies complement it at the K·01 decision point.
