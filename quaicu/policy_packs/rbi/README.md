# Starter policy pack — India RBI/SEBI cloud & outsourcing

> **DRAFT — not legal advice.** A worked starting point to adapt with your compliance team / CRO /
> counsel, not a certified compliance artifact. The kernel *enforces* these rules; you own whether
> they're correct for your licence category (bank / NBFC / PA-PG / SEBI regulated entity) and your
> data. Citations name the source instrument, not a specific clause you can rely on verbatim.

`policies.toml` contains `[[policy.seed]]` entries (see [`../../CEL_POLICY_GUIDE.md`](../../CEL_POLICY_GUIDE.md)
for the CEL schema). Seed them via a kernel config's `[policy]` section, or author them through
`POST /v1/policies` and the DRAFT→backtest→ACTIVATE flow. **Deny-overrides** applies: a violation
beats the allow-baseline (`deny` > `require_approval` > `allow`).

## Action types & required payload contract
Map your real actions onto these four types (edit `governs`). Because a CEL reference to an **absent**
variable fail-closes to DENY (intended here — an action that doesn't declare its posture is denied),
actions of these types **must** carry these payload fields:

**`data.store`** — `data_class` (`"payment"|"kyc"|"personal"|"other"`), `storage_region` (ISO 3166 alpha-2), `encryption_at_rest` (bool).
**`data.transfer`** — `destination_country` (ISO 3166 alpha-2).
**`outsourcing.engage`** — `material` (bool), `audit_rights` (bool), `exit_plan` (bool).
**`access.grant`** — `access_logged` (bool).

## Policies → RBI/SEBI mapping
| Policy id | Rule | Decision | Ref |
|---|---|---|---|
| `rbi-store-allow-baseline` | baseline: storage allowed unless a guardrail fires | allow | `rbi.localization.baseline` |
| `rbi-payment-data-localization` | payment data stored outside India → block | deny | `rbi.localization.payment_data` |
| `rbi-encryption-at-rest` | storage without encryption at rest → block | deny | `rbi.security.encryption_at_rest` |
| `sebi-cloud-localization` | regulated data stored outside India → review | require_approval (`role:compliance`) | `sebi.cloud.localization` |
| `rbi-transfer-allow-baseline` | baseline: transfers allowed unless reviewed | allow | `rbi.transfer.baseline` |
| `rbi-cross-border-transfer` | destination ≠ India → review | require_approval (`role:compliance`) | `rbi.transfer.cross_border` |
| `rbi-outsourcing-allow-baseline` | baseline: engagements allowed unless gated | allow | `rbi.outsourcing.baseline` |
| `rbi-material-outsourcing-approval` | material outsourcing → senior review | require_approval (`role:cro`) | `rbi.outsourcing.material_approval` |
| `rbi-outsourcing-audit-rights` | no right-to-audit → block | deny | `rbi.outsourcing.audit_rights` |
| `rbi-outsourcing-exit-plan` | no documented exit plan → block | deny | `rbi.outsourcing.exit_plan` |
| `rbi-access-allow-baseline` | baseline: access grants allowed unless unlogged | allow | `rbi.security.access_baseline` |
| `rbi-access-logging` | access grant not written to the audit trail → block | deny | `rbi.security.access_logging` |

The `regulatory_refs` follow the K·14 convention (`<regime>.<domain>.<article>`), so K·14 evidence
packs can link each governed action back to the RBI/SEBI requirement it satisfies. The kernel already
models the RBI regime (`core/regmap/model.py` → `Regime.RBI_FREE_AI`); the `sebi.*` refs are free
strings here — add a `SEBI` member to the `Regime` enum if you want catalog-level linking.

## Source instruments (adapt to your licence category)
- **RBI, *Storage of Payment System Data*** (6 Apr 2018) — full payment data stored only in India → `rbi-payment-data-localization`.
- **RBI, *Master Direction on Outsourcing of IT Services*** (2023) — material-outsourcing oversight, right-to-audit, exit/BCP → the three `rbi-outsourcing-*` rules.
- **SEBI, *Framework for Adoption of Cloud Services by SEBI Regulated Entities*** (Mar 2023) — data/jurisdiction localization in India → `sebi-cloud-localization`.
- General RBI/SEBI IT-security expectations — encryption at rest, auditable access logs → `rbi-encryption-at-rest`, `rbi-access-logging`.

## Behavior summary
- Payment data stored in India, encrypted → **allow**; payment data stored abroad → **deny**.
- Any regulated (`payment`/`kyc`/`personal`) data stored abroad → **review** (and **deny** if it's payment).
- Storage without encryption at rest → **deny**.
- Cross-border transfer (destination ≠ `IN`) → **review** by `role:compliance`.
- Material outsourcing → **review** by `role:cro`; outsourcing without audit rights or an exit plan → **deny**.
- Privileged access grant not written to the audit trail → **deny**.

## Before relying on it
Adapt the action types, the `regulated` data-class set, the approver roles, and the localization
posture to your deployment and licence; then **backtest** against recorded history before activating
(see CEL_POLICY_GUIDE). These K·01 decision-point rules complement the kernel's first-class layers
(K·02 ledger/audit for the access-log evidence, K·14 regulatory mapping for the evidence packs).
