# ADR-0007: Capture the approving identity on the sealed `LedgerEntry`

- **Status:** Accepted
- **Date:** 2026-06-12
- **Decided by:** orchestrator
- **Affects:** `quaicu/core/types.py` (`ApprovalOutcome`), `quaicu/core/ports/hitl.py` (`HITLPort.poll`), `quaicu/core/hitl/engine.py`, `quaicu/adapters/hitl/webhook.py`, `quaicu/core/lifecycle/engine.py`

## Context

When a policy returns `REQUIRE_APPROVAL`, the lifecycle gates the action through the K·03 HITLPort
and, on approval, seals the outcome to the K·02 ledger. The sealed `LedgerEntry.approver` field
exists and is surfaced by the ledger-trail API — but the lifecycle always sealed `approver=None`,
because `HITLPort.poll` returned a bare `ApprovalDecision` enum and never told the caller *who*
decided. The decider was captured one layer down (`ApprovalRecord.decided_by` in the HITL store) but
had no path to the ledger.

For a governance kernel sold to banks, "an approval happened" without "by whom" is an incomplete
audit record — separation-of-duties review and regulator evidence both need the approver identity.
`HITLPort` is the frozen contract surface (ADR-0001), so enriching `poll` requires an ADR.

## Decision

`HITLPort.poll` returns a new frozen value type instead of a bare enum:

- **`quaicu/core/types.py`** — add `ApprovalOutcome(decision: ApprovalDecision, decided_by: ActorId | None
  = None)`. `decided_by` is the approver's actor id when the gate is decided by a known actor, else
  None (PENDING, or a TIMED_OUT with no decider).
- **`quaicu/core/ports/hitl.py`** — `poll(handle) -> ApprovalOutcome` (was `-> ApprovalDecision`).
- **Implementers** populate the decider: `InProcessHITLPort` reads `record.decided_by`; the webhook
  adapter reads a `decided_by` field from the poll response body. Both fail closed to
  `ApprovalOutcome(TIMED_OUT)` on the unreachable/error paths.
- **`quaicu/core/lifecycle/engine.py`** — `_gate` seals the decider as
  `ApproverRef(f"user:{outcome.decided_by}")` into `LedgerEntry.approver` (a backend that approves
  without reporting an identity seals `approver=None`). `_poll_until_decided` returns the full
  outcome. Fail-closed is unchanged: REJECTED / TIMED_OUT still DENY, never auto-approve.

The `user:<id>` ref keeps the sealed approver consistent with the `user:` / `role:` convention used
for required approvers and the HITL authority check.

## Consequences

- The ledger now records *who* approved each gated action; `GET /v1/ledger/{tenant}/trail` surfaces
  it with no read-side change. The "capture the approving identity" follow-up is closed.
- The approver is committed inside the Merkle leaf (it was already part of `_canonical_bytes`), so it
  is tamper-evident and point-in-time replayable (F-09).
- Every `HITLPort` implementation must now return `ApprovalOutcome` from `poll`; the three in-tree
  implementers (in-process, webhook, the test fake) are updated. Any future adapter must comply.
- CI: `tests/unit/lifecycle/test_engine.py` asserts the sealed `approver` (with and without a
  reported decider); `tests/unit/hitl/test_engine.py` asserts `poll().decided_by`.

## Alternatives considered

- **Add an optional capability method (e.g. `ApproverAware.last_approver`) and `isinstance`-check it
  in the lifecycle.** Rejected — leaves two ways to read a gate's result and silently skips adapters
  that don't implement the capability, so the approver would be captured for some backends and not
  others. A uniform `poll` return makes every adapter participate.
- **Re-resolve the approver from the HITL store inside the lifecycle.** Rejected — couples core to a
  concrete adapter's store (`get_record`), violating the ports-and-adapters rule; the port should
  report its own outcome.
- **Leave `approver=None`.** Rejected — it's the audit gap this ADR exists to close.
