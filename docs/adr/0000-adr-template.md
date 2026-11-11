# ADR-NNNN: <short title>

- **Status:** Proposed | Accepted | Superseded by ADR-XXXX
- **Date:** YYYY-MM-DD
- **Decided by:** orchestrator
- **Affects:** <layers / directories / interfaces touched>

## Context

What forced this decision? What is the problem or the conflict? Link the relevant build-spec section,
Frozen ADR (F-01–F-11), or skill contract. State what a cold agent needs to know to understand why.

## Decision

The decision, stated as a rule an agent can apply mechanically. If it changes the frozen contract
surface (`quaicu/core/ports`, `quaicu/core/types`, `quaicu/core/errors`), say exactly what changed.

## Consequences

- What becomes easier / required.
- What is now forbidden.
- Which agents/units must be notified or re-run.
- How CI / conformance enforces it (if applicable).

## Alternatives considered

Briefly: what else was on the table and why it lost. (Prevents re-litigation by a future cold agent.)
