"""Scope names for the REST API — the operations a credential may be limited to.

A scope is a stable ``"resource:verb"`` string. The kernel does not issue scoped credentials
itself: its identity adapters authenticate a caller and say who they are, and policies decide what
that caller may do. Scopes are a seam for a host that fronts the API with its own auth layer and
wants coarser, credential-level limits: if that layer sets ``request.state.principal`` (an object
with ``scopes`` and ``has_scope``), each route requires the scope it names via
``quaicu/delivery/api/deps.enforce_scope``. With no principal the scope checks are no-ops.

Adding a scope is additive: define the constant, add it to `ALL_SCOPES`, and assert it where the
operation is performed. Removing or renaming a scope is a breaking change — don't.
"""

from __future__ import annotations

# ── Scope constants (resource:verb) ─────────────────────────────────────────────

ACTIONS_WRITE = "actions:write"        # propose / drive a governed action
ACTIONS_READ = "actions:read"          # look up an action's state
LEDGER_READ = "ledger:read"            # read the tenant's audit trail / proofs
DASHBOARD_READ = "dashboard:read"      # read governance read-models
APPROVAL_READ = "approval:read"        # list the HITL queue
APPROVAL_DECIDE = "approval:decide"    # approve / reject a pending HITL request
POLICY_READ = "policy:read"            # list / inspect policies
POLICY_ADMIN = "policy:admin"          # author / activate / deprecate policies
INFERENCE_WRITE = "inference:write"    # make a governed model call
ERASURE_WRITE = "erasure:write"        # crypto-shred a data subject (GDPR/DPDP right to erasure)


# Every scope the API understands.
ALL_SCOPES: frozenset[str] = frozenset(
    {
        ACTIONS_WRITE,
        ACTIONS_READ,
        LEDGER_READ,
        DASHBOARD_READ,
        APPROVAL_READ,
        APPROVAL_DECIDE,
        POLICY_READ,
        POLICY_ADMIN,
        INFERENCE_WRITE,
        ERASURE_WRITE,
    }
)
