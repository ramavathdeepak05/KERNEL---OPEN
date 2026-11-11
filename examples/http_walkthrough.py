#!/usr/bin/env python3
"""QUAICU over HTTP — the calls any product, in any language, makes to a local kernel.

Start a kernel first (see the README), then run this with the same token:

    quaicu init && quaicu serve                 # prints a token if QUAICU_TOKEN is unset
    QUAICU_TOKEN=<token> python examples/http_walkthrough.py

It uses only the standard library. Every request carries two things: the shared token, and the
name (and roles) of the user your product is acting for.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = os.getenv("QUAICU_URL", "http://127.0.0.1:7000")
TOKEN = os.getenv("QUAICU_TOKEN", "")


def call(method: str, path: str, *, actor: str, roles: str = "", body: dict | None = None, token: str | None = None):
    """Return (status, parsed JSON). The actor headers say who your product is acting for."""
    request = urllib.request.Request(
        BASE + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {TOKEN if token is None else token}",
            "X-Actor-Id": actor,
            "X-Actor-Roles": roles,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def main() -> int:
    if not TOKEN:
        print("Set QUAICU_TOKEN to the kernel's token.", file=sys.stderr)
        return 2
    run = uuid.uuid4().hex[:8]  # keeps idempotency keys unique across runs
    ok = True

    def check(label: str, condition: bool, detail: object = "") -> None:
        nonlocal ok
        ok = ok and condition
        print(f"{'✓' if condition else '✗'} {label}" + (f"  {detail}" if detail else ""))

    # 0. Without the token nothing is served.
    status, _ = call("GET", "/v1/approvals", actor="alice", token="not-the-token-0123456789")
    check("a wrong token is refused", status == 401, f"HTTP {status}")

    # 1. Ask for a decision without doing anything (your product enforces the answer).
    status, verdict = call(
        "POST", "/v1/authorize", actor="alice", roles="analyst",
        body={"type": "payments.wire", "payload": {"amount": 500}},
    )
    check("authorize: a small wire is allowed", status == 200 and verdict.get("allowed") is True, verdict.get("decision"))

    # 2. Record an action through the full lifecycle. Allowed → completed and sealed.
    status, small = call(
        "POST", "/v1/actions/propose", actor="alice", roles="analyst",
        body={"type": "payments.wire", "payload": {"amount": 500}, "idempotency_key": f"wire-small-{run}"},
    )
    check("propose: a small wire completes", status == 202 and small.get("state") == "COMPLETED", small.get("state"))

    # 3. Over the hard limit → denied.
    status, _ = call(
        "POST", "/v1/actions/propose", actor="alice", roles="analyst",
        body={"type": "payments.wire", "payload": {"amount": 5_000_000}, "idempotency_key": f"wire-huge-{run}"},
    )
    check("propose: a wire over the limit is denied", status == 403, f"HTTP {status}")

    # 4. A large wire needs approval: it is recorded as pending and nothing is sealed yet.
    status, large = call(
        "POST", "/v1/actions/propose", actor="alice", roles="manager",
        body={"type": "payments.wire", "payload": {"amount": 50_000}, "idempotency_key": f"wire-large-{run}"},
    )
    check("propose: a large wire waits for approval", large.get("state") == "PENDING_APPROVAL", large.get("state"))
    action_id = large.get("action_id", "")

    # 5. The approver's queue.
    status, queue = call("GET", "/v1/approvals", actor="bob", roles="manager")
    handle = next((a["handle_id"] for a in queue.get("approvals", []) if a["action_id"] == action_id), "")
    check("approvals: the wire is in the manager's queue", bool(handle))

    # 6. The proposer cannot approve their own action, even with the approver role.
    status, _ = call("POST", f"/v1/approvals/{handle}/approve", actor="alice", roles="manager")
    check("approvals: the proposer cannot approve it", status == 409, f"HTTP {status}")

    # 7. Someone else with the role can. The action completes and is sealed.
    status, decided = call("POST", f"/v1/approvals/{handle}/approve", actor="bob", roles="manager")
    check("approvals: another manager approves it", status == 200 and decided.get("decided_by") == "bob")
    status, after = call("GET", f"/v1/actions/{action_id}", actor="alice")
    check("status: the wire is now completed", after.get("state") == "COMPLETED", after.get("state"))

    # 8. The audit trail: who did what, under which policy, approved by whom.
    status, health = call("GET", "/health", actor="-")
    tenant = health.get("tenant", "local")
    status, trail = call("GET", f"/v1/ledger/{tenant}/trail", actor="auditor")
    mine = [e for e in trail.get("entries", []) if e["action_id"] in (small.get("action_id"), action_id)]
    check("ledger: both completed wires are in the signed trail", len(mine) == 2)
    for entry in mine:
        print(f"    seq {entry['ledger_seq']}: {entry['action_type']} by {entry['actor_id']} "
              f"→ {entry['decision']}" + (f", approved by {entry['approver']}" if entry["approver"] else ""))

    print("\nAll steps behaved as governed." if ok else "\nSomething did not behave as expected.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
