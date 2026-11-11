# Underwriting demo — governed, gated, sealed, verified

An AI assistant drafts credit decisions. The kernel governs each one: low-risk drafts go through,
high-risk drafts wait for a human, over-limit drafts are refused, and every completed decision is
sealed to a signed ledger that can be verified offline.

```bash
python examples/underwriting-demo/demo.py
```

It runs in one process with no external services, in about a second:

1. **Low-risk draft** (₹2,50,000): a policy allows it; it executes and is sealed.
2. **High-risk draft** (₹75,00,000): a policy requires approval. The call stops with
   `LifecyclePendingApprovalError`, nothing executes, and the request sits in the approvals queue
   until a risk officer (`role:risk_head`) approves it. The completed action is sealed with the
   approver's identity.
3. **Over-limit draft** (₹6,00,00,000): a policy denies it. The draft does not execute.
4. **Proof bundle**: the ledger is exported with an inclusion proof per action and a signed tree
   head, then verified against the signing key pinned beforehand.

The policies are the `[[policy.seed]]` entries in [`kernel.demo.toml`](kernel.demo.toml).
