# Policy-pack demo — the shipped regulatory packs governing a stream of actions

Loads the three starter policy packs that ship in `quaicu/policy_packs/` (RBI/SEBI outsourcing,
India DPDP Act, EU AI Act) into an in-process kernel and runs about a dozen realistic actions
through them: some are allowed, some denied, some held for approval. The completed ones are sealed
to a signed ledger, which is then exported and verified.

```bash
python examples/policy-pack-demo/demo.py
```

It runs in one process with no external services.

| Pack | Example action | Outcome |
|---|---|---|
| RBI | store KYC data in India, encrypted | sealed |
| RBI | store payment data outside India | denied (localization) |
| RBI | cross-border data transfer | held for approval, then sealed |
| DPDP | process personal data with consent | sealed |
| DPDP | process personal data without consent | denied |
| EU AI Act | invoke a prohibited-risk AI system | denied |

The packs are starting points to adapt, not legal advice. Each pack's `policies.toml` documents the
action types it governs and the payload fields its conditions expect.
