# Security

QUAICU is a governance kernel you run yourself. This file covers how to report a vulnerability and
what the kernel's security model does and does not give you.

## Reporting a vulnerability

- Email **security@quaicu.org** with reproduction steps and the impact you see.
- Please do not disclose publicly until a fix is available.
- Good-faith research under this policy will not be pursued legally. There is no paid bug bounty.

Security fixes are made on the latest release.

## Security model

**Who may call the kernel.** Every `/v1` route of the HTTP API authenticates the caller through the
configured identity adapter; only `/health`, `/readyz`, the API docs and the HMAC-signed approval
links are open.

- `local_token` (the default for a local kernel): the calling product presents one shared token and
  names the acting user in the `X-Actor-Id` / `X-Actor-Roles` headers. The token proves the request
  comes from your product; it does **not** prove who the end user is. Anyone who holds the token can
  act as any user, so treat it like a database password, keep it out of files and logs, and keep
  the API bound to localhost or a private network. The kernel refuses to start without a token of
  at least 16 characters.
- `jwt` / `oidc`: the kernel verifies a signed token per user. Use these when the kernel, not the
  calling product, must establish each user's identity.

When you embed the Python package, your code passes the actor in directly and is trusted in the
same way.

**Fail-closed.** An action runs only if a policy that governs it allows it. No matching policy, a
policy condition that errors, an unresolved identity, missing consent (when the consent layer is
on), an approval that is rejected or times out, or a failure to write the ledger all deny or halt
the action.

**Separation of duties.** The actor who proposed an action cannot approve it, and an approver must
match the roles or users the policy names.

**Tenancy.** One kernel serves one tenant. The Postgres tables carry a `tenant_id` with row-level
security as a second line of defence.

**The ledger: what it proves.** Each completed action is hashed into an append-only Merkle log
(RFC 6962) whose tree head is signed. Against a signing key you pinned beforehand, an exported proof
bundle shows that an entry with a given hash is in the log, and an independent witness (when
configured) shows the log was not forked or rewound.

What it does not yet prove: the readable fields in a bundle or database row (decision, action type,
timestamps) are not bound to the entry's hash by the verifier, and the data needed to recompute
that hash is not exported. Do not rely on the bundle alone to show that a readable field is
unaltered. The ledger design is also awaiting an independent cryptographic review
(`docs/operations/K02_REVIEW_PACKAGE.md`).

**Signing keys.** The default `memory_signed_ledger` generates its signing key when the process
starts; signatures do not survive a restart. Use the OpenBao or cloud KMS signers when they must.

**Data leaving the machine.** With the starter configuration the kernel makes no outbound network
calls. Adapters you opt into (model inference, webhook or email approvals, event sinks, cloud KMS)
call the endpoints you configure.

## Out of scope

The security of services you connect the kernel to (your database, KMS, identity provider, model
provider) is yours and theirs. A flaw in how the kernel uses them is in scope.
