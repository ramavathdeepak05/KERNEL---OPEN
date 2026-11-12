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

**Prompt injection.** The kernel does not detect prompt injection. It does not read the text a
model was given and cannot tell whether that text changed the model's plan. What it does is limit
what a hijacked agent can carry out, and record what it did:

- Every governed tool call is checked against policy before it runs, with its full, structured
  arguments (`payload_*`, `payload`).
- The MCP proxy and server record which untrusted tools (web fetch, email or file readers) a session
  has read. Policies see this as `session_tainted` / `session_sources`. For example, the
  `agent-egress` pack holds outbound actions for a person and denies code execution once a session
  is tainted. The agent cannot clear the taint through its arguments.
- An approval covers one call with the exact arguments the approver saw; the agent's retry runs it
  once. The agent's own identity cannot approve its request.
- The MCP proxy pins each tool's definition when it is first listed and blocks a tool whose
  description later changes. `allowed_tools` limits the catalogue.

What stays your responsibility:

- **Coverage.** Only calls that go through the kernel are governed: the MCP proxy or server,
  `guard` / `wrap` / `governed_tool`, `kernel.generate`, or the HTTP API. A tool the agent can reach
  some other way is not governed.
- **Classification.** Taint only works for tools you mark untrusted, and a policy only holds the
  tools it governs. A read tool that can reach an attacker-chosen URL can also carry data out in
  that URL, so treat it as egress as well.
- **What the model says.** Policies govern actions, not answers: a hijacked model can still give the
  user a misleading reply.
- **Who approves.** With `local_token`, whoever holds the token can claim any role, approver
  included. Keep the token away from the agent (it is a secret of the calling product), and use
  `jwt` or `oidc` when approvals must come from verified people.
- **Tool output reaches the model unchanged.** The kernel does not filter or rewrite it.

**The tool gateway.** `quaicu gateway` is meant to be the agent's only way to act. That holds only
if you set it up that way:

- Make the gateway the agent's only tool source. Turn off the agent app's built-in shell, file and
  web tools, and do not also connect the tool servers to the agent directly.
- Keep the admin token (`QUAICU_TOKEN`) and the tool servers' credentials away from the agent. The
  gateway passes credentials only to the server process that needs them and never lists them.
  But a file tool that can read the agent app's own config file could read them, so cover such
  paths with a deny rule or keep them out of the served directories.
- Keep the admin API on 127.0.0.1 (the default). With `local_token`, whoever holds the token can
  name any user and role.
- Live rule changes are in memory: they are sealed in the ledger, but the gateway falls back to
  `kernel.toml` on restart. Export them with `GET /v1/tools/rules?format=toml`.
- A tool server added or changed at run time (a new tool, a changed description) is covered by the
  rules as they stand. A changed tool definition is blocked until the gateway restarts.

**Model gateway limits.** `kernel.generate` masks PII with regular expressions (or Cloud DLP when
configured), checks the model allowlist, logs prompt hashes and enforces a token budget. The budget
counts whitespace-separated words, not model tokens, so treat it as a rough brake, not a cost
control. `kernel.proxy(...)` around a model client makes a policy decision only: the call does not
pass through the gateway and its result is not sealed.

**Signing keys.** The default `memory_signed_ledger` generates its signing key when the process
starts; signatures do not survive a restart. Use the OpenBao or cloud KMS signers when they must.

**Data leaving the machine.** With the starter configuration the kernel makes no outbound network
calls. Adapters you opt into (model inference, webhook or email approvals, event sinks, cloud KMS)
call the endpoints you configure.

## Out of scope

The security of services you connect the kernel to (your database, KMS, identity provider, model
provider) is yours and theirs. A flaw in how the kernel uses them is in scope.
