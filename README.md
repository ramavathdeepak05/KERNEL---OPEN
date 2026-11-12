# QUAICU Kernel

A governance kernel for AI-driven actions that you run yourself. Before your code acts, the kernel
checks it against your policies, holds it for a human when a policy says so, and records what
happened in a signed, append-only ledger.

- **Yours to run.** Clone it and use it. There is no account, no signup and no hosted service, and
  with the starter configuration the kernel makes no outbound network calls.
- **Fail-closed.** An action runs only if a policy allows it. No matching policy, a policy that
  errors, an unknown caller or a failed ledger write all stop the action.
- **Two ways in.** Embed the Python package in your process, or run it as a local HTTP service and
  call it from any language.

Requires Python 3.11 or newer.

## Use it in Python

```bash
git clone https://github.com/ramavathdeepak05/KERNEL---OPEN.git quaicu && cd quaicu
pip install .
python examples/quickstart.py
```

To add it to an existing project without cloning:

```bash
pip install "git+https://github.com/ramavathdeepak05/KERNEL---OPEN.git"
```

```python
from quaicu import Kernel

kernel = Kernel.local(policies="examples/policies.toml")

@kernel.guard(policy="payments.wire")          # your function, plus one line
async def send_wire(*, amount: int, to: str) -> dict:
    ...

async with kernel.actor_context("alice", roles=("analyst",)):   # who is acting
    await send_wire(amount=500, to="ACME")
```

The keyword arguments become the action payload your policies see. Three things can happen:

| Policy decides | What your call does |
|---|---|
| `allow` | The function runs, and the action is sealed in the ledger. |
| `deny`, or no policy matches | Raises `LifecycleDeniedError`. The function does not run. |
| `require_approval` | Raises `LifecyclePendingApprovalError`. The function does not run; the action waits in the approvals queue. |

A waiting action is approved by someone else who holds the approver role:
`await kernel.approve(handle_id, actor=approver)`. That completes and seals the action. The kernel
does not call your function again, so your application performs the approved step once it sees the
approval.

`@kernel.guard` wraps the call as a coroutine. From synchronous code, call it with
`asyncio.run(...)` or use the HTTP service.

`Kernel.local()` keeps everything in memory. `kernel.check(...)` returns a verdict without running
anything, and `@kernel.governed_tool(...)` wraps agent tools.

## Put it between your AI and its tools

`quaicu gateway` is a governed MCP endpoint that sits in front of every tool server your AI agent
uses. The agent connects only to the gateway. The gateway starts the tool servers itself, with
their credentials, and every call the agent makes (read, write, send, anything) is checked against
the rules in your `kernel.toml` before it runs:

- A tool no rule covers is hidden from the agent and refused.
- `deny` beats `require_approval` beats `allow`.
- A rule can tighten once the session has read untrusted content, such as a web page or an email
  (`when_tainted`). This contains prompt injection: the injected text cannot get a write through
  without a person.
- Approvals and rule changes are for people only, through the admin API. The agent has no tool
  for either.
- Every call and every rule change is sealed in the ledger.

```toml
[tools]
agent_id  = "agent:assistant"
approvers = ["security"]

[[tools.server]]
name    = "github"
command = ["npx", "-y", "@modelcontextprotocol/server-github"]
env     = { GITHUB_PERSONAL_ACCESS_TOKEN = "${GITHUB_TOKEN}" }   # the agent never sees it

[[tools.server]]
name    = "web"
command = ["uvx", "mcp-server-fetch"]
untrusted_output = true

[[tools.rule]]
id       = "read"
tools    = ["web.fetch", "github.get_*", "github.list_*"]
access   = "read"
decision = "allow"

[[tools.rule]]
id           = "github-write"
tools        = ["github.create_*", "github.update_*"]
access       = "write"
decision     = "allow"
when_tainted = "require_approval"
```

```bash
pip install ".[mcp,server]"
quaicu gateway --config kernel.toml --admin-port 7001
```

Point the agent at that command as its only MCP server. For Claude Desktop, put this in
`claude_desktop_config.json`:

```json
{ "mcpServers": { "tools": { "command": "quaicu",
    "args": ["gateway", "--config", "/path/to/kernel.toml", "--admin-port", "7001"],
    "env": { "QUAICU_TOKEN": "<admin token>", "GITHUB_TOKEN": "<github token>" } } } }
```

The agent sees the tools as `github__create_issue`, `web__fetch` and so on. People use the admin
API on `127.0.0.1:7001`. It needs the token and a `policy_admin` role for `/v1/tools`, or an
approver role for `/v1/approvals`:

| Endpoint | Purpose |
|---|---|
| `GET /v1/tools` | Servers, tools, each tool's decision in a clean and a tainted session, the session's taint |
| `GET/POST/PUT/DELETE /v1/tools/rules[/{id}]` | Change the rules while the gateway runs; the next call uses them |
| `GET /v1/tools/rules?format=toml` | Export the live rules to paste into `kernel.toml` (live changes last until restart) |
| `POST /v1/tools/servers/{name}/disable` or `/enable` | Take a whole tool server out of service |
| `POST /v1/tools/session/reset` | Clear the taint when the agent's conversation starts over |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve` | Decide held calls; the agent's retry then runs the call once |

The gateway only governs the tools it fronts. Turn off the agent app's own built-in tools (shell,
file editing, web access), or the agent can act around the gateway. See [SECURITY.md](SECURITY.md).

## Use it from any language

Run the kernel as a local HTTP service:

```bash
pip install ".[server]"
quaicu init        # writes kernel.toml with three example policies
quaicu serve       # http://127.0.0.1:7000, API docs at /docs
```

or with Docker:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Every request carries one shared token and the name of the user your product is acting for. Set
`QUAICU_TOKEN` (16 characters or more) before starting to choose the token. If you leave it unset,
the kernel generates one for that run and prints it (with Docker:
`docker compose -f docker/docker-compose.yml logs kernel`).

```bash
export QUAICU_TOKEN=<the token>

# Ask for a decision. Your product enforces the answer.
curl -s localhost:7000/v1/authorize \
  -H "Authorization: Bearer $QUAICU_TOKEN" -H "X-Actor-Id: alice" -H "X-Actor-Roles: analyst" \
  -H "Content-Type: application/json" \
  -d '{"type": "payments.wire", "payload": {"amount": 500}}'

# Record an action through the full lifecycle.
curl -s localhost:7000/v1/actions/propose \
  -H "Authorization: Bearer $QUAICU_TOKEN" -H "X-Actor-Id: alice" -H "X-Actor-Roles: analyst" \
  -H "Content-Type: application/json" \
  -d '{"type": "payments.wire", "payload": {"amount": 500}, "idempotency_key": "wire-001"}'

# Read the signed audit trail.
curl -s localhost:7000/v1/ledger/local/trail \
  -H "Authorization: Bearer $QUAICU_TOKEN" -H "X-Actor-Id: auditor"
```

`python examples/http_walkthrough.py` runs the whole flow, including an approval, against a running
kernel.

| Endpoint | Purpose |
|---|---|
| `POST /v1/authorize` | A decision only: allow, deny or require approval. |
| `POST /v1/actions/propose` | Run an action through the lifecycle. Returns `COMPLETED` or `PENDING_APPROVAL`; 403 if denied. |
| `GET /v1/actions/{id}` | An action's current state. |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve` or `/reject` | The approvals queue. |
| `GET /v1/ledger/{tenant}/trail`, `/export` | The audit trail and a verifiable proof bundle. |
| `/v1/policies`, `/v1/policy-packs` | Manage policies at run time (needs the `policy_admin` role). |

The token proves a request comes from your product; your product names the user. Anyone who holds
the token can act as any user, so keep it secret and keep the service on localhost or a private
network. To have the kernel verify each user itself, switch `identity` to `jwt` or `oidc` in
`kernel.toml`. See [SECURITY.md](SECURITY.md).

## Policies

Policies are [CEL](https://github.com/google/cel-spec) conditions over `action_type`, `actor_id`,
`actor_roles` and `payload_<field>`:

```toml
[[policy.seed]]
id        = "wire-large-needs-approval"
governs   = "payments.wire"
condition = "payload_amount >= 10000"
decision  = "require_approval"
approvers = ["role:manager"]
```

- An action type with no matching policy is denied.
- When several policies match, `deny` beats `require_approval` beats `allow`.
- A condition that refers to a payload field the action does not carry is an error, and an error
  denies.

[docs/CEL_POLICY_GUIDE.md](docs/CEL_POLICY_GUIDE.md) is the authoring guide. Starter packs for the
DPDP Act, the EU AI Act and RBI/SEBI outsourcing rules ship in `quaicu/policy_packs/`; they are
drafts to adapt, not legal advice.

## Keeping state

The starter configuration keeps actions, approvals and the ledger in memory, so they are lost when
the process stops. For durable storage in PostgreSQL:

```bash
export QUAICU_TOKEN=$(openssl rand -hex 24)
docker compose -f docker/docker-compose.postgres.yml up --build
```

or install `".[server,postgres]"`, run the migrations in `quaicu/adapters/storage/migrations/`, and
use `docker/kernel.postgres.toml` as your config. Connect as an ordinary database role, not a
superuser: PostgreSQL does not apply the kernel's row-level-security policies to superusers. [kernel.example.toml](kernel.example.toml) lists
every option, including ledger signing with OpenBao or a cloud KMS and governed model inference.

## What is inside

| Layer | What it does |
|---|---|
| Policy engine | CEL policies with a draft → review → activate lifecycle and backtesting against recorded actions. |
| Ledger | RFC 6962 Merkle log with signed tree heads, inclusion and consistency proofs, optional external witness. |
| Approvals | Human-in-the-loop queue with separation of duties and expiry. |
| Consent | Purpose-bound consent checked before an action is evaluated (when a consent store is configured). |
| AI gateway | Model allowlist, PII masking, prompt logging and token budgets around model calls. |
| Tool gateway | One MCP endpoint in front of all of an agent's tool servers; rules in `kernel.toml`, changed live through `/v1/tools`; default deny; session taint for prompt injection. |
| Also | Durable workflows, event sinks, a model registry, fairness and drift sweeps, incident rollback, regulatory evidence packs, crypto-shredding for erasure, and an MCP server and proxy that govern agent tool calls. |

[ARCHITECTURE.md](ARCHITECTURE.md) describes the design: governance logic in `quaicu/core/` depends
only on interfaces, and the implementations in `quaicu/adapters/` are selected by configuration.

## Limits to know about

- One kernel serves one tenant, in one process when state is in memory.
- The ledger proves that an entry was recorded and, against a pinned key, that the log was not
  rewritten. A verifier cannot yet recompute an entry's hash from its readable fields, and the
  design is awaiting an independent cryptographic review. Details are in
  [SECURITY.md](SECURITY.md).
- With the default in-memory signer, the ledger's signing key changes on every restart.
- This is version 0.1.0. Interfaces may change.

## Development

```bash
pip install -e ".[test,dev]"
python -m pytest -q
ruff check .
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

QUAICU is a governance control, not a substitute for your own legal and regulatory obligations.
