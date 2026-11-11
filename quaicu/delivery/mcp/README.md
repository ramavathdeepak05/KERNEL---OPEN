# QUAICU MCP governance (D2-1)

Govern an AI agent's **MCP tool calls** with the kernel: every call is mapped to a governed action
(policy → HITL → K·02 seal). Fail-closed — a denied or unapproved call **never runs the tool**.

Install: `pip install .[mcp]`

## Outcomes (all sealed)
| Policy decision | Result to the agent |
|---|---|
| **allow** | the tool runs; its result is returned |
| **deny** | `isError` result — the tool is **blocked** |
| **require_approval** | `isError` result carrying the approval **handle** — the action is PENDING; a human approves via `/v1/approvals` (or the email/Teams link), then the agent retries **the same call with the same arguments**, which runs it once and returns the result. Changed arguments need a new approval; a rejected approval denies the retry |
| infra/tool failure | `isError` (fail-closed HALT) |

## Writing policies for MCP tools

Each tool call is a governed action of type **`mcp.<tool_name>`** (e.g. `mcp.wire_transfer`), and the
tool's **arguments become the action payload** — so a CEL policy can condition on individual
arguments as `payload_<field>`:

```yaml
# governs a specific tool, conditioned on its argument:
- governs: "mcp.wire_transfer"
  condition: "payload_amount > 10000"     # the tool's `amount` argument
  decision: "require_approval"
  approvers: ["role:compliance"]
```

CEL variables available: `action_type`, `action_tenant`, `actor_id`, `actor_roles`,
`payload_<field>` for each tool argument (lists and objects keep their structure), `payload` (all
arguments as a map), and the session provenance variables `session_tracked`, `session_tainted`
and `session_sources` (below).

**Governing a group of tools with one policy.** `governs` matches an action type exactly (or `*`),
so to write a single policy for several tools, point them at a shared action type via the `policy`
knob (`register_tool(name, policy="mcp.tool")` / `default_policy="mcp.tool"` / `policy_for`), then
write one `governs: "mcp.tool"` policy. Without a knob value each tool defaults to its own
`mcp.<tool_name>` action type.

## Containing prompt injection

The kernel does not detect injected instructions. It limits what an agent can do after reading
content an attacker may have written, and records it:

- **Untrusted tools taint the session.** List the tools whose output can carry someone else's
  instructions (web fetch, email or file readers) as `untrusted_tools` (proxy) or register them with
  `untrusted=True` (server). After one runs, policies see `session_tainted == true` and the tool's
  name in `session_sources` for the rest of the session. The agent cannot clear this through its
  arguments; `proxy.provenance.reset()` starts a new session.
- **Pinned tool definitions.** The proxy pins each tool's name, description and input schema when
  first listed. A tool whose definition later changes is hidden from the agent and its calls are
  denied (`pin_tool_descriptions = false` turns this off).
- **`allowed_tools`** limits which downstream tools are listed and callable.
- **Starter policies:** the `agent-egress` pack (`quaicu/policy_packs/agent-egress/`) holds egress
  for approval and denies code execution once a session is tainted.

```toml
[mcp]
mode               = "proxy"
default_policy     = "agent.egress"                # unclassified tools are treated as egress
tool_policies      = { fetch = "agent.read", run_python = "agent.execute" }
untrusted_tools    = ["fetch"]
downstream_command = ["python", "-m", "my_tools_server"]
```

See SECURITY.md, "Prompt injection", for what this does not cover.

## Two ways to use it

### 1. Proxy an existing MCP server (drop-in — no client or tool code change)
Point your agent at `quaicu-kernel-mcp` instead of the real tool server; it mirrors the downstream's
tools and governs each call before forwarding.

```toml
# in your kernel config (KERNEL_CONFIG)
[mcp]
mode               = "proxy"
agent_id           = "agent:mcp"                 # sealed as the actor on every tool call
agent_roles        = ["agent"]
default_policy     = "mcp.tool"                  # the CEL policy that governs the calls
downstream_command = ["python", "-m", "my_tools_server"]
```
```bash
KERNEL_CONFIG=/etc/quaicu/kernel.gcp.toml quaicu-kernel-mcp
```

### 2. Govern your own tools (registered handlers)
```python
from quaicu.delivery.sdk.kernel import Kernel
from quaicu.core.types import Actor, ActorId
from quaicu.delivery.mcp.server import GovernedMCPServer

kernel = Kernel.from_config("kernel.gcp.toml")
await kernel.startup()
agent = Actor(id=ActorId("agent:research"), tenant=kernel.tenant, roles=("agent",))

server = GovernedMCPServer(kernel, actor=agent, default_policy="mcp.tool")
server.register_tool(
    "wire_transfer",
    handler=lambda args: do_transfer(**args),
    policy="payments.transfer",              # e.g. a require_approval CEL policy
    description="Move funds between accounts",
    input_schema={"type": "object", "properties": {"amount": {"type": "number"}}},
)
await server.run_stdio()
```

## Reusable core
`quaicu/delivery/mcp/governance.py::govern_tool_call(kernel, *, actor, tool_name, arguments, policy, execute)`
is a thin wrapper over `kernel.wrap(...)` (the same governed lifecycle the SDK decorators use). It has
no `mcp` dependency, so it's reusable and unit-testable — the server/proxy import `mcp` lazily.
