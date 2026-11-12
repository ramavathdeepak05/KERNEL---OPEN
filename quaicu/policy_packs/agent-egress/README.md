# Starter policy pack — agent egress after untrusted input

> **A starting point, not a guarantee.** This pack limits what a hijacked agent can do. It does not
> detect prompt injection, and it cannot stop harm done through tools you map to `agent.read`.

Indirect prompt injection works like this: an agent reads text an attacker wrote (a web page, an
email, a file), the text tells the model to do something, and the model does it with the tools it
has. The kernel cannot see whether the text changed the model's plan. It can see whether the session
has *read* such text, because the MCP proxy or server records it (see
[`../../../docs/CEL_POLICY_GUIDE.md`](../../../docs/CEL_POLICY_GUIDE.md), "Session provenance").

This pack uses that record:

| Policy id | Rule | Decision |
|---|---|---|
| `agent-read-allow` | reading outside content is allowed (and taints the session) | allow |
| `agent-egress-clean-allow` | clean, tracked session sends data out | allow |
| `agent-egress-tainted-review` | tainted or untracked session sends data out | require_approval |
| `agent-execute-clean-allow` | clean, tracked session runs code | allow |
| `agent-execute-tainted-deny` | tainted or untracked session runs code | deny |

## Wiring it up

```toml
[mcp]
mode               = "proxy"
default_policy     = "agent.egress"          # anything not mapped below is treated as egress
untrusted_tools    = ["fetch", "read_email"] # their output taints the session
downstream_command = ["python", "-m", "my_tools_server"]
```

Map read tools to `agent.read` and code tools to `agent.execute` with the proxy's `policy_for`
(or `register_tool(..., policy=...)` on a `GovernedMCPServer`). Leaving everything else on
`agent.egress` is the fail-closed choice: a tool you forgot to classify is reviewed rather than
trusted.

An approval covers one call with the exact arguments the reviewer saw. The agent retries the same
call after approval and it runs once; changing any argument needs a new approval.

## What it does not cover

- Harm done through a read tool itself (for example a fetch to an attacker URL that carries data in
  the query string). Treat any tool that can reach an attacker-chosen address as `agent.egress`.
- Misleading answers to the user. The model can still say something wrong; only actions are governed.
- Taint does not expire. Reset the session (`proxy.provenance.reset()`) when the conversation is reset.
