# ADR-0014: The tool gateway

- **Status:** Accepted
- **Date:** 2026-11-12
- **Decided by:** maintainers
- **Affects:** `quaicu/core/toolgate/` (new), `quaicu/delivery/toolgate/` (new),
  `quaicu/delivery/api/routes/tools.py` (new), `quaicu/delivery/mcp/proxy.py` (`expose` filter,
  tools-changed notification), `quaicu/delivery/sdk/kernel.py` (`toolgate` field, `expand_env`),
  `quaicu/cli.py` (`quaicu gateway`). No change to `quaicu/core/ports`, `quaicu/core/types`,
  `quaicu/core/errors` or the frozen ledger files.

## Context

The kernel could govern an agent's tool calls, but only one MCP server at a time (`quaicu-kernel-mcp`
in `[mcp]` proxy mode), and the guardrails had to be hand-written CEL policies mapped to tools by
action type. Approvals for a stdio proxy were unreachable with the in-memory default, because the
approvals API ran in a different process. The goal is a gateway that stands between the AI and every
tool it may use, so the AI can only think, and every action goes through policy. The guardrails
should be configured in the kernel, not described in documents.

## Decision

- **One endpoint, many servers.** `quaicu gateway` starts every `[[tools.server]]` as a child process
  with its credentials, and serves their tools to the agent over stdio MCP as `<server>__<tool>`.
  Server names cannot contain `_`, so a name always splits unambiguously and a server cannot
  impersonate another.
- **Rules in config.** `[[tools.rule]]` entries cover tools by glob over `<server>.<tool>` with
  `decision`, an optional `when_tainted` and an optional CEL `when` guard. `ToolRuleSet` compiles
  them into activated `PolicyEnvelope`s that govern the action type `tool.<server>.<tool>` and
  registers them in the kernel's `PolicyStore`, the same trusted path as `[[policy.seed]]`. The
  ordinary policy engine decides every call: deny > require_approval > allow, and no matching
  policy denies.
- **Default deny, twice.** A tool no rule covers, a tool a rule denies unconditionally, or a tool on
  a disabled server is hidden from the listing *and* refused before evaluation (the proxy's `expose`
  filter). With no policy, the engine would deny it anyway.
- **Live changes.** With `--admin-port`, the kernel's REST API runs in the gateway's process, so
  `/v1/approvals` and the new `/v1/tools` routes act on the running gateway. Every `/v1/tools`
  request needs a policy-admin role. Every change is the governed action `kernel.tools.configure`,
  allowed by a compiled policy for the admin roles and sealed with the actor. A change recompiles
  every rule as the next policy version, then deprecates the previous one. Live changes last until
  restart; `?format=toml` exports them.
- **People only.** The gateway exposes no approval or configuration tool to the agent. The agent's
  identity cannot approve its own calls (existing separation of duties).
- **Fail-closed startup.** Invalid `[tools]` config refuses to start: bad CEL, unknown decisions,
  duplicate names, unresolved `${VAR}` in a server's `env`, or a rule naming no configured server.
  So does a tool server that fails to start.

## Consequences

- Operators write guardrails as tool rules in `kernel.toml` and change them through `/v1/tools`;
  hand-written CEL remains available and combines with the rules.
- The gateway needs `adapters.policy = "cel_policy"` and the `mcp` extra (`server` for the admin API).
- Only stdio is served to agents; an HTTP MCP transport, plain REST tools and per-rule rate limits
  are future work.
- Enforced by `tests/unit/toolgate/`, `tests/unit/api/test_tools_routes.py`,
  `tests/unit/cli/test_gateway_cli.py` and the gateway cases in
  `tests/adversarial/test_prompt_injection.py`.

## Alternatives considered

- **A separate rule engine beside CEL.** That would be two decision paths to audit. Compiling rules
  into the existing policy store keeps one engine, one conflict rule and one ledger record per call.
- **Persist live rules in Postgres.** Deferred: `kernel.toml` stays the single reviewed source of truth,
  and every live change is already in the ledger.
- **Run the admin API in `quaicu serve` only.** The stdio gateway holds the pending calls and the
  session's taint in its own process, so approvals and live changes must reach that process.
