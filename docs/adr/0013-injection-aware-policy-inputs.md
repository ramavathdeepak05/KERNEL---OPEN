# ADR-0013: Injection-aware policy inputs

- **Status:** Accepted
- **Date:** 2026-11-11
- **Decided by:** maintainers (proposed in review of the prompt-injection threat model)
- **Affects:** `quaicu/core/policy/evaluator.py` (CEL activation), `quaicu/core/provenance.py` (new),
  `quaicu/delivery/mcp/` (proxy, server, governance), `quaicu/delivery/sdk/kernel.py`
  (`govern_action`, `call_payload`, `resume_approved`), `quaicu/delivery/sdk/proxy.py`. No change to
  `quaicu/core/ports`, `quaicu/core/types` or `quaicu/core/errors`, and none to the frozen ledger files.

## Context

The kernel governs *actions*: an agent's tool call is evaluated against CEL policies before it runs.
That is the right place to contain prompt injection, because the kernel cannot reliably tell
whether text the model read changed its plan, but it can limit what the model is then able to do. A
review found that policies did not have the inputs to do this:

1. A policy saw only the action type, the actor and the payload. It could not tell whether the agent
   session had read untrusted content, so it could not hold "send email after reading a web page".
2. Payload values that were lists or maps reached CEL as Python `repr` strings (`"['a@x.com']"`),
   forcing brittle substring rules. Keys that are not CEL identifiers (`reply-to`) could not be
   referenced.
3. celpy lets `exists`/`all`/`map`/`filter`/`exists_one` iterate a string's characters, which
   standard CEL does not. A deny rule written for a list, `payload_to.exists(r, r.endsWith("@evil"))`,
   is false for the string `"x@evil"` and is skipped. An agent chooses its arguments' types, so this
   was a bypass.
4. `require_approval` on an MCP tool could never lead to the tool running: each retry was a new
   action with a fresh idempotency key, and the approval completed the action without calling the tool.
5. `guard`/`wrap` left positional arguments out of the payload, and `kernel.proxy` sent policies only
   the method name and argument count.

## Decision

- **CEL activation.** Payload values are converted structurally: lists, tuples and sets become CEL
  lists, mappings become CEL maps, `None` becomes `null`. The whole payload is also bound as the map
  `payload` (`payload["reply-to"]`, `"cc" in payload`). Payload strings are a `StringType` subclass
  that raises when iterated (the evaluation then fails closed to DENY) and still satisfies
  `type(x) == string`. The policy-backtest route uses the same conversion.
- **Session provenance.** `quaicu.core.provenance.SessionProvenance` records which untrusted tools a
  session has read. The trusted integration stamps it onto `Actor.attributes["quaicu.session"]` (an
  existing field) before every governed call. Policies see three always-defined variables:
  `session_tracked`, `session_tainted`, `session_sources`. Tool arguments become the payload and can
  never set them. Taint is sticky until the host calls `reset()`.
- **MCP.** The proxy and the server take untrusted tools (`untrusted_tools=` / `register_tool(...,
  untrusted=True)`), record taint after such a tool runs, and stamp provenance on every call. The
  proxy also takes `allowed_tools`, and pins each tool's definition (name, description, input schema)
  when first listed: a tool whose definition later changes is hidden and its calls are denied.
- **Approve, then retry.** `Kernel.govern_action(retry_key=...)` reuses the pending action for a
  retried call with the same fingerprint (tenant, actor, action type, arguments). Such actions carry
  `Actor.attributes["quaicu.execute_on_retry"]`, so an approval records the decision and leaves the
  action pending instead of completing it without its tool. The retry then executes, seals and emits
  once. A rejection or expiry denies the retry. Once the action is terminal, the key is released.
- **SDK payloads.** `guard`, `wrap`, `governed` and `governed_tool` bind positional arguments to their
  parameter names. `kernel.proxy` passes the call's keyword arguments and positional values.

## Consequences

- Existing policies that matched the `repr` of a list or map (for example
  `payload_tags.contains("'urgent'")`) must be rewritten against the structured value. A top-level
  `None` payload value is now `null`, not the string `"None"`.
- A policy that iterates a payload string now denies the action instead of silently iterating.
- Policies that reference positional arguments of a guarded function now evaluate them instead of
  failing closed on a missing field.
- An approved MCP tool call no longer completes at approval time; it completes when the agent retries.
  An identical later call needs a fresh approval.
- The retry index and provenance are in process memory. After a restart a retry requests a fresh
  approval, and a proxy starts with a clean session.
- Enforced by `tests/adversarial/test_prompt_injection.py`, `tests/unit/policy/test_activation.py`,
  `tests/unit/policy/test_agent_egress_pack.py`, `tests/unit/sdk/test_call_payload.py` and
  `tests/unit/mcp/test_proxy_transport.py`.

## Alternatives considered

- **Detect injected text** (classifiers, keyword filters on tool output). Detection is probabilistic
  and evadable, and a false negative fails open. It may be added later as an optional *source* of
  taint; it cannot replace action-level containment.
- **Add a `context` field to `Action`.** Cleaner, but it changes the frozen `core/types.py` contract
  and every storage adapter. `Actor.attributes` already exists, is persisted by the Postgres
  repository, and describes the acting session.
- **Run the tool at approval time** in the approving process. That process does not hold the tool (the
  MCP proxy is a separate process), so the action would complete without its effect.
