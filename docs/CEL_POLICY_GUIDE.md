# Writing QUAICU CEL policies — context for your AI assistant

**How to use this file:** paste it into ChatGPT / Claude / Gemini (or any LLM) as context, then ask:
*"Using these rules, write a QUAICU policy that …"*. Everything the model needs to produce **valid,
compatible** CEL for the QUAICU governance kernel is below. Always review the result and run it through
the kernel's draft → backtest → activate flow before enforcing.

---

## What a QUAICU policy is

QUAICU governs **actions** (e.g. `loan.approve`, `email.send`, `record.delete`). A **policy** has two
parts:

1. a **condition** — a CEL **boolean expression** describing *which actions the policy applies to*; and
2. a **decision** — what to do when the condition is true: `allow`, `deny`, or `require_approval`.

So a policy reads: **"IF `<condition>` THEN `<decision>`."** Produce both parts.

## The ONLY variables a condition may use

The kernel flattens each action into this fixed set of CEL variables. **Use these exact names — no
others exist.** There are **no built-in time, date, request, or environment variables**; if a value
isn't here, it must come from the action payload.

| Variable | Type | Notes / example |
|---|---|---|
| `action_type` | string | the action being governed, e.g. `action_type == "loan.approve"` |
| `action_tenant` | string | the tenant id, e.g. `action_tenant == "acme"` |
| `actor_id` | string | who/what initiated it, e.g. `actor_id == "svc:batch"` |
| `actor_roles` | list&lt;string&gt; | roles of the actor; test with `"role:analyst" in actor_roles` |
| `payload_<field>` | string \| int \| double \| bool \| list \| map \| null | **one variable per top-level payload field**, prefixed with `payload_`. `payload.amount` → `payload_amount` |
| `payload` | map | the whole payload; reaches keys that are not identifiers (`payload["reply-to"]`) and tests presence (`"cc" in payload`) |
| `session_tracked` | bool | the host records session provenance for this actor (an MCP proxy/server does) |
| `session_tainted` | bool | the agent session has read output from a tool marked untrusted |
| `session_sources` | list&lt;string&gt; | names of those untrusted tools, e.g. `"fetch" in session_sources` |

Payload rules:
- Values keep their structure: lists are CEL lists, objects are CEL maps, `null` is `null`. Index
  into them: `payload_to.exists(r, r.endsWith("@acme.com"))`, `payload_request.method == "POST"`.
- Match the literal type: integer field → `payload_amount > 1000000`; decimal field →
  `payload_score >= 0.8`; boolean field → `payload_is_external == true`.
- A list macro (`exists`, `all`, `map`, `filter`) on a **string** is an error, so it denies. An agent
  that sends `"to": "x@evil.com"` instead of a list cannot skip a rule written for a list.
- Referencing a field the action does not carry is an error, so it denies. Use `"field" in payload`
  for optional fields.

### Session provenance (prompt injection)

An agent that has read a web page, an email or a file may be following instructions an attacker
wrote there. The kernel cannot tell whether it is, so it tells the policy whether the session *has
read* such content. Tools whose output is untrusted are listed in the MCP proxy's `untrusted_tools`
(or registered with `untrusted=True`); after one of them runs, `session_tainted` is true for the rest
of the session. The agent cannot set these variables: its tool arguments become `payload_*`.

- **Hold egress after untrusted input:** `session_tainted` → `require_approval`
- **Treat "not tracked" as tainted (fail-closed):** `!session_tracked || session_tainted`
- **Allow only from a clean session:** `session_tracked && !session_tainted` → `allow`

The `agent-egress` policy pack (`quaicu/policy_packs/agent-egress/`) applies this to three action
types: read, egress and execute.

## Decisions and how conflicts resolve

- Values: `"allow"`, `"deny"`, `"require_approval"` (use `require_approval` to route to a human).
- Many policies can match one action. Resolution is **deny-overrides**: **`deny` beats
  `require_approval` beats `allow`.** Prefer the least-privilege decision your rule implies.
- **Fail-closed:** if a condition errors at runtime (e.g. a type mismatch), the whole evaluation is
  treated as **deny**. Write total, type-correct conditions.
- Actions matched by **no** policy fall through to the deployment's **default decision** (often `deny`
  in a fail-closed setup) — so make the outcome you intend explicit.

## CEL syntax you can rely on (celpy)

- Logical: `&&`, `||`, `!`  · Comparison: `== != < <= > >=`  · Arithmetic: `+ - * / %`
- Membership: `x in list` (e.g. `"role:admin" in actor_roles`)
- Ternary: `cond ? a : b`
- String methods: `s.startsWith("x")`, `s.endsWith("x")`, `s.contains("x")`, `s.matches("regex")`
- `size(x)` for a string or list (e.g. `size(actor_roles) == 0`)
- String literals use double quotes: `"loan.approve"`.

- List macros: `list.exists(x, cond)`, `list.all(x, cond)`, `list.filter(x, cond)`, `list.map(x, expr)`
- Type checks: `type(payload_to) == list`, `type(payload_to) == string`

**Do not** invent functions, reference variables not listed above, use dotted access on the action
(`payload.amount` is wrong — use `payload_amount` or `payload["amount"]`), or write multi-statement
code. A condition is one
boolean expression.

## Output format (ask your AI to return this)

```json
{
  "condition": "<one CEL boolean expression using only the variables above>",
  "decision": "allow | deny | require_approval",
  "explanation": "<one sentence: what this enforces>"
}
```

## Worked examples

```json
{ "condition": "action_type == \"loan.approve\" && payload_amount > 1000000",
  "decision": "require_approval",
  "explanation": "Loan approvals over 1,000,000 need a human approver." }
```
```json
{ "condition": "action_type == \"record.delete\" && !(\"role:admin\" in actor_roles)",
  "decision": "deny",
  "explanation": "Only admins may delete records." }
```
```json
{ "condition": "action_type == \"email.send\" && payload_recipient_external == true",
  "decision": "require_approval",
  "explanation": "Outbound email to external recipients is reviewed before sending." }
```
```json
{ "condition": "action_type == \"model.invoke\" && payload_contains_pii == true && action_tenant == \"eu-bank\"",
  "decision": "deny",
  "explanation": "Block model calls carrying PII for the EU tenant." }
```
```json
{ "condition": "action_type == \"refund.issue\" && payload_amount <= 100",
  "decision": "allow",
  "explanation": "Auto-allow small refunds up to 100." }
```

## Common patterns

- **Role gate:** `"role:risk_officer" in actor_roles`
- **Threshold:** `payload_amount > 50000`
- **Type scope (always start here):** `action_type == "<your.action.type>" && <rule>`
- **Combine:** `action_type == "x" && (payload_a > 10 || payload_b == true)`
- **Service vs human actor:** `actor_id.startsWith("svc:")`
- **Pattern match:** `payload_email.matches(".*@partner\\.com$")`
- **Any recipient outside the domain:** `payload_to.exists(r, !r.endsWith("@acme.com"))`
- **Optional field:** `"cc" in payload && size(payload["cc"]) > 0`
- **After untrusted input:** `session_tainted`

## Before it enforces (the safe path)

The drafted policy is a *candidate*. In QUAICU you: register it as **DRAFT** (`POST /v1/policies`),
**backtest** it against recorded history to see what it *would* have allowed/denied, optionally run it
in **shadow**, then **activate** it. So author boldly — you get to verify against real data before any
action is blocked.

---
*Tip: tell your AI the action types and payload fields your system actually emits (you can see them by
running QUAICU in `monitor`/`audit_only` mode first). The more concrete the field names, the better the
policy.*
