# SDK async-approval + error semantics demo

A single-process, zero-dependency walkthrough of how the QUAICU Python SDK surfaces governance
outcomes: the **typed exceptions** you catch and the **`kernel.approve` / `kernel.reject`** helpers
for the human-in-the-loop path (D1-1 / D2-3).

```bash
python examples/sdk-approval-demo/demo.py
```

## What it shows

| Beat | Policy decision | SDK behaviour |
|------|-----------------|---------------|
| 1 | `ALLOW` | the `@kernel.guard`-decorated function runs and returns normally |
| 2 | `DENY` | the call raises **`LifecycleDeniedError`** (terminal — do not retry) |
| 3 | `REQUIRE_APPROVAL` | the call raises **`LifecyclePendingApprovalError`** (not a failure — suspended durably); a *different* compliance officer calls **`await kernel.approve(exc.detail["handle_id"], actor=checker)`** → the action resumes, executes, and seals to the K·02 ledger |
| 4 | `REQUIRE_APPROVAL` | the **maker** approving their own action is blocked (`HITLPortError`) — separation of duties is enforced by the kernel |

## The pattern

```python
from quaicu.delivery.sdk import Kernel, LifecycleDeniedError, LifecyclePendingApprovalError

@kernel.guard(policy="payments.transfer")
async def transfer(*, amount: int, to: str) -> dict:
    return await bank.transfer(amount, to)

try:
    async with kernel.actor_context(maker):
        await transfer(amount=50_000, to="ACC-2")
except LifecycleDeniedError:
    ...  # policy said no — terminal
except LifecyclePendingApprovalError as exc:
    # A human must decide. Point an approver at exc.detail["handle_id"]:
    await kernel.approve(exc.detail["handle_id"], actor=checker)   # or kernel.reject(...)
```

Governance *outcomes* are the typed `LifecycleError` subclasses above. A **programmer** error —
calling a guarded function with no actor in scope, or `kernel.generate` with no inference adapter —
raises `SdkUsageError` instead. Both are importable from `quaicu.delivery.sdk`.
