"""K·01 Policy Engine — the evaluator.

`PolicyEngine` implements the `PolicyEvaluator` protocol (quaicu/core/lifecycle/protocols.py) and satisfies
every guarantee in the frozen ADRs:

- F-03 (fail-closed): any error or empty policy set → DENY, never raise unhandled.
- F-05 (CEL): conditions are evaluated exclusively via celpy; no eval(), no Rego.
- F-08 (hexagonal): only core interfaces are imported; no concrete adapters.

Conflict resolution is total (no undefined outcome path):
  deny > require_approval > allow
  condition-false policies are skipped; if nothing matches → DENY (F-03).
"""

from __future__ import annotations

import logging
from typing import Any

from celpy import celtypes

from quaicu.core.errors import PolicyEvaluationError, PolicyNotFoundError
from quaicu.core.policy.store import PolicyStore
from quaicu.core.types import Action, ApproverRef, Decision, EvaluationResult

log = logging.getLogger("quaicu.policy")


def _build_activation(action: Action) -> dict[str, Any]:
    """Flatten an `Action` into a CEL activation map with dot-free variable names.

    CEL variable names cannot contain dots, so the action hierarchy is flattened:
    - top-level: `action_type`, `action_tenant`
    - actor: `actor_id`, `actor_roles`
    - payload: each key prefixed with `payload_`
    """
    activation: dict[str, Any] = {
        "action_type": celtypes.StringType(action.type),
        "action_tenant": celtypes.StringType(str(action.tenant)),
        "actor_id": celtypes.StringType(str(action.actor.id)),
        "actor_roles": celtypes.ListType([celtypes.StringType(r) for r in action.actor.roles]),
    }
    for key, val in action.payload.items():
        cel_key = f"payload_{key}"
        if isinstance(val, bool):
            activation[cel_key] = celtypes.BoolType(val)
        elif isinstance(val, int):
            activation[cel_key] = celtypes.IntType(val)
        elif isinstance(val, float):
            activation[cel_key] = celtypes.DoubleType(val)
        elif isinstance(val, str):
            activation[cel_key] = celtypes.StringType(val)
        else:
            # Best-effort: stringify anything else; the policy author must know their payload schema.
            activation[cel_key] = celtypes.StringType(str(val))
    return activation


class PolicyEngine:
    """Evaluates an action against all ACTIVATED policies and returns a total `EvaluationResult`.

    This class satisfies the `PolicyEvaluator` protocol structurally — no explicit inheritance is
    needed (or wanted, per the ports-and-adapters rule).
    """

    def __init__(self, store: PolicyStore) -> None:
        self._store = store

    async def evaluate(self, action: Action) -> EvaluationResult:  # noqa: C901 — complexity justified by the totality requirement
        policies = self._store.lookup(action.type, str(action.tenant))

        # F-03: empty policy set → fail-closed DENY (no policy governs this action).
        if not policies:
            log.info(
                "no ACTIVATED policy for action_type=%s tenant=%s — fail-closed DENY",
                action.type,
                action.tenant,
            )
            raise PolicyNotFoundError(
                f"No ACTIVATED policy governs action type {action.type!r} for tenant {action.tenant!r}.",
                detail={"action_type": action.type, "tenant": str(action.tenant)},
            )

        activation = _build_activation(action)

        matching_decisions: list[Decision] = []
        matching_approvers: list[ApproverRef] = []
        evaluated_versions: list[str] = []
        cel_fault = False

        for policy in policies:
            version_tag = f"{policy.id}@v{policy.version}"

            # Safety net: compiled_condition must exist (registered via PolicyStore.register).
            # If somehow it is missing, treat as fail-closed DENY for this policy.
            if policy.compiled_condition is None:
                log.error(
                    "policy %s has no compiled_condition — treating as fail-closed DENY", version_tag
                )
                cel_fault = True
                break

            try:
                raw_result = policy.compiled_condition.evaluate(activation)
                condition_true = bool(raw_result)
            except Exception as exc:  # noqa: BLE001 — CEL runtime fault → fail-closed for entire eval
                log.error(
                    "CEL evaluation error for policy %s: %s — fail-closed DENY", version_tag, exc
                )
                raise PolicyEvaluationError(
                    f"CEL evaluation failed for policy {version_tag}: {exc}",
                    detail={"policy_id": policy.id, "version": policy.version, "cause": str(exc)},
                ) from exc

            evaluated_versions.append(version_tag)

            if not condition_true:
                # Policy does not apply to this action; skip.
                continue

            matching_decisions.append(policy.decision)
            if policy.decision is Decision.REQUIRE_APPROVAL:
                matching_approvers.extend(policy.approvers)

        if cel_fault:
            raise PolicyEvaluationError(
                "CEL compilation artifact missing — fail-closed DENY.",
                detail={"action_type": action.type, "tenant": str(action.tenant)},
            )

        # F-03: no condition matched → fail-closed DENY.
        if not matching_decisions:
            log.info(
                "all policy conditions false for action_type=%s tenant=%s — fail-closed DENY",
                action.type,
                action.tenant,
            )
            raise PolicyNotFoundError(
                f"No policy condition matched action type {action.type!r} for tenant {action.tenant!r}.",
                detail={"action_type": action.type, "tenant": str(action.tenant)},
            )

        # Conflict resolution: deny > require_approval > allow (total — every path is covered).
        if Decision.DENY in matching_decisions:
            final = Decision.DENY
            approvers: tuple[ApproverRef, ...] = ()
        elif Decision.REQUIRE_APPROVAL in matching_decisions:
            final = Decision.REQUIRE_APPROVAL
            approvers = tuple(dict.fromkeys(matching_approvers))  # deduplicate, preserve order
        else:
            final = Decision.ALLOW
            approvers = ()

        log.info(
            "evaluation complete: action_type=%s tenant=%s decision=%s policies=%s",
            action.type,
            action.tenant,
            final.value,
            evaluated_versions,
        )

        return EvaluationResult(
            decision=final,
            policy_versions=tuple(evaluated_versions),
            approvers=approvers,
        )
