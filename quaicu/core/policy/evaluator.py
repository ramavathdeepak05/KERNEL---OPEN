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
from collections.abc import Mapping
from typing import Any

from celpy import celtypes

from quaicu.core.errors import PolicyEvaluationError, PolicyNotFoundError
from quaicu.core.policy.store import PolicyStore
from quaicu.core.provenance import SESSION_ATTRIBUTE
from quaicu.core.types import Action, ApproverRef, Decision, EvaluationResult

log = logging.getLogger("quaicu.policy")


# SESSION_ATTRIBUTE: the actor-attribute key under which the host (SDK / MCP proxy) records the
# session's provenance — which untrusted sources the agent has read so far. Set by trusted integration
# code, never by the agent: tool arguments become the payload, not actor attributes.


class _StringTypeMeta(type):
    """Makes `_PayloadString` compare equal to `celtypes.StringType`, so ``type(x) == string`` holds."""

    def __eq__(cls, other: object) -> bool:
        return other is celtypes.StringType or type.__eq__(cls, other)

    def __ne__(cls, other: object) -> bool:
        return not _StringTypeMeta.__eq__(cls, other)

    def __hash__(cls) -> int:
        return hash(celtypes.StringType)


class _PayloadString(celtypes.StringType, metaclass=_StringTypeMeta):
    """A CEL string that cannot be iterated.

    celpy lets the list macros (``exists``, ``all``, ``map``, ``filter``, ``exists_one``) iterate over a
    string's characters, which standard CEL does not. Then a deny rule written for a list,
    ``payload_to.exists(r, r.endsWith("@evil.example"))``, is false for the *string*
    ``"x@evil.example"`` (no single character ends with the domain), and the rule is skipped. An
    agent can choose the argument's type, so this would be a bypass. Iterating a payload string
    raises instead, which fails the evaluation closed (DENY).
    """

    __slots__ = ()

    def __iter__(self):  # noqa: D105
        raise TypeError("a string is not a list; check the argument's type in the policy")


def to_cel_value(val: Any) -> Any:
    """Convert a Python payload value to its CEL counterpart, preserving structure.

    Lists, tuples and sets become CEL lists, mappings become CEL maps (string keys) and ``None``
    becomes CEL ``null``, so a policy can write ``payload_to.exists(r, r.endsWith("@x.com"))`` or
    ``payload_options.dry_run == true`` instead of matching a Python ``repr`` string
    (docs/adr/0013-injection-aware-policy-inputs.md). Any other object is stringified, as before.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        return celtypes.BoolType(val)
    if isinstance(val, int):
        return celtypes.IntType(val)
    if isinstance(val, float):
        return celtypes.DoubleType(val)
    if isinstance(val, str):
        return _PayloadString(val)
    if isinstance(val, bytes | bytearray):
        return celtypes.BytesType(bytes(val))
    if isinstance(val, Mapping):
        return celtypes.MapType(
            {celtypes.StringType(str(k)): to_cel_value(v) for k, v in val.items()}
        )
    if isinstance(val, list | tuple | set | frozenset):
        items = sorted(val, key=repr) if isinstance(val, set | frozenset) else val
        return celtypes.ListType([to_cel_value(v) for v in items])
    # Best-effort: stringify anything else; the policy author must know their payload schema.
    return _PayloadString(str(val))


def payload_activation(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The payload part of a CEL activation: ``payload_<key>`` per field plus ``payload`` as a map.

    ``payload`` reaches keys that are not valid CEL identifiers (``payload["to-addr"]``) and lets a
    policy test for presence (``"cc" in payload``) without erroring on a missing field.
    """
    activation: dict[str, Any] = {"payload": to_cel_value(dict(payload))}
    for key, val in payload.items():
        activation[f"payload_{key}"] = to_cel_value(val)
    return activation


def session_activation(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """The session-provenance part of a CEL activation; always defined, so a policy never errors.

    - ``session_tracked``: the host records provenance for this actor (an MCP proxy/server, or an
      SDK caller that set it). False means the other two carry no information.
    - ``session_tainted``: the session has read output from a tool marked untrusted.
    - ``session_sources``: the names of those untrusted tools, sorted.

    A policy that must hold even when provenance is not tracked writes
    ``!session_tracked || session_tainted`` (treat "unknown" as tainted — fail-closed).
    """
    raw = (attributes or {}).get(SESSION_ATTRIBUTE)
    tracked = isinstance(raw, Mapping)
    session: Mapping[str, Any] = raw if tracked else {}
    sources = session.get("sources") or ()
    if isinstance(sources, str):
        sources = (sources,)
    names = sorted({str(s) for s in sources})
    return {
        "session_tracked": celtypes.BoolType(tracked),
        "session_tainted": celtypes.BoolType(bool(session.get("tainted")) or bool(names)),
        "session_sources": celtypes.ListType([celtypes.StringType(n) for n in names]),
    }


def _build_activation(action: Action) -> dict[str, Any]:
    """Flatten an `Action` into a CEL activation map with dot-free variable names.

    CEL variable names cannot contain dots, so the action hierarchy is flattened:
    - top-level: `action_type`, `action_tenant`
    - actor: `actor_id`, `actor_roles`
    - payload: each key prefixed with `payload_`, and the whole payload as the map `payload`
    - session provenance: `session_tracked`, `session_tainted`, `session_sources`
    """
    activation: dict[str, Any] = {
        "action_type": celtypes.StringType(action.type),
        "action_tenant": celtypes.StringType(str(action.tenant)),
        "actor_id": celtypes.StringType(str(action.actor.id)),
        "actor_roles": celtypes.ListType([celtypes.StringType(r) for r in action.actor.roles]),
    }
    activation.update(session_activation(action.actor.attributes))
    activation.update(payload_activation(action.payload))
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
