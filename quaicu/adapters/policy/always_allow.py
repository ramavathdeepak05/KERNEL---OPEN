"""AlwaysAllowPolicyAdapter — dev/demo only. Never use in production.

Registers as adapter key ``"always_allow"`` in the Kernel adapter registry.
Every action is allowed with a single pinned policy version. Intended for
local development and Docker demos where a real policy store is not wired.
"""

from __future__ import annotations

from quaicu.core.types import Action, Decision, EvaluationResult


class AlwaysAllowPolicyAdapter:
    """Policy evaluator that unconditionally allows every action."""

    def __init__(self, policy_version: str = "dev-always-allow-v1") -> None:
        self._version = policy_version

    async def evaluate(self, action: Action) -> EvaluationResult:
        return EvaluationResult(
            decision=Decision.ALLOW,
            policy_versions=(self._version,),
            approvers=(),
        )
