"""GovernedProxy — wrap any existing object so its method calls pass through governance.

The proxy sits in front of any object (an LLM client, a database client, a service stub) and
intercepts specified method calls. Before each intercepted call, it asks the kernel for a policy
decision (``kernel.check()``); on DENY it raises ``LifecycleDeniedError`` before the real method
runs; on ALLOW it delegates to the original method and returns its result unchanged.

The policy sees the call's keyword arguments as ``payload_<name>`` (for a model client: ``model``,
``messages``, ``tools``, …), any positional values as ``payload_args``, plus ``payload_method`` and
``payload_args_count``. This is a decision-only check: ``require_approval`` is treated as a denial,
the call does not pass through the AI gateway (no PII masking or prompt logging — use
``kernel.generate`` for that), and the method's result is not sealed.

The actor is resolved from the ContextVar (set by ``kernel.actor_context(actor)``), or from an
explicit ``actor=`` kwarg passed at call time — so the governed object's call-site is unchanged.

Usage::

    import openai
    from quaicu.delivery.sdk import Kernel

    kernel = Kernel.from_config("kernel.toml")
    raw_client = openai.AsyncOpenAI(api_key="...")

    # ONE LINE: wrap the existing client
    client = kernel.proxy(
        raw_client,
        policies={
            "chat.completions.create": "ai.chat",
            "embeddings.create":        "ai.embed",
        },
    )

    # Existing code unchanged:
    async with kernel.actor_context(current_user):
        response = await client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "hello"}],
        )
"""

from __future__ import annotations

import inspect
from typing import Any

from quaicu.core.errors import LifecycleDeniedError
from quaicu.core.lifecycle.context import get_current_actor
from quaicu.core.types import Actor
from quaicu.delivery.sdk.errors import SdkUsageError


class _MethodProxy:
    """Trampoline proxy for a dotted-path method on an object.

    Each attribute access on a ``GovernedProxy`` returns a ``_MethodProxy`` that remembers the
    path walked so far. When the final callable is invoked, the path is checked against the
    policy map and governance is applied before delegating to the real method.
    """

    __slots__ = ("_root", "_path", "_policies", "_kernel", "_bound_actor")

    def __init__(
        self,
        root: Any,
        path: str,
        policies: dict[str, str],
        kernel: Any,
        bound_actor: Actor | None,
    ) -> None:
        self._root = root
        self._path = path
        self._policies = policies
        self._kernel = kernel
        self._bound_actor = bound_actor

    def __getattr__(self, name: str) -> "_MethodProxy":
        new_path = f"{self._path}.{name}"
        target = getattr(self._root, name)
        return _MethodProxy(target, new_path, self._policies, self._kernel, self._bound_actor)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        policy = self._policies.get(self._path)
        if policy is not None:
            return self._governed_call(policy, args, kwargs)
        # Not governed — delegate directly.
        result = self._root(*args, **kwargs)
        return result

    def _governed_call(self, policy: str, args: tuple, kwargs: dict) -> Any:
        """Async-aware governed call: check() then delegate."""
        import asyncio

        actor: Actor | None = kwargs.pop("actor", None) or self._bound_actor or get_current_actor()
        if actor is None:
            raise SdkUsageError(
                f"GovernedProxy.{self._path}: no actor in scope. "
                "Call inside `async with kernel.actor_context(actor): ...` "
                "or pass actor=<Actor> as a keyword argument."
            )

        real_method = self._root
        method_path = self._path
        kernel = self._kernel

        async def _async_call():
            result = await kernel.check(
                action_type=policy,
                actor=actor,
                payload=_proxy_payload(method_path, args, kwargs),
                record=None,  # follow profile default
            )
            if not result.allowed:
                raise LifecycleDeniedError(
                    f"GovernedProxy.{method_path} denied by governance",
                    detail={
                        "method": method_path,
                        "policy": policy,
                        "reason": result.reason,
                        "actor_id": str(result.actor_id),
                    },
                )
            # Delegate to the real method.
            ret = real_method(*args, **kwargs)
            if inspect.isawaitable(ret):
                return await ret
            return ret

        # If the original method is a coroutine function, return a coroutine.
        if inspect.iscoroutinefunction(real_method):
            return _async_call()

        # Sync method: run the check in the running event loop if available, else block.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — run synchronously via asyncio.run.
            return asyncio.run(_async_call())

        # Running loop — return a coroutine that the caller must await.
        return _async_call()


def _proxy_payload(method_path: str, args: tuple, kwargs: dict[str, Any]) -> dict[str, Any]:
    """What a policy sees for a proxied call: the method, the keyword arguments (for a model client:
    ``model``, ``messages``, ``tools`` …), and any positional values as ``args``."""
    payload: dict[str, Any] = dict(kwargs)
    if args:
        payload.setdefault("args", list(args))
    payload["method"] = method_path
    payload["args_count"] = len(args)
    return payload


class GovernedProxy:
    """A transparent proxy that governs specified method calls on any object.

    Attribute access not in the ``policies`` map is forwarded unchanged, so the proxy is truly
    transparent: the caller's code doesn't need to know it's there.
    """

    def __init__(
        self,
        target: Any,
        *,
        policies: dict[str, str],
        kernel: Any,
        actor: Actor | None = None,
    ) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_policies", policies)
        object.__setattr__(self, "_kernel", kernel)
        object.__setattr__(self, "_bound_actor", actor)

    def __getattr__(self, name: str) -> Any:
        target = object.__getattribute__(self, "_target")
        policies = object.__getattribute__(self, "_policies")
        kernel = object.__getattribute__(self, "_kernel")
        bound_actor = object.__getattribute__(self, "_bound_actor")

        attr = getattr(target, name)
        # If any policy path starts with this name, return a MethodProxy for deeper traversal.
        if any(p == name or p.startswith(name + ".") for p in policies):
            return _MethodProxy(attr, name, policies, kernel, bound_actor)
        return attr

    def __setattr__(self, name: str, value: Any) -> None:
        target = object.__getattribute__(self, "_target")
        setattr(target, name, value)

    def __repr__(self) -> str:
        target = object.__getattribute__(self, "_target")
        return f"GovernedProxy({target!r})"
