"""Session provenance ("taint") — which untrusted sources an agent session has read.

Prompt injection reaches an agent through data it reads: a web page, an email, a file, a tool
result. The kernel cannot tell whether that text changed the agent's plan, so it records that the
session *has read* untrusted data, and lets a policy act on it. For example, it can hold an outbound
email for approval once the agent has fetched a web page:

    governs   = "mcp.send_email"
    condition = "session_tainted"
    decision  = "require_approval"

A `SessionProvenance` is held by the trusted integration (the MCP proxy or server, or your own code
around an agent loop). After an untrusted tool returns, `record()` marks the session. Before each
governed call, `stamp()` copies the state into the actor's attributes under
`SESSION_ATTRIBUTE`; the policy engine exposes it as `session_tracked`,
`session_tainted` and `session_sources`. The agent cannot clear it: tool arguments become the
payload, never the actor.

Taint is sticky. It only grows until `reset()` is called, which the host does when a new
conversation starts. It does not decay with time and is not cleared by later trusted output.

Pure core: standard library only (AGENTS.md §1).
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Callable, Iterable
from typing import Any

from quaicu.core.types import Actor

# The actor-attribute key the policy engine reads (quaicu/core/policy/evaluator.py).
SESSION_ATTRIBUTE = "quaicu.session"

# Decides whether a tool's output is untrusted. A set of names (with "*" for every tool), or a
# callable taking the tool name.
TrustRule = Callable[[str], bool]


def untrusted_rule(spec: Iterable[str] | TrustRule | None) -> TrustRule:
    """Build a `TrustRule` from a set of tool names (``"*"`` = all), a callable, or None (none)."""
    if spec is None:
        return lambda _name: False
    if callable(spec):
        return spec
    names = frozenset(str(n) for n in spec)
    if "*" in names:
        return lambda _name: True
    return lambda name: name in names


class SessionProvenance:
    """The untrusted sources one agent session has read. Thread-safe; taint only grows."""

    def __init__(self) -> None:
        self._sources: set[str] = set()
        self._lock = threading.Lock()

    @property
    def tainted(self) -> bool:
        with self._lock:
            return bool(self._sources)

    @property
    def sources(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sources))

    def record(self, source: str) -> None:
        """Mark the session as having read output from ``source`` (an untrusted tool's name)."""
        with self._lock:
            self._sources.add(str(source))

    def reset(self) -> None:
        """Start a new session: forget every recorded source. Call only when the conversation
        context the agent carries has also been reset."""
        with self._lock:
            self._sources.clear()

    def as_attribute(self) -> dict[str, Any]:
        sources = self.sources
        return {"tainted": bool(sources), "sources": list(sources)}

    def stamp(self, actor: Actor) -> Actor:
        """Return ``actor`` with this session's provenance in its attributes (replacing any value
        already there, so a caller cannot pre-set an "untainted" state)."""
        attributes = dict(actor.attributes)
        attributes[SESSION_ATTRIBUTE] = self.as_attribute()
        return dataclasses.replace(actor, attributes=attributes)
