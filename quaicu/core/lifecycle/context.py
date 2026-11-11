"""Actor context variable — set the governed actor once at the request/session boundary.

This is the zero-friction integration primitive. Instead of threading ``actor=`` through every
function call, a developer sets the actor once and all ``guard``/``wrap``-decorated functions
inside that scope automatically pick it up:

    async with kernel.actor_context(actor):
        result = await existing_function(arg1, arg2)   # signature unchanged

ContextVar semantics: correct for async tasks (each asyncio.create_task() inherits the parent
context at creation time, then runs in its own copy — no cross-task contamination).
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import AsyncGenerator, Generator

from quaicu.core.types import Actor

# The kernel-wide actor variable. One per async task / thread context.
_ACTOR_VAR: ContextVar[Actor | None] = ContextVar("quaicu_actor", default=None)


def get_current_actor() -> Actor | None:
    """Return the actor currently bound in this async task / thread, or None."""
    return _ACTOR_VAR.get()


def set_actor(actor: Actor | None) -> None:
    """Imperatively set the actor for this async task / thread.

    Prefer the context managers (``actor_scope`` / ``async_actor_scope``) which guarantee cleanup.
    Use this only when you can't use ``with`` / ``async with`` (e.g. in a coroutine that spans
    multiple await boundaries without a natural scope boundary).
    """
    _ACTOR_VAR.set(actor)


@contextmanager
def actor_scope(actor: Actor) -> Generator[None, None, None]:
    """Sync context manager: bind ``actor`` for the duration of the block, then restore.

    Usage::

        with kernel.actor_context(actor):
            result = existing_sync_function(arg1, arg2)
    """
    token = _ACTOR_VAR.set(actor)
    try:
        yield
    finally:
        _ACTOR_VAR.reset(token)


@asynccontextmanager
async def async_actor_scope(actor: Actor) -> AsyncGenerator[None, None]:
    """Async context manager: bind ``actor`` for the duration of the block, then restore.

    Usage::

        async with kernel.actor_context(actor):
            result = await existing_async_function(arg1, arg2)
    """
    token = _ACTOR_VAR.set(actor)
    try:
        yield
    finally:
        _ACTOR_VAR.reset(token)
