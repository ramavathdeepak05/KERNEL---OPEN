"""SDK-level error types.

Governance *outcomes* (deny / halt / pending approval) are the typed ``LifecycleError`` subclasses in
``core.errors`` — catch those to react to a decision. ``SdkUsageError`` is different: it signals a
**programmer error** in how the SDK was called (no actor in scope, a required adapter not configured).
It subclasses the frozen ``QUAICUError`` root so it carries a stable ``code`` and is catchable
alongside the rest of the kernel error tree, without adding a new type inside the frozen ``core/``
error surface.
"""

from __future__ import annotations

from quaicu.core.errors import QUAICUError


class SdkUsageError(QUAICUError):
    """The SDK was called incorrectly (missing actor, unconfigured adapter). Fix the call site.

    This is never raised for a governance outcome — a denied/halted/pending action raises the
    corresponding ``LifecycleError`` subclass instead.
    """

    code = "SDK_USAGE_ERROR"
