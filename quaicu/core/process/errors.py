"""K·06 Process Engine — error hierarchy.

All process errors extend ProcessError, which carries an ``error_code`` for
structured logging and an arbitrary ``context`` dict for debugging context.
Error codes are stable identifiers; changing one is a breaking change.
"""

from __future__ import annotations


class ProcessError(Exception):
    """Base class for all K·06 process errors."""

    error_code: str = "PE_000"

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.context: dict[str, object] = context


class WorkflowStartError(ProcessError):
    """Raised when a workflow cannot be started (PE_001)."""

    error_code = "PE_001"


class WorkflowStepError(ProcessError):
    """Raised when a step fails after all retries (PE_002).

    Carries the step name and the attempt number that triggered the error.
    """

    error_code = "PE_002"

    def __init__(self, message: str, step_name: str, attempt: int, **ctx: object) -> None:
        super().__init__(message, **ctx)
        self.step_name = step_name
        self.attempt = attempt


class WorkflowDeadlockError(ProcessError):
    """Raised when a deadlock is detected and cannot be recovered (PE_003)."""

    error_code = "PE_003"


class WorkflowDeadLetterError(ProcessError):
    """Raised when a workflow step is moved to the dead-letter queue (PE_004)."""

    error_code = "PE_004"


class WorkflowStuckError(ProcessError):
    """Raised when a workflow has been in a non-terminal state beyond its SLA (PE_005)."""

    error_code = "PE_005"


class WorkflowSignalError(ProcessError):
    """Raised when a signal cannot be delivered to a workflow (PE_006)."""

    error_code = "PE_006"


class WorkflowReplayError(ProcessError):
    """Raised when event-sourced replay produces an inconsistency (PE_007)."""

    error_code = "PE_007"


class WorkflowCompensationError(ProcessError):
    """Raised when the compensation / rollback sequence itself fails (PE_008)."""

    error_code = "PE_008"


class WorkflowTenantIsolationError(ProcessError):
    """Raised when a cross-tenant access is detected (PE_009).

    This is a security boundary violation — always fail-closed.
    """

    error_code = "PE_009"


class WorkflowNotFoundError(ProcessError):
    """Raised when a workflow handle references a non-existent workflow (PE_010)."""

    error_code = "PE_010"
