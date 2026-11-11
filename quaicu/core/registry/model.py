"""K·08 Model Registry — ModelRecord and ModelStatus.

Per F-07 the allowlist is always per-tenant. A model approved for tenant A is
never implicitly approved for tenant B.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ModelStatus(str, Enum):
    PENDING = "PENDING"         # awaiting human activation
    ACTIVE = "ACTIVE"           # approved for governed inference
    DEPRECATED = "DEPRECATED"   # no new actions; existing sealed entries unchanged
    RETIRED = "RETIRED"         # hard stop — Gateway denies all calls


@dataclass(frozen=True)
class ModelRecord:
    """An immutable snapshot of a model's registry entry for one tenant."""

    model_id: str
    version: str
    tenant_id: str
    status: ModelStatus
    registered_at: datetime
    deprecated_at: datetime | None = None
    retired_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
