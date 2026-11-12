"""Tool gateway (core): the configuration model and the rule compiler.

The runtime that fronts MCP servers is in ``quaicu/delivery/toolgate``; this package is pure.
"""

from quaicu.core.toolgate.model import (
    ToolConfigError,
    ToolGatewayConfig,
    ToolRule,
    ToolServerSpec,
    parse_rule,
    parse_tools_config,
)
from quaicu.core.toolgate.rules import (
    CONFIGURE_ACTION,
    ToolRuleSet,
    action_type,
    exposed_name,
    internal_name,
    split_exposed,
)

__all__ = [
    "CONFIGURE_ACTION",
    "ToolConfigError",
    "ToolGatewayConfig",
    "ToolRule",
    "ToolRuleSet",
    "ToolServerSpec",
    "action_type",
    "exposed_name",
    "internal_name",
    "parse_rule",
    "parse_tools_config",
    "split_exposed",
]
