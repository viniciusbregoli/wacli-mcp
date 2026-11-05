"""The `account` tool argument.

In multi-account mode every tool takes a required `account`, limited to the
aliases the operator configured. In single-account mode the argument is
resolved on the server and left out of the schema, so existing clients see
exactly the tool signatures they had before.
"""

# No `from __future__ import annotations`: the returned annotation is evaluated by the SDK.
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import Resolve
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from .config import Config


def account_param(cfg: Config, views: tuple[Config, ...], purpose: str) -> Any:
    """Annotation for the `account` parameter of a tool that serves `views`."""
    if not cfg.multi_account:
        alias = views[0].alias

        async def single_account() -> str:
            return alias

        return Annotated[str, Resolve(single_account)]
    aliases = tuple(view.alias for view in views)
    described = ", ".join(f"{v.alias} ({v.label})" if v.label else v.alias for v in views)
    return Annotated[
        Literal[aliases],  # type: ignore[valid-type]
        Field(description=f"Which WhatsApp account to {purpose}: one of {described}. Accounts never share data."),
    ]


def select(cfg: Config, alias: str) -> Config:
    try:
        return cfg.account_view(alias)
    except KeyError:
        raise ToolError("unknown account") from None
