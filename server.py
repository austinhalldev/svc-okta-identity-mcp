"""MCP server exposing read-only Okta identity lookups over Streamable HTTP.

No tool here returns a raw Okta object. Every field a tool can return is
named explicitly in identity_fields.py -- see that module for the
allowlists and the reasoning behind them.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.types import ToolAnnotations

from auth import DEFAULT_SCOPE
from config import load_config
from identity_fields import select_lookup_user_fields, select_lookup_user_org_context_fields
from okta_users import fetch_user
from token_cache import TokenCache

HOST = "127.0.0.1"
# Correct as-is for running server.py directly in the dev container.
# When this moves into the runtime (Podman) container, the process inside
# the container must bind 0.0.0.0 -- 127.0.0.1 inside a container is not
# reachable from the host at all. The loopback restriction then has to be
# enforced at the port publish step instead: `-p 127.0.0.1:8000:8000`, not
# `-p 8000:8000`. Don't just flip this constant to 0.0.0.0 without adding
# that publish flag, or the port opens to every interface on the host.
PORT = 8000  # change this one value to move the server to a different port


@dataclass
class AppContext:
    org_url: str
    token_cache: TokenCache


@asynccontextmanager
async def lifespan(server: MCPServer) -> AsyncIterator[AppContext]:
    config = load_config()
    yield AppContext(org_url=config.org_url, token_cache=TokenCache(config, scope=DEFAULT_SCOPE))


mcp = MCPServer("okta-identity-mcp", lifespan=lifespan)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def lookup_user(user_id: str, ctx: Context) -> dict:
    """Look up an Okta user's core identity fields plus their last status change.

    Parameters:
        user_id: Okta user ID, login, or email.

    Returns: id, status, login, email, firstName, lastName, statusChanged.
    status is Okta's raw value (ACTIVE, DEPROVISIONED, SUSPENDED, STAGED,
    etc.), returned as-is -- not translated or prettified.
    """
    app_ctx = ctx.request_context.lifespan_context
    access_token, token_type, dpop_key = app_ctx.token_cache.get_token()
    user = fetch_user(app_ctx.org_url, access_token, dpop_key, user_id, token_type=token_type)
    return select_lookup_user_fields(user)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def lookup_user_org_context(user_id: str, ctx: Context) -> dict:
    """Look up an Okta user's core identity fields plus their org placement.

    Parameters:
        user_id: Okta user ID, login, or email.

    Returns: id, status, login, email, firstName, lastName, department,
    manager, title. department/manager/title are null when not set in
    Okta, not omitted -- see identity_fields.py.
    """
    app_ctx = ctx.request_context.lifespan_context
    access_token, token_type, dpop_key = app_ctx.token_cache.get_token()
    user = fetch_user(app_ctx.org_url, access_token, dpop_key, user_id, token_type=token_type)
    return select_lookup_user_org_context_fields(user)


# readOnlyHint above is a hint the MCP client MAY use for its own UI/policy
# decisions -- it is not enforced by the server or the protocol. The real
# read-only guarantee in this project comes from two things that don't exist
# yet: the Okta OAuth scopes granted to the credential, and the simple fact
# that no write tool is implemented. A client that ignores the hint entirely
# still can't call a tool that was never registered.


def main() -> None:
    mcp.run(transport="streamable-http", host=HOST, port=PORT)


if __name__ == "__main__":
    main()
