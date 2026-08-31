"""MCP server exposing read-only Okta identity lookups over Streamable HTTP.

No tool here returns a raw Okta object. Every field a tool can return is
named explicitly in identity_fields.py -- see that module for the
allowlists and the reasoning behind them.
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.types import ToolAnnotations

from auth import DEFAULT_SCOPE
from config import load_config
from identity_fields import (
    MalformedGroupResponse,
    MalformedUserResponse,
    select_group_fields,
    select_lookup_user_fields,
    select_lookup_user_org_context_fields,
    select_user_core_fields,
)
from okta_users import OktaRequestError, fetch_user, fetch_user_groups
from token_cache import TokenCache

MAX_COMPARE_USERS = 5  # refuse above this, never truncate -- see compare_user_groups

HOST = os.environ.get("MCP_HOST", "127.0.0.1")
# Configurable via MCP_HOST so the same server.py works unmodified in both
# places this runs. Default stays 127.0.0.1, the safe value, for running
# server.py directly in the dev container.
#
# Inside the runtime (Podman) container, 127.0.0.1 would only be reachable
# from within that container's own network namespace -- Podman would have
# nothing to forward the published port to. The runtime container's image
# sets MCP_HOST=0.0.0.0 explicitly to bind all interfaces inside the
# container. The loopback restriction is then enforced at the port publish
# step instead: `-p 127.0.0.1:8000:8000`, not `-p 8000:8000`. Don't publish
# without the 127.0.0.1 prefix, or the port opens to every interface on the
# host.
PORT = 8000  # change this one value to move the server to a different port


@dataclass
class AppContext:
    org_url: str
    token_cache: TokenCache


@asynccontextmanager
async def lifespan(server: MCPServer) -> AsyncIterator[AppContext]:
    config = load_config()
    yield AppContext(org_url=config.org_url, token_cache=TokenCache(config, scope=DEFAULT_SCOPE))


mcp = MCPServer("okta-identity-mcp", version="0.1.0", lifespan=lifespan)


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


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def compare_user_groups(user_ids: list[str], ctx: Context) -> dict:
    """Compare group membership across up to 5 Okta users, for access review.

    Parameters:
        user_ids: 1-5 Okta user IDs, logins, or emails to compare.
            Refuses (never truncates) if more than 5 are given.

    Returns a dict:
        requested: number of user_ids passed in.
        returned: number of users successfully resolved (len(results)).
            If returned < requested, at least one user_id failed to
            resolve -- check errors for which one and why. Do not
            describe this as a complete N-way comparison unless
            requested == returned.
        results: one entry per successfully resolved user: user_id (as
            requested), id, status, login, email, firstName, lastName,
            and groups (list of {id, name, description, type}).
        errors: one entry per user_id that failed to resolve: user_id
            (as requested) and error.

    Raw data only -- no diff, intersection, or common/unique summary is
    computed. Group membership comparison is the caller's job, checkable
    against this output.
    """
    if len(user_ids) > MAX_COMPARE_USERS:
        raise ValueError(
            f"compare_user_groups accepts at most {MAX_COMPARE_USERS} user_ids; got {len(user_ids)}."
        )

    app_ctx = ctx.request_context.lifespan_context
    access_token, token_type, dpop_key = app_ctx.token_cache.get_token()

    results = []
    errors = []
    for user_id in user_ids:
        try:
            user = fetch_user(app_ctx.org_url, access_token, dpop_key, user_id, token_type=token_type)
            raw_groups = fetch_user_groups(
                app_ctx.org_url, access_token, dpop_key, user_id, token_type=token_type
            )
            entry = {"user_id": user_id, **select_user_core_fields(user)}
            entry["groups"] = [select_group_fields(group) for group in raw_groups]
            results.append(entry)
        except (OktaRequestError, MalformedUserResponse, MalformedGroupResponse) as exc:
            errors.append({"user_id": user_id, "error": str(exc)})

    return {
        "requested": len(user_ids),
        "returned": len(results),
        "results": results,
        "errors": errors,
    }


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
