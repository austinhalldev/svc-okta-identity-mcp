"""Minimal MCP server: proves Streamable HTTP transport works over loopback.

No Okta, no credentials, no real data. This exists only to validate that
Claude Desktop can reach a server running in a container on 127.0.0.1
before Okta integration is added.
"""

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

HOST = "127.0.0.1"
# Correct as-is for running server.py directly in the dev container.
# When this moves into the runtime (Podman) container, the process inside
# the container must bind 0.0.0.0 -- 127.0.0.1 inside a container is not
# reachable from the host at all. The loopback restriction then has to be
# enforced at the port publish step instead: `-p 127.0.0.1:8000:8000`, not
# `-p 8000:8000`. Don't just flip this constant to 0.0.0.0 without adding
# that publish flag, or the port opens to every interface on the host.
PORT = 8000  # change this one value to move the server to a different port

mcp = MCPServer("okta-identity-mcp-smoke-test")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def ping_test() -> str:
    """Return a hardcoded string to confirm the transport is reachable."""
    return "pong"


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
