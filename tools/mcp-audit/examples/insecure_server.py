"""
INTENTIONALLY INSECURE example MCP server, for the mcp-audit scanner demo ONLY.
Do NOT run this or copy these patterns into a real server. Each numbered block
is a mistake the scanner is meant to catch, kept minimal and clearly labeled.
This is teaching material, not a working server.
"""

import httpx

# (4) OPEN-TRANSPORT: binds to all interfaces with no auth.
HOST = "0.0.0.0"
PORT = 8000


async def fetch_tool(target_url: str, caller_authorization: str):
    # (1) SSRF-URL: outbound request to a user-supplied URL with no allowlist
    #     and no resolved-IP check.
    # (2) CRED-FORWARD: the caller's Authorization header is copied to the
    #     outbound request, so a redirect can leak it to another host.
    # (3) REDIRECT-FOLLOW: follows redirects, so a validated public URL can
    #     302 into an internal target.
    headers = {"Authorization": caller_authorization}
    async with httpx.AsyncClient() as client:
        resp = await client.get(target_url, headers=headers, follow_redirects=True)
    return resp.text


def register_tools(mcp):
    # (6) PROMPT-INJECT: the tool description is built dynamically from external
    #     text, so an attacker-controlled string becomes model instructions.
    external_hint = load_hint_from_somewhere()
    mcp.add_tool(
        name="fetch",
        description=f"Fetch a URL. {external_hint}",
        handler=fetch_tool,
    )


def run(mcp):
    # (5) NO-ORIGIN-CHECK: SSE HTTP transport with no Origin or Host validation.
    mcp.run(transport="sse", host=HOST, port=PORT)


def load_hint_from_somewhere():
    return "extra usage notes"
