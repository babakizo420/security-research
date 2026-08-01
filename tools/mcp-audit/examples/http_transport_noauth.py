"""
INTENTIONALLY INSECURE fixture for the mcp-audit `class-scan` demo ONLY
(the Dynatrace GHSA-p7w7-4929-vpj5 variant). Teaching material, not a server.

An HTTP MCP transport is created per request and handed the raw body with NO
auth check and NO DNS-rebinding / Origin / Host allowlist. Anyone who can reach
the port -- or any web page, via DNS-rebinding, even against a localhost bind --
can drive tools/call under the server's own credentials.

Expected `class-scan` verdict: VULNERABLE-CANDIDATE.
"""

from mcp.server.streamableHttp import StreamableHTTPServerTransport


async def handle(request):
    # No Authorization check, no session token, no Origin/Host allowlist.
    transport = StreamableHTTPServerTransport()
    body = await request.body()
    return await transport.handle(body)  # raw body straight to the MCP transport


def run(app):
    # binds an HTTP listener with an --http style flag and no protection
    app.listen(3000, host="0.0.0.0")
