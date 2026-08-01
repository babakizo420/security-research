"""
PROTECTED reference fixture for the mcp-audit `class-scan` demo ONLY
(the fixed shape, mirroring Dynatrace v2.0.0). Teaching material, not a server.

The HTTP MCP transport is gated by a bearer token checked with a constant-time
compare BEFORE the body reaches the transport, and DNS-rebinding protection is
enabled with Host and Origin allowlists.

Expected `class-scan` verdict: LIKELY-PROTECTED.
"""

import hmac

from mcp.server.streamableHttp import StreamableHTTPServerTransport

EXPECTED = "set-me"  # MCP_BEARER_TOKEN in real deployments


async def handle(request):
    # Auth gates the transport: reject before any MCP work.
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    if not hmac.compare_digest(token, EXPECTED):
        return response(401, {"WWW-Authenticate": "Bearer"})
    transport = StreamableHTTPServerTransport(
        enableDnsRebindingProtection=True,
        allowedHosts=["127.0.0.1:3000"],
        allowedOrigins=["http://127.0.0.1:3000"],
    )
    body = await request.body()
    return await transport.handle(body)


def run(app):
    app.listen(3000, host="127.0.0.1")


def response(status, headers):
    return (status, headers)
