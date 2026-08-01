# mcp-audit - defensive security self-audit for MCP servers

`mcp-audit` helps you audit **your own** MCP (Model Context Protocol) server for
the security-boundary mistakes that recur across MCP servers. MCP servers are a
sharp edge: they take instructions from an LLM (which untrusted content can
steer) and they hold real credentials and network reach, so a small slip turns
"an assistant with a tool" into "an SSRF proxy with your secrets."

It has a **static** scan of your source tree and an optional **live** smoke test
against a localhost or own-endpoint server. It ships a companion human checklist,
[`MCP-SECURITY-CHECKLIST.md`](MCP-SECURITY-CHECKLIST.md).

This tool is defensive by design. It reads code you own, and its live mode only
probes an endpoint you own, with benign requests. It has no third-party scanning,
no payload spraying, and no mass-target capability.

Author: [@babakizo420](https://github.com/babakizo420). License: MIT.

## What it checks

Six classes, each reported with a severity, the offending line, and a fix:

1. **SSRF-URL** - a user or model-settable outbound URL fetched with no allowlist and no resolved-IP check.
2. **CRED-FORWARD** - `Authorization` / `Cookie` / other credential headers copied to an outbound request (leakable via redirect).
3. **REDIRECT-FOLLOW** - redirect following on a fetch of a user-supplied URL (a validated public URL can 302 into an internal target: the classic MCP gateway SSRF).
4. **OPEN-TRANSPORT** - the transport bound to `0.0.0.0` or with no auth, exposing every tool to the network.
5. **NO-ORIGIN-CHECK** - an HTTP or SSE transport with no DNS-rebinding, Host, or Origin validation.
6. **PROMPT-INJECT** - a tool description or parameter doc built dynamically or carrying instruction-like text, a prompt-injection channel into the client model.

These map to the real MCP-class bugs seen in the wild (SSRF and credential
forwarding in MCP gateways, redirect-following on health-check and fetch paths,
unauthenticated transports). The scanner is mitigation-aware: when a file also
contains an allowlist, an Origin check, or another mitigation in code (not just
a comment), the finding is downgraded to REVIEW so you confirm the mitigation
covers that call.

## Install

Python 3.8+ and `rg` (ripgrep) for the static scan. `live` uses only the standard
library.

```
python3 mcp_audit.py --help
```

## Usage

Static scan of your MCP server source:

```
python3 mcp_audit.py static --repo /path/to/your/mcp-server
python3 mcp_audit.py static --repo /path/to/your/mcp-server --ext py,ts --format json
```

Benign live smoke test against your OWN localhost endpoint (opt-in; refuses a
non-localhost target unless you pass `--i-own-this-endpoint`):

```
python3 mcp_audit.py live --url http://127.0.0.1:8000/sse
```

Live mode sends only benign GET/OPTIONS requests. It checks whether the transport
answers without auth, whether it reflects a foreign `Origin`, and it notes the
Host-validation question. It is a smoke test, not a scanner.

### class-scan (repo-level verdict for the Dynatrace unauth-transport variant)

`class-scan` rolls the per-line `OPEN-TRANSPORT` and `NO-ORIGIN-CHECK` signals up
into one verdict for a specific, high-impact shape: an HTTP or SSE MCP transport
that has **neither** auth gating the transport **nor** DNS-rebinding / Origin
protection. That is the class of Dynatrace's MCP server before v2.0.0
([GHSA-p7w7-4929-vpj5](https://github.com/advisories/GHSA-p7w7-4929-vpj5)): in
`--http` mode it handed the raw request body to a per-request transport with no
auth and no Host/Origin allowlist, so anyone who could reach the port (or, by
DNS-rebinding, any web page even against a localhost bind) could fire
`tools/call` under the server's own credentials.

```
python3 mcp_audit.py class-scan --repo /path/to/your/mcp-server
python3 mcp_audit.py class-scan --repo /path/to/your/mcp-server --format json
```

Verdicts: **VULNERABLE-CANDIDATE** (http transport, no auth, no DNS-rebinding),
**REVIEW** (http transport with an auth signal but no DNS-rebinding: confirm the
auth actually runs before the body reaches the transport), **LIKELY-PROTECTED**
(a DNS-rebinding/Origin allowlist is present), or **N/A** (stdio-only). Auth and
DNS-rebinding signals are read from code, not comments, so a keyword in a
docstring does not mask a real gap. The `examples/http_transport_noauth.py` and
`examples/http_transport_protected.py` fixtures are the positive and negative
cases. A VULNERABLE-CANDIDATE is a lead: read the HTTP handler by hand and
enumerate what the exposed tools can do before calling it a finding.

## Worked example

The repo ships an intentionally-insecure fixture,
[`examples/insecure_server.py`](examples/insecure_server.py), that packs one of
each mistake into a tiny labeled file (teaching material, not a runnable server).
Running the scanner against it:

```
$ python3 mcp_audit.py static --repo examples --ext py

Findings: HIGH=5, MEDIUM=2 (total 7)

[HIGH] Auth header / credential forwarded to an outbound request
    insecure_server.py:22
    headers = {"Authorization": caller_authorization}
    fix: Never copy Authorization, Cookie, or other credential headers ...

[HIGH] Transport bound to 0.0.0.0 or missing auth on the MCP transport
    insecure_server.py:11
    HOST = "0.0.0.0"
    fix: Bind local MCP servers to 127.0.0.1 ...

[HIGH] Redirect following on fetch / health-check paths
    insecure_server.py:24
    resp = await client.get(target_url, headers=headers, follow_redirects=True)
    fix: Disable redirect following on any fetch of a user-supplied URL ...

[HIGH] User-settable outbound URL / fetch with no allowlist
    insecure_server.py:24
    resp = await client.get(target_url, ...)
    fix: Resolve and pin the destination, then check the resolved IP ...

[MEDIUM] HTTP/SSE transport without DNS-rebinding / Host / Origin validation
    insecure_server.py:41
    mcp.run(transport="sse", host=HOST, port=PORT)

[MEDIUM] Tool description / params carry injectable instructions
    insecure_server.py:34
    description=f"Fetch a URL. {external_hint}",
```

All six classes fire on the one fixture. Point it at your real server and work
the findings, then walk [`MCP-SECURITY-CHECKLIST.md`](MCP-SECURITY-CHECKLIST.md)
by hand for the items static search cannot judge (tool blast radius, secret
handling, human-approval gates on code-executing tools).

## Why this exists

The author's vulnerability research includes the MCP / AI-agent security class:
SSRF and credential-forwarding bugs in MCP gateways, redirect-following on
health-check paths, and unauthenticated transports. `mcp-audit` turns that
offensive knowledge into a defensive checklist any team can run on their own MCP
server before shipping it.

## Limitations

- Static text search flags patterns, not proven bugs, and its absence is not proven safety. Every hit is a lead to verify, and you must still walk the checklist for what it cannot see.
- Mitigation detection is best-effort and code-only (it ignores comments), but a mitigation applied in a different file or via a wrapper can still cause a false positive; confirm by reading the call's real path.
- Language coverage is Python, JavaScript, TypeScript, Go, and Ruby by default; tune `--ext` for your stack.
