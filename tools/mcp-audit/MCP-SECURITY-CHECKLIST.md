# MCP server security checklist

A hand checklist for auditing YOUR OWN MCP (Model Context Protocol) server. Work
it top to bottom. The `mcp_audit.py` scanner automates the first pass of items 1
through 6; the rest need human judgment.

MCP servers sit in a dangerous spot: they take instructions from an LLM (which
may be steered by untrusted content) and they hold real credentials and network
reach. The recurring failures below are the ones that turn "an assistant with a
tool" into "an SSRF proxy with your secrets."

## 1. Outbound URLs and SSRF

- [ ] Every tool that fetches a user-supplied or model-supplied URL resolves the host and checks the **resolved IP** against an allowlist (or rejects private, loopback, link-local `169.254.0.0/16`, and cloud-metadata `169.254.169.254` ranges) BEFORE connecting.
- [ ] The check is on the IP you will actually connect to, not on the hostname string. Validate-by-name then connect-by-name is a DNS-rebinding TOCTOU: the name can resolve to a safe IP at check time and an internal IP at connect time. Pin the resolved IP.
- [ ] IPv6 and IPv4-mapped IPv6 (`::ffff:169.254.169.254`), and alternate encodings of an IP, are all normalized before the check.
- [ ] There is no "fetch this URL" tool that a prompt-injected model can aim at your internal network.

## 2. Credential forwarding

- [ ] No outbound request copies the caller's `Authorization`, `Cookie`, or other credential headers to a host that is user controlled or reachable by redirect.
- [ ] Each secret (API key, token) is scoped to its intended destination host and is not attached to arbitrary outbound requests.
- [ ] After a redirect, credentials are NOT re-sent to the new host.

## 3. Redirect following

- [ ] Redirect following is disabled on any fetch of a user-supplied URL (`follow_redirects=False` in httpx, `allow_redirects=False` in requests, `redirect: "manual"` in fetch).
- [ ] If you must follow redirects, you re-run the resolved-IP allowlist check on EACH hop's target, not just the first URL.
- [ ] Remember: Python `requests` follows redirects by default, and many HTTP clients follow by default. An absent setting is still a risk.

## 4. Transport binding and authentication

- [ ] Local MCP servers bind to `127.0.0.1`, not `0.0.0.0`. Binding to all interfaces exposes every tool to the local network.
- [ ] If the transport must be reachable off-host, every request requires an auth token, checked server-side.
- [ ] There is no debug or admin transport left listening without auth.

## 5. DNS rebinding, Host and Origin validation (HTTP / SSE transports)

- [ ] HTTP and SSE transports validate the `Origin` header against an allowlist, so a malicious web page cannot drive a locally-bound MCP server from the user's browser.
- [ ] The `Host` header is validated, closing the DNS-rebinding path to a `127.0.0.1`-bound server.
- [ ] CORS does not reflect an arbitrary `Origin` with credentials.

## 6. Prompt-injection surface in tool metadata

- [ ] Tool names, descriptions, and parameter docs are STATIC. None are built from external or user data (an attacker-controlled description becomes instructions to the client model).
- [ ] No description contains instruction-like text (`ignore previous`, `always`, `instead`, a fake system prompt) that a model would follow.
- [ ] Tool OUTPUT that returns untrusted content is clearly framed as data, not as instructions, and the risk that a client model may act on it is documented.

## 7. Tool authorization and blast radius

- [ ] Each tool does the least it needs. A "read a file" tool cannot write; a "run a query" tool cannot run arbitrary shell.
- [ ] Any tool that executes code, runs shell, spawns a process, or writes files is gated behind explicit human approval, not auto-run on model request.
- [ ] File-path and command arguments from the model are validated and confined (no traversal, no shell metacharacters reaching a shell).

## 8. Secrets and logging

- [ ] Secrets come from the environment or a secrets manager, never hardcoded, never committed.
- [ ] Request and error logs do not record tokens, cookies, or full credential headers.
- [ ] Error messages returned to the client do not leak internal hostnames, file paths, or stack traces.

## 9. Dependencies and updates

- [ ] The MCP SDK and HTTP client libraries are current; you track their advisories.
- [ ] You re-run this checklist and the scanner after each security fix, to catch the sibling path the fix missed.

## References

- Model Context Protocol specification, security best practices: https://modelcontextprotocol.io
- OWASP Server Side Request Forgery Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- CWE-918 (SSRF), CWE-306 (missing authentication), CWE-441 (unintended proxy), CWE-350 (trusting reverse DNS), CWE-1021 (improper restriction of rendered UI / clickjacking and rebinding surface).
