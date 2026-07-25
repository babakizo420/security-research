#!/usr/bin/env python3
"""
mcp-audit - a DEFENSIVE security self-audit for MCP (Model Context Protocol)
servers.

Point it at YOUR OWN MCP server's source tree and it statically flags the six
security-boundary mistakes that recur in MCP servers (SSRF, credential
forwarding, redirect following, open/unauthenticated transport, missing
DNS-rebinding and Origin validation, and prompt-injection surface in tool
metadata). Each hit comes with a severity, a remediation, and a reference.

An optional `live` mode runs a few BENIGN checks against a localhost or
own-endpoint MCP server you supply. It sends no attack payloads.

This tool audits code you own. It has no third-party scanning or mass-target
capability by design.

Author: babakizo420
License: MIT

Dependencies: Python 3.8+ standard library, plus `rg` (ripgrep) for static scan.
`live` mode uses only the standard library (urllib).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.request
import urllib.error

DOC = "See MCP-SECURITY-CHECKLIST.md in this directory for the full guidance."

# Each check: risky patterns (things to find), mitigation patterns (whose
# presence in the same file downgrades a hit to "verify, may be handled"),
# a severity, a remediation, and a reference note.
CHECKS = [
    {
        "id": "SSRF-URL",
        "title": "User-settable outbound URL / fetch with no allowlist",
        "severity": "HIGH",
        "risky": [
            r"requests\.(get|post|put|delete|request|head)\s*\(",
            r"httpx\.(get|post|put|delete|request|stream)\s*\(",
            r"httpx\.(Async)?Client\s*\(",
            r"\bclient\.(get|post|put|delete|request|stream)\s*\(",
            r"\bsession\.(get|post|put|delete|request)\s*\(",
            r"aiohttp\.[A-Za-z_]*[Ss]ession\(",
            r"urllib\.request\.urlopen\s*\(",
            r"\bfetch\s*\(",
            r"axios\.(get|post|put|delete|request)\s*\(",
            r"node-fetch",
        ],
        "mitigation": [
            r"allow[_-]?list", r"allowed_hosts", r"is_private", r"ip_address",
            r"ipaddress", r"validate_url", r"ssrf", r"deny[_-]?list",
            r"is_loopback", r"link_local",
        ],
        "remediation": "Resolve and pin the destination, then check the resolved "
                       "IP against an allowlist (or reject private, loopback, "
                       "link-local and cloud-metadata ranges) BEFORE the request. "
                       "Do the check on the resolved IP you will actually connect "
                       "to, not on the hostname string.",
    },
    {
        "id": "CRED-FORWARD",
        "title": "Auth header / credential forwarded to an outbound request",
        "severity": "HIGH",
        "risky": [
            r"[\"']Authorization[\"']\s*:",
            r"[\"']Cookie[\"']\s*:",
            r"[\"']Proxy-Authorization[\"']\s*:",
            r"Bearer\s+",
            r"headers\s*=\s*[A-Za-z_]+\.headers",
            r"forward.*header",
        ],
        "mitigation": [
            r"allow[_-]?list", r"same[_-]?origin", r"strip.*header",
            r"del\s+headers", r"drop.*credential",
        ],
        "remediation": "Never copy Authorization, Cookie, or other credential "
                       "headers into an outbound request whose host is user "
                       "controlled or reachable by redirect. Scope each secret to "
                       "its intended host and do not re-send it after a redirect.",
    },
    {
        "id": "REDIRECT-FOLLOW",
        "title": "Redirect following on fetch / health-check paths",
        "severity": "HIGH",
        "risky": [
            r"follow_redirects\s*=\s*True",
            r"allow_redirects\s*=\s*True",
            r"redirect\s*:\s*[\"']follow[\"']",
            r"maxRedirects\s*:\s*[1-9]",
        ],
        "mitigation": [
            r"follow_redirects\s*=\s*False",
            r"allow_redirects\s*=\s*False",
            r"redirect\s*:\s*[\"']manual[\"']",
            r"maxRedirects\s*:\s*0",
        ],
        "remediation": "Disable redirect following on any fetch of a user-supplied "
                       "URL. A validated public URL can 302-redirect into an "
                       "internal target (the classic MCP gateway SSRF). If you must "
                       "follow, re-validate the redirect target's resolved IP each "
                       "hop. NOTE: Python requests follows redirects by DEFAULT, so "
                       "an absent allow_redirects is still a finding.",
    },
    {
        "id": "OPEN-TRANSPORT",
        "title": "Transport bound to 0.0.0.0 or missing auth on the MCP transport",
        "severity": "HIGH",
        "risky": [
            r"0\.0\.0\.0",
            r"host\s*=\s*[\"']0\.0\.0\.0[\"']",
            r"host\s*:\s*[\"']0\.0\.0\.0[\"']",
            r"HOST\s*=\s*[\"']0\.0\.0\.0[\"']",
        ],
        "mitigation": [
            r"127\.0\.0\.1", r"localhost", r"require.*auth", r"api[_-]?key",
            r"bearer.*verify", r"auth.*middleware", r"Depends\(",
        ],
        "remediation": "Bind local MCP servers to 127.0.0.1, not 0.0.0.0. If the "
                       "transport must be reachable off-host, require an auth token "
                       "on every request. An unauthenticated MCP transport on all "
                       "interfaces exposes every tool to the network.",
    },
    {
        "id": "NO-ORIGIN-CHECK",
        "title": "HTTP/SSE transport without DNS-rebinding / Host / Origin validation",
        "severity": "MEDIUM",
        "risky": [
            r"SseServerTransport", r"streamable[_-]?http", r"transport\s*=\s*[\"']sse[\"']",
            r"@app\.(get|post)\s*\(\s*[\"']/sse[\"']", r"EventSourceResponse",
            r"text/event-stream",
        ],
        "mitigation": [
            r"[Oo]rigin", r"[Hh]ost.*validate", r"allowed_origins",
            r"TrustedHost", r"check.*origin", r"validate.*host",
        ],
        "remediation": "For HTTP or SSE transports, validate the Origin header "
                       "against an allowlist and validate the Host header, so a "
                       "malicious web page cannot reach a locally-bound MCP server "
                       "via DNS rebinding. The MCP spec recommends this for all "
                       "local HTTP transports.",
    },
    {
        "id": "PROMPT-INJECT",
        "title": "Tool description / params carry injectable instructions",
        "severity": "MEDIUM",
        "risky": [
            r"description\s*=\s*f[\"']",
            r"description\s*=\s*[A-Za-z_]+\s*\+",
            r"description\s*=\s*[\"'][^\"']*\b(ignore|disregard|instead|must|always|system prompt)\b",
            r"__doc__\s*=",
            r"docstring.*format",
        ],
        "mitigation": [
            r"sanitize.*description", r"escape.*description", r"static.*description",
        ],
        "remediation": "Keep tool names, descriptions, and parameter docs STATIC "
                       "and free of instruction-like text. A description built from "
                       "external or user data, or one that contains imperative "
                       "phrases, becomes a prompt-injection channel into the client "
                       "model. Review each dynamically-built or instruction-bearing "
                       "description by hand.",
    },
]


def die(msg):
    sys.stderr.write("mcp-audit: " + msg + "\n")
    sys.exit(2)


def have_rg():
    return shutil.which("rg") is not None


def rg_matches(pattern, root, globs):
    cmd = ["rg", "--json", "--no-heading", "-e", pattern] + globs + [root]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        die("ripgrep (rg) not found on PATH")
    results = []
    for raw in out.stdout.splitlines():
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if obj.get("type") != "match":
            continue
        d = obj["data"]
        path = d["path"].get("text")
        if path is None:
            continue
        results.append((path, d["line_number"], d["lines"].get("text", "").rstrip("\n")))
    return results


def file_code_has(pattern, path):
    """True if `pattern` appears in the file's CODE (comment lines and inline
    comments stripped), so a security term used in a comment does not read as a
    real mitigation."""
    import re as _re
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            code_lines = []
            for ln in fh:
                s = ln.lstrip()
                if s.startswith(("#", "//", "*", "/*", "///")):
                    continue
                code_lines.append(ln.split("#", 1)[0].split("//", 1)[0])
        return _re.search(pattern, "".join(code_lines)) is not None
    except OSError:
        return False


def cmd_static(args):
    if not have_rg():
        die("ripgrep (rg) is required for static scan")
    root = args.repo
    if not os.path.isdir(root):
        die("repo path is not a directory: " + root)

    exts = args.ext.split(",") if args.ext else ["py", "js", "ts", "tsx", "mjs", "go", "rb"]
    globs = []
    for e in exts:
        globs += ["-g", "*." + e.lstrip(".")]

    findings = []
    for check in CHECKS:
        hits = []
        for pat in check["risky"]:
            hits += rg_matches(pat, root, globs)
        # dedupe by (path, line)
        seen = set()
        uniq = []
        for h in hits:
            key = (h[0], h[1])
            if key not in seen:
                seen.add(key)
                uniq.append(h)
        for path, line, text in uniq:
            mitigated = any(file_code_has(m, path) for m in check["mitigation"])
            findings.append({
                "check": check["id"],
                "title": check["title"],
                "severity": ("REVIEW" if mitigated else check["severity"]),
                "mitigation_seen_in_file": mitigated,
                "path": os.path.relpath(path, root) if path.startswith(root) else path,
                "line": line,
                "snippet": text.strip()[:160],
                "remediation": check["remediation"],
            })

    sev_rank = {"HIGH": 0, "MEDIUM": 1, "REVIEW": 2}
    findings.sort(key=lambda f: (sev_rank.get(f["severity"], 3), f["check"],
                                 f["path"], f["line"]))

    if args.format == "json":
        print(json.dumps({"repo": root, "findings": findings,
                          "doc": DOC}, indent=2))
        return 0

    print("# mcp-audit static scan")
    print("# repo: " + root)
    print("# " + DOC)
    print()
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("Findings: " + ", ".join("%s=%d" % (k, counts[k])
                                    for k in ("HIGH", "MEDIUM", "REVIEW")
                                    if k in counts) + " (total %d)" % len(findings))
    print()
    for f in findings:
        tag = f["severity"]
        if f["mitigation_seen_in_file"]:
            tag += " (a mitigation pattern was seen in this file; verify it covers this call)"
        print("[%s] %s" % (tag, f["title"]))
        print("    %s:%d" % (f["path"], f["line"]))
        print("    %s" % f["snippet"])
        print("    fix: %s" % f["remediation"])
        print()
    if not findings:
        print("No matches for the six check classes. Still walk the checklist by "
              "hand; static text search does not prove safety.")
    print("These are LEADS for a human to verify. A pattern hit is not a proven "
          "bug, and an absence is not proven safety.")
    return 0


def cmd_live(args):
    """Benign, opt-in checks against a localhost/own-endpoint MCP server."""
    url = args.url
    allowed_local = ("http://127.0.0.1", "http://localhost", "https://127.0.0.1",
                     "https://localhost", "http://[::1]", "http://0.0.0.0")
    if not (url.startswith(allowed_local) or args.i_own_this_endpoint):
        die("live mode only targets localhost by default. To probe a non-local "
            "endpoint you own, re-run with --i-own-this-endpoint. This tool sends "
            "only benign requests and must not be pointed at systems you do not own.")

    print("# mcp-audit live (benign checks only): " + url)
    print("# This sends benign GET/OPTIONS requests. No attack payloads.")
    print()

    def probe(method, headers=None):
        req = urllib.request.Request(url, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {})
        except Exception as e:  # noqa: BLE001
            return None, {"error": str(e)}

    # 1) Does the transport answer without any auth header?
    status, hdrs = probe("GET")
    if status is None:
        print("[info] could not reach the endpoint: %s" % hdrs.get("error"))
        print("       start your own MCP server locally, then re-run.")
        return 0
    if status in (200, 400, 405, 406):
        print("[CHECK auth] transport answered a no-auth request with HTTP %d." % status)
        print("            Confirm your MCP transport requires an auth token; an "
              "unauthenticated transport exposes every tool.")
    elif status in (401, 403):
        print("[ok] transport rejected a no-auth request with HTTP %d (auth is "
              "enforced at the edge)." % status)
    else:
        print("[info] no-auth request returned HTTP %d." % status)

    # 2) Cross-origin: does it echo/accept an attacker Origin?
    _, hdrs2 = probe("GET", {"Origin": "http://evil.example"})
    aco = hdrs2.get("Access-Control-Allow-Origin")
    if aco in ("*", "http://evil.example"):
        print("[CHECK origin] Access-Control-Allow-Origin is '%s' for a foreign "
              "Origin. A local server that reflects Origin is reachable by a "
              "malicious web page (DNS-rebinding surface). Validate Origin against "
              "an allowlist." % aco)
    else:
        print("[ok] server did not reflect a foreign Origin in CORS headers.")

    # 3) Host header handling (rebinding hint): benign alternate Host.
    _, hdrs3 = probe("GET", {"Host": "attacker.local"})
    print("[note] sent a benign alternate Host header; if your server does not "
          "validate Host, a rebinding attack can reach it. Confirm Host/Origin "
          "validation in code (see the NO-ORIGIN-CHECK static finding).")

    print()
    print("Live mode is a smoke test, not a scanner. Use the static scan and the "
          "checklist for coverage.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="mcp_audit.py",
        description="Defensive security self-audit for MCP servers. Audit code "
                    "you own; no third-party or mass-target scanning.")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("static", help="static scan of your MCP server source")
    ps.add_argument("--repo", required=True, help="path to your MCP server source tree")
    ps.add_argument("--ext", default=None,
                    help="comma-separated extensions (default: py,js,ts,tsx,mjs,go,rb)")
    ps.add_argument("--format", choices=["text", "json"], default="text")
    ps.set_defaults(func=cmd_static)

    pl = sub.add_parser("live", help="benign smoke test against your own localhost endpoint")
    pl.add_argument("--url", required=True, help="your MCP endpoint, e.g. http://127.0.0.1:8000/sse")
    pl.add_argument("--i-own-this-endpoint", action="store_true",
                    help="required to target a non-localhost endpoint you own")
    pl.add_argument("--timeout", type=float, default=5.0)
    pl.set_defaults(func=cmd_live)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
