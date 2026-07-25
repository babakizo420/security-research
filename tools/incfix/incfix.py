#!/usr/bin/env python3
"""
incfix - incomplete-fix / patch-diff sibling analyzer.

Given a security fix (a diff, or a guard function name) and a codebase, incfix
finds the SIBLING call sites that reach the same sensitive sink or serve the same
class of content but do NOT call the guard the fix added. Those siblings are the
residual paths a point-fix commonly misses.

This is a heuristic lead generator, not a sound analysis. It surfaces candidates
for a human to read and verify. Read the README for the worked example
(CVE-2026-27761, Gitea) and the honest limitations.

Author: babakizo420
License: MIT

Dependencies: Python 3.8+ standard library, plus `rg` (ripgrep) on PATH.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# Language block styles. Brace languages close on balanced { }; Python and
# similar close on a dedent back to the header's indentation.
BRACE_EXTS = {".go", ".js", ".ts", ".tsx", ".jsx", ".rs", ".java", ".c", ".cc",
              ".cpp", ".h", ".hpp", ".cs", ".kt", ".scala", ".php", ".swift"}
INDENT_EXTS = {".py", ".rb"}

# Heuristic: a "guard-ish" identifier added by a security fix tends to be a
# call to a checker/validator. These substrings help auto-extract the guard
# from a diff when the user does not name it explicitly.
GUARD_HINTS = ("check", "validate", "verify", "ensure", "require", "assert",
               "scope", "permission", "perm", "authorize", "authz", "canaccess",
               "sanitize", "guard", "confine", "isallowed", "hasaccess")


def die(msg):
    sys.stderr.write("incfix: " + msg + "\n")
    sys.exit(2)


def have_rg():
    return shutil.which("rg") is not None


def rg_json(pattern, root, extra=None):
    """Run ripgrep and yield (path, line_no, line_text) for each match."""
    cmd = ["rg", "--json", "--no-heading"]
    if extra:
        cmd += extra
    cmd += ["-e", pattern, root]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        die("ripgrep (rg) not found on PATH")
    for raw in out.stdout.splitlines():
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if obj.get("type") != "match":
            continue
        data = obj["data"]
        path = data["path"].get("text")
        if path is None:
            continue
        line_no = data["line_number"]
        text = data["lines"].get("text", "")
        yield path, line_no, text.rstrip("\n")


def read_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


def indent_of(line):
    return len(line) - len(line.lstrip(" \t"))


def enclosing_block(lines, idx, ext):
    """
    Return (start, end) line indices (0-based, inclusive) of the function or
    handler block that contains line index `idx`. Best-effort across languages.
    """
    header_re = re.compile(
        r"^\s*(?:pub\s+|public\s+|private\s+|protected\s+|static\s+|async\s+|"
        r"export\s+|func|def|function|fn|sub)\b")
    # Walk up to the nearest header line.
    start = idx
    while start > 0 and not header_re.search(lines[start]):
        start -= 1
    if not header_re.search(lines[start]):
        # No header found; fall back to a small window around the match.
        return max(0, idx - 8), min(len(lines) - 1, idx + 20)

    header_line = start

    # Include the contiguous doc-comment lines directly above the header.
    # Route and middleware annotations (e.g. "[middleware: AllowBasic]") very
    # commonly live in the handler's doc comment, so they belong to the block.
    # Walk up over immediately-adjacent comment lines only; stop at any blank
    # or code line so we never merge into the previous handler.
    comment_prefixes = ("//", "#", "*", "/*", "///", "@")
    hdr = header_line
    while hdr - 1 >= 0 and lines[hdr - 1].strip().startswith(comment_prefixes):
        hdr -= 1
    start = hdr

    if ext in INDENT_EXTS:
        base = indent_of(lines[header_line])
        end = header_line + 1
        while end < len(lines):
            ln = lines[end]
            if ln.strip() == "" or ln.lstrip().startswith(("#", '"""', "'''")):
                end += 1
                continue
            if indent_of(ln) <= base:
                break
            end += 1
        return start, min(end, len(lines) - 1)

    # Brace languages: balance { } from the HEADER line forward. Count braces
    # only on code, not on comments, so route placeholders like {owner}/{repo}
    # in a doc comment do not fool the balancer.
    depth = 0
    seen_open = False
    end = header_line
    for j in range(header_line, len(lines)):
        stripped = lines[j].lstrip()
        if stripped.startswith(("//", "*", "///", "#")):
            code = ""  # whole-line comment: no braces
        else:
            code = lines[j].split("//", 1)[0]  # drop trailing inline comment
        depth += code.count("{") - code.count("}")
        if code.count("{") > 0:
            seen_open = True
        end = j
        if seen_open and depth <= 0:
            break
    return start, end


def block_text(lines, start, end):
    return "".join(lines[start:end + 1])


def contains(text, pattern):
    return re.search(pattern, text) is not None


def cmd_diff(args):
    """Parse a unified diff and report the guard(s) the fix appears to add."""
    if args.patch == "-":
        diff = sys.stdin.read()
    else:
        try:
            with open(args.patch, "r", encoding="utf-8", errors="replace") as fh:
                diff = fh.read()
        except OSError as exc:
            die("cannot read patch: " + str(exc))

    added = [l[1:] for l in diff.splitlines()
             if l.startswith("+") and not l.startswith("+++")]
    files = re.findall(r"^\+\+\+ [ab]/(.+)$", diff, re.MULTILINE)

    # Candidate guard identifiers: calls appearing in added lines whose name
    # looks like a checker. Rank by how many added lines mention them.
    call_re = re.compile(r"([A-Za-z_][A-Za-z0-9_\.]{2,})\s*\(")
    counts = {}
    for line in added:
        for name in call_re.findall(line):
            base = name.split(".")[-1].lower()
            if any(h in base for h in GUARD_HINTS):
                counts[name] = counts.get(name, 0) + 1

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))

    print("# incfix diff analysis")
    print()
    print("Files touched by the fix:")
    for f in sorted(set(files)):
        print("  - " + f)
    if not files:
        print("  (none parsed; is this a unified diff?)")
    print()
    print("Guard candidate(s) the fix appears to ADD (call sites in added lines):")
    if ranked:
        for name, n in ranked:
            print("  - %s  (added %d time(s))" % (name, n))
    else:
        print("  (none auto-detected; pass the guard name explicitly to `scan --guard`)")
    print()
    if ranked:
        top = ranked[0][0]
        print("Next step - hunt siblings that lack this guard:")
        print("  incfix.py scan --repo <REPO> --guard '%s' \\" % top)
        print("      --serves '<pattern that marks the protected sink or content>' \\")
        print("      [--auth '<auth middleware marker>'] [--exclude '<false-positive marker>']")
    return 0


def cmd_scan(args):
    if not have_rg():
        die("ripgrep (rg) is required for scan mode")
    root = args.repo
    if not os.path.isdir(root):
        die("repo path is not a directory: " + root)

    exts = None
    if args.ext:
        exts = set("." + e.lstrip(".") for e in args.ext.split(","))

    globs = []
    if exts:
        for e in exts:
            globs += ["-g", "*" + e]

    # 1) Collect candidate handler blocks: regions that serve the class.
    candidates = {}  # (path, start) -> block info
    for path, line_no, _ in rg_json(args.serves, root, globs):
        ext = os.path.splitext(path)[1]
        lines = read_lines(path)
        if not lines:
            continue
        start, end = enclosing_block(lines, line_no - 1, ext)
        key = (path, start)
        if key not in candidates:
            candidates[key] = {
                "path": path, "start": start, "end": end,
                "header": lines[start].strip()[:120],
                "text": block_text(lines, start, end),
            }

    # 2) Classify each candidate.
    findings = []
    guard_re = re.escape(args.guard) if args.literal else args.guard
    for key, c in candidates.items():
        text = c["text"]
        has_guard = contains(text, guard_re)
        has_auth = contains(text, args.auth) if args.auth else True
        excluded = contains(text, args.exclude) if args.exclude else False

        if has_guard:
            continue  # already protected; not a residual
        if excluded:
            continue  # matched a known false-positive marker; pruned

        score = 1
        reasons = ["serves the protected class (matches --serves) but does NOT "
                   "call the guard '%s'" % args.guard]
        if args.auth:
            if has_auth:
                score += 2
                reasons.append("carries the auth marker (matches --auth), so a "
                               "token/credential reaches this sink")
            else:
                # No auth marker: weaker lead (may be session-only). Keep but low.
                score -= 1
                reasons.append("no auth marker found in block (possible "
                               "session-only path; verify before trusting)")
        findings.append({
            "path": c["path"],
            "line": c["start"] + 1,
            "header": c["header"],
            "score": score,
            "reasons": reasons,
        })

    findings.sort(key=lambda f: (-f["score"], f["path"], f["line"]))

    if args.format == "json":
        print(json.dumps({
            "guard": args.guard, "serves": args.serves, "auth": args.auth,
            "exclude": args.exclude, "candidate_blocks": len(candidates),
            "findings": findings,
        }, indent=2))
        return 0

    print("# incfix scan")
    print()
    print("Guard the fix added : %s" % args.guard)
    print("Serves marker       : %s" % args.serves)
    if args.auth:
        print("Auth marker         : %s" % args.auth)
    if args.exclude:
        print("Exclude (prune)     : %s" % args.exclude)
    print("Candidate blocks     : %d" % len(candidates))
    print("Residual candidates  : %d (blocks that serve the class + lack the guard)"
          % len(findings))
    print()
    if not findings:
        print("No residual siblings found. Either the fix covered every sibling,")
        print("or the markers need tuning. This is a heuristic; re-check by hand.")
        return 0
    for i, f in enumerate(findings, 1):
        print("[%d] score=%d  %s:%d" % (i, f["score"], f["path"], f["line"]))
        print("    %s" % f["header"])
        for r in f["reasons"]:
            print("    - " + r)
        print()
    print("These are LEADS. Open each, confirm it truly reaches the sensitive")
    print("sink, and confirm the guard is genuinely absent (not enforced by a")
    print("shared middleware or a different code path). See the README.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="incfix.py",
        description="Find the sibling call sites a security fix missed "
                    "(incomplete-fix / variant analysis). Heuristic lead "
                    "generator; a human verifies every hit.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pd = sub.add_parser("diff", help="parse a fix diff and name the guard it adds")
    pd.add_argument("--patch", required=True,
                    help="path to a unified diff, or - for stdin")
    pd.set_defaults(func=cmd_diff)

    ps = sub.add_parser("scan", help="find siblings that lack the guard")
    ps.add_argument("--repo", required=True, help="path to the codebase to scan")
    ps.add_argument("--guard", required=True,
                    help="the guard/check function the fix added "
                         "(regex, or use --literal for a plain string)")
    ps.add_argument("--serves", required=True,
                    help="regex marking the protected sink or content class "
                         "(e.g. the sink call, a content-type, a route family)")
    ps.add_argument("--auth", default=None,
                    help="regex marking the auth/credential path "
                         "(e.g. AllowBasic); raises the score when present")
    ps.add_argument("--exclude", default=None,
                    help="regex marking known false positives to prune "
                         "(e.g. a session-cookie-only marker)")
    ps.add_argument("--ext", default=None,
                    help="comma-separated file extensions to limit the scan "
                         "(e.g. go,py)")
    ps.add_argument("--literal", action="store_true",
                    help="treat --guard as a literal string, not a regex")
    ps.add_argument("--format", choices=["text", "json"], default="text")
    ps.set_defaults(func=cmd_scan)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
