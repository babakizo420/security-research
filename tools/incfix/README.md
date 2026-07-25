# incfix - incomplete-fix / patch-diff sibling analyzer

`incfix` productizes a specific vulnerability-research technique: **incomplete-fix
analysis**. When a project patches a security bug, the fix often adds a guard (a
scope check, a permission check, a path sanitizer) to the one endpoint that was
reported, and leaves the *sibling* endpoints, the ones that reach the same
sensitive sink or serve the same class of content, untouched. Those siblings are
the residual bug the patch missed.

`incfix` takes the fix (a diff, or just the name of the guard it added) and a
codebase, and lists the sibling call sites that serve the same class but do
**not** call that guard. Those are your leads.

It is written in Python 3 (standard library only) and shells out to
[ripgrep](https://github.com/BurntSushi/ripgrep) (`rg`) for fast search.

Author: [@babakizo420](https://github.com/babakizo420). License: MIT.

## This is a heuristic, not a proof

`incfix` is a **lead generator**, not a sound analyzer. It flags candidates for a
human to read and confirm. It can produce false positives (a sibling that is
actually protected by shared middleware or a different code path) and false
negatives (a residual it does not recognize). Every hit must be verified by
opening the code. The value is that it turns "read every route by hand" into a
ranked short list.

## Install

No install step. You need Python 3.8+ and `rg` on your PATH.

```
python3 incfix.py --help
```

## Usage

Two subcommands, meant to be chained:

**1. `diff` - name the guard the fix added.** Feed it the security fix as a
unified diff; it reports the touched files and the guard-like function the fix
introduced.

```
python3 incfix.py diff --patch fix.patch
```

**2. `scan` - find the siblings that lack the guard.** Point it at the codebase,
give it the guard name, a pattern that marks the protected sink or content, and
optionally an auth marker and a false-positive marker.

```
python3 incfix.py scan --repo /path/to/repo \
    --guard checkDownloadTokenScope \
    --serves serveRepoContent \
    --auth AllowBasic \
    --exclude AllowSessionOnly \
    --ext go
```

- `--guard`   the check function the fix added (a regex, or `--literal` for a plain string). A block that calls it is considered protected and is skipped.
- `--serves`  a regex that marks a block as reaching the sensitive sink or serving the protected content class.
- `--auth`    (optional) a regex marking the auth or credential path (for example the middleware that lets a token authenticate). A block that carries it scores higher, because a token or credential actually reaches the sink there.
- `--exclude` (optional) a regex marking known false positives to prune (for example a session-cookie-only marker: a session has no token scope to bypass).
- `--ext`     (optional) comma-separated extensions to limit the scan (for example `go` or `py,js`).
- `--format`  `text` (default) or `json`.

`incfix` reads the enclosing function block of each `--serves` hit, including the
handler's doc comment (route and middleware annotations often live there), and
reports the blocks that serve the class but do not call the guard.

## Worked example: CVE-2026-27761 (Gitea)

This is the real case the tool models. Gitea (a self-hosted Git service) lets you
mint a Personal Access Token with a narrow scope, for example `read:issue` with
no repository access. The download endpoints (`/raw`, `/media`, `/archive`)
correctly enforce that scope by calling `checkDownloadTokenScope`. The prior fix
(for CVE-2026-20706) added that guard to the download paths. The RSS/Atom **feed**
handlers carry the same `AllowBasic` auth middleware and serve the same private
commit data, but never call the guard, so a token scoped to grant zero code
access can still read a private repo's commit history through its feeds. The
session-cookie-only routes (`.patch`, `.diff`, blame) also serve content, but a
session has no token scope to bypass, so they are false positives.

Full write-up: [`../../writeups/CVE-2026-27761-gitea.md`](../../writeups/CVE-2026-27761-gitea.md).

The repo ships a small labeled fixture (`examples/gitea-like/`) that models this
shape so the tool is runnable end to end. It is a synthetic stand-in, not Gitea
source.

Step 1, read the fix and name the guard:

```
$ python3 incfix.py diff --patch examples/gitea-like/fix.patch

Files touched by the fix:
  - routers/web/repo/download.go

Guard candidate(s) the fix appears to ADD (call sites in added lines):
  - checkDownloadTokenScope  (added 1 time(s))
```

Step 2, hunt the siblings that lack it:

```
$ python3 incfix.py scan --repo examples/gitea-like \
    --guard checkDownloadTokenScope --serves serveRepoContent \
    --auth AllowBasic --exclude AllowSessionOnly --ext go

Candidate blocks     : 9
Residual candidates  : 4 (blocks that serve the class + lack the guard)

[1] score=3  examples/gitea-like/repo_handlers.go:50
    // GET /{owner}/{repo}/rss/branch/{branch}   [middleware: AllowBasic]
    - serves the protected class (matches --serves) but does NOT call the guard 'checkDownloadTokenScope'
    - carries the auth marker (matches --auth), so a token/credential reaches this sink
[2] ... /atom/branch/{branch}
[3] ... /{owner}/{repo}.rss
[4] ... /{owner}/{repo}/tags.rss
```

The three guarded download handlers are skipped (they call the guard), the two
session-only routes are pruned by `--exclude`, and the four RSS/Atom feed
handlers, the exact sibling paths the real fix missed, are what remain. Each is a
lead to open and confirm by hand.

## More real cases this tool models

- **CVE-2026-55667 (File Browser), incomplete-fix, symlink / path traversal.** A prior fix added a containment guard to some file operations; sibling write and read paths that reached the same filesystem sink without routing through the guard remained. Model it with the containment function as `--guard` and the filesystem sink as `--serves`. Write-up: [`../../writeups/CVE-2026-55667-filebrowser.md`](../../writeups/CVE-2026-55667-filebrowser.md).
- **CVE-2026-63131 (OpenBao), cross-fork, access-control bypass.** A fork that lagged an upstream access-control fix: the same guard existed upstream and was absent in the fork's release. The same `scan` works across a fork boundary: point it at the fork with the upstream guard name and see which handlers never adopted it. Write-up: [`../../writeups/CVE-2026-63131-openbao.md`](../../writeups/CVE-2026-63131-openbao.md).

## Cross-fork mode

The same technique finds bugs a fork inherited but never fixed. Clone the fork,
use the guard name from the upstream fix as `--guard`, and `scan`. A handler that
serves the protected class but never calls the guard is a candidate the fork
lagged. Confirm the guard is genuinely absent on that path (not enforced by a
different middleware the fork uses) before trusting it.

## Defensive use

Run `incfix` against **your own** codebase after you ship a security fix, to
check you covered every sibling before an attacker finds the one you missed. It
reads source only; it never touches a running system or a third-party target.

## Limitations

- Block detection is best-effort. Brace languages balance `{ }`; Python-style languages use indentation. Unusual formatting can mis-bound a block.
- A guard enforced by shared middleware or a wrapper, rather than an in-handler call, will make a genuinely-protected sibling look unprotected. This is the most common false positive; always confirm by reading the route's full middleware chain.
- It matches text, not semantics. Tune `--serves`, `--auth`, and `--exclude` to the codebase.
