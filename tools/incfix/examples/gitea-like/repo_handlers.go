// Synthetic fixture that models the shape of the real CVE-2026-27761 case in
// Gitea (self-hosted Git service). It is NOT Gitea source; it is a small,
// labeled stand-in so `incfix.py scan` has something to run against and
// demonstrably flags the same residual the real hunt found.
//
// The real story: the download endpoints (/raw, /media, /archive) call the
// token-scope guard checkDownloadTokenScope. The RSS/Atom feed handlers carry
// the AllowBasic auth middleware and serve the same repository content, but
// never call that guard - so a narrowly scoped token reads private commit data
// through the feeds. Session-cookie-only routes (.patch, .diff, blame) also
// serve content but have no token scope to bypass, so they are false positives
// and must be pruned.
//
// Each handler below is annotated with its route and middleware chain, the way
// many codebases document handlers. incfix reads the enclosing function block.

package repo

// ---- guarded download handlers (the fix covered these) ----

// GET /{owner}/{repo}/raw/branch/{branch}/{path}   [middleware: AllowBasic]
func SingleDownload(ctx *Context) {
	if !checkDownloadTokenScope(ctx) {
		ctx.Error(403)
		return
	}
	serveRepoContent(ctx, ctx.Repo.Commit)
}

// GET /{owner}/{repo}/media/branch/{branch}/{path}   [middleware: AllowBasic]
func SingleDownloadOrLFS(ctx *Context) {
	if !checkDownloadTokenScope(ctx) {
		ctx.Error(403)
		return
	}
	serveRepoContent(ctx, ctx.Repo.Commit)
}

// GET /{owner}/{repo}/archive/{ref}.{ext}   [middleware: AllowBasic]
func Download(ctx *Context) {
	if !checkDownloadTokenScope(ctx) {
		ctx.Error(403)
		return
	}
	serveRepoContent(ctx, ctx.Repo.Archive)
}

// ---- RSS/Atom feed handlers (the sibling paths the fix missed) ----

// GET /{owner}/{repo}/rss/branch/{branch}   [middleware: AllowBasic]
func ShowBranchFeedRSS(ctx *Context) {
	// serves the branch commit history as RSS; no token-scope check here
	serveRepoContent(ctx, ctx.Repo.Commit)
}

// GET /{owner}/{repo}/atom/branch/{branch}   [middleware: AllowBasic]
func ShowBranchFeedAtom(ctx *Context) {
	serveRepoContent(ctx, ctx.Repo.Commit)
}

// GET /{owner}/{repo}.rss   [middleware: AllowBasic]
func ShowRepoActivityFeed(ctx *Context) {
	serveRepoContent(ctx, ctx.Repo.Activity)
}

// GET /{owner}/{repo}/tags.rss   [middleware: AllowBasic]
func ShowTagsFeed(ctx *Context) {
	serveRepoContent(ctx, ctx.Repo.Tags)
}

// ---- session-cookie-only routes (false positives; must be pruned) ----

// GET /{owner}/{repo}/commit/{sha}.patch   [middleware: AllowSessionOnly]
func RawPatch(ctx *Context) {
	// authenticates by session cookie, not by token; no token scope to bypass
	serveRepoContent(ctx, ctx.Repo.Commit)
}

// GET /{owner}/{repo}/blame/{path}   [middleware: AllowSessionOnly]
func RefBlame(ctx *Context) {
	serveRepoContent(ctx, ctx.Repo.Commit)
}
