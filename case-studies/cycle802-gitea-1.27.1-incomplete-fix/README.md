# Cycle802 Lane 2 (incomplete-fix, big-name maintained) - Gitea 1.27.1: VERDICT WALK

- **Target:** go-gitea/gitea @ tag `v1.27.1` (HEAD a62dfffb, 2026-07-27). Big-name, actively maintained, has a GitHub Security Advisory program. NOT Forgejo (brief exclusion honored).
- **Program / policy read first:** Gitea publishes coordinated GHSA advisories; no cash bounty (credit/GHSA channel). Severity would map to CWE + GHSA. NO submission made.
- **Why this target:** v1.27.1 shipped a large cluster of fresh security fixes (CVE-2026-59774 org-mode file-read, CVE-2026-22874 incomplete SSRF allow-list, CVE-2026-59765/58418/58314/58441 migration SSRF, GHSA-rcr6 diffpatch RCE). A just-landed batch = the incomplete-fix window. Applied banked Go-SSRF incomplete-fix detectors.
- **Discipline note:** a batch this large is also a maintainer SWEEP + active-researcher SWARM (per banked lesson "incomplete-fix vein swarmed on popular targets"), so dup/low-residual risk is high. Ran the cheap detectors, found one real lead, refuted it rigorously. NO forced finding.

## Vein 1 - org-mode local file read (CVE-2026-59774 / GHSA-6v53-hr58-556r)
**Fix:** `modules/markup/orgmode/orgmode.go:73-79` overrides `org.New().ReadFile` to a STUB that returns the plaintext `#+INCLUDE: [[path]]` and never touches disk.
**Incomplete-fix hypotheses tested:**
- Sibling `org.New()` call sites (README/wiki/file-preview) still using default ReadFile? -> **REFUTED.** Grep: exactly ONE `org.New()` in the whole repo (centralized Render). 
- A second go-org file-read directive bypassing ReadFile (`#+SETUPFILE:`)? -> **REFUTED.** go-org v1.9.1 `keyword.go`: both `parseInclude` (:158) and `loadSetupFile` (:174) route through the SAME `d.ReadFile` callback that Gitea stubbed. No `os.Open`/`ioutil.ReadFile` bypass in those paths.
Fix is COMPLETE.

## Vein 2 - incomplete SSRF allow-list default filter (CVE-2026-22874)
**Fix:** `modules/hostmatcher/hostmatcher.go` adds `reservedIPNets` + `isReservedIP()` layered on `net.IP.IsPrivate()`, gated by `IsGlobalUnicast()` (:157/:163).
**Incomplete-fix hypotheses tested (banked SSRF-guard tells):**
- Cloud-metadata 169.254.169.254 reachable? -> blocked: it is link-local, `IsGlobalUnicast()==false`, so it matches neither `external` nor `private` builtin.
- IPv4-embedding IPv6 transitions (NAT64 / Teredo / 6to4) that smuggle 169.254.x? -> **already covered**: reservedIPNets lists `64:ff9b::/96` (explicitly noted for 169.254.169.254), `2001::/32` Teredo, `2002::/16` 6to4, plus CGNAT `100.64/10` and Azure WireServer `168.63.129.16/32`.
- ULA/link-local IPv6 (fd00::/7, fe80::/10) -> IsPrivate / not-GlobalUnicast. Covered.
Residual would be DNS-rebinding (resolve-public / connect-internal) = a separate, acknowledged class, not this fix's scope. Classification fix is COMPREHENSIVE.

## Vein 3 - migration/webhook raw-HTTP SSRF bypass (CVE-2026-59765/58418/58314 class) - THE REAL LEAD
Banked lesson "SSRF fix guards realm not blob-redirect": the sweep routed most outbound HTTP through `NewMigrationHTTPTransport()` (hostmatcher-validated `DialContext`, validates every dial incl. redirects). I enumerated EVERY outbound client in `services/migrations/`:
- github.go (:98/:115), gitlab.go (:317), gitea_downloader.go (:276), onedev.go (:81), gogs.go -> all use `NewMigrationHTTPTransport()`. Asset-download sinks (gitea_downloader:302, gitlab:337) ALSO have a `hasBaseURL(assetURL, g.baseURL)` prefix guard = doubly guarded.
- **codebase.go:88-96 = the ONLY raw `&http.Transport{Proxy:...}` (no hostmatcher DialContext).** Surfaced as the unguarded sibling the sweep missed.

**Skeptic gate / refutation (anti-overclaim):** NOT attacker-reachable SSRF.
- `NewCodebaseDownloader` HARDCODES `baseURL = https://api3.codebasehq.com` (codebase.go:81). The API client only ever dials that fixed third-party host.
- Factory (codebase.go:35-51) uses the user CloneAddr ONLY for its PATH: `fields = Split(Trim(u.Path,"/"), "/")`, requires `len==2`; `project=fields[0]`, `repoName=fields[1]`. Both are non-empty and contain no `/` (Trim strips edge slashes; Split can't yield empty edge fields). So `endpoint = "/proj/repo"` always begins with exactly one `/`, and `baseURL.Parse(endpoint)` keeps the host = api3.codebasehq.com. User input CANNOT force a `//host` protocol-relative host change.
- A redirect-to-internal would require api3.codebasehq.com (a fixed third party the attacker does not control) to issue the redirect. Not attacker-controllable.
-> **Defense-in-depth INCONSISTENCY, not an exploitable SSRF.** Worth a hardening note to Gitea (route codebase through the guarded transport for consistency + future-proofing if the host ever becomes dynamic), but NOT a submittable finding and NOT queued. Matches banked lesson "a sibling lacking the NAMED guard may be safe via a DIFFERENT mechanism (here: hardcoded host)."

## VERDICT: WALK. No finding. No submission.
The 1.27.1 security batch is a COMPLETE sweep on the three veins tested: org-mode file-read (stubbed, both directives), SSRF IP classification (comprehensive reservedIPNets incl. IPv4-embedding transitions), and migration outbound-HTTP (all provider clients guarded except the non-exploitable hardcoded-host codebase client). The one real lead (codebase raw transport) is refuted on reachability. Consistent with the swept-batch expectation for a popular, actively-swarmed target.

## Observation (hardening note, NOT a cash/CVE candidate)
`services/migrations/codebase.go:88` builds `&http.Client{Transport: &http.Transport{Proxy:...}}` instead of `NewMigrationHTTPTransport()`. Not currently exploitable (host hardcoded to api3.codebasehq.com), but it is the lone migration client outside the SSRF-validated transport - a latent gap if the Codebase base URL ever becomes configurable. Low/informational, defense-in-depth only.
