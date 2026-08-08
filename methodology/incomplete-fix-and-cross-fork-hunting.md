# How I hunt incomplete-fix and cross-fork bugs

Most of my published CVEs come from two ideas that are cheap to state and productive in practice.

## 1. Incomplete-fix hunting

When a project patches a vulnerability, the patch usually fixes the exact case that was reported. It often does not fix every code path that shares the same underlying weakness.

My process:

1. Start from a recently patched advisory. Read the patch, not just the description.
2. Understand precisely what the fix changed, and just as importantly, what it did not touch.
3. Find the sibling paths: another operation, another input, another entry point that reaches the same unsafe behaviour the fix only closed in one place.
4. Prove it against the released, patched version. A residual only counts if it is live in the artifact people actually run.

CVE-2026-55667 (File Browser) is a clean example: a prior CVE had addressed a link/traversal issue, but the recursive-delete path still followed symlinks across the user's scope boundary. Same weakness, a path the fix did not reach.

## 2. Cross-fork watching

Open-source projects get forked. When a security fix lands upstream, forks and downstream ports frequently lag, sometimes for a long time. That leaves a known-and-fixed bug still live in the fork.

My process:

1. Track security-relevant changes in a project and its known forks.
2. When the upstream fixes something, check whether the fork carried the fix.
3. Read the two codebases side by side around the changed area.
4. If the fork still has the issue, verify on the released fork build and disclose responsibly.

CVE-2026-63131 (OpenBao) came from exactly this: a policy-evaluation issue handled in HashiCorp Vault had not fully carried into the OpenBao fork.

## 3. The MCP / AI-agent security angle

The newest surface I focus on is the Model Context Protocol (MCP) and AI-agent ecosystem, where the same primitives keep recurring: a server that accepts a user-controllable URL and then forwards the operator's credentials or reaches internal endpoints (SSRF plus credential forwarding), or an auth boundary that is not actually enforced. It is a young, fast-moving class, which is why both the finding rate and the impact are high right now.

## 4. Scaling it

To run this continuously rather than by hand, I built an autonomous multi-agent pipeline that watches advisories and releases, surfaces incomplete-fix and cross-fork candidates, and helps verify and triage them, so the manual effort goes to the high-signal cases.

## Principles

- Prove it on the **released** version, never a development branch.
- Read the code to the metal; do not overclaim from a description.
- Separate confirmed from unconfirmed, and disclose responsibly.

## Reproduction fidelity (added from a cross-fork port-lag case study)
A cross-fork port-lag is confirmed at the SOURCE level when the fork carries the exact pre-fix code and the
upstream shipped a fix the fork has not ported. That is a strong LEAD. It becomes a confirmed EXPLOIT only when
reproduced against the target's real execution lifecycle: identical clone/repo mode, the same number of
operations per request, the same commit/teardown boundaries, and the same runtime (git version, core.hooksPath,
temp-filesystem exec flags). A local "primitive" that fires through a sequence the target never performs is a
false-confirm; downgrade to "source-lead, empirically unverified" until it reproduces on the target itself.
