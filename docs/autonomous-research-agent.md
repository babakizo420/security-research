# Architecture of an autonomous vulnerability-research pipeline

This is an abstracted write-up of a system I built and run: an autonomous
pipeline that discovers, verifies, and documents security vulnerabilities in
open-source software, and stops at a hard human-approval gate before anything is
disclosed. It is a methodology and architecture piece. It contains no target
lists, no credentials, no infrastructure details, and no client information.

The point of the system is not "an AI that finds bugs." The point is a
disciplined loop that turns a broad, noisy search space into a small set of
verified, honestly-scoped findings, while keeping a human in control of every
external action. The design choices that matter are the ones that raise
precision and enforce restraint, not the ones that raise raw output.

## Lead with the floor: nothing is disclosed without a human

The single most important property of the system is what it does NOT do. It never
files, submits, publishes, or contacts a vendor on its own. Every candidate stops
at a human-approval floor, and a person does the independent review and the
disclosure.

A candidate is only allowed to reach a human as "ready" after it clears a
seven-gate check. Each gate is a question the system must answer with evidence,
not assertion:

1. **Reachability.** Prove the full path from an attacker-controlled entry point to the sensitive sink, every link named at file and line. If a live end-to-end proof is genuinely infeasible, document the exact blocker and the complete source trace with no gaps.
2. **Privilege.** Establish the minimum privilege that reaches the sink (unauthenticated, any self-registered user, admin only). If it needs elevated privilege, the severity drops and the write-up says so.
3. **No other guard.** Confirm that nothing upstream already blocks it: a shared middleware, an egress policy, an allowlist, a feature flag. Trace the whole path, not just the named function.
4. **Disclosure status.** Search by the exact sink identity (file, function, parameter) across advisory databases and, critically, the project's own open and closed issues and pull requests. A public report or an open fix already naming the sink means it is not novel.
5. **Version currency.** Confirm the bug is present in the current released artifact, not only on an unreleased branch. A fix already shipped, or a bug that only exists on a development branch, does not count.
6. **Adversarial review.** Write the strongest reason a maintainer would reject the finding (intended behavior, by-design, duplicate, privilege too high) and the strongest rebuttal to each. A finding that cannot survive its own red-team is not ready.
7. **Impact and severity.** State the concrete impact and a defensible severity, separating what is confirmed from what is inferred.

Two rules sit on top of the gates. First, **no overclaim**: severity is only what can be proven deterministically; a gated, sandboxed, or multi-step-unconfirmed chain is downgraded and labeled, and any unproven step is marked unverified out loud. Second, **read the sink to the metal**: impact is never inferred from an endpoint name or a two-line grep; the actual sink code is read to confirm what it does.

This is the part I care most about in a hiring conversation. Autonomy without a
disclosure floor is a liability. The floor is the design.

## The loop

The pipeline runs as a cycle, not a one-shot. Each cycle either produces a
verified candidate, produces a documented walk-away (a target that was checked
and found not vulnerable, which is itself a useful result), or does neither and
stands the system down. A cycle that produces no verified candidate still banks a
lesson, so the methodology sharpens every time.

```
trigger watch  ->  router / lead scoring  ->  saturation pre-check
      ->  parallel triage (fan out)  ->  deep audit (per lead)
      ->  verification  ->  human-approval floor (the 7 gates)
      ->  bank the lesson  ->  (next cycle)
```

### Trigger watch

The system does not hunt at random. It watches for events that make a target
temporarily high-value: a fresh security fix in a widely-used project, a new
release, or an upstream fix landing in software that has downstream forks. A
fresh fix is the strongest signal, because a point-fix often patches the one
reported path and leaves sibling paths untouched (see the incomplete-fix
technique below). The watch turns "what should I look at" into an event-driven
queue instead of a guess.

### Router and lead scoring

Each candidate target is scored before any expensive work. The score combines
signals such as: how reachable the class of bug tends to be, how specific the
sink is (a concrete function reads and verifies faster than a diffuse
architecture concern), whether the project is small and single-maintained (which
correlates with missed guards) versus large and security-mature (which correlates
with swept, robust fixes), and whether the surface has already produced multiple
public reports. The router spends compute where the expected yield is highest and
skips the rest.

### Saturation pre-check

Before committing to a target, the system checks whether the vulnerability class
on that target is already saturated: two or more recent public reports of the
same class mean other researchers are actively sweeping it, and a new finding is
likely to be a duplicate. Saturated surfaces are deprioritized. This one check
prevents a large amount of wasted effort on bugs that are being fixed out from
under you.

### Parallel triage

For a target that clears the pre-checks, the system fans out. Independent
lightweight agents each take a slice of the surface (a subsystem, a class of
endpoint, a fork) and report a structured verdict: is there an asymmetry worth a
deep look, where, and why. Fanning out covers breadth cheaply and surfaces the
one or two slices worth the expensive deep read. Independence matters: each agent
is blind to the others, so they do not converge prematurely on a single theory.

### Deep audit

The single most promising lead gets a careful, single-threaded read to the metal.
This is where the seven gates start to be answered: the full reachability chain
is traced, the guard is confirmed present or absent on the actual path, shared
middleware and service layers are checked (a guard hiding in middleware is the
most common false positive), and the exact behavior of the sink is read rather
than inferred.

### Verification

A candidate that survives the deep audit is verified as far as is safely
possible: a faithful, source-accurate proof against a released artifact, or, when
a live proof is infeasible, a complete source trace with the blocker documented.
Verification is adversarial: the system tries to refute its own finding, and a
finding that a refutation survives is downgraded or dropped.

### Bank the lesson

Every cycle ends by banking what it learned, win or loss. A technique that worked
becomes a reusable method; a dead end becomes a rule that stops the next cycle
repeating it; a surprising piece of target behavior becomes a note to investigate.
This is the compounding step, described next.

## The compounding lessons library

The system keeps a growing library of banked lessons: positive case studies
(this pattern of guard is robust, walk it fast), anti-patterns (this shape of
reasoning caused a false positive, do not repeat it), and methodology refinements
(this check belongs at this phase). Each cycle reads the relevant lessons before
it starts and writes new ones when it ends.

The effect is that the methodology gets sharper over time rather than staying
flat. A false positive is only paid for once: the lesson that explains it stops
the same mistake next time. A hard-won verification discipline (for example,
"confirm the guard is not enforced by shared middleware before claiming a fork
lacks it") becomes a standing rule that every future cycle inherits. The library
is the difference between a tool that runs and a system that learns.

## Techniques the pipeline specializes in

Two techniques recur, because they have a high ratio of verified findings to
effort and because they are hard for a project to fully close.

**Incomplete-fix analysis.** When a project fixes a bug, the fix commonly adds a
guard to the one reported endpoint and leaves the sibling endpoints, the ones
that reach the same sink or serve the same class of content, untouched. The
pipeline reads the fix, identifies the guard it added and the sink it now
protects, and enumerates the siblings that lack the guard. Those are the residual
bugs the patch missed. This technique is productized as a standalone tool in this
repository (`tools/incfix`).

**Cross-fork lag.** When an upstream project ships a security fix, its hard-forks
often lag: the same guard exists upstream and is absent in the fork's current
release. The pipeline watches for upstream fixes, then checks whether each
downstream fork adopted them. A fork that serves the protected content but never
calls the guard, at its released version, is a live bug the fork inherited and
never fixed. The critical discipline here is the false-positive guard: never
conclude a fork lacks a guard by comparing named function call sites, because
forks diverge their security architecture; trace the actual access computation on
the released tag before believing it.

Both techniques share a property that makes them safe to automate: they produce
concrete, file-and-line candidates that a human can verify quickly, rather than
speculative claims.

## What the system deliberately does not do

The guardrails are as much a part of the architecture as the pipeline:

- It does not disclose, file, or contact anyone. A human does that.
- It does not run destructive tests, denial-of-service, or resource-exhaustion attacks.
- It does not scan or exploit systems without authorization; active testing is limited to authorized programs and to the researcher's own instances.
- It does not overclaim: severity is bounded by what is proven, and unproven steps are labeled.
- It does not chase saturated surfaces or unreleased-branch-only bugs.

## Why this is worth reading as an engineering artifact

The interesting engineering is not the search. It is the control loop: an
event-driven trigger watch, a scoring router that allocates compute by expected
yield, a saturation pre-check that avoids duplicated work, a fan-out and deep-read
split that trades breadth for depth at the right moment, a verification step that
is adversarial by construction, a human-approval floor that keeps every external
action under human control, and a lessons library that makes the whole thing
compound. It is a system for producing a small number of correct, honestly-scoped
results from a large and noisy space, with restraint built in rather than bolted
on.

Author: babakizo420.
