# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] — 2026-10-29

**Availability fix: `tools.restrict()` rejected the whole allow-list whenever it named a
tool that is not on the *global* surface, which killed every delegation in the live
deployment.**

`restrict()` validates names against `view(scope).restrictableNames` and throws
`names unknown global tools "…"; known global tools: …` for anything else. An allow-list
naturally mixes two kinds of name:

- globally-registered tools (`pwsh`, `read`, `write`, …) — `restrict()` can narrow these;
- agent-scoped registrations (dsh-ling's `recall` / `tree_read` / `library_search`, the
  official `subagent` / `list_subagent_models`) — `restrict()` cannot see them at all.

Measured here: the deployment cap listed three dsh-ling tools, so `restrict()` threw on
every call and each delegation was cancelled. The testbed never reproduced it because its
profile has no dsh-ling, so the same allow-list matched in full.

### Fixed
- Narrowing is now tolerant: when `restrict()` rejects names, those names are dropped from
  the `restrict` call and **retried**; whatever survives still narrows the global surface.
  Dropped names stay in the runtime guard's allow-set, so scoped tools keep working while
  `restrict()` keeps doing what it can. Three attempts, then fail-closed as before.
- Errors that are *not* name rejections still fail closed — a genuine `restrict()` failure
  must never degrade into a silent pass.
- `restrict({ allow: [] })` is legal (only `restrict({})` is the no-op error), so an empty
  cap still masks the entire global surface instead of being skipped.
- The fail-closed diagnostic trailer now reports which names had to be dropped.

## [0.3.9] — 2026-10-29

**Availability fix: `delegate` failed closed on every call in the live deployment, because
the two ends of the binding used different id sources.** Registration keyed the pending
policy on `agent.session.id`; the child records its `parentSession` from
`parent.session.header.id` (`dsh-subagent/lib/index.js:354-359`). On a long-lived session
these differ — measured here, `session.id` pointed at the current file while
`session.header.id` carried the durable id — so `takePending()` missed every time, the
policy was never claimed, and each delegation was cancelled before it started.

### Fixed
- `sidOf()` now reads `agent.session.header.id` first (the exact field the host copies into
  the child's `parentSession`), then `agent.session.id`, then `agent.id`. Every caller
  benefits: the pending key, the `pinned` table, the fail-closed cancel target.
- The fail-closed error now carries a diagnostic trailer — registration key, the child's
  observed `parentSession`, whether the claim matched, whether the binding ran, and the
  failure reason. This exists because `ctx.logger` does not reach `logs/` on this machine:
  once the child is cancelled the scene is gone, and without these values the only thing
  left to do is guess.

### Why the testbed never caught it
A fresh session has `session.id === session.header.id`, so both keys agree. The divergence
only appears on a session resumed across restarts, which is what the live host runs.

## [0.3.8] — 2026-10-29

**Security fix: the cold-resume fallback never matched anything, so every narrowed child
regained its full tool surface after `send_message`.** Both the binding and the fallback
read `agent.sessionId` — a property that does not exist on `Agent` (its keys are
`loopCtx, id, options, session, inbox, phase, activityDone, scope, ctx, dispatch, …`;
the session id lives at `agent.session.id`). The binding therefore stored the policy
under the literal string key `"undefined"`, and the fallback looked up a real session id
that could never be there. The scoped layer (which closes over `allowed` directly) kept
working, so the first turn of every child was correctly narrowed — which is exactly why
this looked fixed.

Measured on the testbed (`0.2.1-rc.2`, headless): a child delegated with `tools=['read']`
was asked, after cold resume, to run `Set-Content … PWNED`. It succeeded and the file
appeared on disk. With the key fixed, the same probe is refused with
`工具 "pwsh" 不在该子代理的授权工具面内（delegate 策略，冷恢复兜底）；可用工具：list_subagent_models, read`
and no file is created.

Root cause of the blind spot: the 0.3.6 test faked the agent as `{ sessionId: 'x' }`,
mirroring the wrong property name, so the suite agreed with the bug.

### Fixed
- A single `sidOf()` helper resolves a session id from `agent.session.id`, then `agent.id`
  (plus a legacy `agent.sessionId` fallback for hand-built probe objects). Every site that
  used `.sessionId` now goes through it: the fallback lookup, the `pinned` binding, the
  fail-closed cancel target, and the parent-side pending key.
- The cold-resume regression test now reads the id through the same helper the runtime
  does, so a wrong key fails the suite instead of passing it.

## [0.3.7] — 2026-10-29

**Crash fix: a malformed cancellation cause killed the host process.** The fail-closed
branch cancelled an unbound child with a bare string instead of an `AgentCancelCause`
object. That string reached `AbortController.abort()`, so `signal.reason` was not an
object; DSH's `abortedCancelCause` threw from *inside* `turn()`'s catch block, leaving
`turnEnds` at its `null` initial value, and the `finally` persisted
`turn/end { reason: null }`. Every later load of that subagent session then crashed the
whole process in the subagent projection:
`TypeError: Cannot read properties of null (reading 'kind')`.

Found on the real machine, once again by a probe rather than by the suite: the tests
verified that a policy-unbound child is cancelled and that the delegation fails, but
never asserted what the cancellation writes into the session log.

### Fixed

- The fail-closed cancellation now passes `{ kind: 'disposed' }`. `disposed` is the
  accurate cause for a child torn down because its policy never bound, and it keeps the
  loop's `?.kind !== 'disposed'` wake judgement correct. Verified by a regression test
  that fails on the string form.
- Two defensive patches accompany it (applied by hand, they live in `node_modules`):
  `dsh-agent-loop`'s `abortedCancelCause` returns `{ kind: 'disposed' }` for a non-object
  reason instead of reaching `assertNever`, and `dsh-subagent`'s `turn/end` projection
  reads `event.data?.reason?.kind`. A DSH upgrade overwrites both.

### Also

- Incident write-up: `docs/incidents/2026-10-29-cancel-cause-fatal.md` — the full
  three-layer chain, the on-disk evidence (one poisoned 1703-byte frame out of 981
  session logs), and the recovery steps.

## [0.3.6] — 2026-10-29

**Security fix: the delegate gate did not survive a resumed child.** Found by a probe
on the real machine, not by the test suite. `restrict()` and the per-child `guard()`
both live on the child's own context; `send_message` waking an idle child goes through
cold resume, which rebuilds that context and silently drops both registrations.

Reproduced end to end: a child delegated with `tools: ["read", "glob", "grep"]` reported
five tools on its first turn, then — after the parent sent it one message — reported
roughly ninety, and successfully called `subagent` to spawn a grandchild
(`794cebdb`, `depth=2`, confirmed present in the descendant listing).

### Fixed

- **A plugin-scoped guard now backstops the per-child one.** Each delegated child's
  authorised tool set is recorded by session id on the plugin context, and a guard
  registered there refuses anything outside it. That registration lives as long as the
  plugin, so a rebuilt child context cannot shed it. Verified by a regression test that
  simulates the child's own guards being gone.
- The backstop only recognises session ids the plugin itself pinned, so the parent
  session and ordinary subagents are untouched.

### Known limit

- **Visibility still resets on cold resume.** The child's tool schema returns to the
  inherited surface; the refused tools are listed but rejected when called. `dsh-tools`
  exposes no API to remove a scoped registration, so "visible but denied" is the ceiling
  for this design. It is a `deny`, not a leak.

### Also

- Test-suite runner note for maintainers: the suites report failures with `✖`, not
  TAP's `not ok`. Grepping for `not ok` silently reports a red suite as green — that is
  how this bug reached a release candidate.

## [0.3.5] — 2026-10-29

**Two corrections that only a real-machine probe could produce.** 0.3.4 exempted
`task_begin` / `task_end` from the gate 3 guard on the assumption that a child agent
registers them. It does not: a probe child that followed the runtime's own lifecycle
nudge called `task_begin({name})` and got `Error: unknown tool "task_begin"`. The
exemption therefore had exactly one effect — the denial message advertised two tools
that do not exist. Separately, the allow-list shipped without any way for a child to
read the memory store or the library, even though the stated rule was "exclude the
tools that *write* memory".

### Fixed

- **`task_begin` / `task_end` are no longer exempt.** On DSH `0.2.1-rc.2` a subagent
  does not register either tool; exempting them only put phantom names into the
  `可用工具：` list. `list_subagent_models` stays exempt — it is genuinely scoped,
  genuinely present, and harmless.
- **`recall`, `tree_read` and `library_search` are back in the allow-list.** A child
  could previously not consult the library or the memory tree at all, which broke any
  delegation whose job was verification rather than production. Memory **writes**
  (`deep_item`, `branch_edit`, `rule_add`, `memory_forget`, `habit_*`) remain excluded.

### Changed

- Allow-list grows 89 → **92** names.

### Verified

- 6 suites / 95 assertions green.
- Real machine, post-restart: `delegate(tools: ["read","glob","grep"])` produced a child
  whose schema held `read / glob / grep / list_subagent_models / subagent`; calling
  `subagent` was refused with
  `工具 "subagent" 不在该子代理的授权工具面内（delegate 策略）` and **no grandchild was
  created**. The visible-but-denied `subagent` is a known limit: `restrict()` cannot
  remove scoped registrations, and `dsh-tools` exposes no API that can.

## [0.3.4] — 2026-10-29

**The deployment cap is now on, with a populated allow-list.** Turning `enforceMaxTools`
on exposed a gap the previous tests did not cover: `restrict()` only narrows the global
tool surface, so the agent-scoped registrations (`task_begin`, `task_end`,
`list_subagent_models`) stayed visible *and* were denied by gate 3's execution-time
guard — a child could see the tools but calling them failed. Caught by a real-machine
probe: a `delegate(tools: ["read"])` child self-reported
`list_subagent_models / read / subagent / task_begin / task_end`.

### Fixed

- **Scoped harness tools are exempt from the gate 3 guard.** `task_begin`, `task_end`
  and `list_subagent_models` are always allowed, regardless of `maxTools`; they cannot
  escape the cap because `restrict()` never covered them in the first place. The
  derivation channels (`subagent`, `subagent_fork`, `delegate`) are **not** exempt — a
  child that can spawn is a child that can hand its grandchild a wider policy.

### Changed

- **`cordis.patch.yml` now ships with `enforceMaxTools: true`** and an 89-name allow-list
  covering everything except the memory-writing tools. The list is a ceiling, not an
  assignment: each `delegate()` call narrows it further via `tools: [...]`.
- **Three tools are deliberately excluded** from the ceiling:
  - `plugin_manager` — a child that can install or remove plugins can rewrite the host,
    which contradicts the entire point of limiting children;
  - `task_board_run` — it opens a *new execution session* at parent level, outside every
    gate this plugin installs, so a child holding it can run arbitrary work unconstrained;
  - `subagent` / `subagent_fork` / `delegate` — the derivation channels themselves
    (see the fix above).
  Add any of them back only with a deliberate decision.

## [0.3.3] — 2026-10-29

**Gate 3 registered no tool at all when `subagents` arrived late.** Found on a test bench,
not by any test: `subagents` is an asynchronously-provided service, so `ctx.get('subagents')`
is `undefined` during `apply()`. Since 0.3.1 had removed `subagents` from `inject` (see
below), that path took the "service unavailable" branch, logged at most one line, and
never registered `delegate`. Three gates silently became two, and `--dump-config` still
showed the plugin row.

### Fixed

- Gate 3 now attaches through `ctx.inject(['subagents'], cb)` instead of polling
  `ctx.get()` once during `apply()`. The tool appears when the service appears, and the
  absence of `subagents` no longer disables gates 1 and 2.

## [0.3.2] — 2026-10-29

Second round of the same audit, covering the twelve findings the coverage path reported
after the first round's fixes had already shipped.

### Fixed

- **Unknown sandbox modes are now treated as the widest.** An unregistered mode used to
  compare as "not wider than the cap" and was left untouched without a word — so a host
  that adds a mode would silently escape gate 1. Unknown now caps to `read-only` and warns.
- **`commandArg` accepts arrays and nested arguments.** It used to read one exact
  top-level string, so a shell tool passing `['cmd', '/c', …]`, or nesting the command
  under another field, was invisible to gate 2.
- **Every `-File` path in a command line is inspected**, not just the first.
- **`commandArg: ''` and `provider: ''` now fail at load.** The first silently disabled
  gate 2; the second contradicted its own comment and always threw `NO_PROVIDER` later.
- **Config validation covers every field** that can produce a silent no-op, plus a check
  that `maxTools` names real tools.
- **`subagents` is validated by shape, not by `!== undefined`.**
- **Gate 1 ignores agents with no `parentSession`.** Root sessions also emit
  `agent/created`; a malformed one used to be capped as if it were a child.
- **A failed claim disposes the activation** when `cancel()` is out of reach (external
  backends), instead of leaving an unconstrained child running.
- **Delegation windows reject the official `subagent` / `subagent_fork`.** Claiming is
  keyed by `parentSession`, so an official child created first would steal the pending
  policy. `subagent/descriptor` is written inside the child's *first turn*, later than
  `agent/created`, so label-based matching is not available.
- **The failed dynamic `import` of the official package now warns** instead of silently
  losing the cross-check.

## [0.3.1] — 2026-10-28

First round of adversarial audit fixes (two red-team paths; the third arrived later and
drove 0.3.2).

### Fixed

- **The `denyPatterns` YAML example used single quotes**, so copying it verbatim produced
  rules that never matched — while startup still printed the rule count. Examples now use
  double quotes, with a comment saying why.
- **A failed claim left its policy in the pending queue**, so the next delegation on the
  same parent could inherit the previous child's tool surface and prompt.
- **Cancellation was announced before it was attempted**, and a string cancel cause
  tripped `assertNever`. Now the message follows the actual outcome and says
  "could not confirm cancellation" when it cannot.
- **`hardCap` logged an error on its success path** and hard-coded "mode unreadable".
- **The refusal text claimed "cannot be bypassed in this session"** while telling the
  model to edit the profile. It now says it stops accidents, not adversaries, and names
  base64 / variable splicing / wrapping as escapes.
- **`exec.cwd` does not exist** on the host's tool-run context; relative script paths now
  resolve against `agent.session.header.cwd`.
- **`shellTools` is documented as hint-only** — argument-shape detection is what actually
  finds command tools.
- **The tool description no longer implies a cap that is off by default.**

## [0.3.0] — 2026-10-28

**The two plugins are now one.** `dsh-delegate-policy` (a separate package that pinned
each child's tool surface and system prompt) is merged in as **gate 3**. Cloud installs
need a single bundle; deployments that want to tune the split can ask their agent to
edit the config instead of adding a second package.

The merge is not cosmetic — running the two halves separately left a real hole:

### Fixed

- **A read-only child could spawn an all-tools grandchild.** `tools.restrict()` masks
  only the inherited (global) tool surface: `dsh-tools/lib/index.js:2985-2987` states
  *"Restrictions intersect; scoped registrations remain visible"*. The official
  `dsh-tool-subagent:605-607` registers `subagent` and `list_subagent_models` directly
  on the child's own context from `agent/created`, so a restricted child still saw them.
  Calling `subagent` produced a grandchild that the policy layer never registered a
  policy for — measured on a live deployment as `delegationDepth: 2` with `tools(97)`
  including `pwsh`, `write`, `edit` and `workflow`, from a parent that had been handed
  `read` only.
  Two layers now hold: `restrict()` cleans the visible surface, and an agent-scoped
  `tools.guard()` denies every unlisted tool at execution time.
- **Concurrent delegations could be bound to the wrong child.** Policies are claimed
  per parent session, and `maxActiveSubagents` defaults to 50. Two interleaved `delegate`
  calls could hand child A's policy to child B — the exact failure this gate exists to
  prevent. The claim → create → verify sequence is now serialized (`serializeBind`,
  default on).

### Added

- Gate 3: a `delegate` tool that takes `prompt`, optional `persona` and optional `tools`.
  The persona is a real system-prompt section (not a message prefix); `tools` becomes a
  scoped `restrict()` plus the execution-time guard above.
- `enableDelegateTool`, `toolName`, `provider`, `enforceMaxTools`, `maxTools`,
  `sectionOrder`, `sectionName`, `serializeBind` configuration options.
- Deployment cap: the child's final tool surface is `tools ∩ maxTools`. The model may
  narrow it, never widen it. `maxTools: []` with `enforceMaxTools: true` means the child
  gets no tools at all.
- Fail-closed binding: if the child does not consume its policy, the delegation cancels
  the child and throws rather than leaving an unpoliced subagent running.

### Notes

- Gates 1 and 2 work without the `subagents` service; gate 3 registers its tool only
  when that service is present.

## [0.2.0] — 2026-10-24

Response to an [external coverage audit](./docs/research/2026-10-24-external-audit.md)
run against a real Windows deployment. Five gaps were reported; all five are addressed
or explicitly scoped out below.

### Fixed

- **Gate 2 no longer enumerates tool names.** Detection is now based on the **argument
  shape**: any tool whose arguments carry the command string (keyed by `commandArg`,
  default `command`) is inspected, regardless of the name it registered under. The
  previous `shellTools: [bash, pwsh]` allowlist silently skipped third-party shells —
  `win_bash` being the reported instance. `shellTools` remains as an *extra* list for
  tools whose command parameter is named something else, and now defaults to
  `[bash, pwsh, win_bash]`.
- **Gate 1 is fail-closed.** When the current sandbox mode cannot be read, the child is
  forced to `read-only` and an error is logged, instead of warning and continuing. Gate 1
  is frequently the only barrier between a subagent and `danger-full-access`, so failing
  open there was backwards.
- **`denyScope` defaults are aligned.** The schema default was `all` while the bundled
  `cordis.patch.yml` shipped `subagent`; bundle installs silently got the looser one.
  Both now default to `subagent`. The effective configuration is logged once at startup
  so documented and deployed values cannot drift unnoticed.
- **Indirect script execution is inspected.** `pwsh -File x.ps1`, `bash x.sh`,
  `& 'x.ps1'`, `.\x.ps1` and friends now have their target file read and re-checked
  against the same rules (`scriptInspection`, on by default). Unreadable or oversized
  files are allowed with a warning — a path typo would fail to execute anyway.

### Added

- `cipher /w` and `sdelete` rules — irreversible data erasure.
- `commandArg`, `scriptInspection`, `maxScriptBytes` configuration keys.
- Runtime comparison against the official `delegationDepthOf` when
  `@deepseek-ai/dsh-subagent` happens to be resolvable, warning on divergence.
- Startup log line with the effective configuration.
- Nine new tests (24 → 33), covering shape-based detection, fail-closed capping, default
  alignment, and script inspection both ways.

### Changed

- Local helper copies now carry a pointer to the audit, and the README documents the
  verified DSH version (`0.2.1-rc.2`) and what silently breaks on a version bump.

### Not adopted

- `robocopy … /mir` and `mountvol` were considered for the default denylist and
  rejected: mirror sync is a routine operation and unmounting is administrative, so both
  would produce more false positives than protection.
- "Refuse to create the subagent" (suggested in the audit for gate 1): `agent/created`
  fires *after* creation, so the child already exists. Forcing `read-only` is the
  strongest fail-closed action available at that extension point.

## [0.1.0] — 2026-10-20

### Added

- Gate 1: sandbox ceiling via `agent/created` + `sandbox/mode` (downgrade only).
- Gate 2: monotonic command denylist via `ctx.tools.guard()`, 16 default rules covering
  shadow copies, restore points, partitions, boot configuration and host availability.
- `subagentSandboxCap`, `denyScope`, `shellTools`, `denyPatterns` configuration.
- 24 host-free tests across the rules and wiring layers.
