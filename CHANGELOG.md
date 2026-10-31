# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.7] — 2026-10-31

**Third audit pass: the gate-3 heterogeneous red team that failed to produce anything in 0.4.6
finally ran (opus), plus a maintainer sweep of the script-inspection surface.**

### Fixed
- **Quoted sub-commands were mistaken for file paths (M-1, fail-open).** `cmd /c "pwsh -File
  evil.ps1"` put the *whole quoted sub-command* into the path candidate list; it happens to end
  in `.ps1`, so it passed the extension check and then resolved to a file that does not exist —
  which is silently skipped. The real `evil.ps1` was never read. Interpreter look-behind now
  accepts a quote / `&` / `(`, and `-File` accepts quoted and comma-separated argument lists
  (M-2: `Start-Process pwsh -ArgumentList "-File evil.ps1"` and the
  `'-NoProfile','-File','x.ps1'` array form). Quoted strings that start with an interpreter and
  bare `-`-prefixed tokens are no longer treated as paths.
- **Cold resume without a request header kept the derived channels (F1, blocking).** When a
  child's log has our section but no `request/header`, recovery returned the parsed section face
  as-is. That face can name `subagent` / `subagent_fork`, which bypass `restrict()` and are
  installed scoped by the host — a recovered child could spawn unconstrained grandchildren. The
  no-header branch now filters them exactly like the header branch.
- **`serializeBind: false` dropped the binding mutex (F2).** With the mutex skipped, two
  concurrent delegations from one parent raced: `agent/created` order belongs to the host while
  claiming is FIFO per parent session, so a child could claim the *other* call's policy. The
  option is now ignored (one warning at the first `delegate` call) and every binding is
  serialized. The mutex covers only the register → create → verify window, so child execution
  concurrency is unaffected.

### Known limits
- Script inspection still cannot resolve dynamically built command lines
  (`Start-Process -ArgumentList @('-File', $p)`, `Invoke-Expression`) — best-effort by design.
- `serializeBind: false` is deprecated and ignored.

### Tests
- 123 cases (19 + 21 + 27 + 39 + 7 + 10). New regressions: M-1/M-2 (quoted sub-command and
  `-ArgumentList` forms resolve to the real script), F1 (no-header recovery drops derived
  channels), F2 (`serializeBind: false` still binds one-to-one). F1 and F2 were re-verified by
  reverting each fix in place and watching the new case go red.

## [0.4.6] — 2026-10-31

**Two defects from the second audit pass, one of them a regression introduced by 0.4.5's
own gate-2 fix.**

### Fixed
- **Quoted separators split script paths (R2-02, blocking; regression in 0.4.5).** 0.4.5 fixed
  `pwsh -File a.ps1;pwsh -File b.ps1` by splitting the command on `;` / `&` / `|` before
  extracting script paths — but the split ignored quoting, so `pwsh -File "C:\work\a;b.ps1"`
  yielded `b.ps1` instead of the real file. The real script was never read, and an unreadable
  script is allowed with a warning. Segmentation is now quote-aware (`splitSegments`): a
  separator inside `"…"` or `'…'` no longer ends the segment.
- **Unknown sandbox modes were capped to the configured cap, not to `read-only` (F-06).**
  Three "we cannot tell how wide this is" paths disagreed: a missing `sandboxPolicy` service
  and a throwing `overrideOf()` both hard-capped to `read-only`, while an **unregistered mode
  name** went through `shouldCapSandbox` (which treats unknown as widest) and was then written
  as `subagentSandboxCap`. With the default cap that is `workspace-write`, i.e. a child running
  in an unknown (possibly wider) mode could be pinned down to a **wider** mode than read-only.
  All three paths now hard-cap to `read-only`.

### Known limits
- Gate 3 (the `delegate` tool / cold-resume claim surface) had **no successful heterogeneous
  red team** this pass: four attempts across opus and grok died mid-run with no output, so that
  face rests on the 0.4.4 heterogeneous round, the delta review, and unit tests only. Recorded
  rather than papered over.
- Two injected canaries were found to be unreachable and are therefore excluded from the
  recall denominator: dropping the `-f` alias (the generic bare-path branch still catches the
  file) and dropping the process-cwd candidate (the executing cwd *is* the session cwd, so a
  file that only exists under the process cwd is never executed anyway).

### Tests
- 119 cases (18 + 21 + 27 + 36 + 7 + 10). New regressions: F-06 (unknown mode caps to
  `read-only`) and R2-02 (quoted separators do not split; unquoted ones still do). Both go red
  against the shipped 0.4.5 bytes.

## [0.4.5] — 2026-10-31

**Twelve more defects, found by the second pass of the adversarial audit: three heterogeneous
red teams (sonnet / opus / astra, re-run after the model routes recovered) attacking 0.4.4,
each finding independently re-falsified.** Six are denylist bypasses, four are script-inspection
bypasses, and two are gate-3 gaps where a child could still be granted a derivation tool.

### Fixed
- **Denylist was spelling-sensitive (G1–G6).** Command text is now normalized before matching:
  backtick/caret/backslash line continuations fold to a space, quotes are stripped, and
  whitespace/newlines collapse. So `shutdown` + newline + `/s`, `"C:\…\shutdown.exe" /s` and
  `Start-Process shutdown -ArgumentList "-s"` all match the shutdown rule (which now accepts
  dash flags and only the real power-flag letters, so `Get-Help shutdown -examples` is
  unaffected). `format.com C:` matches like `format C:`; `reg delete HKEY_LOCAL_MACHINE\…`
  now matches like `HKLM` (all five root keys accepted).
- **Script inspection bypasses (S1–S4).** The command is split on `;` `&` `|` and newlines
  *before* extracting targets, so `pwsh -File a.ps1;pwsh -File b.ps1` inspects both. Content
  is decoded by BOM (`FF FE` UTF-16LE, `FE FF` UTF-16BE, `EF BB BF` UTF-8) with a NUL-ratio
  UTF-16LE fallback, instead of assuming UTF-8. Relative paths resolve against the **session
  cwd first**, and *every* existing candidate is inspected — a same-named file in the process
  cwd can no longer shadow the real target. Explicit interpreters (`bash ./payload`) get their
  extension-less, path-shaped targets inspected too.
- **Cold-resume parsing was not structurally anchored (C1).** The `可用工具：` line is now
  taken from the last match **before** the fixed scope marker (host sections ordered 1000+
  follow it), and the result is **intersected** with the `request/header` surface: either
  source can veto. `subagent` / `subagent_fork` are dropped on both sides.
- **A non-string session id could pin the literal `"undefined"` key (C3, T1).** `applyPolicy`
  now refuses to bind (`fail-closed`) and logs an error instead of writing a key that would
  make the whole fallback table allow every tool.
- **Gate 3 accepted derivation tools as an authorized face (T2).** `resolveAllowedTools` now
  rejects `subagent` / `subagent_fork` before the deployment cap is applied, so a parent can
  no longer grant them explicitly; the pinned set filters them as defense in depth, keeping
  the "no derivation channel" paragraph true.
- **Cold resume had no host-capability check (C2).** Startup probes for `agents.resume` and
  warns once when the host cannot cold-resume at all; the precondition is documented.

### Known limits
- Intersecting surfaces can **over-narrow**: an agent-scoped tool absent from that particular
  request header is dropped (fewer tools, never more).
- `provider: 'fork'` children are restored from the parent's historical paragraph surface
  (over-restriction).
- Dynamically built commands (base64 / `-EncodedCommand`, variable paths, `node -e`, scripts
  running scripts) remain outside static matching.
- `serializeBind: false` can swap policies between concurrent delegations (DoS, not escalation).
- A `fork`/`subagent` child created outside a `delegate` window is not pinned; gate 1 still caps
  its sandbox.

### Tests
117 cases across six suites (17 / 21 / 26 / 36 / 7 / 10), all host-free. The nine new
regressions were run against the 0.4.4 bytes (kept in a scratch tree) and fail there, so they
are not tautologies.

## [0.4.4] — 2026-10-31

**Seven defects that 0.4.3 introduced or left open, all found by the adversarial audit
(`plans/WORKFLOW-对抗审计2.0-20261008.md`: canaries → three red teams → per-finding
falsification → delta review). Three are fail-open paths in gate 2, three are cold-resume
holes (one of them a regression in the 0.4.3 fix itself), and one is a gate-1 branch that
could widen.**

### Fixed
- **Cold resume trusted the model-visible face (R1-01, blocking).** 0.4.3 rebuilt the pinned
  surface from the earliest `request/header`'s `tools` — but that is what the *model* sees,
  not what was authorized. The official `dsh-tool-subagent` installs `subagent` /
  `subagent_fork` as agent-scoped registrations, which bypass `tools.restrict()` and therefore
  appear in the header; a pinned child was consequently allowed to call `subagent` after a
  restart and could spawn an **unrestricted grandchild**. The authoritative source is the
  paragraph this plugin itself writes: the `可用工具：<list>` line in the same
  `system/message` as the scope marker. It is now parsed (last match wins, so a caller-supplied
  persona cannot poison it), and only logs without that line fall back to the header — with
  the two scoped derivation tools removed.
- **Trailing-dot script paths bypassed content inspection (R3).** Windows ignores a trailing
  dot, so `pwsh -File evil.ps1.` really executes `evil.ps1` (verified on the host), but the
  extension test rejected `evil.ps1.` and the file was never read. Paths are now normalized
  before classification and read through the normalized form.
- **Oversized scripts were silently allowed (R5).** Exceeding `maxScriptBytes` used to return
  "unreadable", which the caller treats as "allow with a warning" — writing a bigger script
  was enough to switch content inspection off. Oversized scripts are now refused with a
  message that names the limit; raise `maxScriptBytes` to allow them.
- **A forked child could adopt the parent's historical header (R1-02).** `provider: 'fork'`
  seeds the child's log with the parent's history, so an early `request/header` may describe
  the parent's surface. Only headers that come **after** the scope paragraph are now
  considered; a header that predates it is ignored, which falls back to the empty surface
  (fail-closed).
- **The anti-hijack window in gate 2 never ran, and would have misfired if it had (F8,
  R2-X1).** The check that refuses an official `subagent` call while a `delegate` policy is
  unclaimed sat *after* the "no command argument ⇒ return" early exit — official `subagent`
  has no command field, so it was dead code and two delegations in one turn could still steal
  each other's policy. It was also gated on the global `pending.size > 0`, so making it
  reachable would have rejected healthy `subagent` calls from **every other session**. It now
  runs before the early exit and compares the caller's own session id.
- **Delegation diagnostics could describe the wrong child (audit finding 7).** An unclaimed
  `agent/created` during the delegation window — typically the official `subagent` creating a
  child first — overwrote the in-memory trace, so a real fail-closed error could report
  *another* child's parent session and "claim = hit, bind = success". The trace is now written
  only by the claiming child; an unclaimed birth just makes the message say a foreign child
  landed in the window.
- **`enableDelegateTool: false` also turned off cold-resume recovery (audit finding A).** The
  early return that skips gate 3 sat *before* the `agent/created` claim/recovery listener, so
  disabling the delegation tool left the suppression guard with an empty `pinned` map: a child
  woken by `send_message` came back to the full inherited surface and nothing denied it
  (fail-open). The recovery listener now registers unconditionally — recovery belongs to gate 2,
  not gate 3 — and runs even when the delegation tool is off.
- **A missing `sandboxPolicy` service wrote `subagentSandboxCap`, which can widen (R1-04).**
  With the service absent we cannot know the child's current mode, and writing the cap to a
  child that was **narrower** than the cap (e.g. `read-only`) is an upgrade — the opposite of
  the documented "downgrade only". That branch now writes `read-only`. Unreachable in the
  audited deployment (the service is resident and the executor tools inject it), but the code
  now matches the promise.

### Known limits
- A guard-created child that died **before its first request** has no scope paragraph and no
  request header, so it is not identified as this plugin's on resume: it comes back with the
  inherited surface. That window is narrow (the child never ran a turn) and was observed zero
  times among real delegations; the previous wording ("restored with an empty surface")
  described only the marked-but-headerless case.
- The scope marker lives in the same text as a caller-supplied `persona`; a persona that
  copies both the marker and the `可用工具` line could masquerade as a guard-created child.
  The caller already chooses the tool list, so this is not an escalation path, but it is why
  the parser takes the last match and never trusts the header alone.

### Tests
- `apply.test.mjs`: trailing-dot path is inspected and denied; an oversized script is denied.
- `audit-20261028.test.mjs`: `scriptPathsOf` normalizes trailing dots.
- `delegate.test.mjs`: cold resume prefers the `可用工具` line over a header that lists
  `subagent`; the header-only fallback drops the scoped derivation tools.

## [0.4.3] — 2026-10-31

**Two defects that the unit suite could not see, both found by running the plugin on a
real host and reading host-side evidence (session logs, files on disk, exit codes) instead
of the child's own report.**

### Fixed
- **Gate 1 was widening, not capping (F-A).** `sandboxPolicy` was read once in the plugin's
  `apply()`, where the service is not registered yet: a probe plugin measured every
  relevant service as `undefined` during `apply`, becoming visible ~300 ms later. The
  snapshot was therefore always `undefined`, the fail-closed branch always fired, and the
  child was forced to `subagentSandboxCap` regardless of its current mode — so a
  `read-only` parent with a `workspace-write` cap produced a child that **wrote to disk**,
  while the `cap: inherit` control was correctly refused by the read-only sandbox. The
  service is now read inside the `agent/created` handler; a mode that is still unreadable
  at event time keeps the old fail-closed behaviour. This also revives the
  `overrideOf`/`shouldCapSandbox` path, which had been dead code.
- **Cold resume lost the pinned surface entirely (F-B).** `pinned` is an in-memory map, and
  `restrict()` / the scoped guard die with the process. After a host restart, a child woken
  by `send_message` came back with 26 tools instead of 1 and really did spawn a shell to
  write `coldresume-escaped2.txt`; the global fallback guard found no record and allowed
  everything. DSH offers no third-party write path for custom session events (an unknown
  type without `ignorable` makes the whole session unreadable), so the plugin now rebuilds
  the surface from the child's **own log**: the fixed scope paragraph in `system/message`
  identifies a guard-created child with an explicit tool list, and the earliest
  `request/header`'s `tools` is the surface that was in effect. It then re-applies
  `restrict`, re-registers the scope section, and re-pins the child on every
  `agent/created` that has no pending policy.

### Known limits
- The caller-supplied `persona` cannot be separated from the same `system/message`, so a
  restored child's section states only its tool surface.
- A guard-created child whose log has no `request/header` (no request was ever issued) is
  restored with an **empty** surface, fail-closed.
- The restore path relies on the exact text of the scope paragraph; a future version that
  changes that text must keep a stable marker (see `ABSENT_CHANNELS_NOTE`).

### Tests
- `apply.test.mjs`: two cases pin the service-late-registration timing of gate 1 (one
  asserting no widening, one that a genuinely absent service still caps).
- `delegate.test.mjs`: three cases cover cold-resume restore (rebuild, non-guard child left
  alone, marker without a request header falls back to an empty surface). Both F-A and F-B
  regressions fail against 0.4.2's `lib/index.js` and pass against this one.

## [0.4.2] — 2026-10-29

**0.4.1 shipped two misreports of its own. Both surfaced by running it on the real host
minutes after the restart — not by the test suite, which was green throughout.**

### Fixed
- **"Not narrowed" was never actually displayed.** 0.4.1 only said so when `tools` was
  `undefined`, but with `enforceMaxTools: true` an omitted `tools` resolves to `[...cap]` — a
  real array — so that branch was unreachable in the deployment. The result now carries
  `toolsSource` (`inherit` | `cap-default` | `requested`), and only `cap-default` renders
  `未收窄 —— 子代理获得了全部 N 个白名单工具`.
- **`personaApplied` reported `已设置` for every delegation.** 0.4.1 decoupled the scope
  section from `persona`, so `sectionText` became almost always defined and the flag — derived
  from it — lost all meaning. It now reflects whether the caller actually passed a `persona`.

## [0.4.1] — 2026-10-29

**Four ways a delegation could misrepresent its own scope — all found by running it and reading
what the child actually reported, not by reasoning about the code.**

The probe that surfaced them: `delegate(tools: ["this_tool_does_not_exist_12345"])`. The child's
closing message listed exactly two tools (`list_subagent_models`, `subagent`) and said it had no
"available tools" statement anywhere in context.

### Fixed
- **A name outside `maxTools` is an error now, not a silent filter.** The old filter turned a
  typo into `allow: []`, which emptied the global surface while leaving scoped registrations
  reachable — the child could do nothing, yet still held a `subagent` tool it was not allowed
  to call. `delegate` now throws, names the rejected entries, and never creates the child.
- **The scope section no longer depends on `persona`.** It used to be skipped whenever
  `persona` was empty, so `delegate(tools: ['read'])` produced a child with no statement of its
  own limits — it inferred from the function table alone and counted `subagent` as usable. The
  section is now emitted whenever `allowTools` is set.
- **The section states which channels are absent.** `subagent` / `subagent_fork` / `delegate`
  stay visible as scoped registrations, and the host's system prompt names `task_begin` /
  `task_end` / `task_board_run`, none of which a child can be granted. The section says so
  instead of leaving the child to guess.
- **The tool result distinguishes "not narrowed" from "narrowed".** Returning the full cap used
  to look like a deliberate scope; it now reads
  `未收窄 —— 子代理获得了全部白名单工具`.

### Unchanged
- `tools: []` still means exactly zero tools — the only way to ask for an empty scope.

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
