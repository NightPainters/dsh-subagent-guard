# dsh-subagent-guard

Three gates for subagents in [DeepSeek Harness][dsh]: a **sandbox ceiling**, a **destructive-command denylist**, and a **delegation tool** that pins each child's tool surface and system prompt.

> 中文说明见 [README.zh-CN.md](./README.zh-CN.md)。

[dsh]: https://github.com/deepseek-ai/deepseek-harness

## The gap

When DSH creates a subagent it captures a **snapshot** of the parent session's policy
(`captureDelegatedPolicyOverrides` in `@deepseek-ai/dsh-subagent`):

- the child's approval policy is pinned to `never` — anything requiring approval is
  rejected inside the child, never escalated to a human;
- the child inherits the parent's **explicit** sandbox override — if the parent runs
  `danger-full-access`, so does the child, unsandboxed;
- nothing on the model side can widen it again.

This is a [deliberate design decision][note], not a bug: *"Snapshot-at-delegation is the
semantic: the child keeps the policy it was handed."* The consequence is that a
subagent gets exactly the privileges the parent handed over at spawn time, while having
none of the parent's context, history, or judgement.

This plugin adds an operator-controlled ceiling on top of that snapshot — something the
harness intentionally does not provide.

[note]: https://github.com/jasonkneen/deepseek-harness-plus/blob/master/.agents/notes/implemented/feature/2026-07-25-subagent-policy-inheritance.md

## Three gates

### Gate 1 — sandbox ceiling (`agent/created`)

On subagent creation the plugin reads the effective sandbox mode (session override or
deployment default) and, if it is wider than `subagentSandboxCap`, appends a
`sandbox/mode` event lowering it. **Downgrade only**: a `read-only` child is never
raised to `workspace-write`.

The mode is read **when `agent/created` fires**, not inside the plugin's `apply()`.
Through 0.4.2 the service snapshot was taken in `apply()` — where the service is usually
not registered yet (a real-host probe measured every relevant service as `undefined` in
`apply`, becoming visible ~300 ms later). The snapshot was therefore always empty, the
fail-closed branch always won, and a **narrower** child was raised to the cap. 0.4.3
reads the service inside the event.

If the mode still **cannot be read** at event time, the child is forced to
`subagentSandboxCap` and an error is logged (fail-closed). This matters because gate 1 is
often the only thing standing between a subagent and `danger-full-access`.

Applies to subagents created *after* the plugin loads.

### Gate 2 — command denylist (`ctx.tools.guard`)

`ctx.tools.guard()` is a **monotonic gate**: it runs after the `tools/pre-execute`
waterfall and *cannot be overridden in the allow direction* by any other plugin. A
returned string denies the call; there is no `ask` path around it and no approval
policy (`never` included) can bypass it.

Which tools does it inspect? **Any tool whose arguments carry a command string**, keyed
by `commandArg` (default `command`). This is deliberately *not* a tool-name allowlist —
an earlier version enumerated `shellTools: [bash, pwsh]` and silently skipped every
third-party shell (e.g. `win_bash`) that registered under a different name. Tool names
change per deployment; argument shape does not.

Default rules cover operations that cannot be undone without external media:

| Category | Examples |
|---|---|
| Shadow copies | `vssadmin delete shadows`, `wmic shadowcopy delete`, `Get-WmiObject Win32_ShadowCopy … Delete` |
| Restore points | `Remove-ComputerRestorePoint`, `Disable-ComputerRestore` |
| Disks / partitions | `diskpart`, `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `format C:` |
| Boot configuration | `bcdedit`, `reg delete HKLM…` |
| Host availability | `Stop-Computer`, `Restart-Computer`, `shutdown /…` |
| Irreversible erase | `cipher /w`, `sdelete` |

Command text is **normalized** before matching (0.4.5): PowerShell's backtick+newline, cmd's
caret+newline and bash's backslash+newline continuations are folded to a space, quotes are
stripped, and all whitespace/newlines collapse to a single space. The same action written
differently therefore lands on the same rule: `shutdown` + newline + `/s`,
`"C:\Windows\System32\shutdown.exe" /s`, and `Start-Process shutdown -ArgumentList "-s"` all
match "shutdown with a power flag"; `format.com C:` and `reg delete HKEY_LOCAL_MACHINE\…` are
equivalent to `format C:` and `HKLM`. Power flags are matched against the real letter set
(`/s` `/r` `/g` `/p` `/h` `/l` `/a`, dashes included), so `Get-Help shutdown -examples` and
`shutdown /?` are untouched.

**Deliberately not blocked**: `Remove-Item`, `del`, `rmdir` and friends — blocking
everyday file operations makes the agent useless. Add your own patterns if you need
more.

#### Indirect execution

`pwsh -File build.ps1` puts nothing dangerous in the command string. With
`scriptInspection: true` (the default) the plugin extracts the target path of explicit
script-execution forms (`-File` / `-f`, `bash|sh|zsh|source`, `& 'x.ps1'`, `.\x.ps1`)
and runs the same rules against the file contents.

0.4.5 closed four fail-open paths here:

- **Every script in a command is inspected**: the text is split on `;` `&` `|` and newlines
  (no surrounding whitespace required) and each segment is parsed. `pwsh -File a.ps1;pwsh
  -File b.ps1` used to check only `b.ps1`.
- **BOM-aware decoding**: `FF FE` → UTF-16LE, `FE FF` → UTF-16BE (byte-swapped manually),
  `EF BB BF` → UTF-8 without the BOM; without a BOM, a high NUL ratio triggers a UTF-16LE
  retry. Fixed `utf8` decoding turned UTF-16 scripts into `\u0000`-laden garbage that no
  rule could match.
- **Session cwd first, and every existing candidate is checked**: a relative path resolves
  against the child session's `cwd`, then the process cwd, then as given; any candidate that
  matches a rule denies the call. Previously the first readable file won, so a same-named
  file in the process cwd could shadow the one that actually runs.
- **Extension-less targets of explicit interpreters are inspected**: `bash ./payload`,
  `sh /opt/run` — any path-shaped target (contains `/`, `\`, or starts with `.`) is read.

If the file cannot be read, the call is **allowed** with a warning — an unreadable path
normally means a typo, and the script would fail to run anyway. A file that exceeds
`maxScriptBytes` (256 KiB by default), however, is **refused**: a script whose contents were
never inspected must not run. Raise the limit if you really need a larger one. Trailing dots
in the path (`evil.ps1.`, which Windows ignores) are normalized before classification and
reading. One level deep only — a script that runs another script is not followed.

### Gate 3 — delegation policy (`delegate` tool)

DSH 0.2 closed the `persona` and `toolFilter` parameters
(`dsh-tool-subagent/lib/index.js:355` rejects them outright), leaving `agentPreset` as
the only way to change a child's composition. But the harness still uses both mechanisms
internally on the cold-resume path (`dsh-subagent/lib/types/child-agent.js:153-167`):

```js
childCtx.systemPrompt.section(...)   // shadows a same-named global section
childCtx.tools.restrict(...)         // removes inherited tools
```

Gate 3 routes that path back into **fresh delegation**. It registers a `delegate` tool
that takes `prompt`, an optional `persona`, and an optional `tools` list:

1. the policy is registered under the **parent session id** before anything is created;
2. `subagents.startActivation()` creates the child;
3. in `agent/created` (serial, and awaited before any queued input) the policy is claimed
   by parent session and applied to the child's own context;
4. after `startActivation` returns, the plugin **verifies the child actually consumed its
   policy** — if it did not, the child is cancelled and the call throws.

Step 4 is what makes the binding `fail-closed`: a child whose scope could not be applied
does not get to run unpoliced.

#### Why two enforcement layers, not one

`restrict()` masks only the **inherited** tool surface. Its own documentation
(`dsh-tools/lib/index.js:2985-2987`) says *"Restrictions intersect; scoped registrations
remain visible"*. Meanwhile the official `dsh-tool-subagent:605-607` registers `subagent`
and `list_subagent_models` directly on the child's context from `agent/created`.

Measured on a live deployment before this was fixed: a child handed **only `read`** called
`subagent`, spawned a grandchild, and that grandchild ran with `delegationDepth: 2` and
**97 tools** including `pwsh`, `write`, `edit` and `workflow` — the policy never applied
because the grandchild was not registered by a `delegate` call.

So gate 3 installs both:

| Layer | Mechanism | Covers |
|---|---|---|
| visible surface | `childCtx.tools.restrict({ allow })` | inherited tools |
| execution surface | agent-scoped `childCtx.tools.guard()` | scoped tools that `restrict` cannot see |

The second layer denies any tool outside the allowlist with:
`Tool "subagent" is not in this subagent's authorized tool surface (delegate policy); available: read`.

#### Deployment cap

`tools` is passed by the model, so it cannot be trusted as an upper bound. With
`enforceMaxTools: true` the effective scope is:

```
child tool surface = tools (from the model) ∩ maxTools (from deployment config)
```

The model may narrow the surface, never widen it. `maxTools: []` with
`enforceMaxTools: true` means the child gets no tools at all.

#### Concurrency

Policies are claimed per parent session, and `maxActiveSubagents` defaults to 8. Two
interleaved `delegate` calls could therefore bind child A's policy to child B — the exact
failure this gate exists to prevent. The claim → create → verify sequence is serialized
(`serializeBind`, default on).

## Install

```bash
dsh plugin add dsh-subagent-guard
```

Or declare it in your profile as a `file:` / `link:` dependency and add
`dsh-subagent-guard` to `dsh.profile.bundles`. The bundle ships its own
`cordis.patch.yml`, so the row is inserted automatically.

## Configuration

Override by `id` in your profile, or edit the bundled patch:

```yaml
- insert:
    - id: dsh-subagent-guard
      name: dsh-subagent-guard
      config:
        enabled: true
        # inherit | read-only | workspace-write | danger-full-access
        subagentSandboxCap: workspace-write
        # all = parent and subagents; subagent = subagents only
        denyScope: subagent
        # argument name that carries the command (shape-based detection)
        commandArg: command
        # EXTRA tool names — detection is shape-based, this is not the full set
        shellTools: [bash, pwsh, win_bash]
        # read the target of `pwsh -File x.ps1` and check its contents
        scriptInspection: true
        maxScriptBytes: 262144
        # regex sources; REPLACES the defaults, it does not append
        denyPatterns:
          # ⚠️ Use DOUBLE quotes here. In YAML single quotes the backslashes are
          # literal, so '\\bvssadmin' compiles to a regex matching a backslash
          # followed by "bvssadmin" — the rule then matches nothing, silently.
          - "\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b"
          - "\\bdiskpart\\b"
```

The effective configuration is logged once at startup
(`生效配置：subagentSandboxCap=… denyScope=… 规则=18 条 …`), so drift between the
documented default and the deployed one is visible instead of silent.

Invalid configuration (unknown mode, unknown scope, uncompilable regex, non-positive
size limit) throws at load time rather than failing silently.

## Version warning

**Versions `0.3.6` and earlier can take the whole host process down with them.**

Their fail-closed path in `delegate` cancelled the child with a bare string
(`target.cancel('delegation-policy-unbound')`) instead of a well-formed
`AgentCancelCause`. The bad value propagated into `turn/end { reason: null }` in the
session log; replaying that session then read `reason.kind` on `null` and threw, which
made the *entire* DSH process fatal — every sibling process in the same Job Object
died with it, not just the subagent.

The trigger is narrow: a `delegate` call whose tool binding fails (for example tool
names not in your configured `maxTools`), followed by a restart that replays the
session. It is not reachable from ordinary delegation.

**`0.3.7` fixes the cause.** Upgrade before enabling gate 3 on a host you care about.
Full write-up: [`docs/incidents/2026-10-29-cancel-cause-fatal.md`](docs/incidents/2026-10-29-cancel-cause-fatal.md).

If you cannot upgrade yet, keep `enforceMaxTools: false` and pass no `tools` to
`delegate` — the binding then cannot fail, so that path is never entered.

## Known limits

- **Text matching, not a syscall sandbox.** `run_code`, `node -e`, inline evaluation
  (`pwsh -c "…"`), and multi-level script chains are not inspected — gate 1 is the
  backstop for those.
- **Indirect execution is best-effort.** Since 0.4.7 the path extractor also resolves
  `cmd /c "pwsh -File x.ps1"`, `Start-Process pwsh -ArgumentList "-File x.ps1"` and the
  `'-NoProfile','-File','x.ps1'` array form, so the script **content** is matched against the
  same rules. Command lines that build their arguments at runtime
  (`Start-Process -ArgumentList @('-File', $p)`, `Invoke-Expression`, variables) cannot be
  resolved from text and are not inspected.
- **`serializeBind: false` is deprecated and ignored (0.4.7).** Policy claiming is FIFO per
  parent session while `agent/created` order belongs to the host; letting two bindings overlap
  let a child claim the other call's policy. Every binding is now serialized. The mutex covers
  only the register → create → verify window, so child execution concurrency is unaffected.
- **Regex is not a sandbox.** Multi-line splitting, base64 decoding then executing,
  obfuscation — none are caught. This gate stops accidents and casual mistakes, not a
  determined adversary.
- **Policy cannot outrun the kernel.** [CVE-2026-82533][cve] (fixed in
  `0.1.2-alpha.1`) let an agent reach an unauthenticated local API from inside the
  sandbox and self-promote to `danger-full-access`. Any plugin operating at the policy
  layer is bypassable by a process that can execute arbitrary code. Pair this with a
  non-administrator account and a host you can snapshot.
- `denyScope: subagent` relies on `delegationDepthOf`; when it throws the call is
  treated as a subagent (fail-closed). Note the converse: if it throws for the **parent**
  too, a parent call is also treated as a subagent and gets blocked.
- **Gate 3 only guards the `delegate` tool it registers itself.** Outside a delegation
  window the official `subagent` / `subagent_fork` tools remain available in the parent
  session. A model that calls them instead of `delegate` gets a child whose tool surface
  was **not** narrowed — the very 97-tool shape this plugin was built against. Gate 1
  still caps that child's sandbox, so this is a narrowing gap, not a privilege escalation.
  *While* a `delegate` call is binding they are refused outright, because claiming is keyed
  by `parentSession`: an official child created inside that window would steal the pending
  policy. If you need the gap closed outside the window too, deny those tools yourself.
- **Gate 3 needs the `subagents` service.** If it never appears, `delegate` is not
  registered and gates 1 and 2 keep working. That degradation is logged once, but from the
  model's point of view gate 3 is simply gone.
- **Cold resume rebuilds the tool surface from the session log (0.4.3, authorization source
  corrected in 0.4.4).** `restrict()` and any guard registered on the child's own
  `agent.ctx` do not survive `agents.resume()`: an idle child woken by `send_message` comes
  back with roughly the full inherited surface — observed on a child delegated `read` alone,
  which reported 91 tools afterwards. After a host restart the plugin's own side table
  (in-memory) is gone too, and a woken child really did write a file with `pwsh` (a real
  defect in 0.4.2 and earlier). Since 0.4.3, when `agent/created` fires with no pending
  policy, the plugin rebuilds from the child's **own session log**:
  - the fixed scope paragraph inside `system/message` proves the child was created by this
    plugin **and** that an explicit tool list was given (a delegation without `tools` has
    nothing to restore);
  - the `可用工具：<list>` line inside that same paragraph — written by this plugin — is the
    **authorized** surface. This is the 0.4.4 correction: 0.4.3 used the earliest
    `request/header`'s `tools`, which is the **model-visible** surface. The official
    `dsh-tool-subagent` installs `subagent` / `subagent_fork` as agent-scoped registrations
    that bypass `restrict()`, so they appear in the header — and a pinned child could then
    call `subagent` after a restart and spawn an **unrestricted grandchild** (2026-10-31
    adversarial audit, R1-01, blocking). Only logs without that line fall back to the
    header, with those two scoped derivation tools removed.

  It then re-applies `restrict`, re-registers the scope section, and re-pins the child.
  DSH gives third-party plugins no way to append a custom session event (an unknown type
  without `ignorable` makes the **whole session unreadable**), so this is the only
  recovery path that adds no state and still works across processes.

  0.4.5 tightened three more things: parsing is anchored to the fixed scope paragraph (only
  the **last** `可用工具：` line *before* the marker counts; host sections ordered 1000+ come
  after it and cannot displace it); the paragraph surface is **intersected** with the
  `request/header` surface, so either source can veto, and `subagent` / `subagent_fork` —
  installed scoped by the host — are dropped on both sides (a parent can no longer put them
  in `tools` and let its child spawn an unconstrained grandchild); and a child whose session
  id cannot be read is **not** pinned at all — binding fails closed instead of writing a
  literal `"undefined"` key that would make the whole side table allow everything.

  Known limits: a caller-supplied `persona` cannot be separated from the same
  `system/message`, so the restored section only states the tool surface; a **marked** log
  with neither the `可用工具` line nor a request header is treated as an empty surface
  (fail-closed). Conversely, a child with **no marker at all** — it died before its first
  request and never ran a turn — cannot be identified as this plugin's, so it is not restored
  and keeps the inherited surface. That window is narrow and was observed zero times among
  real delegations. Intersecting is the safe direction but can **over-narrow**: an
  agent-scoped tool that was absent from that particular request header is dropped (fewer
  tools, never more).
- **Cold resume has exactly one trigger: `agent/created`.** If a future host stops emitting
  it from `agents.resume()`, the whole fallback silently allows. The plugin probes cheaply at
  startup (warns when the `agents` service has no `resume`) and documents the precondition;
  deeper verification is a real-host regression. `0.2.1-rc.2` emits it before the first
  request of the resumed child.
- **Gate 2 cannot see dynamically built commands.** String concatenation, base64 /
  `-EncodedCommand`, variable paths, extension-less interpreter targets that do not look like
  paths, `node -e`, and scripts that run other scripts are outside static matching — an
  explicit boundary, confirmed by the 2026-10-31 heterogeneous red teams (A2/A5/A7).
- **Gate 2 also blocks the auditor itself.** Read-only queries such as `Get-Help shutdown` are
  unaffected, but audit scripts that actually run sensitive commands are refused. That is by
  design; an exemption would itself be a bypass surface.
- **A `provider: 'fork'` child is restored from the parent's historical paragraph surface**,
  which can be narrower than it should be (over-restriction, not widening).
- **With `serializeBind: false`, two concurrent delegations can swap policies** (DoS shape,
  not escalation); the default is `true`.
- **The side table (`pinned`) is an in-process closure Map** covering only children of this
  plugin; children created by other plugins or the official `subagent` are capped by gate 1.
- **An unknown sandbox mode is treated as the widest** and capped to `read-only`, exactly like an
  unreadable mode. It is **not** capped to `subagentSandboxCap`: that cap defaults to
  `workspace-write`, so capping a stricter unknown mode to it would widen the sandbox.
  (default `workspace-write`) with a warning. A host that introduces a new mode is a
  migration event for this plugin: gate 1
  would otherwise treat it as "already narrow" and leave it alone.
- The ceiling rewrite is stored as a `sandbox/mode` event, so it replays with the
  session. Archived sessions are not replayed.

[cve]: https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape/

## Compatibility

Verified against `@deepseek-ai/dsh-*` **0.2.1-rc.2** (0.3.3, 2026-10-29 — gates 1 and 2
checked on a real `danger-full-access` parent, gate 3 on both a test bench and the same
host). The plugin copies two small helpers instead of importing sibling `dsh-*` packages,
because a profile's `node_modules` usually contains only `schemastery` and a static import
would fail at load time. If DSH renames `subagentDepth`, `delegationDepth` or the
`sandbox/mode` event, these copies fail **silently** — the plugin tries to `import()` the
official package at runtime and warns when the two disagree, but that check only fires when
the package happens to be resolvable.

## Tests

```bash
npm test   # six suites, 123 cases, no host required
```

| suite | cases | covers |
|---|---|---|
| `guard.test.mjs` | 19 | rules layer: regex, command normalization, script paths (incl. quoted separators and `cmd /c` sub-commands), depth, mode ranking |
| `policy.test.mjs` | 21 | delegation policy: caps, derived-tool rejection, sections, pending queue |
| `apply.test.mjs` | 27 | wiring: gates 1 and 2 against a stub context (incl. F-A, R3, R5, BOM, session-cwd, F-06 unknown-mode regressions) |
| `delegate.test.mjs` | 39 | gate 3 wiring, concurrency, fail-closed claim, F-B/R1-01/C1/T1 cold resume, F1 derived-channel filter, F2 forced serialization, F8 window |
| `regressions.test.mjs` | 7 | YAML quoting, pending cleanup, cap intersection |
| `audit-20261028.test.mjs` | 10 | every audit finding that can be pinned host-free |

## External audits

- [2026-10-24 — subagent guard coverage audit](./docs/research/2026-10-24-external-audit.md):
  five gaps found by a user on a real deployment, with maintainer responses and the
  fixes that landed in 0.2.0.
- **2026-10-28 — internal adversarial audit (three red-team paths, 8 planted canaries,
  recall 8/8).** Twenty-two findings across five categories (silent no-ops, receipts that
  lie, boundary flips, half-fixes, gates with missing upper layers). Fixes landed in 0.3.1
  and 0.3.2; 0.3.3 came from the test bench, which caught a regression introduced by the
  0.3.1 fix itself. Records live in the private maintainer workspace, not in this repo.

## License

MIT — see [LICENSE](./LICENSE).
