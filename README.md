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

If the current mode **cannot be read**, the child is forced to `read-only` and an error
is logged (fail-closed). This matters because gate 1 is often the only thing standing
between a subagent and `danger-full-access`.

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

**Deliberately not blocked**: `Remove-Item`, `del`, `rmdir` and friends — blocking
everyday file operations makes the agent useless. Add your own patterns if you need
more.

#### Indirect execution

`pwsh -File build.ps1` puts nothing dangerous in the command string. With
`scriptInspection: true` (the default) the plugin extracts the target path of explicit
script-execution forms (`-File` / `-f`, `bash|sh|zsh|source`, `& 'x.ps1'`, `.\x.ps1`)
and runs the same rules against the file contents.

If the file cannot be read, or exceeds `maxScriptBytes`, the call is **allowed** with a
warning. That is deliberate: an unreadable path normally means a typo, and the script
would fail to run anyway. One level deep only — a script that runs another script is not
followed.

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

Policies are claimed per parent session, and `maxActiveSubagents` defaults to 50. Two
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
- **Cold resume re-expands the tool surface.** `restrict()` and any guard registered on the
  child's own `agent.ctx` do not survive `agents.resume()`: an idle child woken by
  `send_message` comes back with roughly the full inherited surface — observed on a child
  delegated `read` alone, which reported 91 tools afterwards and successfully spawned a
  grandchild. Visibility cannot be removed (`dsh-tools` exposes no way to unregister a
  scoped tool), so the plugin pins each granted surface in a side table and registers a
  fallback guard on **its own** context, which is not torn down with the child. The
  practical consequence: after a cold resume the tools are still *listed* to the model and
  are refused only at call time. Verified — a woken child calling `subagent` gets
  `工具 "subagent" 不在该子代理的授权工具面内（delegate 策略，冷恢复兜底）` and creates no
  grandchild. **If you plan to talk to a narrowed child over multiple turns, give it the
  full surface up front** rather than relying on the narrowing to hold across resume.
- **An unknown sandbox mode is treated as the widest** and capped to `read-only` with a
  warning. A host that introduces a new mode is a migration event for this plugin: gate 1
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
npm test   # six suites, 90 cases, no host required
```

| suite | cases | covers |
|---|---|---|
| `guard.test.mjs` | 13 | rules layer: regex, script paths, depth, mode ranking |
| `policy.test.mjs` | 20 | delegation policy: caps, sections, pending queue |
| `apply.test.mjs` | 20 | wiring: gates 1 and 2 against a stub context |
| `delegate.test.mjs` | 21 | gate 3 wiring, concurrency, fail-closed claim |
| `regressions.test.mjs` | 7 | YAML quoting, pending cleanup, cap intersection |
| `audit-20261028.test.mjs` | 9 | every audit finding that can be pinned host-free |

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
