# dsh-subagent-guard

Two gates for subagents in [DeepSeek Harness][dsh]: a **sandbox ceiling** and a **destructive-command denylist**.

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

## Two gates

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
          - '\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b'
          - '\\bdiskpart\\b'
```

The effective configuration is logged once at startup
(`生效配置：subagentSandboxCap=… denyScope=… 规则=16 条 …`), so drift between the
documented default and the deployed one is visible instead of silent.

Invalid configuration (unknown mode, unknown scope, uncompilable regex, non-positive
size limit) throws at load time rather than failing silently.

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
- The ceiling rewrite is stored as a `sandbox/mode` event, so it replays with the
  session. Archived sessions are not replayed.

[cve]: https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape/

## Compatibility

Verified against `@deepseek-ai/dsh-*` **0.2.1-rc.2** (2026-10-24). The plugin copies two
small helpers instead of importing sibling `dsh-*` packages, because a profile's
`node_modules` usually contains only `schemastery` and a static import would fail at
load time. If DSH renames `subagentDepth`, `delegationDepth` or the `sandbox/mode`
event, these copies fail **silently** — the plugin tries to `import()` the official
package at runtime and warns when the two disagree, but that check only fires when the
package happens to be resolvable.

## Tests

```bash
node tests/guard.test.mjs    # rules layer, no host required
node tests/apply.test.mjs    # wiring layer, stub context
```

33 cases, all host-free: `lib/rules.js` has no DSH imports.

## External audits

- [2026-10-24 — subagent guard coverage audit](./docs/research/2026-10-24-external-audit.md):
  five gaps found by a user on a real deployment, with maintainer responses and the
  fixes that landed in 0.2.0.

## License

MIT — see [LICENSE](./LICENSE).
