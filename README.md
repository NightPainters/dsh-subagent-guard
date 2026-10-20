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

Applies to subagents created *after* the plugin loads.

### Gate 2 — command denylist (`ctx.tools.guard`)

`ctx.tools.guard()` is a **monotonic gate**: it runs after the `tools/pre-execute`
waterfall and *cannot be overridden in the allow direction* by any other plugin. A
returned string denies the call; there is no `ask` path around it and no approval
policy (`never` included) can bypass it.

It matches the **full command string** of `bash` / `pwsh` calls, case-insensitively.

Default rules cover operations that cannot be undone without external media:

| Category | Examples |
|---|---|
| Shadow copies | `vssadmin delete shadows`, `wmic shadowcopy delete`, `Get-WmiObject Win32_ShadowCopy … Delete` |
| Restore points | `Remove-ComputerRestorePoint`, `Disable-ComputerRestore` |
| Disks / partitions | `diskpart`, `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, `format C:` |
| Boot configuration | `bcdedit`, `reg delete HKLM…` |
| Host availability | `Stop-Computer`, `Restart-Computer`, `shutdown /…` |

**Deliberately not blocked**: `Remove-Item`, `del`, `rmdir` and friends — blocking
everyday file operations makes the agent useless. Add your own patterns if you need
more.

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
        # tools subject to the denylist
        shellTools: [bash, pwsh]
        # regex sources; REPLACES the defaults, it does not append
        denyPatterns:
          - '\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b'
          - '\\bdiskpart\\b'
```

Invalid configuration (unknown mode, unknown scope, uncompilable regex) throws at load
time rather than failing silently.

## Known limits

- **Shell tools only.** The denylist inspects the `command` argument of `bash`/`pwsh`.
  `run_code`, `node -e`, or "write a script then execute it" never pass through it —
  gate 1 is the backstop for those.
- **Regex is not a sandbox.** Multi-line splitting, base64 decoding then executing,
  obfuscation — none are caught. This gate stops accidents and casual mistakes, not an
  adversary.
- **Policy cannot outrun the kernel.** [CVE-2026-82533][cve] (fixed in
  `0.1.2-alpha.1`) let an agent reach an unauthenticated local API from inside the
  sandbox and self-promote to `danger-full-access`. Any plugin operating at the policy
  layer is bypassable by a process that can execute arbitrary code. Pair this with a
  non-administrator account and a host you can snapshot.
- `denyScope: subagent` relies on `delegationDepthOf`; when it throws the call is
  treated as a subagent (fail-closed).
- The ceiling rewrite is stored as a `sandbox/mode` event, so it replays with the
  session. Archived sessions are not replayed.

[cve]: https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape/

## Tests

```bash
node tests/guard.test.mjs    # rules layer, no host required
node tests/apply.test.mjs    # wiring layer, stub context
```

`lib/rules.js` has no DSH imports, which is what makes the 24 tests host-free.

## License

MIT — see [LICENSE](./LICENSE).
