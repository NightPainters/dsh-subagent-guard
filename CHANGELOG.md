# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
