/**
 * 接线层集成测试：import 真实的 lib/index.js，用假 ctx 驱动 apply，
 * 断言两道闸真的挂上、判定真的对。不启动 DSH 宿主。
 *
 * 依赖 node_modules 下的 peer 包（本地开发用 junction 指向宿主副本）。
 * 跑法：node tests/apply.test.mjs
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { apply, depthOf, name, inject, Config } from '../lib/index.js'

/** 造一个最小可用的假 ctx。 */
function makeCtx({ override, defaultMode = 'danger-full-access' } = {}) {
  const guards = []
  const listeners = {}
  const disposers = []
  const logs = []
  const ctx = {
    logger: () => ({
      info: (m) => logs.push(['info', m]),
      warn: (m) => logs.push(['warn', m]),
      error: (m) => logs.push(['error', m]),
    }),
    on: (event, fn) => {
      listeners[event] = fn
    },
    effect: (fn) => {
      const disposer = fn()
      disposers.push(disposer)
    },
    tools: {
      guard: (fn) => {
        guards.push(fn)
        return () => {}
      },
    },
    sandboxPolicy: {
      overrideOf: () => override,
      defaultMode,
    },
  }
  // 2026-10-28 审计 F11：插件改用 `ctx.get('sandboxPolicy')` 可选获取，
  // 这样服务缺失时不会再让整个插件 INACTIVE。
  ctx.get = (serviceName) => (serviceName === 'sandboxPolicy' ? ctx.sandboxPolicy : undefined)
  return { ctx, guards, listeners, disposers, logs }
}

/** 造一个假 agent。delegationDepthOf 读 session.header.delegationDepth 与 options.subagentDepth。 */
function makeAgent(depth, sessionId = `s-${depth}`) {
  const appended = []
  const session = {
    // 2026-10-28 审计 F2：闸一只对**真正有父会话**的 agent 生效
    // （根会话创建时也会发 `agent/created`，不能把它当子代理压档）。
    header: {
      delegationDepth: depth,
      ...(depth > 0 ? { parentSession: `parent-${depth}` } : {}),
    },
    sessionId,
    append: (type, data) => appended.push([type, data]),
  }
  return { agent: { options: {}, session, sessionId }, appended }
}

/**
 * 测试用的完整配置。
 * 注意：这里必须把 Config 的每个字段都写全——`apply` 收到的是宿主已经用
 * Schemastery 填充过默认值的对象，裸 config 缺字段会让校验提前抛错。
 */
const baseConfig = {
  enabled: true,
  subagentSandboxCap: 'workspace-write',
  commandArg: 'command',
  shellTools: ['bash', 'pwsh', 'win_bash'],
  denyPatterns: [],
  denyScope: 'all',
  scriptInspection: true,
  maxScriptBytes: 262144,
  // 本文件只测闸一（档位）与闸二（命令），关掉闸三，避免注册 delegate 工具。
  enableDelegateTool: false,
  toolName: 'delegate',
  provider: 'spawn',
  enforceMaxTools: false,
  maxTools: [],
  sectionOrder: 120,
  sectionName: 'subagent-guard:persona',
  serializeBind: true,
}

test('导出的契约形状正确', () => {
  assert.equal(name, 'dsh-subagent-guard')
  assert.deepEqual(inject, ['tools'])
  assert.equal(typeof Config, 'function', 'Config 必须是 Schemastery schema')
  assert.equal(typeof apply, 'function')
})

test('默认值对齐：schema 与 bundle patch 的 denyScope 都是 subagent', () => {
  // 审计缺口 4：两处默认值不一致会让"装完比文档更松"。
  const resolved = Config({})
  assert.equal(resolved.denyScope, 'subagent')
  assert.equal(resolved.subagentSandboxCap, 'workspace-write')
  assert.equal(resolved.scriptInspection, true)
})

test('闸一：danger-full-access 的子代理被压到 workspace-write', () => {
  const { ctx, listeners, logs } = makeCtx({ override: undefined, defaultMode: 'danger-full-access' })
  apply(ctx, { ...baseConfig })
  assert.equal(typeof listeners['agent/created'], 'function', '必须挂 agent/created')

  const { agent, appended } = makeAgent(1)
  listeners['agent/created']({ agent })

  assert.deepEqual(appended, [['sandbox/mode', { mode: 'workspace-write' }]])
  assert.ok(logs.some(([, m]) => m.includes('硬顶')))
})

test('闸一：顶层会话不动', () => {
  const { ctx, listeners } = makeCtx({ defaultMode: 'danger-full-access' })
  apply(ctx, { ...baseConfig })
  const { agent, appended } = makeAgent(0)
  listeners['agent/created']({ agent })
  assert.deepEqual(appended, [])
})

test('闸一：本来就不宽的子代理不动（只降不升）', () => {
  const { ctx, listeners } = makeCtx({ override: 'read-only', defaultMode: 'danger-full-access' })
  apply(ctx, { ...baseConfig })
  const { agent, appended } = makeAgent(2)
  listeners['agent/created']({ agent })
  assert.deepEqual(appended, [])
})

test('闸一：cap=inherit 完全不干预', () => {
  const { ctx, listeners } = makeCtx({ defaultMode: 'danger-full-access' })
  apply(ctx, { ...baseConfig, subagentSandboxCap: 'inherit' })
  const { agent, appended } = makeAgent(1)
  listeners['agent/created']({ agent })
  assert.deepEqual(appended, [])
})

test('闸一：读取档位抛错时 fail-closed，补压到 read-only', () => {
  // 审计缺口 3：原实现 warn 一句就放行。现在必须压到最严档。
  const { ctx, listeners, logs } = makeCtx()
  ctx.sandboxPolicy.overrideOf = () => {
    throw new Error('boom')
  }
  apply(ctx, { ...baseConfig })
  const { agent, appended } = makeAgent(1)
  assert.doesNotThrow(() => listeners['agent/created']({ agent }))
  assert.deepEqual(appended, [['sandbox/mode', { mode: 'read-only' }]], '读不到档位必须压到 read-only')
  assert.ok(logs.some(([lvl]) => lvl === 'error'), '必须以 error 级别留痕')
})

test('闸一：写入档位抛错时用 error 留痕，不炸宿主', () => {
  const { ctx, listeners, logs } = makeCtx({ defaultMode: 'danger-full-access' })
  apply(ctx, { ...baseConfig })
  const agent = {
    options: {},
    sessionId: 's-broken',
    session: {
      header: { delegationDepth: 1, parentSession: 'parent-broken' },
      append: () => {
        throw new Error('append failed')
      },
    },
  }
  assert.doesNotThrow(() => listeners['agent/created']({ agent }))
  assert.ok(logs.some(([lvl, m]) => lvl === 'error' && m.includes('封顶失败')))
})

test('闸二：guard 真的被注册，且按整串命令拒绝', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b[^\\r\\n]*\\bdelete\\b'] })
  // 两条全局 guard：闸二的黑名单 + 冷恢复兜底（后者只认 pinned 里的会话，见 delegate.test.mjs）。
  assert.equal(guards.length, 2)

  const { agent } = makeAgent(1)
  const reason = guards[0]({ name: 'pwsh', arguments: { command: 'vssadmin delete shadows /all' }, agent })
  assert.equal(typeof reason, 'string')
  assert.match(reason, /dsh-subagent-guard/)
  assert.match(reason, /vssadmin/)
})

test('闸二：安全命令放行', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b'] })
  const { agent } = makeAgent(1)
  assert.equal(guards[0]({ name: 'pwsh', arguments: { command: 'Get-Date' }, agent }), undefined)
})

test('闸二：参数形状驱动——第三方 shell 不在名单也照样拦', () => {
  // 审计缺口 1：`win_bash` 这类第三方 shell 工具名不在白名单里就会被整类放行。
  const { ctx, guards, logs } = makeCtx()
  apply(ctx, { ...baseConfig, shellTools: ['bash', 'pwsh'], denyPatterns: ['\\bvssadmin\\b'] })

  const { agent } = makeAgent(1)
  const reason = guards[0]({
    name: 'some_third_party_shell',
    arguments: { command: 'vssadmin delete shadows' },
    agent,
  })
  assert.equal(typeof reason, 'string', '只要参数里有 command，就必须被检查')
  assert.ok(logs.some(([, m]) => m.includes('自动纳入命令类工具')), '必须留一条可见的告警')
})

test('闸二：不带命令参数的工具不受约束', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b'] })
  const { agent } = makeAgent(1)
  assert.equal(
    guards[0]({ name: 'read', arguments: { file_path: 'C:\\x.txt' }, agent }),
    undefined,
    '没有 command 参数的工具不该被拦',
  )
})

test('闸二：denyScope=subagent 时顶层放行、子代理照拒', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyScope: 'subagent', denyPatterns: ['\\bdanger\\b'] })

  const top = makeAgent(0)
  const child = makeAgent(1)
  const call = (agent) => guards[0]({ name: 'bash', arguments: { command: 'echo danger' }, agent })

  assert.equal(call(top.agent), undefined, '顶层应放行')
  assert.equal(typeof call(child.agent), 'string', '子代理应拒绝')
})

test('闸二：空 denyPatterns 不拦任何命令', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: [] })
  const { agent } = makeAgent(1)
  assert.equal(guards[0]({ name: 'pwsh', arguments: { command: 'diskpart /s x' }, agent }), undefined)
})

test('闸二：enabled=false 时两道闸都不生效', () => {
  const { ctx, guards, listeners } = makeCtx()
  apply(ctx, { ...baseConfig, enabled: false, denyPatterns: ['\\bvssadmin\\b'] })

  const { agent, appended } = makeAgent(1)
  listeners['agent/created']({ agent })
  assert.deepEqual(appended, [])
  assert.equal(guards[0]({ name: 'pwsh', arguments: { command: 'vssadmin delete shadows' }, agent }), undefined)
})

test('闸二：脚本旁路——-File 指向含危险命令的脚本被拒', () => {
  // 审计缺口 2：`pwsh -File x.ps1` 的命令行里看不到脚本内容。
  const dir = mkdtempSync(join(tmpdir(), 'guard-test-'))
  try {
    const script = join(dir, 'evil.ps1')
    writeFileSync(script, 'Write-Output "start"\nvssadmin delete shadows /all /quiet\n', 'utf8')

    const { ctx, guards } = makeCtx()
    apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b'] })
    const { agent } = makeAgent(1)

    const reason = guards[0]({
      name: 'pwsh',
      arguments: { command: `pwsh -File "${script}"` },
      agent,
      cwd: dir,
    })
    assert.equal(typeof reason, 'string', '脚本内容命中规则时必须拒绝')
    assert.match(reason, /间接执行的脚本/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('闸二：脚本旁路——干净的脚本放行', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guard-test-'))
  try {
    const script = join(dir, 'ok.ps1')
    writeFileSync(script, 'Get-Date\nGet-ChildItem\n', 'utf8')

    const { ctx, guards } = makeCtx()
    apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b'] })
    const { agent } = makeAgent(1)

    assert.equal(
      guards[0]({ name: 'pwsh', arguments: { command: `pwsh -File "${script}"` }, agent, cwd: dir }),
      undefined,
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('闸二：脚本旁路可关闭', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guard-test-'))
  try {
    const script = join(dir, 'evil.ps1')
    writeFileSync(script, 'vssadmin delete shadows /all\n', 'utf8')

    const { ctx, guards } = makeCtx()
    apply(ctx, { ...baseConfig, scriptInspection: false, denyPatterns: ['\\bvssadmin\\b'] })
    const { agent } = makeAgent(1)

    assert.equal(
      guards[0]({ name: 'pwsh', arguments: { command: `pwsh -File "${script}"` }, agent, cwd: dir }),
      undefined,
      'scriptInspection=false 时只查命令行文本',
    )
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('加载期校验：未知档位 / 未知作用域 / 非法正则都响亮失败', () => {
  const { ctx } = makeCtx()
  assert.throws(() => apply(ctx, { ...baseConfig, subagentSandboxCap: 'root' }), /subagentSandboxCap/)
  assert.throws(() => apply(ctx, { ...baseConfig, denyScope: 'everything' }), /denyScope/)
  assert.throws(() => apply(ctx, { ...baseConfig, denyPatterns: ['vssadmin('] }), /非法的 denyPatterns 正则/)
  assert.throws(() => apply(ctx, { ...baseConfig, maxScriptBytes: 0 }), /maxScriptBytes/)
})

test('depthOf 在判不清时 fail-closed 当作子代理', () => {
  assert.equal(depthOf({ options: {}, session: { header: { delegationDepth: 3 } } }), 3)
  assert.equal(depthOf({ options: { subagentDepth: 5 }, session: { header: { delegationDepth: 1 } } }), 5)
  assert.equal(depthOf({}), 1, '读不到深度时必须当子代理')
})
