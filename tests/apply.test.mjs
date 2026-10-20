/**
 * 接线层集成测试：import 真实的 lib/index.js，用假 ctx 驱动 apply，
 * 断言两道闸真的挂上、判定真的对。不启动 DSH 宿主。
 *
 * 依赖 node_modules 下的 peer 包（本地开发用 junction 指向宿主副本）。
 * 跑法：node tests/apply.test.mjs
 */
import assert from 'node:assert/strict'
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
  return { ctx, guards, listeners, disposers, logs }
}

/** 造一个假 agent。delegationDepthOf 读 session.header.delegationDepth 与 options.subagentDepth。 */
function makeAgent(depth, sessionId = `s-${depth}`) {
  const appended = []
  const session = {
    header: { delegationDepth: depth },
    sessionId,
    append: (type, data) => appended.push([type, data]),
  }
  return { agent: { options: {}, session, sessionId }, appended }
}

const baseConfig = {
  enabled: true,
  subagentSandboxCap: 'workspace-write',
  shellTools: ['bash', 'pwsh'],
  denyPatterns: [],
  denyScope: 'all',
}

test('导出的契约形状正确', () => {
  assert.equal(name, 'dsh-subagent-guard')
  assert.deepEqual(inject, ['tools', 'sandboxPolicy'])
  assert.equal(typeof Config, 'function', 'Config 必须是 Schemastery schema')
  assert.equal(typeof apply, 'function')
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

test('闸一：读取档位抛错时 fail-open 跳过，不炸宿主', () => {
  const { ctx, listeners, logs } = makeCtx()
  ctx.sandboxPolicy.overrideOf = () => {
    throw new Error('boom')
  }
  apply(ctx, { ...baseConfig })
  const { agent, appended } = makeAgent(1)
  assert.doesNotThrow(() => listeners['agent/created']({ agent }))
  assert.deepEqual(appended, [])
  assert.ok(logs.some(([, m]) => m.includes('跳过封顶')))
})

test('闸二：guard 真的被注册，且按整串命令拒绝', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b[^\\r\\n]*\\bdelete\\b'] })
  assert.equal(guards.length, 1)

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

test('闸二：非 shell 工具不受约束', () => {
  const { ctx, guards } = makeCtx()
  apply(ctx, { ...baseConfig, denyPatterns: ['\\bvssadmin\\b'] })
  const { agent } = makeAgent(1)
  assert.equal(guards[0]({ name: 'read', arguments: { command: 'vssadmin delete shadows' }, agent }), undefined)
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

test('加载期校验：未知档位 / 未知作用域 / 非法正则都响亮失败', () => {
  const { ctx } = makeCtx()
  assert.throws(() => apply(ctx, { ...baseConfig, subagentSandboxCap: 'root' }), /subagentSandboxCap/)
  assert.throws(() => apply(ctx, { ...baseConfig, denyScope: 'everything' }), /denyScope/)
  assert.throws(() => apply(ctx, { ...baseConfig, denyPatterns: ['vssadmin('] }), /非法的 denyPatterns 正则/)
})

test('depthOf 在判不清时 fail-closed 当作子代理', () => {
  assert.equal(depthOf({ options: {}, session: { header: { delegationDepth: 3 } } }), 3)
  assert.equal(depthOf({ options: { subagentDepth: 5 }, session: { header: { delegationDepth: 1 } } }), 5)
  assert.equal(depthOf({}), 1, '读不到深度时必须当子代理')
})
