/**
 * 2026-10-28 对抗审计（红 3 终稿）12 条缺陷的回归护栏。
 *
 * 每一条都对应一个"改回去必须变红"的断言 —— 这是审计规程 §6 要求的
 * 反证脚本的最小形态：断言的是**修复后的正确行为**，而不是"代码长什么样"。
 *
 * 跑法：node tests/audit-20261028.test.mjs
 */
import assert from 'node:assert/strict'
import test from 'node:test'

import { apply, inject, Config } from '../lib/index.js'
import { commandOf, shouldCapSandbox, scriptPathsOf } from '../lib/rules.js'

// ---------------------------------------------------------------- F1 / F4 / F5

test('F1 未登记的沙箱档位按最宽处理（不会静默放过）', () => {
  // 宿主哪天加了新档位，旧插件不能当作"比 read-only 窄"而放过。
  assert.equal(shouldCapSandbox('super-loose-mode', 'workspace-write'), true)
  assert.equal(shouldCapSandbox('workspace-write', 'workspace-write'), false, '同档不重写')
})

test('F4 commandOf 认数组、认嵌套、认自定义参数名', () => {
  assert.equal(commandOf({ command: ['a', 'b'] }), 'a\nb')
  assert.equal(commandOf({ input: { command: 'nested-cmd' } }), 'nested-cmd')
  assert.equal(commandOf({ script: 'diskpart' }, 'script'), 'diskpart')
  assert.equal(commandOf({ script: ['x', 'y'] }, ['command', 'script']), 'x\ny')
  assert.equal(commandOf({ unrelated: 'x' }), undefined)
  assert.equal(commandOf({ command: '   ' }), undefined, '空白串不算命令')
})

test('F5 一条命令里的多个脚本全部被认出来', () => {
  const paths = scriptPathsOf('pwsh -File a.ps1; pwsh -File b.ps1')
  assert.deepEqual(paths, ['a.ps1', 'b.ps1'])
  assert.deepEqual(scriptPathsOf('bash x.sh && sh ./y.bat'), ['x.sh', './y.bat'])
  assert.deepEqual(scriptPathsOf('echo nothing'), [])
})

// R3（2026-10-31 对抗审计）：Windows 忽略尾随的点，`pwsh -File evil.ps1.` 真的
// 会执行 `evil.ps1`。旧实现的扩展名判定对 `evil.ps1.` 失败，于是脚本内容
// 一个字节都不检查、直接放行。
test('R3 尾随点的脚本路径仍被认出（并按归一化后的路径读文件）', () => {
  assert.deepEqual(scriptPathsOf('pwsh -File evil.ps1.'), ['evil.ps1'])
  assert.deepEqual(scriptPathsOf('pwsh -File "C:\\work\\evil.ps1."'), ['C:\\work\\evil.ps1'])
  assert.deepEqual(scriptPathsOf('.\evil.ps1.'), ['.\evil.ps1'])
})

// --------------------------------------------------------- F9 / F10 / F13 / F11

const base = {
  enabled: true,
  subagentSandboxCap: 'workspace-write',
  commandArg: 'command',
  shellTools: ['bash', 'pwsh'],
  denyPatterns: ['\\bdanger\\b'],
  denyScope: 'subagent',
  scriptInspection: true,
  maxScriptBytes: 262144,
  enableDelegateTool: false,
  toolName: 'delegate',
  provider: 'spawn',
  enforceMaxTools: false,
  maxTools: [],
  sectionOrder: 120,
  sectionName: 'subagent-guard:persona',
  serializeBind: true,
}

/** 只够跑加载期校验的最小 ctx。 */
function makeCtx() {
  const ctx = {
    logger: () => ({ info() {}, warn() {}, error() {} }),
    on() {},
    effect(fn) {
      fn()
    },
    tools: { guard: () => () => {}, register: () => () => {} },
  }
  ctx.get = () => undefined
  return ctx
}

test('F9 commandArg 为空串时加载期响亮失败（否则静默关掉闸二）', () => {
  assert.throws(() => apply(makeCtx(), { ...base, commandArg: '' }), /commandArg 不能是空串/)
  assert.throws(() => apply(makeCtx(), { ...base, commandArg: [] }), /commandArg 数组不能为空/)
})

test('F10 enableDelegateTool 打开时 provider 不能为空', () => {
  assert.throws(
    () => apply(makeCtx(), { ...base, enableDelegateTool: true, provider: '' }),
    /provider 不能为空/,
  )
})

test('F13 toolName / sectionName / maxTools 的形状都校验', () => {
  assert.throws(() => apply(makeCtx(), { ...base, toolName: '' }), /toolName 不能为空/)
  assert.throws(() => apply(makeCtx(), { ...base, sectionName: '' }), /sectionName 不能为空/)
  assert.throws(() => apply(makeCtx(), { ...base, maxTools: [1] }), /maxTools 必须是字符串数组/)
})

test('F11 sandboxPolicy 不在 inject 里（缺它不该让整个插件 INACTIVE）', () => {
  assert.deepEqual(inject, ['tools'])
  // 服务缺失时插件必须仍然挂上闸二：能跑到"生效配置"那行日志、且注册了 guard。
  const ctx = makeCtx()
  let registered = 0
  ctx.tools.guard = () => {
    registered += 1
    return () => {}
  }
  assert.doesNotThrow(() => apply(ctx, { ...base }))
  // 两条全局 guard：闸二的黑名单 + 冷恢复兜底（后者注册在插件 ctx 上，不依赖任何服务）。
  assert.equal(registered, 2, 'sandboxPolicy 缺失时闸二与冷恢复兜底仍然要挂上')
})

// ------------------------------------------------------------------------ F2

test('F2 根会话（没有 parentSession）不会被闸一动手', () => {
  const ctx = makeCtx()
  const appended = []
  let capturedCreate
  ctx.on = (event, fn) => {
    if (event !== 'agent/created') return
    // 真 ctx 支持多监听（闸一封顶 + 冷恢复各一个），桩不能只留最后一个。
    const previous = capturedCreate
    capturedCreate =
      previous === undefined
        ? fn
        : (...args) => {
            previous(...args)
            fn(...args)
          }
  }
  ctx.get = (name) => {
    if (name !== 'sandboxPolicy') return undefined
    return { overrideOf: () => 'danger-full-access', defaultMode: 'danger-full-access' }
  }
  apply(ctx, { ...base })

  // 根会话：delegationDepth 0、没有 parentSession
  capturedCreate({
    agent: { options: {}, sessionId: 'root', session: { header: {}, append: (t, d) => appended.push([t, d]) } },
  })
  assert.deepEqual(appended, [], '根会话不该被压档')

  // 真正的子代理：有 parentSession
  capturedCreate({
    agent: {
      options: {},
      sessionId: 'child',
      session: { header: { delegationDepth: 1, parentSession: 'root' }, append: (t, d) => appended.push([t, d]) },
    },
  })
  assert.deepEqual(appended, [['sandbox/mode', { mode: 'workspace-write' }]], '子代理才压')
})

// ------------------------------------------------------------------ 默认值一致性

test('Config 默认值与 bundle patch 一致（denyScope subagent / provider spawn）', () => {
  const cfg = Config({})
  assert.equal(cfg.denyScope, 'subagent')
  assert.equal(cfg.provider, 'spawn')
  assert.equal(cfg.enableDelegateTool, true)
  assert.equal(cfg.serializeBind, true)
})
