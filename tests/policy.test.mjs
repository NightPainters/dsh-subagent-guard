/**
 * policy.js 的纯逻辑单测：不依赖宿主，`node tests/policy.test.mjs` 直跑。
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertToolName,
  buildPolicy,
  normalizeCap,
  pushPending,
  renderSection,
  resolveAllowedTools,
  takePending,
} from '../lib/policy.js'

// ---- normalizeCap ----------------------------------------------------------

test('normalizeCap: 未开启时恒为 null', () => {
  assert.equal(normalizeCap(false, ['read']), null)
  assert.equal(normalizeCap(false, []), null)
})

test('normalizeCap: 开启后空数组合法（表示一个都不给）', () => {
  assert.deepEqual(normalizeCap(true, []), [])
})

test('normalizeCap: 开启后必须是数组', () => {
  assert.throws(() => normalizeCap(true, 'read'), /必须是字符串数组/)
})

test('normalizeCap: 拒绝形状非法的工具名', () => {
  assert.throws(() => normalizeCap(true, ['read files']), /形状非法/)
  assert.throws(() => normalizeCap(true, ['']), /非空字符串/)
})

// ---- resolveAllowedTools ---------------------------------------------------

test('resolveAllowedTools: 模型没指定 + 无上限 ⇒ 不施加 restrict', () => {
  assert.equal(resolveAllowedTools(undefined, null), undefined)
})

test('resolveAllowedTools: 模型没指定 + 有上限 ⇒ 用上限', () => {
  assert.deepEqual(resolveAllowedTools(undefined, ['read', 'grep']), ['read', 'grep'])
})

test('resolveAllowedTools: 模型指定 + 无上限 ⇒ 原样（去重）', () => {
  assert.deepEqual(resolveAllowedTools(['read', 'read', 'grep'], null), ['read', 'grep'])
})

test('resolveAllowedTools: 请求超出部署上限 ⇒ 响亮失败（不再静默裁剪）', () => {
  // 2026-10-29 实测：静默过滤会把「打错一个字」变成「零工具 + scoped 工具残留」，
  // 而调用方以为按自己说的配置在跑。宁可抛错也不许静默降级。
  assert.throws(
    () => resolveAllowedTools(['read', 'pwsh', 'write'], ['read', 'grep']),
    /delegate 的 tools 里有 2 个名字不在部署上限里[\s\S]*"pwsh"[\s\S]*"write"/,
  )
})

test('resolveAllowedTools: 要的全在上限外 ⇒ 响亮失败', () => {
  assert.throws(() => resolveAllowedTools(['pwsh'], ['read']), /不在部署上限里/)
})

test('resolveAllowedTools: 上限为空数组 ⇒ 请求任何名字都失败，但显式 [] 合法', () => {
  assert.throws(() => resolveAllowedTools(['read'], []), /不在部署上限里/)
  assert.deepEqual(resolveAllowedTools([], []), [])
})

// ---- renderSection ---------------------------------------------------------

test('renderSection: 空 persona 但有工具面 ⇒ 仍然产生说明段落（与 persona 解耦）', () => {
  // 2026-10-29 实测：旧实现在 persona 为空时整段不注册，于是
  // delegate(tools:['read']) 的子代理上下文里没有任何「可用工具」文字。
  const text = renderSection({ persona: '', allowTools: ['read'] })
  assert.match(text, /可用工具：read/)
  assert.match(text, /没有 subagent \/ subagent_fork \/ delegate/)
  assert.equal(renderSection({}), undefined)
})

test('renderSection: persona + 工具清单', () => {
  const text = renderSection({ persona: '你是审查员。', allowTools: ['read', 'grep'] })
  assert.match(text, /你是审查员。/)
  assert.match(text, /可用工具：read, grep/)
})

test('renderSection: 空工具集合明确说"无可用工具"', () => {
  const text = renderSection({ persona: '只读审查。', allowTools: [] })
  assert.match(text, /（无可用工具）/)
})

test('renderSection: 没传 tools 时回落到 label，不谎报工具面', () => {
  const text = renderSection({ persona: '你是审查员。', label: '审查 PR' })
  assert.match(text, /本次委派：审查 PR/)
  assert.doesNotMatch(text, /可用工具/)
})

test('renderSection: persona 里的 {{...}} 原样保留（不做模板替换）', () => {
  const text = renderSection({ persona: '把 {{var}} 当字面量。' })
  assert.match(text, /\{\{var\}\}/)
})

// ---- buildPolicy -----------------------------------------------------------

test('buildPolicy: 全量参数各就各位', () => {
  const policy = buildPolicy(
    { persona: '你是审查员。', tools: ['read', 'grep'], label: '审查' },
    ['read', 'grep', 'pwsh'],
  )
  assert.deepEqual(policy.allowTools, ['read', 'grep'])
  assert.equal(policy.label, '审查')
  assert.match(policy.sectionText, /你是审查员。/)
  assert.match(policy.sectionText, /可用工具：read, grep/)
})

test('buildPolicy: 只传 prompt 时不施加任何策略', () => {
  const policy = buildPolicy({}, null)
  assert.equal(policy.allowTools, undefined)
  assert.equal(policy.sectionText, undefined)
  assert.equal(policy.label, undefined)
})

// ---- FIFO 队列 -------------------------------------------------------------

test('takePending: 按插入顺序消费，取走即删', () => {
  const map = new Map()
  pushPending(map, 'p1', { id: 'a' })
  pushPending(map, 'p1', { id: 'b' })
  assert.equal(takePending(map, 'p1').id, 'a')
  assert.equal(takePending(map, 'p1').id, 'b')
  assert.equal(takePending(map, 'p1'), undefined)
  assert.equal(map.has('p1'), false)
})

test('takePending: 不同父会话互不干扰', () => {
  const map = new Map()
  pushPending(map, 'p1', { id: 'a' })
  pushPending(map, 'p2', { id: 'b' })
  assert.equal(takePending(map, 'p2').id, 'b')
  assert.equal(takePending(map, 'p1').id, 'a')
})

test('assertToolName: 常见工具名通过', () => {
  for (const name of ['read', 'pwsh', 'win_bash', 'dsh-ling', 'mcp__x']) {
    assert.equal(assertToolName(name, 'test'), name)
  }
})
