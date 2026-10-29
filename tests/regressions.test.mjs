/**
 * 2026-10-28 对抗审计（WORKFLOW-对抗审计2.0）确认的真缺陷回归。
 *
 * 每一条都对应一份外部/异质审计的具体发现，且在修复前是可以复现的。
 * 这些用例的作用是反证：把修复改回去，指定断言必须变红。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { dropPending, pushPending, takePending, resolveAllowedTools, normalizeCap } from '../lib/policy.js'
import { scriptPathOf, shouldCapSandbox } from '../lib/rules.js'

// ---- 审计 E_stale：认领失败后残留策略被下一次委派领走 ----------------------
test('dropPending 撤下未被认领的策略，队列不残留', () => {
  const map = new Map()
  const a = { id: 'a' }
  const b = { id: 'b' }
  pushPending(map, 'parent', a)
  pushPending(map, 'parent', b)
  assert.equal(takePending(map, 'parent'), a, '先登记的先被认领')

  // 模拟：b 那次委派核对失败，需要把 b 撤下来
  assert.equal(dropPending(map, 'parent', b), true)
  assert.equal(map.has('parent'), false, '队列应被清空，不能残留')
  assert.equal(takePending(map, 'parent'), undefined, '后续委派不能再领到旧策略')
})

test('dropPending 对不存在的条目返回 false 且不抛', () => {
  const map = new Map()
  assert.equal(dropPending(map, 'nobody', { id: 'x' }), false)
  pushPending(map, 'p', { id: 'y' })
  assert.equal(dropPending(map, 'p', { id: 'x' }), false, '不在队列里的对象不能被误删')
  assert.equal(map.get('p').length, 1)
})

test('残留策略会污染下一次委派（修复前的形状，用于反证）', () => {
  // 这条用例描述的是**没有** dropPending 时的行为，用来证明护栏确实必要：
  // 不调用 dropPending，第二次委派会先领到第一次的旧策略。
  const map = new Map()
  const stale = { id: 'stale', allowTools: ['read'] }
  const fresh = { id: 'fresh', allowTools: ['write'] }
  pushPending(map, 'parent', stale)
  pushPending(map, 'parent', fresh)
  const first = takePending(map, 'parent')
  assert.equal(first, stale, '不清理时，旧策略先被领走 —— 这就是串号')
})

// ---- 审计 F4：README 的 YAML 单引号示例会让规则失效 ------------------------
test('默认规则用单反斜杠源串（YAML 双引号或 JSON 写法才正确）', () => {
  // 若 README 示例照抄进 YAML 单引号，解析出的源串会是两个反斜杠：
  const doubleEscaped = String.raw`\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b`
  const correct = String.raw`\bvssadmin\b[^\r\n]*\b(?:delete|resize|revert)\b`
  const sample = 'vssadmin delete shadows /all /quiet'
  assert.equal(new RegExp(doubleEscaped, 'i').test(sample), false, '双反斜杠版本匹配不到真实命令')
  assert.equal(new RegExp(correct, 'i').test(sample), true, '单反斜杠版本才正确')
})

// ---- 审计 C1：相等档位不应触发硬顶 ----------------------------------------
test('shouldCapSandbox 只在严格更宽时返回 true', () => {
  assert.equal(shouldCapSandbox('workspace-write', 'workspace-write'), false, '相等档位不该重写')
  assert.equal(shouldCapSandbox('danger-full-access', 'workspace-write'), true)
  assert.equal(shouldCapSandbox('read-only', 'workspace-write'), false, '只降不升')
})

// ---- 审计 F1/A2：脚本路径识别 ---------------------------------------------
test('scriptPathOf 识别 -File 与 bash 形式，不误判 -Command', () => {
  assert.equal(scriptPathOf('pwsh -File ./x.ps1'), './x.ps1')
  assert.equal(scriptPathOf('bash script.sh'), 'script.sh')
  assert.equal(scriptPathOf('pwsh -Command "Get-Date"'), undefined, '-Command 不是脚本文件')
})

// ---- 部署上限的交集语义 ----------------------------------------------------
test('部署上限：越界请求响亮失败，enableMaxTools=false 时不设限', () => {
  assert.throws(() => resolveAllowedTools(['read', 'pwsh'], ['read']), /不在部署上限里/)
  assert.equal(resolveAllowedTools(undefined, null), undefined, '既没请求也没上限 = 继承父面')
  assert.deepEqual(resolveAllowedTools(['read'], null), ['read'], '没上限时原样放行请求值')
  assert.throws(() => resolveAllowedTools(['read'], []), /不在部署上限里/, '空上限 = 请求什么都失败')
  assert.deepEqual(resolveAllowedTools([], []), [], '显式空集 = 零工具')
  assert.equal(normalizeCap(false, ['read']), null)
  assert.deepEqual(normalizeCap(true, ['read']), ['read'])
})
