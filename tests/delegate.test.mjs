/**
 * 接线层单测：用假 ctx / 假子代理驱动 apply()，验证两道策略真的被施加、
 * 以及没施加成功时 fail-closed。
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { apply, Config, createMutex, parametersToJsonSchema } from '../lib/index.js'
import { ABSENT_CHANNELS_NOTE } from '../lib/policy.js'

/** Schemastery 的默认值：apply() 之前宿主会填一遍，这里手工补上。 */
function withDefaults(overrides = {}) {
  return {
    enabled: true,
    // 闸一、闸二：本文件只测闸三，档位设 inherit、黑名单清空，避免干扰。
    subagentSandboxCap: 'inherit',
    commandArg: 'command',
    shellTools: ['bash', 'pwsh', 'win_bash'],
    denyPatterns: [],
    denyScope: 'subagent',
    scriptInspection: false,
    maxScriptBytes: 262144,
    // 闸三
    enableDelegateTool: true,
    toolName: 'delegate',
    provider: 'spawn',
    enforceMaxTools: false,
    maxTools: [],
    sectionOrder: 120,
    sectionName: 'subagent-guard:persona',
    serializeBind: true,
    ...overrides,
  }
}

/**
 * 造一个能记录一切的假宿主。
 * @param {{ providerExists?: boolean, emitCreated?: boolean, restrictThrows?: boolean }} opts
 */
function makeHarness(opts = {}) {
  const {
    providerExists = true,
    emitCreated = true,
    restrictThrows = false,
    restrictUnknown = [],
    childOverride,
  } = opts
  const listeners = new Map()
  const log = []
  const calls = { restrict: [], sections: [], cancelled: [], guards: [], globalGuards: [], activations: [] }
  let toolDef
  let createdHandler
  let restrictAttempts = 0

  const childCtx = {
    tools: {
      restrict(filter) {
        restrictAttempts += 1
        if (restrictThrows) throw new Error('restrict exploded')
        // 首次调用模拟真机：白名单里混着 scoped 注册（或根本不存在）的工具名，
        // `restrict()` 会整单抛错并点名。第二次起按剔除后的集合正常工作。
        if (restrictAttempts === 1 && restrictUnknown.length > 0) {
          throw new Error(
            `tools.restrict() names unknown global tool${restrictUnknown.length > 1 ? 's' : ''} ` +
              `${restrictUnknown.map((name) => `"${name}"`).join(', ')}; ` +
              'known global tools: baz, foo, read',
          )
        }
        calls.restrict.push(filter)
        return () => {}
      },
      guard(fn) {
        calls.guards.push(fn)
        return () => {}
      },
    },
    systemPrompt: {
      section(section) {
        calls.sections.push(section)
        return () => {}
      },
    },
  }

  const childAgent = {
    sessionId: 'child-1',
    session: { id: 'child-1', header: { parentSession: 'parent-1' } },
    ctx: childCtx,
  }

  const agentsStub = {
    get(id) {
      return {
        cancel(cause) {
          calls.cancelled.push({ id, cause })
        },
      }
    },
  }

  const ctx = {
    logger() {
      return {
        info: (m) => log.push(['info', m]),
        warn: (m) => log.push(['warn', m]),
        error: (m) => log.push(['error', m]),
      }
    },
    on(name, handler) {
      if (!listeners.has(name)) listeners.set(name, [])
      listeners.get(name).push(handler)
      if (name === 'agent/created') createdHandler = handler
      return () => {}
    },
    effect(fn) {
      return fn()
    },
    tools: {
      register(definition) {
        toolDef = definition
        return () => {}
      },
      /** 闸二的全局命令 guard + 冷恢复兜底（本文件只关心后者）。 */
      guard(fn) {
        calls.globalGuards.push(fn)
        return () => {}
      },
    },
    subagents: {
      getProvider(name) {
        return providerExists ? { name } : undefined
      },
      async startActivation(spec) {
        calls.activations.push(spec)
        if (emitCreated) {
          // 宿主在 startActivation 内部同步派发 agent/created（serial + await）。
          const handlers = listeners.get('agent/created') ?? []
          for (const handler of handlers) await handler({ agent: childOverride ?? childAgent, source: 'subagent' })
        }
        return { childId: 'child-1', messageId: 'msg-1', spec }
      },
    },
    /**
     * `ctx.inject(deps, callback)`：真实宿主在依赖就绪后才执行回调；测试桩里
     * `subagents` 始终存在，所以视为"已就绪"同步执行。
     */
    inject(_deps, callback) {
      callback(ctx)
      return { dispose() {} }
    },
    /** 可选服务查找：插件用 ctx.get('subagents') 拿委派服务，失败路径用 'agents'。 */
    get(serviceName) {
      if (serviceName === 'subagents') return this.subagents
      if (serviceName === 'agents') return agentsStub
      return undefined
    },
  }

  const parent = {
    sessionId: 'parent-1',
    session: { id: 'parent-1' },
  }

  return {
    ctx,
    parent,
    calls,
    log,
    getTool: () => toolDef,
    emitCreated: (agent = childAgent) => createdHandler({ agent, source: 'subagent' }),
  }
}

/** 调一次 delegate 工具。 */
async function callDelegate(harness, args, execExtra = {}) {
  const tool = harness.getTool()
  return tool.execute(args, { agent: harness.parent, signal: new AbortController().signal, ...execExtra })
}

// ---- 基本接线 --------------------------------------------------------------

test('enabled: false 时不注册工具', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults({ enabled: false }))
  assert.equal(h.getTool(), undefined)
})

test('注册出来的工具名与 output 契约正确', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const tool = h.getTool()
  assert.equal(tool.name, 'delegate')
  assert.equal(typeof tool.output.render, 'function')
  assert.equal(tool.parameters.type, 'object')
  assert.deepEqual(tool.parameters.required.sort(), ['description', 'prompt'])
})

// 真机回归：宿主 assertSupportedJsonSchema 拒绝属性级 `required: true`
// （`unsupported JSON schema: schema.properties.<name>.required`），
// 必填只能写在顶层数组里。这条用例是 3090 测试台首次装载失败后补的。
test('output.schema 与 parameters 都不使用属性级 required（宿主会拒）', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const tool = h.getTool()

  for (const [name, schema] of [
    ['parameters', tool.parameters],
    ['output.schema', tool.output.schema],
  ]) {
    for (const [key, value] of Object.entries(schema.properties ?? {})) {
      assert.equal(
        value.required,
        undefined,
        `${name}.properties.${key} 不能带属性级 required（宿主 assertSupportedJsonSchema 会抛）`,
      )
    }
  }
  assert.deepEqual(tool.output.schema.required.sort(), ['kind', 'personaApplied', 'subagentId', 'toolsSource'])
})

// ---- 策略真的落地 ----------------------------------------------------------

test('delegate 把 tools 收窄成 restrict，把 persona 注册成 system prompt 段', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const value = await callDelegate(h, {
    description: '审查',
    prompt: '审查这个仓库',
    persona: '你是严格的审查员。',
    tools: ['read', 'grep'],
  })

  assert.equal(value.kind, 'delegation')
  assert.equal(value.subagentId, 'child-1')
  assert.deepEqual(value.tools, ['read', 'grep'])
  assert.equal(value.personaApplied, true)

  assert.deepEqual(h.calls.restrict, [{ allow: ['read', 'grep'] }])
  assert.equal(h.calls.sections.length, 1)
  assert.match(h.calls.sections[0].text, /你是严格的审查员。/)
  assert.equal(h.calls.sections[0].name, 'subagent-guard:persona')
  assert.equal(h.calls.sections[0].interpolate, false)
})

test('模型请求在白名单内 ⇒ 原样施加', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults({ enforceMaxTools: true, maxTools: ['read', 'grep'] }))
  const value = await callDelegate(h, { description: '审查', prompt: 'x', tools: ['read', 'grep'] })

  assert.deepEqual(value.tools, ['read', 'grep'])
  assert.deepEqual(h.calls.restrict, [{ allow: ['read', 'grep'] }])
})

test('模型请求超出部署上限 ⇒ 抛错且不创建子代理（不静默裁剪）', async () => {
  // 2026-10-29 实测的坏行为：静默过滤成空集后仍会创建子代理，
  // 它只剩 scoped 注册的 subagent/list_subagent_models，却什么都不能做。
  const h = makeHarness()
  apply(h.ctx, withDefaults({ enforceMaxTools: true, maxTools: ['read', 'grep'] }))
  await assert.rejects(
    () => callDelegate(h, { description: '审查', prompt: 'x', tools: ['read', 'pwsh'] }),
    /不在部署上限里/,
  )
  assert.deepEqual(h.calls.restrict, [], '抛错时不应施加任何 restrict')
  assert.equal(h.calls.activations.length, 0, '抛错时不应创建子代理')
})

test('模型没传 tools + 部署上限为空数组 ⇒ 子代理一个工具都拿不到', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults({ enforceMaxTools: true, maxTools: [] }))
  const value = await callDelegate(h, { description: '仅审查', prompt: 'x' })

  assert.deepEqual(value.tools, [])
  assert.deepEqual(h.calls.restrict, [{ allow: [] }])
})

test('只传 prompt 时不施加任何策略（保持与官方 subagent 一致的默认行为）', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const value = await callDelegate(h, { description: '看看', prompt: 'x' })

  assert.equal(value.tools, undefined)
  assert.equal(value.personaApplied, false)
  assert.deepEqual(h.calls.restrict, [])
  assert.deepEqual(h.calls.sections, [])
})

// ---- fail-closed -----------------------------------------------------------

test('子代理没消费到策略 ⇒ 取消它并抛错', async () => {
  const h = makeHarness({ emitCreated: false })
  apply(h.ctx, withDefaults())

  await assert.rejects(
    () => callDelegate(h, { description: '审查', prompt: 'x', tools: ['read'] }),
    /fail-closed/,
  )
  assert.equal(h.calls.cancelled.length, 1)
  // 契约：cancel(cause) 只接受 AgentCancelCause 对象（{kind: user|parent|disposed|hook}）。
  // 2026-10-29 事故：这里曾传裸字符串 'delegation-policy-unbound'，abort reason 遂不是对象，
  // DSH 的 abortedCancelCause 在 turn() 的 catch 内抛错，使 turnEnds 停在 null，
  // finally 写出 turn/end{reason:null}，此后每次加载该会话都在投影层 fatal。
  // 见 docs/incidents/2026-10-29-cancel-cause-fatal.md
  const cause = h.calls.cancelled[0].cause
  assert.ok(
    cause !== null && typeof cause === 'object',
    `cancel 必须收到 cause 对象，实际收到：${typeof cause} ${String(cause)}`,
  )
  assert.deepEqual(cause, { kind: 'disposed' })
  assert.ok(
    ['user', 'parent', 'disposed', 'hook'].includes(cause.kind),
    `cause.kind 超出 AgentCancelCause 联合：${String(cause.kind)}`,
  )
})

test('restrict 抛错 ⇒ 认领被判失败 ⇒ 取消子代理', async () => {
  const h = makeHarness({ restrictThrows: true })
  apply(h.ctx, withDefaults())

  await assert.rejects(
    () => callDelegate(h, { description: '审查', prompt: 'x', tools: ['read'] }),
    /fail-closed/,
  )
  assert.equal(h.calls.cancelled.length, 1)
})

test('provider 不存在 ⇒ 在创建前就抛错', async () => {
  const h = makeHarness({ providerExists: false })
  apply(h.ctx, withDefaults())

  await assert.rejects(
    () => callDelegate(h, { description: '审查', prompt: 'x' }),
    /找不到子代理 backend/,
  )
  assert.equal(h.calls.cancelled.length, 0)
})

test('创建失败时不会把策略留在队列里污染下一次委派', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const tool = h.getTool()

  // 第一次：让 startActivation 抛错
  const original = h.ctx.subagents.startActivation
  h.ctx.subagents.startActivation = async () => {
    throw new Error('boom')
  }
  await assert.rejects(() => callDelegate(h, { description: 'a', prompt: 'x', tools: ['read'] }))

  // 第二次：恢复正常，策略必须干净地绑定
  h.ctx.subagents.startActivation = original
  const value = await callDelegate(h, { description: 'b', prompt: 'y', tools: ['grep'] })
  assert.deepEqual(value.tools, ['grep'])
  assert.deepEqual(h.calls.restrict, [{ allow: ['grep'] }])
})

// F3（red-3c）：`agent/created` 从未触发时，被拒的那次委派不能把策略留在队列里。
// 红队的 D-3 探针只模拟了 pending 队列原语（没有 dropPending），据此判"该修"；
// 真实控制流在认领失败分支就 dropPending 了（lib/index.js:1253-1259），这条用例
// 把"原语行为"与"端到端行为"的差别钉死在回归里。
test('F3：认领失败（agent/created 未触发）后，策略不残留到下一次委派', async () => {
  const h = makeHarness({ emitCreated: false })
  apply(h.ctx, withDefaults())

  // 第一次：子代理已创建，但宿主没有派发 agent/created ⇒ 认领失败 ⇒ cancel + 抛错
  await assert.rejects(
    () => callDelegate(h, { description: 'a', prompt: 'x', tools: ['read'] }),
    /fail-closed/,
  )
  assert.equal(h.calls.cancelled.length, 1)

  // 第二次：宿主这次正常派发 created；新子代理必须拿到自己的工具面（grep），
  // 而不是上一次被拒时残留的 read。
  h.ctx.subagents.startActivation = async (spec) => {
    h.calls.activations.push(spec)
    await h.emitCreated()
    return { childId: 'child-1', messageId: 'msg-2', spec }
  }
  const value = await callDelegate(h, { description: 'b', prompt: 'y', tools: ['grep'] })
  assert.deepEqual(value.tools, ['grep'])
  assert.deepEqual(h.calls.restrict.at(-1), { allow: ['grep'] }, '不得复用到上一次残留的策略')
})

// 真机回归：`restrict()` 只管全局继承面，**scoped 注册的工具仍然可见**
// （`dsh-tools/lib/index.js:2985-2987`）。官方 `dsh-tool-subagent:605-607` 会在
// `agent/created` 里把 `subagent` / `list_subagent_models` 注册到子代理自己的 ctx，
// 它们因此绕过 restrict。必须有 agent-scoped guard 在执行期兜住，否则子代理能再
// 派一个不受本策略约束的孙代理。
test('传 tools 时同时注册 agent-scoped guard，拦住 restrict 管不到的 scoped 工具', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  await callDelegate(h, { description: '审查', prompt: 'x', tools: ['read'] })
  assert.equal(h.calls.guards.length, 1, '应注册一个 guard')

  const guard = h.calls.guards[0]
  assert.equal(guard({ name: 'read' }), undefined, '授权工具放行')
  const denied = guard({ name: 'subagent' })
  assert.match(denied, /subagent/)
  assert.match(denied, /不在该子代理的授权工具面内/)
  assert.match(guard({ name: 'pwsh' }), /不在该子代理的授权工具面内/)
})

test('不传 tools 时不注册 guard（继承父面，没有可拦的集合）', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  await callDelegate(h, { description: '审查', prompt: 'x' })
  assert.equal(h.calls.guards.length, 0)
  assert.deepEqual(h.calls.restrict, [])
})

test('maxTools 收窄成空集合时 guard 拒绝业务工具，但放行 scoped 的 harness 工具', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  await callDelegate(h, { description: '只读', prompt: 'x', tools: ['read'] })
  const guard = h.calls.guards[0]
  assert.equal(guard({ name: 'read' }), undefined)

  const h2 = makeHarness()
  apply(h2.ctx, withDefaults())
  const value = await callDelegate(h2, { description: '无工具', prompt: 'x', tools: [] })
  assert.deepEqual(value.tools, [])
  // `restrict()` 管不到 scoped 注册，`list_subagent_models` 始终可见，guard 放行它。
  // 真机实测（2026-10-29，0.2.1-rc.2）：子代理**没有**注册 `task_begin` / `task_end`，
  // 所以它们不再豁免 —— 否则拒绝消息会把两个幽灵工具说成"可用"。
  assert.match(h2.calls.guards[0]({ name: 'read' }), /可用工具：list_subagent_models$/)
  assert.equal(h2.calls.guards[0]({ name: 'list_subagent_models' }), undefined)
  assert.match(h2.calls.guards[0]({ name: 'task_begin' }), /不在该子代理的授权工具面内/)
  // 派生通道不受豁免。
  assert.match(h2.calls.guards[0]({ name: 'subagent' }), /不在该子代理的授权工具面内/)
})

// ---- 非法配置 --------------------------------------------------------------

test('非法 sectionOrder 在加载期抛错', () => {
  const h = makeHarness()
  assert.throws(() => apply(h.ctx, withDefaults({ sectionOrder: -1 })), /sectionOrder/)
})

test('enforceMaxTools 开启但 maxTools 不是数组 ⇒ 加载期抛错', () => {
  const h = makeHarness()
  assert.throws(() => apply(h.ctx, withDefaults({ enforceMaxTools: true, maxTools: 'read' })), /字符串数组/)
})

// 真机回归：in-process 后端注册的 provider 名是 `spawn`
// （`dsh-subagent-spawn-in-process/lib/index.js:12` `providerName.default("spawn")`），
// 不是包名 `subagent-spawn-in-process`。写错就是「找不到子代理 backend」。
test('默认 provider 是 spawn（包名不是 provider 名）', () => {
  assert.equal(Config().provider, 'spawn')
})

// ---- 参数方言转换 ----------------------------------------------------------

test('parametersToJsonSchema 把 required 从字段里提出来', () => {
  const schema = parametersToJsonSchema({
    a: { type: 'string', required: true, description: 'x' },
    b: { type: 'array', items: { type: 'string' } },
  })
  assert.deepEqual(schema.required, ['a'])
  assert.equal(schema.properties.b.type, 'array')
  assert.equal(schema.additionalProperties, false)
})

test('Config 是有默认值的 Schemastery 对象', () => {
  const resolved = Config(withDefaults())
  assert.equal(resolved.toolName, 'delegate')
  assert.equal(resolved.enforceMaxTools, false)
  assert.equal(resolved.serializeBind, true)
})

// ---- 并发派发不串号 --------------------------------------------------------

/**
 * 造一个能模拟「多个子代理、创建耗时可不同」的假宿主。
 * 策略按父会话 FIFO 认领，所以这正是串号风险的形状。
 * @param {number[]} delays 第 n 次 startActivation 的耗时（ms）
 */
function makeConcurrentHarness(delays) {
  const created = []
  const restricts = []
  let seq = 0
  let toolDef

  const ctx = {
    logger: () => ({ info() {}, warn() {}, error() {} }),
    on(name, handler) {
      if (name === 'agent/created') created.push(handler)
      return () => {}
    },
    effect: (fn) => fn(),
    /** 依赖已就绪的语义：同步执行回调。 */
    inject(_deps, callback) {
      callback(ctx)
      return { dispose() {} }
    },
    get(serviceName) {
      return serviceName === 'subagents' ? this.subagents : undefined
    },
    tools: {
      register(d) { toolDef = d; return () => {} },
      guard() { return () => {} },
    },
    subagents: {
      getProvider: () => ({ name: 'spawn' }),
      async startActivation() {
        const index = seq++
        const delay = delays[index] ?? 0
        if (delay > 0) await new Promise((resolve) => setTimeout(resolve, delay))
        const childId = `child-${index}`
        const childCtx = {
          tools: {
            restrict(filter) {
              restricts.push({ childId, allow: [...filter.allow] })
              return () => {}
            },
            guard() { return () => {} },
          },
          systemPrompt: { section() { return () => {} } },
        }
        const agent = {
          sessionId: childId,
          session: { id: childId, header: { parentSession: 'parent-1' } },
          ctx: childCtx,
        }
        for (const handler of created) await handler({ agent, source: 'subagent' })
        return { childId }
      },
    },
  }

  return { ctx, restricts, getTool: () => toolDef }
}

test('serializeBind 保证并发派发时策略与子代理一一对应', async () => {
  // 第一次创建很慢（20ms），第二次瞬时。不串行化的话，第二个子代理会先出生
  // 并领走第一个调用的策略，形成「把读权限给了本该写的人」的串号。
  const h = makeConcurrentHarness([20, 0])
  apply(h.ctx, withDefaults())
  const tool = h.getTool()
  const parent = { sessionId: 'parent-1', session: { id: 'parent-1' } }
  const call = (args) =>
    tool.execute(args, { agent: parent, signal: new AbortController().signal })

  await Promise.all([
    call({ description: '读任务', prompt: 'a', tools: ['read'] }),
    call({ description: '写任务', prompt: 'b', tools: ['write'] }),
  ])

  assert.equal(h.restricts.length, 2)
  // 第一个调用 → child-0 → read；第二个调用 → child-1 → write
  assert.deepEqual(h.restricts[0], { childId: 'child-0', allow: ['read'] })
  assert.deepEqual(h.restricts[1], { childId: 'child-1', allow: ['write'] })
})

test('F2（red-3c）：serializeBind:false 不再跳过串行闸，策略仍一一对应', async () => {
  // 0.4.6 及以前：false ⇒ 不进 bindMutex。第二个子代理先出生就会领走第一个调用
  // 的策略（把「读」的面给了本该写的人）。现在 false 只发一次告警，绑定一律串行。
  const h = makeConcurrentHarness([20, 0])
  apply(h.ctx, withDefaults({ serializeBind: false }))
  const tool = h.getTool()
  const parent = { sessionId: 'parent-1', session: { id: 'parent-1' } }
  const call = (args) =>
    tool.execute(args, { agent: parent, signal: new AbortController().signal })

  await Promise.all([
    call({ description: '读任务', prompt: 'a', tools: ['read'] }),
    call({ description: '写任务', prompt: 'b', tools: ['write'] }),
  ])

  assert.equal(h.restricts.length, 2)
  assert.deepEqual(h.restricts[0], { childId: 'child-0', allow: ['read'] })
  assert.deepEqual(h.restricts[1], { childId: 'child-1', allow: ['write'] })
})

test('createMutex 按提交顺序执行，且前一个失败不影响后一个', async () => {
  const order = []
  const mutex = createMutex()
  const slow = mutex.run(async () => {
    await new Promise((r) => setTimeout(r, 15))
    order.push('slow')
    throw new Error('boom')
  })
  const fast = mutex.run(async () => {
    order.push('fast')
    return 'ok'
  })

  await assert.rejects(slow, /boom/)
  assert.equal(await fast, 'ok')
  // 即使 slow 更慢且抛错，fast 也必须排在它后面
  assert.deepEqual(order, ['slow', 'fast'])
})

// 真机回归（2026-10-29）：`send_message` 唤醒一个 idle 子代理会走 cold resume，
// 子代理的 ctx 被重建，挂在它上面的 `restrict()` 与 scoped `guard()` 全部消失。
// 实测后果：一个只被授权 read/glob/grep 的子代理，被唤醒后工具面恢复成全量，
// 并成功调 `subagent` 派出了孙代理（会话 794cebdb，depth=2，确实存在）。
// 兜底：插件 ctx 上的全局 guard 按 sessionId 查授权表，冷恢复后依然生效。
test('冷恢复后 scoped 注册消失，插件 ctx 上的全局兜底仍然拦住越权工具', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const value = await callDelegate(h, {
    description: '只读',
    prompt: 'x',
    tools: ['read'],
  })

  // 闸二的黑名单 guard 也注册在插件 ctx 上，所以按"它是否拦 subagent"来认人，
  // 不按数组下标 —— 下标会随闸二是否启用、注册顺序变化而漂移。
  const bail = h.calls.globalGuards.find((fn) => {
    const verdict = fn({ name: 'subagent', agent: { sessionId: value.subagentId } })
    return typeof verdict === 'string' && verdict.includes('冷恢复兜底')
  })
  assert.ok(bail, '应当注册一条冷恢复兜底的全局 guard')

  // 父会话不在授权表里 ⇒ 完全不受影响。
  assert.equal(bail({ name: 'pwsh', agent: { sessionId: 'parent-1' } }), undefined)
  // 没有 sessionId 的调用（后台作业等）也不受影响。
  assert.equal(bail({ name: 'pwsh', agent: undefined }), undefined)
  // 授权内的工具冷恢复后仍放行。
  assert.equal(bail({ name: 'read', agent: { sessionId: value.subagentId } }), undefined)
  assert.equal(
    bail({ name: 'list_subagent_models', agent: { sessionId: value.subagentId } }),
    undefined,
  )
  // 越权工具：即使 scoped guard 已经不在了，这一层仍然拒绝。
  const denied = bail({ name: 'subagent', agent: { sessionId: value.subagentId } })
  assert.match(denied, /冷恢复兜底/)
  assert.match(denied, /不在该子代理的授权工具面内/)
})

// 2026-10-29 真机事故（fold #58）：白名单里混进 dsh-ling 的 `recall` / `tree_read` /
// `library_search`。它们由 agent-scoped 注册，不在 `restrict()` 认识的
// `restrictableNames` 里，于是 `restrict({ allow: [...92 项] })` 整单抛错
// `names unknown global tools ...`，每一次 delegate 都 fail-closed——而测试台
// 的 profile 没有 dsh-ling，同一条白名单在那边全部命中，永远复现不了。
test('白名单含 scoped 注册的工具名时降级收窄，而不是整单 fail-closed', async () => {
  const h = makeHarness({ restrictUnknown: ['recall', 'tree_read'] })
  apply(h.ctx, withDefaults())

  const value = await callDelegate(h, {
    description: '读记忆',
    prompt: 'x',
    tools: ['read', 'recall', 'tree_read'],
  })

  // 委派成功：不再因为一个名字不认识就整单失败。
  assert.equal(typeof value.subagentId, 'string')
  assert.deepEqual(value.tools, ['read', 'recall', 'tree_read'])

  // restrict 最终只拿到全局可收窄的那部分（第一次抛错不算落地）。
  assert.equal(h.calls.restrict.length, 1)
  assert.deepEqual(h.calls.restrict[0].allow, ['read'])

  // 被剔出 restrict 的两个名字仍然由 scoped guard 放行 —— 它们是真实存在的
  // scoped 工具，不能因为 restrict 不认就把它们拒掉。
  const scopedGuard = h.calls.guards[0]
  assert.equal(scopedGuard({ name: 'recall' }), undefined)
  assert.equal(scopedGuard({ name: 'tree_read' }), undefined)
  // 授权外的工具照旧被拒。
  assert.match(scopedGuard({ name: 'pwsh' }), /不在该子代理的授权工具面内/)
})

// 反面：restrict 抛的不是「名字不认识」时，仍然必须 fail-closed（不能把真失败
// 降级成静默放行）。
test('restrict 抛非命名类错误时仍然 fail-closed', async () => {
  const h = makeHarness({ restrictThrows: true })
  apply(h.ctx, withDefaults())

  await assert.rejects(
    () => callDelegate(h, { description: '只读', prompt: 'x', tools: ['read'] }),
    /未能绑定工具面与 prompt.*fail-closed/,
  )
})

// ---- F-B：冷恢复重建 -------------------------------------------------------
// 2026-10-31 真机狂测：宿主重启后 `send_message` 唤醒的子代理，`pinned` 随进程
// 消失 → 工具面从 1 个回到 26 个，子代理真的用 `pwsh` 写出了文件。
// DSH 不允许第三方新增事件类型（会让整条会话打不开），也没有别的写入点，
// 所以从既有事件推导：`system/message` 里的固定段落 + 最早 `request/header`。

/**
 * 造一个「宿主重启后被唤醒」的子代理：只剩会话日志与新的 ctx。
 *
 * `sectionFace`：本插件写进 system prompt 的「可用工具」名单（`null` = 旧日志，
 * 只有固定段落没有这一行）；`headerFace`：模型可见面的工具清单（`null` = 没有请求头）。
 * @param {{ note?: boolean, sectionFace?: string[] | null, headerFace?: string[] | null, sid?: string }} opts
 */
function makeColdAgent({
  note = true,
  sectionFace = ['read'],
  headerFace = ['read'],
  sid = 'child-cold-1',
} = {}) {
  const calls = { restrict: [], guards: [], sections: [] }
  const log = []
  if (note) {
    const lines = []
    if (sectionFace !== null) {
      const list = sectionFace.length === 0 ? '（无可用工具）' : sectionFace.join(', ')
      lines.push(
        `可用工具：${list}。你没有其他工具；需要超出范围的操作用文字说明交回父会话。`,
      )
      lines.push('')
    }
    lines.push(ABSENT_CHANNELS_NOTE)
    log.push({
      type: 'system/message',
      seq: 8,
      data: {
        message: {
          content: [{ type: 'text', text: lines.join('\n') }],
        },
      },
    })
  }
  if (headerFace !== null) {
    log.push({
      type: 'request/header',
      seq: 11,
      data: { header: { tools: headerFace.map((name) => ({ name })) } },
    })
  }
  const agent = {
    sessionId: sid,
    session: { id: sid, header: { id: sid, parentSession: 'parent-1' }, log },
    ctx: {
      tools: {
        restrict(filter) {
          calls.restrict.push(filter)
          return () => {}
        },
        guard(fn) {
          calls.guards.push(fn)
          return () => {}
        },
      },
      systemPrompt: {
        section(section) {
          calls.sections.push(section)
          return () => {}
        },
      },
    },
  }
  return { agent, calls }
}

test('F-B：冷恢复时按会话日志重建工具面并重新收窄', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({ sectionFace: ['read', 'glob'], headerFace: ['read', 'glob'] })

  h.emitCreated(agent)

  assert.equal(calls.restrict.length, 1, '必须重新施加 restrict')
  assert.deepEqual(calls.restrict[0].allow, ['read', 'glob'])
  assert.equal(calls.sections.length, 1, '必须重新注册 prompt 段落')
  assert.match(calls.sections[0].text, /可用工具：read, glob/)

  // 续命层的全局 guard 现在认得这个会话：按记录放行/拒绝。
  const fallback = h.calls.globalGuards.at(-1)
  assert.equal(fallback({ agent, name: 'read' }), undefined)
  assert.match(fallback({ agent, name: 'pwsh' }), /不在该子代理的授权工具面内/)
})

// R1-01（2026-10-31 对抗审计，🔴 阻断）：v0.4.3 把 `request/header.tools` 当授权面，
// 而官方 `dsh-tool-subagent` 会把 `subagent` 以 scoped 方式装进子代理，它绕开
// `restrict()`、直接出现在 header 里。冷恢复若照抄 header，`pinned` 就放行
// `subagent`，被钉死的子代理能再派生不受约束的孙代理。
test('R1-01：冷恢复只认本插件写的「可用工具」行，不把 scoped 的 subagent 当授权面', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({
    sectionFace: ['read'],
    headerFace: ['read', 'subagent', 'subagent_fork', 'pwsh'],
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, ['read'], '授权面必须来自说明段落')
  const fallback = h.calls.globalGuards.at(-1)
  assert.equal(fallback({ agent, name: 'read' }), undefined)
  assert.match(fallback({ agent, name: 'subagent' }), /不在该子代理的授权工具面内/)
  assert.match(fallback({ agent, name: 'subagent_fork' }), /不在该子代理的授权工具面内/)
})

test('R1-01：旧日志没有「可用工具」行时退回请求头，并剔除 scoped 派生工具', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({
    sectionFace: null,
    headerFace: ['read', 'glob', 'subagent', 'pwsh'],
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, ['read', 'glob', 'pwsh'])
  const fallback = h.calls.globalGuards.at(-1)
  assert.match(fallback({ agent, name: 'subagent' }), /不在该子代理的授权工具面内/)
})

test('F1（red-3c）：有段落但无请求头时，段落里的派生通道也不能进授权面', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  // `headerFace: null` = 日志里没有请求头可对照，只剩段落面。
  const { agent, calls } = makeColdAgent({
    sectionFace: ['read', 'subagent', 'subagent_fork'],
    headerFace: null,
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, ['read'], '派生通道必须被剔除')
  const fallback = h.calls.globalGuards.at(-1)
  assert.match(fallback({ agent, name: 'subagent' }), /不在该子代理的授权工具面内/)
  assert.match(fallback({ agent, name: 'subagent_fork' }), /不在该子代理的授权工具面内/)
})

test('F-B：不是本插件派的子代理（日志里没有段落）不恢复', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({ note: false, headerFace: ['pwsh'] })

  h.emitCreated(agent)

  assert.equal(calls.restrict.length, 0)
  assert.equal(calls.sections.length, 0)
  // 没有被 pin 的会话不受续命层影响。
  const fallback = h.calls.globalGuards.at(-1)
  assert.equal(fallback({ agent, name: 'pwsh' }), undefined)
})

// F8 / R2-X1（2026-10-31 对抗审计）：这段防串号检查原先写在「没有命令参数就返回」
// 之后 —— 官方 `subagent` 的参数里没有命令字段，所以它**从未执行过**；而且判据是
// 全局 `pending.size > 0`，一旦生效又会误伤别的会话。现在挪到判空之前，并按调用方
// 自己的会话 id 判。
test('F8：同一父会话的委派窗口内拒绝官方 subagent，其他会话不受影响', async () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults({ denyPatterns: ['\\bvssadmin\\b'] }))
  // 让这次委派卡在 pending 里（窗口不关闭）。
  h.ctx.subagents.startActivation = () => new Promise(() => {})
  void callDelegate(h, { description: 'hang', prompt: 'hang' })
  await Promise.resolve()
  await Promise.resolve()

  const gate2 = h.calls.globalGuards.find(
    (fn) => typeof fn({ name: 'pwsh', arguments: { command: 'vssadmin delete shadows' } }) === 'string',
  )
  assert.ok(gate2 !== undefined, '必须能找到闸二的 guard')

  const otherSession = { sessionId: 'parent-2', session: { id: 'parent-2' } }
  assert.equal(
    gate2({ name: 'subagent', arguments: { prompt: 'x' }, agent: otherSession }),
    undefined,
    '别的会话在委派窗口内不该被误伤',
  )
  const denied = gate2({ name: 'subagent', arguments: { prompt: 'x' }, agent: h.parent })
  assert.match(String(denied), /委派正在进行/)
})

// R1-02（2026-10-31 对抗审计）：`provider: 'fork'` 会把父会话的历史请求头带进子会话，
// 那种 header 早于段落、带的是父面；只有段落之后的请求头才可能是本子代理的。
test('R1-02：段落之前的请求头（fork 继承的父面）不作为授权面', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({ sectionFace: null, headerFace: null })
  agent.session.log.unshift({
    type: 'request/header',
    seq: 1,
    data: { header: { tools: [{ name: 'pwsh' }, { name: 'write' }] } },
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, [], '早于段落的 header 不可信 → 空面 fail-closed')
})

// 追加发现 A（2026-10-31 对抗审计，blue-1）：`enableDelegateTool: false` 的 early return
// 原来把 `agent/created` 的恢复监听也一起跳过，冷恢复兜底整条消失（fail-open）。
test('追加A：enableDelegateTool=false 仍注册冷恢复监听', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults({ enableDelegateTool: false, subagentSandboxCap: 'inherit' }))
  const { agent, calls } = makeColdAgent({
    sectionFace: ['read'],
    headerFace: ['read', 'subagent'],
  })

  h.emitCreated(agent)

  assert.equal(calls.restrict.length, 1, '关掉 delegate 工具不等于关掉恢复')
  assert.deepEqual(calls.restrict[0].allow, ['read'])
  const fallback = h.calls.globalGuards.at(-1)
  assert.match(fallback({ agent, name: 'subagent' }), /不在该子代理的授权工具面内/)
})

test('F-B：日志有段落却没有请求头时按空工具面 fail-closed', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  // 旧日志：只有固定段落，既没有「可用工具」行也没有请求头 ⇒ 面完全未知。
  const { agent, calls } = makeColdAgent({ sectionFace: null, headerFace: null })

  h.emitCreated(agent)

  assert.equal(calls.restrict.length, 1)
  assert.deepEqual(calls.restrict[0].allow, [], '授权面未知时按一个工具都不给处理')
  const fallback = h.calls.globalGuards.at(-1)
  assert.match(fallback({ agent, name: 'read' }), /不在该子代理的授权工具面内/)
})

// C1（2026-10-31 异质红队 sonnet F-R1）：`system/message` 是全部 system prompt
// 段落的拼接，本插件段落（order 120）之后还有 order 1000+ 的宿主段落。旧实现
// 取**最后一条**「可用工具：」匹配，后面的段落文本可以把它顶掉。
test('C1：修复段落之后出现的同名文本不能顶掉授权面', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({ note: false, headerFace: ['read'] })
  agent.session.log.unshift({
    type: 'system/message',
    seq: 7,
    data: {
      message: {
        content: [
          {
            type: 'text',
            text: [
              '可用工具：read。你没有其他工具；需要超出范围的操作用文字说明交回父会话。',
              '',
              ABSENT_CHANNELS_NOTE,
              '',
              '可用工具：pwsh, write, subagent。你没有其他工具；需要超出范围的操作用文字说明交回父会话。',
            ].join('\n'),
          },
        ],
      },
    },
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, ['read'], '锚点之后的文本不能参与解析')
})

// C1 后半：段落与请求头取交集 —— 任一来源说不许就不许。旧实现只认段落，
// header 里没有的名字也被恢复出来（宽于模型当时真实可见的面）。
test('C1：授权面取「段落 ∩ 请求头」，任一来源说不许就不许', () => {
  const h = makeHarness()
  apply(h.ctx, withDefaults())
  const { agent, calls } = makeColdAgent({
    sectionFace: ['read', 'glob'],
    headerFace: ['read', 'pwsh', 'subagent'],
  })

  h.emitCreated(agent)

  assert.deepEqual(calls.restrict[0].allow, ['read'])
})

// T1（2026-10-31 异质红队 opus，同 sonnet F-R3）：`pinned.set(String(childSid))`
// 拿到 undefined 时会写进字面量 "undefined" 键，兜底层等于没兜。必须显式判类型，
// 拿不到 id 就 fail-closed，不能假装绑定成功。
test('T1：拿不到会话 id 的子代理不登记 pinned，绑定必须 fail-closed', async () => {
  const nameless = {
    session: { header: { parentSession: 'parent-1' }, log: [] },
    ctx: {
      tools: {
        restrict() {
          return () => {}
        },
        guard() {
          return () => {}
        },
      },
      systemPrompt: {
        section() {
          return () => {}
        },
      },
    },
  }
  const h = makeHarness({ childOverride: nameless })
  apply(h.ctx, withDefaults())

  const error = await callDelegate(h, { description: 'x', prompt: 'y', tools: ['read'] }).then(
    () => undefined,
    (err) => err,
  )
  assert.ok(error, '绑定失败必须 fail-closed，而不是假装成功')
  assert.match(String(error.message), /原因=sidOf/)
})
