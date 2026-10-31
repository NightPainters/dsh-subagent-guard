/**
 * dsh-subagent-guard — 子代理的三道闸（权限 / 命令 / 工具面与 prompt）
 *
 * 一个插件管住三件事，因为它们防的是同一类事故：**子代理在没有全局观的情况下
 * 拿到过多能力**。分开装会漏——2026-10-28 实测过，只装工具面那一层时，子代理
 * 可以通过官方 scoped 的 `subagent` 工具派出一个完全不受约束的孙代理。
 *
 * ## 闸一：沙箱档位硬顶
 *
 * DSH 创建子代理时捕获父会话的权限快照（`captureDelegatedPolicyOverrides`）：
 * approval 恒为 `never`、沙箱只继承父会话的显式 override。父会话是
 * `danger-full-access` 时子代理同档且不套沙箱——这就是 2026-10-18 批量删除
 * 卷影副本那类事故的形状。闸一在 `agent/created` 里把档位压到配置上限，只降不升。
 *
 * ## 闸二：破坏性命令黑名单
 *
 * `ctx.tools.guard()` 是单调门——在 `tools/pre-execute` 瀑布之后**强制**运行
 * （`@deepseek-ai/dsh-tools/lib/index.js:3337`），返回字符串即拒绝，任何插件都
 * 无法再放行。按**参数形状**识别命令类工具（不看工具名），所以第三方 shell
 * （`win_bash` 之类）自动纳入。
 *
 * ## 闸三：委派策略（工具面 + prompt）
 *
 * DSH 0.2 关闭了 `persona` / `toolFilter` 两个参数
 * （`dsh-tool-subagent/lib/index.js:355` 明文拒绝），但官方自己的冷恢复路径仍在
 * 用这两个能力（`dsh-subagent/lib/types/child-agent.js:153-167`）：
 *
 *     childCtx.systemPrompt.section(...)   // 遮同名段落
 *     childCtx.tools.restrict(...)         // 移除继承面工具
 *
 * 闸三把这条路接回**新派发**：自己开 `delegate` 工具 → 先登记策略 → 调
 * `subagents.startActivation` → 在 `agent/created` 里按父会话精确认领并施加。
 *
 * 认领是精确的：策略只属于「登记它的那个父会话」，并在 `startActivation` 返回
 * 后核对子代理确实消费了它；没消费就取消这个子代理（fail-closed）。
 *
 * 两道工具面措施必须同时存在：
 * - `restrict()` 管**可见面**，但只作用于全局继承面
 *   （`dsh-tools/lib/index.js:2985-2987`："scoped registrations remain visible"）；
 * - 官方 `dsh-tool-subagent:605-607` 会在 `agent/created` 里 `installScoped()`
 *   把 `subagent` / `list_subagent_models` 注册到子代理自己的 ctx 上，绕过 restrict；
 * - 所以再加一层 agent-scoped `guard()`，在执行期拦住一切未授权的工具调用。
 *
 * 三道闸都只走公开扩展点，不碰内核。
 */
import { readFileSync, statSync } from 'node:fs'
import { isAbsolute, resolve as resolvePath } from 'node:path'

import Schema from '@deepseek-ai/schemastery'
import {
  DEFAULT_DENY_PATTERNS,
  DENY_SCOPES,
  SANDBOX_CAPS,
  commandOf,
  compileRules,
  delegationDepthOf,
  isKnownSandboxMode,
  matchCommand,
  scriptPathOf,
  scriptPathsOf,
  setSessionSandboxMode,
  shouldCapSandbox,
  skipByScope,
} from './rules.js'
import {
  ABSENT_CHANNELS_NOTE,
  DEFAULT_SECTION_ORDER,
  buildPolicy,
  dropPending,
  normalizeCap,
  pushPending,
  renderSection,
  takePending,
} from './policy.js'

export const name = 'dsh-subagent-guard'

/**
 * 只声明 `tools`。
 *
 * 2026-10-28 审计的 F11：原先把 `sandboxPolicy` 也写进 inject——它缺失时
 * cordis 会把整个插件置 `INACTIVE`，**连闸二（命令黑名单）一起消失**，而
 * `--dump-config` 里那行照样在。这与"`subagents` 故意不写进 inject"是同一个
 * 理由，当时没有用到它自己身上。现在两个可选服务都走 `ctx.get()`：
 * 缺 `sandboxPolicy` ⇒ 闸一降级（读不到档位就按最宽处理，压到 cap）；
 * 缺 `subagents` ⇒ 只有闸三不注册。
 */
export const inject = ['tools']

export const Config = Schema.object({
  /** 总开关。关掉后三道闸都不生效。 */
  enabled: Schema.boolean().default(true),

  // ---- 闸一：沙箱档位硬顶 --------------------------------------------------
  /** 子代理的沙箱档位硬顶；`inherit` 表示不干预。 */
  subagentSandboxCap: Schema.string().default('workspace-write'),

  // ---- 闸二：命令黑名单 ----------------------------------------------------
  /**
   * 携带命令文本的参数名。闸二按**参数形状**识别命令类工具：
   * 任何工具的参数里有这个字段，都会被纳入检查，与它注册叫什么名字无关。
   */
  commandArg: Schema.string().default('command'),
  /**
   * 额外纳入的工具名。**不是全集，也不参与识别**——命令类工具一律按
   * `commandArg` 的参数形状自动识别。这一项只用于启动期提示「配置与工具对不上」
   * （例如列出 `bash` 但它的参数里没有 `command`）。2026-10-28 审计 F7 指出
   * 早先的注释让人以为它参与识别，实际只用于告警。
   */
  shellTools: Schema.array(Schema.string()).default(['bash', 'pwsh', 'win_bash']),
  /** 命令黑名单（正则源串）。空数组 = 不拦任何命令。 */
  denyPatterns: Schema.array(Schema.string()).default([...DEFAULT_DENY_PATTERNS]),
  /** `all` = 父会话与子代理都拦；`subagent` = 只拦子代理。 */
  denyScope: Schema.string().default('subagent'),
  /** 是否对 `pwsh -File x.ps1` 这类间接执行读取脚本内容再检查一遍。 */
  scriptInspection: Schema.boolean().default(true),
  /** 脚本内容检查的体积上限（字节）。超过就没法检查内容，按拒绝执行处理。 */
  maxScriptBytes: Schema.number().default(262144),

  // ---- 闸三：委派策略（工具面 + prompt）------------------------------------
  /** 是否注册 `delegate` 工具（闸三的入口）。关掉后闸一、闸二照常工作。 */
  enableDelegateTool: Schema.boolean().default(true),
  /** 委派工具名。 */
  toolName: Schema.string().default('delegate'),
  /** 使用的子代理 backend；空字符串 = 让宿主自己选。 */
  provider: Schema.string().default('spawn'),
  /** 是否启用部署级工具上限。 */
  enforceMaxTools: Schema.boolean().default(false),
  /** 部署级上限：子代理最终工具面永远不超过这个集合。空数组 = 一个工具都不给。 */
  maxTools: Schema.array(Schema.string()).default([]),
  /** persona 段落在 system prompt 里的排序位置。 */
  sectionOrder: Schema.number().default(DEFAULT_SECTION_ORDER),
  /** 段落名。同名段落会遮蔽全局同名段落，所以取一个不会撞的名字。 */
  sectionName: Schema.string().default('subagent-guard:persona'),
  /**
   * 是否把「登记策略 → 创建子代理 → 核对认领」这一整段串行化。
   *
   * 官方允许子代理并行派发（`maxActiveSubagents` 默认 50），而策略是按父会话
   * FIFO 认领的：若两次 `delegate` 交错执行，先创建出来的子代理可能领到另一个
   * 调用的策略 —— 那正是本插件要防的事。串行化用极小的延迟保证一一对应。
   */
  serializeBind: Schema.boolean().default(true),
})

/**
 * 判断一次调用属于哪个 delegation 深度。`delegationDepthOf` 是官方口径
 * （会话头为权威、运行时 options 只能加深）；它抛错时按「是子代理」处理，
 * 让 `denyScope: 'subagent'` 在判不清身份时 fail-closed。
 * @param {unknown} agent
 * @returns {number}
 */
export function depthOf(agent) {
  try {
    return delegationDepthOf(/** @type {any} */ (agent))
  } catch {
    return 1
  }
}

/**
 * 闸一的兜底：把会话压到最严档位。
 *
 * `agent/created` 是**创建之后**的事件，此时子代理已经在跑了，"拒绝创建"在
 * 这个扩展点上做不到（2026-10-24 审计报告的建议在这里技术上不成立）。能做
 * 的只有立即改档位，所以 fail-closed 的含义是"压到 `read-only`"，不是"拦下创建"。
 *
 * @param {any} session
 * @param {string} mode
 * @param {string} why
 * @param {{ error: (msg: string) => void }} logger
 * @returns {boolean} 是否写入成功
 */
/**
 * 取一个 Agent 的会话 id。
 *
 * **不要写 `agent.sessionId`。** `Agent` 对象上没有这个属性——实测键是
 * loopCtx, id, options, session, inbox, phase, activityDone, scope, ctx,
 * dispatch, requestHeaderLogged, requestSurfaceGeneration；会话 id 在
 * `agent.session.id` 上。
 *
 * 2026-10-29 的教训：`AgentRegistry.create` 的入参叫 `sessionId`，我照着这个
 * 名字去读 `agent.sessionId`，于是续命层拿到的 sid 恒为 undefined、`pinned`
 * 里存进一个字面量 "undefined" 键。scoped 那层（闭包里直接握着 allowed）照样
 * 工作，所以首轮限制看起来是好的；等 `send_message` 触发冷恢复、scoped 注册
 * 消失、只剩这层兜底时，兜底查不到键，于是全部放行。
 *
 * @param {unknown} agent
 * @returns {string | undefined}
 */
function sidOf(agent) {
  const a = /** @type {any} */ (agent)
  // 必须优先 `session.header.id`：官方写子代理的 `parentSession` 用的正是它
  // （`dsh-subagent/lib/index.js:354-359` → `parentSession: parentHeader.id`）。
  // 真机上 `session.id` 与 `session.header.id` **可以不同**（本次实测：前者指向
  // 当前活动文件、后者是持久会话 id），只认 `session.id` 会让认领键对不上，
  // 于是每次 delegate 都被 fail-closed（2026-10-29）。
  const viaHeader = a?.session?.header?.id
  if (typeof viaHeader === 'string') return viaHeader
  const viaSession = a?.session?.id
  if (typeof viaSession === 'string') return viaSession
  const viaId = a?.id
  if (typeof viaId === 'string') return viaId
  // 兜底：没有已知宿主版本会在 Agent 上放这个字段，留着只为让手工构造的
  // 探针/测试对象也能被认出来。真实宿主永远走上面三条。
  const legacy = a?.sessionId
  return typeof legacy === 'string' ? legacy : undefined
}

function hardCap(session, mode, why, logger) {
  try {
    setSessionSandboxMode(session, mode)
    // 文案只说"做了什么 + 为什么"，不预设调用方的原因——早先写成"档位无法读取"，
    // 一旦将来有别的调用点借用 hardCap，那句话就会变成假话（红队 F5）。
    logger.error(`已兜底把档位压到 ${mode}：${why}`)
    return true
  } catch (error) {
    logger.error(
      `子代理档位兜底失败（${why}）：${error?.message ?? error}——这个子代理的权限未被约束`,
    )
    return false
  }
}

/**
 * DSH 的参数字言 → JSON Schema。只覆盖本工具用到的形状。
 * @param {Record<string, any>} spec
 */
export function parametersToJsonSchema(spec) {
  const properties = {}
  const required = []
  for (const [key, raw] of Object.entries(spec)) {
    const { required: isRequired, ...rest } = raw
    properties[key] = rest
    if (isRequired === true) required.push(key)
  }
  return {
    type: 'object',
    properties,
    ...(required.length === 0 ? {} : { required }),
    additionalProperties: false,
  }
}

/**
 * 一个最小串行闸：把异步任务按提交顺序串起来，前一个失败不影响后一个。
 * @returns {{ run: <T>(task: () => Promise<T>) => Promise<T> }}
 */
export function createMutex() {
  let tail = Promise.resolve()
  return {
    run(task) {
      const result = tail.then(task, task)
      tail = result.then(
        () => undefined,
        () => undefined,
      )
      return result
    },
  }
}

/**
 * 拒绝文案。三段：命中什么、为什么拦、怎么改。
 * @param {string} what
 * @returns {string}
 */
function denyText(what) {
  return [
    `命令被 dsh-subagent-guard 拒绝：${what}。`,
    '这道闸按整条命令串做正则匹配，保护卷影副本、还原点、分区表、引导配置与宿主可用性。',
    '它防的是误触与惯性操作，**不是沙箱**：base64、变量拼接、多层包装都能绕（见 README 的 Known limits）。',
    '确实需要执行时请由人工操作，或修改 profile 里 dsh-subagent-guard 的 denyPatterns。',
  ].join('')
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {ReturnType<typeof Config>} config
 */
export function apply(ctx, config) {
  if (!SANDBOX_CAPS.includes(config.subagentSandboxCap)) {
    throw new Error(
      `dsh-subagent-guard: subagentSandboxCap 必须是 ${SANDBOX_CAPS.join(' | ')} 之一，收到 ${JSON.stringify(config.subagentSandboxCap)}`,
    )
  }
  if (!DENY_SCOPES.includes(config.denyScope)) {
    throw new Error(
      `dsh-subagent-guard: denyScope 必须是 ${DENY_SCOPES.join(' | ')} 之一，收到 ${JSON.stringify(config.denyScope)}`,
    )
  }
  if (!Number.isFinite(config.maxScriptBytes) || config.maxScriptBytes <= 0) {
    throw new Error(
      `dsh-subagent-guard: maxScriptBytes 必须是正数，收到 ${JSON.stringify(config.maxScriptBytes)}`,
    )
  }
  // 2026-10-28 审计 F9/F13：这几个字段只做形状校验，漏一个就会**静默关掉一道闸**。
  if (typeof config.commandArg === 'string' && config.commandArg.trim().length === 0) {
    throw new Error(
      'dsh-subagent-guard: commandArg 不能是空串——空串会让闸二找不到任何命令字段，等于静默关掉黑名单',
    )
  }
  if (Array.isArray(config.commandArg) && config.commandArg.length === 0) {
    throw new Error('dsh-subagent-guard: commandArg 数组不能为空')
  }
  if (typeof config.toolName !== 'string' || config.toolName.trim().length === 0) {
    throw new Error('dsh-subagent-guard: toolName 不能为空')
  }
  if (typeof config.sectionName !== 'string' || config.sectionName.trim().length === 0) {
    throw new Error('dsh-subagent-guard: sectionName 不能为空')
  }
  if (!Array.isArray(config.maxTools) || config.maxTools.some((n) => typeof n !== 'string')) {
    throw new Error('dsh-subagent-guard: maxTools 必须是字符串数组')
  }
  if (typeof config.provider !== 'string') {
    throw new Error(`dsh-subagent-guard: provider 必须是字符串，收到 ${JSON.stringify(config.provider)}`)
  }
  // F10：注释曾写"空字符串 = 让宿主自己选"，但 DSH 没有列举 backend 的 API，
  // 空值会在派发时抛 no provider。与其让它变成运行时错误，不如加载期就说清。
  if (config.enableDelegateTool && config.provider.trim().length === 0) {
    throw new Error(
      'dsh-subagent-guard: enableDelegateTool 为真时 provider 不能为空——DSH 没有「自动选 backend」的 API，空值会在派发时抛 no provider；请显式写，例如 "spawn"',
    )
  }
  if (!Number.isFinite(config.sectionOrder) || config.sectionOrder < 0) {
    throw new Error(
      `dsh-subagent-guard: sectionOrder 必须是非负数，收到 ${JSON.stringify(config.sectionOrder)}`,
    )
  }

  const rules = compileRules(config.denyPatterns)
  const logger = ctx.logger('subagent-guard')
  /**
   * 子会话 id → 已授权的工具面。
   *
   * 存在的唯一理由：**scoped 注册活不过冷恢复**。`childCtx.tools.restrict()` 与
   * `childCtx.tools.guard()` 都挂在子代理自己的 ctx 上，而 `send_message` 唤醒一个
   * idle 子代理走的是 cold resume（`dsh-subagent` 用 `agents.resume()` 重建 agent），
   * 两条注册随之消失。
   *
   * 2026-10-29 真机实测：一个被授权 `read/glob/grep` 的子代理，在被 `send_message`
   * 唤醒后工具面恢复成全量（约 90 个），并成功调 `subagent` 派出了一个孙代理。
   * 插件 ctx 上的全局 guard 用这张表兜底，register 一次、活到插件卸载。
   * @type {Map<string, Set<string>>}
   */
  const pinned = new Map()
  /**
   * 已尝试冷恢复的 agent 对象（同一次创建/恢复只施加一次）。
   *
   * 放在这里而不是恢复函数旁边：`enableDelegateTool: false` 时闸三整段会提前
   * return，而恢复监听属于闸二、必须照常注册（2026-10-31 对抗审计追加发现 A）。
   * @type {WeakSet<object>}
   */
  const restoredAgents = new WeakSet()
  const extraTools = new Set(config.shellTools)
  /**
   * 绕过 `tools.restrict()` 但仍应无条件放行的 scoped 工具。
   *
   * 官方 `dsh-tool-subagent` 会在子代理自己的 ctx 上 `installScoped()` 注册
   * `subagent` / `list_subagent_models`，它们不在全局可收窄面里。`subagent` 必须
   * 继续由 guard 拒绝（否则子代理能派一个不受策略约束的孙代理），
   * `list_subagent_models` 只读且无害，放行。详细推理见 `applyPolicy` 里的长注释。
   */
  const SAFE_SCOPED_TOOLS = new Set(['list_subagent_models'])
  /**
   * 由宿主动态 scoped 注册、**永远不属于授权面**的派生工具。
   *
   * 冷恢复只能退回 `request/header`（模型可见面）时，这两个名字会出现在里面却
   * 从未被 `delegate` 授权过；把它们当授权面会让被钉死的子代理再派生孙代理
   * （2026-10-31 对抗审计 R1-01，🔴 阻断）。
   */
  const DERIVED_SCOPED_TOOLS = new Set(['subagent', 'subagent_fork'])
  /** 每个提示键只输出一次，避免刷屏。 */
  const warned = new Set()

  /**
   * 父会话 id → 待认领的委派策略队列。
   *
   * 提到闸二之前定义，是因为闸二需要在"正在委派"的窗口里挡另一路委派（F8）。
   */
  const pending = new Map()

  const warnOnce = (key, message) => {
    if (warned.has(key)) return
    warned.add(key)
    logger.warn(message)
  }

  // 生效配置打一行：默认值不一致这类问题，运维一眼能看出来。
  logger.info(
    `生效配置：subagentSandboxCap=${config.subagentSandboxCap} denyScope=${config.denyScope} ` +
      `commandArg=${config.commandArg} 规则=${rules.length} 条 scriptInspection=${config.scriptInspection} ` +
      `delegateTool=${config.enableDelegateTool ? config.toolName : 'off'} ` +
      `maxTools=${config.enforceMaxTools ? config.maxTools.length : 'unbounded'}`,
  )
  if (rules.length === 0) {
    logger.warn('denyPatterns 为空：闸二不拦任何命令，只有闸一在起作用')
  }

  // ---- 冷恢复的前置条件（C2，2026-10-31 异质红队 sonnet F-R2）---------------
  // 整条冷恢复链只挂在 `agent/created` 上：宿主用 `agents.resume()` 重建 idle
  // 子代理时若不派发该事件，`pinned` 永不重建、兜底 guard 静默放行。第三方插件
  // 拿不到请求钩子，能做的最廉价探测是「宿主的 agents 服务有没有 resume()」：
  // 没有的版本根本不提供冷恢复路径。真正「派发不派发」只能靠真机验证（测试台
  // 已覆盖），其余作为前置条件写进 README。
  // 探测本身是尽力而为：单测里的 ctx 桩不需要实现 `inject`，真实 Cordis ctx 一定有。
  if (typeof /** @type {any} */ (ctx).inject === 'function') {
    ctx.inject(['agents'], (agentCtx) => {
      if (!config.enabled) return
      const service = /** @type {any} */ (agentCtx).get?.('agents')
      if (service !== undefined && typeof service.resume !== 'function') {
        warnOnce(
          'no-resume',
          'agents 服务没有 resume()：该宿主版本不支持冷恢复，本插件的冷恢复兜底不会触发' +
            '（被 send_message 唤醒的子代理会回到继承工具面）',
        )
      }
    })
  }

  // ---- 官方实现的可选比对（审计缺口 5）-------------------------------------
  // 插件**故意不静态 import** 兄弟 `dsh-*` 包（profile 里不一定有它们，
  // 静态 import 会让插件加载期就解析失败）。这里在后台尽力 resolve 一次，
  // 成功就拿来比对本地副本，不一致时报错——版本迁移导致的静默失配变成响亮告警。
  /** @type {((agent: unknown) => number) | undefined} */
  let officialDepthOf
  void import('@deepseek-ai/dsh-subagent')
    .then((mod) => {
      if (typeof mod?.delegationDepthOf === 'function') officialDepthOf = mod.delegationDepthOf
    })
    .catch((error) => {
      // 包不在是正常情况（profile 里通常没有它）；但**解析失败**意味着我们失去了
      // 与官方实现的交叉核对能力——2026-10-28 审计 F15：原来这里静默吞掉，
      // 于是"核对器本身失效"这件事永远不可见。报一次。
      warnOnce(
        'official-import',
        `无法加载官方 @deepseek-ai/dsh-subagent 做契约交叉核对（${error?.message ?? error}）——本地副本若与宿主失配将不会告警`,
      )
    })

  // ---- 闸一：子代理沙箱档位硬顶 ------------------------------------------
  // F11：`sandboxPolicy` 走可选获取，缺失时闸一降级而不是整个插件卸载。
  //
  // F-A（2026-10-31 真机狂测，🔴 安全方向是**放宽**）：这里**绝不能**在
  // `apply()` 里一次性 `ctx.get('sandboxPolicy')`。测试台探针实测：apply 执行时
  // `sandboxPolicy` / `subagents` / `sessionProjections` 全是 undefined，
  // `ctx.inject` 约 300ms 后才可见；于是旧实现拿到的快照恒为 undefined，
  // 闸一每次请求都走下面的 fail-closed 分支，把子代理**抬到** cap
  // （read-only 父 + workspace-write cap 时子代理写盘成功）。
  // 现在在事件内取服务：`agent/created` 触发时服务已经就绪（同一次探针实测
  // `sandboxPolicy=object`），只有事件时刻仍然缺失才降级。
  // 注：`sandboxPolicy` 服务消失后 Cordis 会重跑 apply，不需要在这里缓存。
  ctx.on('agent/created', ({ agent }) => {
    if (!config.enabled) return
    if (config.subagentSandboxCap === 'inherit') return

    // F2：**根会话创建时也会发 `agent/created`**。只认真正有父会话的子代理，
    // 否则 `depthOf` 一旦抛错（fail-closed 归 1）就会把父会话自己压档、误拦命令。
    const parentSessionId = agent?.session?.header?.parentSession
    if (typeof parentSessionId !== 'string') return

    const depth = depthOf(agent)
    if (officialDepthOf !== undefined && depth > 0) {
      let official
      try {
        official = officialDepthOf(agent)
      } catch {
        official = depth
      }
      if (official !== depth) {
        warnOnce(
          'depth-mismatch',
          `本地 delegationDepthOf 与官方实现不一致（本地 ${depth} / 官方 ${official}）——DSH 可能改了字段，闸一可能失配`,
        )
      }
    }
    if (depth <= 0) return

    // 事件内取服务（F-A）：此刻宿主已注册完 `sandboxPolicy`（探针实测 object）。
    const sandboxPolicy = /** @type {any} */ (ctx).get?.('sandboxPolicy')
    // 服务缺失：读不到当前档位 = 不知道它有多宽。写成 `cap` 对比 cap **更窄**的
    // 子代理是一次放宽（read-only → workspace-write），与「只降不升」相反
    // （R1-04，2026-10-31 对抗审计；现役部署里该分支不可达，但代码必须先自洽）。
    // 按最窄处理：read-only。
    if (sandboxPolicy === undefined) {
      hardCap(agent.session, 'read-only', 'sandboxPolicy 服务不可用', logger)
      return
    }

    let effective
    try {
      effective = sandboxPolicy.overrideOf(agent.session) ?? sandboxPolicy.defaultMode
    } catch (error) {
      // fail-closed：读不到当前档位 = 不知道它有多宽，直接压到最严。
      hardCap(agent.session, 'read-only', `读取生效档位失败：${error?.message ?? error}`, logger)
      return
    }
    // F1 + F-06（2026-10-31 红队审计））：未登记的档位名不静默放过；而且**不能**压到
    // `subagentSandboxCap`。那个 cap 可能是 `workspace-write`（默认）甚至
    // `danger-full-access` ——宿主若新增一个比它更严格的档位（例如 `strict-readonly`），
    // 压到 cap 就是一次**放宽**，与「只降不升」相反。三条失败路径必须一致：
    // 读不到（服务缺失 / overrideOf 抛错 / 名字不认识）⇒ 不知道它多宽 ⇒ read-only。
    if (typeof effective === 'string' && !isKnownSandboxMode(effective)) {
      warnOnce(
        `unknown-mode:${effective}`,
        `读到未登记的沙箱档位 ${JSON.stringify(effective)}（宿主可能新增了档位）——按最宽处理并压到 read-only`,
      )
      hardCap(agent.session, 'read-only', `未登记的档位 ${effective}`, logger)
      return
    }
    if (!shouldCapSandbox(effective, config.subagentSandboxCap)) return

    try {
      setSessionSandboxMode(agent.session, config.subagentSandboxCap)
      logger.info(
        `子代理 ${sidOf(agent)} 沙箱档位 ${effective} → ${config.subagentSandboxCap}（硬顶）`,
      )
    } catch (error) {
      // 写不进去就只能报错——此时子代理带着 `effective` 那一档在跑，必须让人看见。
      logger.error(
        `子代理 ${sidOf(agent)} 封顶失败（当前仍在 ${effective}）：${error?.message ?? error}`,
      )
    }
  })

  /**
   * 「脚本太大，内容没检查」的哨兵值。
   *
   * R5（2026-10-31 对抗审计）：旧实现把超限脚本当 `undefined` 返回，调用方
   * 对 `undefined` 的语义是「读不到就放行」——于是**只要把脚本写大过阈值，
   * 内容检查就静默失效**，只留一行告警。放行一个没看过的可执行文件，与这个
   * 插件的承诺相反，所以超限改成显式拒绝（调大 `maxScriptBytes` 可放行）。
   */
  /**
   * 按 BOM 判定脚本编码后解码。
   *
   * S2（2026-10-31 异质红队 astra A6）：旧实现固定 `utf8` 解码。用 PowerShell /
   * 记事本存成「带 BOM 的 UTF-16LE」是 Windows 上的常见做法，而 `utf8` 解出来是
   * 一堆带 `\u0000` 的乱码——黑名单正则全部失配，**脚本内容一个字节都没被检查**。
   *
   * 判定顺序：`FF FE` → UTF-16LE；`FE FF` → UTF-16BE（Node 没有原生 BE 解码，
   * 手工两两换序后按 LE 解）；`EF BB BF` → UTF-8 去 BOM；无 BOM 时抽样看 NUL
   * 比例，超过 1/4 按 UTF-16LE 再试一次（UTF-16 文本的 ASCII 段高位全是 0）。
   *
   * @param {Buffer} buffer
   * @returns {string}
   */
  const decodeScript = (buffer) => {
    if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
      return buffer.subarray(2).toString('utf16le')
    }
    if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
      const body = Buffer.from(buffer.subarray(2))
      body.swap16()
      return body.toString('utf16le')
    }
    if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
      return buffer.subarray(3).toString('utf8')
    }
    const sample = buffer.subarray(0, Math.min(buffer.length, 512))
    let zeros = 0
    for (const byte of sample) if (byte === 0) zeros += 1
    if (sample.length > 0 && zeros / sample.length > 0.25) return buffer.toString('utf16le')
    return buffer.toString('utf8')
  }

  /**
   * 一条脚本路径在磁盘上**所有**可能对应的文件。
   *
   * S3（2026-10-31 异质红队 astra A8）：旧实现按「原样 → 会话 cwd → 进程 cwd」
   * 顺序找**第一个能读到的**文件就检查。两个问题：
   *   1. 顺序反了：相对路径先按**插件进程**的 cwd 解析。宿主进程的 cwd 与会话
   *      的 cwd 可以不同，同名文件在进程 cwd 下存在时，会话里真正要执行的脚本
   *      就永远不会被读到。
   *   2. 只检查第一个可读候选：会话 cwd 下是干净脚本、进程 cwd 下是可恶意脚本
   *      时，检查通过、执行的可能不是被检查的那个。
   * 现在返回全部存在的候选，由调用方逐个检查、任一命中即拒。
   *
   * @param {string} rawPath
   * @param {string | undefined} cwd 会话工作目录
   * @returns {{ path: string, size: number }[]}
   */
  const scriptFilesOf = (rawPath, cwd) => {
    /** @type {string[]} */
    const candidates = []
    if (isAbsolute(rawPath)) {
      candidates.push(rawPath)
    } else {
      // 会话 cwd 优先：那才是被执行命令的工作目录。
      if (typeof cwd === 'string' && cwd.length > 0) candidates.push(resolvePath(cwd, rawPath))
      candidates.push(resolvePath(process.cwd(), rawPath))
      candidates.push(rawPath)
    }
    /** @type {{ path: string, size: number }[]} */
    const out = []
    for (const candidate of candidates) {
      if (out.some((entry) => entry.path === candidate)) continue
      try {
        const stat = statSync(candidate)
        if (stat.isFile()) out.push({ path: candidate, size: stat.size })
      } catch {
        // 这个候选不存在，换下一个
      }
    }
    return out
  }

  // ---- 闸二：命令黑名单（单调门，不可被放行） ------------------------------
  ctx.effect(() =>
    ctx.tools.guard((exec) => {
      if (!config.enabled) return undefined

      // F8：认领只按 `parentSession` 匹配，而官方 `subagent` / `subagent_fork`
      // 派出的子代理同样带着这个 parentSession —— 它若先创建，就会把本次委派
      // 的策略领走（官方那个被误收窄、真正的委派方认领失败被取消）。
      // 委派窗口只有一次 startActivation 那么长，窗口内先不接受同一父会话的
      // 另一路委派。
      //
      // 位置很重要：这段必须在 `commandOf()` 之前。官方 `subagent` 的参数里没有
      // 命令字段，旧实现把它放在「没有命令参数就返回」之后，于是**从来没执行过**
      // （2026-10-31 对抗审计 K3/blue-2 实测）。
      // R2-X1：判据也不能是全局 `pending.size > 0` —— A 会话委派期间 B 会话正常
      // 的官方调用会被误伤。冲突只在同一父会话成立，按调用方自己的会话 id 判。
      if (
        (exec.name === 'subagent' || exec.name === 'subagent_fork') &&
        pending.has(String(sidOf(exec.agent)))
      ) {
        return (
          'dsh-subagent-guard：一次 delegate 委派正在进行（策略尚未认领），' +
          '此时不接受官方 subagent 委派，以免两路策略串号。请稍后重试。'
        )
      }

      if (rules.length === 0) return undefined

      const command = commandOf(exec.arguments, config.commandArg)

      if (command === undefined) {
        // 没有命令参数：只有显式名单里的工具才值得再看一眼——名单里但没有参数，
        // 说明配置与工具对不上，提示一次。
        if (extraTools.has(exec.name)) {
          warnOnce(
            `noparam:${exec.name}`,
            `shellTools 里包含 ${exec.name}，但它的参数里没有 ${config.commandArg}——这条配置项可能是多余的`,
          )
        }
        return undefined
      }

      // 参数形状驱动：任何工具只要带命令参数就纳入，不看它叫什么名字。
      if (!extraTools.has(exec.name)) {
        warnOnce(
          `auto:${exec.name}`,
          `按参数形状自动纳入命令类工具 ${exec.name}（不在 shellTools 里，已覆盖）`,
        )
      }

      if (skipByScope(config.denyScope, depthOf(exec.agent))) return undefined

      const hit = matchCommand(command, rules)
      if (hit !== undefined) {
        logger.warn(
          `拒绝 ${exec.name} 调用（会话 ${sidOf(exec.agent) ?? '未知'}，命中规则 ${hit}）`,
        )
        return denyText(`命中破坏性命令规则 ${JSON.stringify(hit)}`)
      }

      // 间接执行：`pwsh -File x.ps1` 的命令行里看不到脚本内容。
      if (config.scriptInspection) {
        // F5：一条命令里可能有多个脚本（`pwsh -File a.ps1; pwsh -File b.ps1`），
        // 只查第一个等于给后面的脚本留了一条旁路。全部读一遍。
        // S1（2026-10-31 异质红队）：紧贴分隔符（`a.ps1;pwsh -File b.ps1`）的
        // 链式命令由 `scriptPathsOf` 先切段再解析，这里只管逐个检查。
        // S3：同一条路径的**所有**候选文件都要检查，不能只读第一个能读到的。
        const sessionCwd = /** @type {any} */ (exec)?.agent?.session?.header?.cwd
        for (const scriptPath of scriptPathsOf(command)) {
          const files = scriptFilesOf(scriptPath, sessionCwd)
          if (files.length === 0) {
            // 读不到通常意味着路径写错或文件不存在，那种命令执行不起来；为一个
            // 执行不了的命令拦住整个调用，误伤远大于收益（保持旧语义）。
            warnOnce(`unread:${scriptPath}`, `无法读取脚本 ${scriptPath}，内容未检查`)
            continue
          }
          for (const file of files) {
            if (file.size > config.maxScriptBytes) {
              logger.warn(
                `脚本 ${file.path} 有 ${file.size} 字节，超过 maxScriptBytes=${config.maxScriptBytes}，` +
                  '内容未检查 → 拒绝执行（调大 maxScriptBytes 可放行）',
              )
              return denyText(
                `间接执行的脚本 ${JSON.stringify(scriptPath)} 超过 maxScriptBytes ` +
                  `(${config.maxScriptBytes} 字节)，无法检查内容，拒绝执行；` +
                  '确认脚本可信后可调大 maxScriptBytes 放行',
              )
            }
            let content
            try {
              content = decodeScript(readFileSync(file.path))
            } catch (error) {
              warnOnce(
                `readfail:${file.path}`,
                `无法读取脚本 ${file.path}（${error?.message ?? error}），内容未检查`,
              )
              continue
            }
            const scriptHit = matchCommand(content, rules)
            if (scriptHit !== undefined) {
              logger.warn(`拒绝 ${exec.name} 调用（脚本 ${file.path} 命中规则 ${scriptHit}）`)
              return denyText(
                `间接执行的脚本 ${JSON.stringify(scriptPath)}（${file.path}）命中破坏性命令规则 ${JSON.stringify(scriptHit)}`,
              )
            }
          }
        }
      }

      return undefined
    }),
  )

  // ---- 闸二的续命层：冷恢复之后仍然拦得住 ----------------------------------
  // 见 `pinned` 的注释。这条 guard 注册在**插件自己的 ctx** 上，不随子代理重建
  // 而消失；它只认 `pinned` 里有记录的会话，父会话与普通子代理都不受影响。
  //
  // 它管不到**可见性**：冷恢复后子代理的 schema 会恢复成继承面，越权工具仍然
  // 列在那里，调用时才被拒绝。`dsh-tools` 没有移除 scoped 注册的 API，这是封顶。
  ctx.effect(() =>
    ctx.tools.guard((exec) => {
      if (!config.enabled) return undefined
      const agent = /** @type {any} */ (exec)?.agent
      const sid = sidOf(agent)
      if (typeof sid !== 'string') return undefined
      const allowed = pinned.get(sid)
      if (allowed === undefined) return undefined
      const name = /** @type {any} */ (exec)?.name
      if (typeof name !== 'string' || allowed.has(name)) return undefined
      logger.warn(`冷恢复兜底：拒绝 ${name}（会话 ${sid}，已授权 ${allowed.size} 个工具）`)
      return (
        `工具 "${name}" 不在该子代理的授权工具面内（delegate 策略，冷恢复兜底）；` +
        `可用工具：${[...allowed].sort().join(', ') || '(无)'}`
      )
    }),
  )

  // ---- 闸三：委派策略（工具面 + prompt）-----------------------------------
  // `subagents` 是**异步注册**的服务：`apply()` 执行时它可能还没就绪，直接
  // `ctx.get('subagents')` 会拿到 undefined，于是整个闸三静默不注册
  // （2026-10-29 在测试台 headless profile 上实测：工具表里根本没有 `delegate`）。
  // 所以改成 `ctx.inject` 等它就绪；服务消失时 Cordis 会自动回滚这次注册。
  let subagents = /** @type {any} */ (ctx).get?.('subagents')
  if (!config.enabled || !config.enableDelegateTool) {
    // 追加发现 A（2026-10-31 对抗审计，blue-1）：这个 early return 原来把下面
    // `agent/created` 的认领/恢复监听一起跳过了。于是 `enableDelegateTool: false`
    // 不只关掉 `delegate` 工具，连闸二续命层的**重建**也一起关掉：子代理被
    // `send_message` 唤醒后 `pinned` 是空的，越权工具直接放行（fail-open）。
    // 恢复监听属于闸二，不属于闸三，必须无条件注册。
    ctx.on('agent/created', ({ agent }) => {
      if (!config.enabled) return
      if (typeof /** @type {any} */ (agent)?.session?.header?.parentSession !== 'string') return
      recoverPolicy(agent)
    })
    logger.info('闸三已禁用：不注册委派工具')
    return
  }
  if (typeof subagents?.startActivation !== 'function') {
    logger.info('subagents 尚未就绪：闸三会在该服务注册后挂载（闸一、闸二已生效）')
  }

  const cap = normalizeCap(config.enforceMaxTools, config.maxTools)
  // `pending` 已在闸二之前定义（F8 要在那里读它）。
  /** 子会话 id → 已施加的策略（用于事后核对）。 */
  const consumed = new Map()
  /**
   * 最近一次「登记 → 认领」的接线痕迹。
   *
   * fail-closed 会把子代理真的创建出来再取消，失败现场随即消失，事后无处取证；
   * 而 `ctx.logger` 的输出在本机不进 `logs/` 目录（只有 daemon 行），运维看不到。
   * 所以把这条链路上的关键值留在内存里，绑定时拼进**工具返回的错误**——
   * 那是唯一一定能到达调用方与日志的通道。
   * @type {{ registeredParent?: string, childParentSession?: string, claimedSid?: string, appliedSid?: string, matched?: boolean, bound?: boolean, foreignCreated?: boolean, error?: string }}
   */
  const claimTrace = {}
  /** 绑定序列的串行闸（见 Config.serializeBind）。 */
  const bindMutex = createMutex()

  /**
   * 从本插件写的那段 system prompt 里取出**授权面**。
   *
   * `renderSection` 固定渲染成
   * `可用工具：<a, b>。你没有其他工具；需要超出范围的操作用文字说明交回父会话。`
   * 所以这里认「可用工具：」到「。你没有其他工具」之间的那段，把它当权威名单。
   *
   * 取**最后一条**匹配：persona 是父模型自由写的文本，可以伪造一行同样的
   * 字样；说明段落永远拼在 persona 之后，后出现的那条才是真的。
   *
   * @param {string} text
   * @returns {string[] | undefined} 空数组 = 显式的「无可用工具」；`undefined` = 没这段
   */
  function authorizedFaceOfSection(text) {
    if (typeof text !== 'string') return undefined
    // C1（2026-10-31 异质红队 sonnet F-R1）：只认「固定说明段落**之前**」的
    // 匹配。整条 `system/message` 是全部 system prompt 段落的拼接，本插件的段落
    // order=120，宿主其它段落 order=1000+ 排在它后面；那些文本里若出现同样的
    // 「可用工具：」字样，旧实现取**最后一条**就会取到它们。
    // 锚点用 ABSENT_CHANNELS_NOTE：它由本插件无条件追加在本段落末尾。
    const noteAt = text.lastIndexOf(ABSENT_CHANNELS_NOTE)
    const scope = noteAt === -1 ? text : text.slice(0, noteAt)
    /** @type {string[] | undefined} */
    let face
    for (const match of scope.matchAll(/可用工具：([^\n]*?)。你没有其他工具/g)) {
      const list = match[1].trim()
      face =
        list === '（无可用工具）'
          ? []
          : list
              .split(',')
              .map((name) => name.trim())
              .filter((name) => name.length > 0)
    }
    return face
  }

  /**
   *
   * F-B（2026-10-31 真机狂测，🔴 冷恢复越权）：`pinned` 是纯内存表，宿主重启后
   * `send_message` 唤醒 idle 子代理走 `agents.resume()`，`restrict()` / `guard()` /
   * `pinned` 三道全随进程消失，工具面回到继承面（实测 1 → 26 个，子代理用
   * `pwsh` 真的写出了文件）。
   *
   * DSH 没有给第三方插件留下「往会话里写策略」的口子：未知类型事件不带
   * `ignorable` 会让 `validateStoredEvents` 拒绝**整条会话**，而
   * `appendPluginRecord` 只从 `@deepseek-ai/dsh-session` 导出（profile 里没有
   * 这个包）；官方恢复路径只重放 `subagent/descriptor` 里**第一条**的
   * persona/toolFilter，且创建路径根本不写它们。所以只能从既有事件推导。
   *
   * R1-01（2026-10-31 对抗审计，🔴 阻断）：v0.4.3 用**最早一条
   * `request/header.tools`** 当授权面，而那是**模型可见面**，不是授权面 ——
   * 官方 `dsh-tool-subagent` 会把 `subagent` 以 agent-scoped 方式装进子代理，
   * 它绕开 `restrict()`，于是会被原样写进 header。冷恢复时 `pinned` 因此放行
   * `subagent`，一个被钉死的子代理能再派生**不受策略约束的孙代理**。
   *
   * 真正权威的来源是本插件自己写的那段 system prompt：说明段落里
   * `可用工具：<list>` 这一行就是 `allowTools` 的原样落地（`renderSection`），
   * 并且与 {@link ABSENT_CHANNELS_NOTE} 同在一条 `system/message` 里。
   * 所以：
   * - 段落里的「可用工具」行 ⇒ 授权面（空面写作「（无可用工具）」）；
   * - 没有这一行（0.4.2 及更早的日志）才退回 `request/header`，并剔除
   *   {@link DERIVED_SCOPED_TOOLS} 里那些由宿主动态装上的派生工具；
   * - 只有段落、没有任何请求头 ⇒ `null`，调用方按空面 fail-closed。
   *
   * @param {any} session
   * @returns {string[] | null | undefined} 工具面；`null` = 是本插件派的但无法确定面；
   *   `undefined` = 不是本插件派的/无需恢复。
   */
  function recoverFaceFromLog(session) {
    const events = Array.isArray(session?.log) ? session.log : []
    let marked = false
    /** @type {string[] | undefined} */
    let sectionFace
    /** @type {string[] | undefined} */
    let headerFace
    for (const event of events) {
      if (event?.type === 'system/message') {
        const content = event?.data?.message?.content
        if (!Array.isArray(content)) continue
        const text = content
          .map((part) => (typeof part?.text === 'string' ? part.text : ''))
          .join('\n')
        if (!text.includes(ABSENT_CHANNELS_NOTE)) continue
        marked = true
        const parsed = authorizedFaceOfSection(text)
        if (parsed !== undefined) sectionFace = parsed
      } else if (marked && headerFace === undefined && event?.type === 'request/header') {
        // `marked` 前置：只认**段落之后**的请求头。R1-02（2026-10-31 对抗审计）：
        // `provider: 'fork'` 会因为继承父会话的历史而在子会话里写入更早的请求头，
        // 那种 header 带的是父会话的面，不是本子代理的授权面。
        const tools = event?.data?.header?.tools
        if (Array.isArray(tools)) {
          headerFace = tools
            .map((tool) => (typeof tool === 'string' ? tool : tool?.name))
            .filter((toolName) => typeof toolName === 'string')
        }
      }
      // 注意这里**不能**在拿到段落面之后就 break：C1 要求与 `request/header`
      // 取交集，而请求头排在段落事件之后，提前退出会让交集退化成「只认段落」。
      // 请求头只取 `marked` 之后的第一条（`headerFace === undefined` 守卫）。
    }
    if (!marked) return undefined
    if (sectionFace !== undefined) {
      // C1 后半：与 `request/header` 取**交集**。段落是我们自己写的，但日志是
      // 可追加的（persona 里伪造一行、或日志被改写）；header 由宿主在请求时写入，
      // 两对照着看，任一来源说不许就不许。旧日志没有段落时才单靠 header。
      // F1（2026-10-31 red-3c）：这个分支同样要剔除派生通道。旧日志里
      // `headerFace === undefined` 说明没有请求头可对照，只剩段落面——而段落面
      // 是我们自己写的，`subagent` / `subagent_fork` 由宿主 scoped 装上、从来
      // 不在授权面里。不剔除就等于把 R1-01 那个洞原样留在「无请求头」这条岔路上。
      if (headerFace === undefined) {
        return sectionFace.filter((name) => !DERIVED_SCOPED_TOOLS.has(name))
      }
      const visible = new Set(headerFace.filter((name) => !DERIVED_SCOPED_TOOLS.has(name)))
      return sectionFace.filter((name) => visible.has(name))
    }
    if (headerFace === undefined) return null
    // 旧日志：只能退回请求头。`subagent` / `subagent_fork` 由宿主 scoped 装上，
    // 从来不在授权面里，必须剔除——否则就是把 R1-01 那个洞原样留着。
    return headerFace.filter((name) => !DERIVED_SCOPED_TOOLS.has(name))
  }

  /**
   * 冷恢复兜底：按子会话日志重建 `pinned` 并重新施加工具面与 prompt 段落。
   *
   * 幂等由 `restoredAgents` 保证；同进程唤醒（agent 对象曾恢复过）不会重复注册
   * 同名 prompt 段落（同层重复会抛错）。
   *
   * @param {any} childAgent
   */
  function recoverPolicy(childAgent) {
    if (restoredAgents.has(childAgent)) return
    restoredAgents.add(childAgent)
    const face = recoverFaceFromLog(childAgent?.session)
    if (face === undefined) return
    const sid = sidOf(childAgent)
    if (typeof sid !== 'string') return
    // 本插件派的，但日志里没有请求头：知道它被收窄过、不知道收窄成什么。
    // fail-closed 到一个工具都不给，比放它回继承面安全。
    const allow = face ?? []
    pinned.set(sid, new Set([...allow, ...SAFE_SCOPED_TOOLS]))
    const childCtx = childAgent.ctx
    if (childCtx === undefined) {
      warnOnce(
        `recover-noctx:${sid}`,
        `冷恢复：子代理 ${sid} 没有 agent 上下文，只能靠全局 guard 兜底（工具面可见性无法恢复）`,
      )
      return
    }
    const narrowing = restrictTolerant(childCtx, allow)
    const restricted = narrowing.ok === true
    if (!restricted) {
      logger.error(`冷恢复：子代理 ${sid} 重新收窄工具面失败：${narrowing.error}`)
    }
    // persona 无法从日志里分离（与固定说明段落在同一条 system/message 里），
    // 只恢复工具面说明。这是 README「Known limits」里写明的那条边界。
    const sectionText = renderSection({ allowTools: allow })
    if (sectionText !== undefined) {
      try {
        childCtx.systemPrompt.section({
          name: config.sectionName,
          order: config.sectionOrder,
          text: sectionText,
          interpolate: false,
        })
      } catch (error) {
        warnOnce(
          `recover-section:${sid}`,
          `冷恢复：子代理 ${sid} prompt 段落注册失败：${error?.message ?? error}`,
        )
      }
    }
    logger.info(
      `冷恢复：按会话日志重建子代理 ${sid} 的工具面（${allow.length} 个` +
        `${restricted ? '' : '，restrict 未生效仅 guard 兜底'}` +
        `${face === null ? '，日志无请求头按空面处理' : ''}）`,
    )
  }

  /**
   * 尽力收窄工具面：`restrict()` 只认**全局继承面**的工具名，白名单里一旦混进
   * scoped 注册的工具（dsh-ling 的 `recall`、官方的 `subagent`…），它会**整单
   * 抛错**、一个都不施加；而 `restrict({ allow: [] })` 是合法的（空集表示把全局
   * 继承面整个 mask 掉），所以剩余集合变空时不能跳过调用。
   *
   * 按报错点名的名字剔除后重试；被剔除的名字仍留在 `allowed` 集合里，由 guard
   * 在执行期把关。详细来由见 `applyPolicy` 里的长注释。
   *
   * @param {any} childCtx
   * @param {readonly string[]} allow
   * @returns {{ ok: boolean, applied?: string[], scopedOnly: string[], error?: string }}
   */
  function restrictTolerant(childCtx, allow) {
    let remaining = [...allow]
    /** @type {string[]} */
    const scopedOnly = []
    for (let attempt = 0; attempt < 3; attempt += 1) {
      try {
        childCtx.tools.restrict({ allow: remaining })
        return { ok: true, applied: remaining, scopedOnly }
      } catch (error) {
        const text = String(error?.message ?? error)
        const unknown = [...text.matchAll(/"([^"]+)"/g)]
          .map((match) => match[1])
          .filter((name) => remaining.includes(name))
        if (unknown.length === 0) return { ok: false, scopedOnly, error: text }
        scopedOnly.push(...unknown)
        remaining = remaining.filter((name) => !unknown.includes(name))
      }
    }
    return {
      ok: false,
      scopedOnly,
      error: `tools.restrict 连续三次被拒（allow=${JSON.stringify(allow)}）`,
    }
  }

  /**
   * 把策略施加到一个刚创建的子代理上。
   * @param {any} childAgent
   * @param {any} policy
   * @returns {boolean} 是否全部施加成功
   */
  function applyPolicy(childAgent, policy) {
    const childCtx = childAgent.ctx
    if (childCtx === undefined) {
      logger.error(`子代理 ${sidOf(childAgent) ?? '未知'} 没有 agent 上下文，策略未施加`)
      claimTrace.error = '子代理没有 agent 上下文（childAgent.ctx 为 undefined）'
      return false
    }

    if (policy.allowTools !== undefined) {
      // `restrict()` 只认**全局继承面**的工具名（`dsh-tools/lib/index.js:2993-3004`：
      // `const known = this.view(scope).restrictableNames`），遇到不在其中的名字会
      // **整单抛错**、一个都不施加。而白名单里天然混着两类名字：
      //   - 全局注册的工具（`pwsh` / `read` / `write`…）—— restrict 能收窄；
      //   - agent-scoped 注册的工具（dsh-ling 的 `recall` / `tree_read` /
      //     `library_search`，官方的 `subagent` / `list_subagent_models`）——
      //     restrict 根本不认它们。
      // 2026-10-29 真机实测：白名单含三个 dsh-ling 工具，`restrict` 直接抛
      // `tools.restrict() names unknown global tools "library_search", "recall",
      // "tree_read"`，整个委派 fail-closed。测试台复现不了——它的 profile 里
      // 没有 dsh-ling，同一条白名单在那边全部命中。
      //
      // 所以：先按全局可收窄面收窄；抛错时把报错点名的名字剔掉再试。被剔掉的名字
      // 仍留在下面 guard 的 `allowed` 集合里 —— 它们正是 scoped 注册的工具，
      // guard 才是唯一能管住它们的那一层。
      const allow = [...policy.allowTools]
      // 注意 `restrict({ allow: [] })` 是**合法**的（`restrict({})` 才抛 no-op）：
      // 空集表示把全局继承面整个 mask 掉，正是「一个工具都不给」要的效果。
      // 所以剩余集合变空时不能跳过这一调用。见 `restrictTolerant`。
      const narrowing = restrictTolerant(childCtx, allow)
      if (!narrowing.ok) {
        // 不是「名字不认识」这类可降级的错误：策略没落地，必须让调用方知道。
        logger.error(`子代理 ${sidOf(childAgent) ?? '未知'} 工具面收窄失败：${narrowing.error}`)
        claimTrace.error = `tools.restrict 失败：${narrowing.error}（allow=${JSON.stringify(allow)}）`
        return false
      }
      const scopedOnly = narrowing.scopedOnly
      if (scopedOnly.length > 0) {
        logger.info(
          `子代理 ${sidOf(childAgent) ?? '未知'} 的 ${scopedOnly.length} 个工具不是全局可收窄面` +
            `（${scopedOnly.join(', ')}），交给 guard 把关`,
        )
      }
      claimTrace.scopedOnly = scopedOnly.length > 0 ? scopedOnly : undefined
      claimTrace.restricted = narrowing.applied

      // `restrict()` 只挡**全局继承面**：`dsh-tools/lib/index.js:2985-2987` 明写
      // "Restrictions intersect; scoped registrations remain visible"。官方
      // `dsh-tool-subagent:605-607` 会在 `agent/created` 里 `installScoped()`
      // 把 `subagent` / `list_subagent_models` 直接注册到子代理自己的 ctx 上，
      // 那两个工具因此绕过 restrict——留着它们，子代理就能再派一个不受本策略
      // 约束的孙代理。用 agent-scoped guard 在执行期补齐这一层。
      // `list_subagent_models` 同样绕开 `restrict()`，且对子代理无害（只读模型
      // 清单），无条件放行。
      //
      // 曾经把 `task_begin` / `task_end` 也写进这里，理由是"子代理也该能打任务
      // 标记"。2026-10-29 真机实测推翻了它：`0.2.1-rc.2` 的子代理**根本没有注册**
      // 这两个工具，它们的 scoped 注册只在父会话发生；豁免它们的唯一效果是
      // "拒绝消息里列出两个幽灵工具"，反而让子代理以为能用（实测子代理照做后
      // 收到 `unknown tool "task_begin"`）。谁真需要就在这里显式加回来，并且先
      // 实测该宿主版本确实注册了它。
      //
      // `subagent` 同样绕开 `restrict()` 且**不豁免**：留着它，子代理就能派生一个
      // 不受本策略约束的孙代理。代价是它在子代理的工具 schema 里仍然可见、调用
      // 时才被下面这个 guard 拒绝 —— `dsh-tools` 没有移除 scoped 注册的 API。
      // T2（2026-10-31 异质红队 opus）：`policy.allowTools` 里若混进派生工具
      // （`subagent`/`subagent_fork`），旧实现原样放进 `allowed`，于是父会话显式
      // 授权 `tools:['subagent']` 就能让子代理派生一个不受策略约束的孙代理。
      // 冷恢复路径（`recoverFaceFromLog`）早就剔除了它们，两条路语义必须一致。
      // `resolveAllowedTools` 现在也在入口处拒绝，这里是第二道。
      const derived = policy.allowTools.filter((name) => DERIVED_SCOPED_TOOLS.has(name))
      if (derived.length > 0) {
        warnOnce(
          `derived-tools:${derived.join(',')}`,
          `delegate 的 tools 里含派生工具 ${derived.join(', ')}，已从授权面剔除（子代理不能派孙代理）`,
        )
      }
      const allowed = new Set([
        ...policy.allowTools.filter((name) => !DERIVED_SCOPED_TOOLS.has(name)),
        ...SAFE_SCOPED_TOOLS,
      ])
      // 另存一份给插件 ctx 上的全局 guard：scoped 注册活不过冷恢复（详见 `pinned`）。
      // 键必须走 `sidOf`：Agent 上没有 `sessionId` 属性，照名字取会得到 undefined，
      // 于是这张表存进一个字面量 "undefined" 键、兜底层全部放行（2026-10-29 实测）。
      //
      // T1（2026-10-31 异质红队 opus，同 sonnet F-R3）：仅靠 `String()` 不够——
      // 拿到 undefined 时 `String(undefined) === 'undefined'`，正好又落回那个
      // 字面量键，兜底层等于没兜。必须显式判类型；拿不到 id 就**不登记**并报错
      // （此时 `restrict` 已生效，丢的只是跨进程兜底，但不该假装绑定成功）。
      const childSid = sidOf(childAgent)
      if (typeof childSid !== 'string') {
        logger.error(
          `子代理 ${/** @type {any} */ (childAgent)?.id ?? '未知'} 取不到会话 id` +
            `（sidOf 返回 ${typeof childSid}），冷恢复兜底无法登记`,
        )
        claimTrace.error = `sidOf(childAgent) 不是字符串（${String(childSid)}），pinned 未登记`
        return false
      }
      pinned.set(childSid, allowed)
      try {
        childCtx.tools.guard((exec) => {
          const name = /** @type {any} */ (exec)?.name
          if (typeof name !== 'string' || allowed.has(name)) return undefined
          return (
            `工具 "${name}" 不在该子代理的授权工具面内（delegate 策略）；` +
            `可用工具：${[...allowed].sort().join(', ') || '(无)'}`
          )
        })
      } catch (error) {
        logger.error(
          `子代理 ${sidOf(childAgent) ?? '未知'} 工具面 guard 注册失败：${error?.message ?? error}`,
        )
        claimTrace.error = `tools.guard 注册失败：${error?.message ?? error}`
        return false
      }
    }

    if (policy.sectionText !== undefined) {
      try {
        childCtx.systemPrompt.section({
          name: config.sectionName,
          order: config.sectionOrder,
          text: policy.sectionText,
          interpolate: false,
        })
      } catch (error) {
        logger.error(
          `子代理 ${sidOf(childAgent) ?? '未知'} prompt 段注册失败：${error?.message ?? error}`,
        )
        claimTrace.error = `systemPrompt.section 失败：${error?.message ?? error}`
        return false
      }
    }

    logger.info(
      `已绑定委派策略到子代理 ${sidOf(childAgent) ?? '未知'}` +
        `（工具 ${policy.allowTools === undefined ? '继承父面' : `${policy.allowTools.length} 个`}` +
        `，prompt ${policy.sectionText === undefined ? '未设置' : '已设置'}）`,
    )
    return true
  }

  // 认领：子代理出生时按父会话取走策略并立即施加。
  ctx.on('agent/created', ({ agent }) => {
    if (!config.enabled) return
    const childAgent = /** @type {any} */ (agent)
    const parentSessionId = childAgent?.session?.header?.parentSession
    if (typeof parentSessionId !== 'string') return

    const policy = takePending(pending, parentSessionId)
    if (policy === undefined) {
      // 没有待认领策略：可能是被 `send_message` 唤醒的旧子代理。本进程内
      // `pinned` 还在，跨进程就只剩会话日志可用——按日志重建（F-B）。
      //
      // 追加发现 7（2026-10-31 对抗审计，blue-3）：这里**不能**写 `claimTrace`。
      // 委派窗口里先落地的可能是官方 `subagent` 派出的子代理（认领不到很正常），
      // 一旦写进去，失败文案就会显示别人的 parentSession / 认领=命中 / 绑定=成功，
      // 把真正的失败现场覆盖掉。只留一个布尔标记，让文案能说"窗口里有别人"。
      claimTrace.foreignCreated = true
      recoverPolicy(childAgent)
      return
    }

    claimTrace.childParentSession = parentSessionId
    claimTrace.matched = true
    claimTrace.claimedSid = sidOf(childAgent) ?? String(childAgent?.id)
    policy.bound = applyPolicy(childAgent, policy)
    claimTrace.bound = policy.bound === true
    claimTrace.appliedSid = claimTrace.claimedSid
    const childId = sidOf(childAgent)
    if (typeof childId === 'string') consumed.set(childId, policy)
  })

  /**
   * 一次委派的完整绑定序列：登记 → 创建 → 核对认领。
   * 必须在 `bindMutex` 内运行（否则并发派发会串号）。
   * @param {any} args
   * @param {any} exec
   */
  async function runDelegation(args, exec) {
    const parent = exec?.agent
    if (parent === undefined) {
      throw new Error('dsh-subagent-guard: delegate 没有拿到底层 agent，无法委派')
    }

    const providerName = config.provider
    const provider =
      providerName === '' ? undefined : subagents.getProvider?.(providerName)
    if (providerName !== '' && provider === undefined) {
      throw new Error(
        `dsh-subagent-guard: 找不到子代理 backend ${JSON.stringify(providerName)}；` +
          '检查 profile 里 dsh-subagent 的 provider 配置',
      )
    }

    const policy = buildPolicy(
      { persona: args.persona, tools: args.tools, label: args.description },
      cap,
    )

    const parentSessionId = sidOf(parent)
    if (typeof parentSessionId !== 'string') {
      throw new Error('dsh-subagent-guard: 父会话没有可用 id，无法精确绑定策略')
    }

    // 每次委派重建痕迹：失败现场只有一次机会，别让上一次的结果串进来。
    claimTrace.error = undefined
    claimTrace.matched = undefined
    claimTrace.bound = undefined
    claimTrace.claimedSid = undefined
    claimTrace.appliedSid = undefined
    claimTrace.registeredParent = parentSessionId
    claimTrace.childParentSession = undefined
    claimTrace.foreignCreated = undefined

    // 先登记、再创建：`agent/created` 一定在 startActivation 之前/期间派发。
    pushPending(pending, parentSessionId, policy)

    let activation
    try {
      activation = await subagents.startActivation({
        ...(providerName === '' ? {} : { provider: providerName }),
        label: policy.label ?? args.description,
        request: {
          ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
          prompt: [{ type: 'text', text: args.prompt }],
          parent,
        },
        signal: exec.signal,
        delivery: 'parent',
      })
    } catch (error) {
      // 创建失败：把没被认领的策略撤回来，别让它污染下一次委派。
      const queue = pending.get(parentSessionId)
      if (queue !== undefined) {
        const index = queue.indexOf(policy)
        if (index >= 0) queue.splice(index, 1)
        if (queue.length === 0) pending.delete(parentSessionId)
      }
      throw error
    }

    const childId = activation?.childId ?? activation?.id
    const claimed = typeof childId === 'string' ? consumed.get(childId) : undefined

    if (claimed !== policy || policy.bound !== true) {
      // 认领失败：子代理已经在跑，但它的权限没被收住 —— 必须取消它。
      //
      // 同时撤下仍挂在队列里的这条策略：`takePending` 只在 `agent/created` 里跑，
      // 那个回调没触发时策略会残留，被**下一次**同父委派领走，把上一次的工具面
      // 与 prompt 施加到另一个子代理上（2026-10-28 审计 E_stale）。
      dropPending(pending, parentSessionId, policy)
      if (typeof childId === 'string') consumed.delete(childId)

      // 取消是尽力而为：`agents` 是可选取到的服务，`cancel` 也可能缺席。
      // 只有真的调用到了才敢说"已取消"——否则运维会以为已经止血了（审计 B_cancel）。
      let cancelled = false
      try {
        const agents = /** @type {any} */ (ctx).get?.('agents')
        const target = agents?.get?.(childId)
        if (typeof target?.cancel === 'function') {
          // cancel(cause) 的 cause 必须是 AgentCancelCause（`{ kind }` 对象）。
          // 传裸字符串会让 agent-loop 的 abortedCancelCause 落到 assertNever 抛错，
          // 该抛错发生在 turn() 的 catch 内，使 turnEnds 停在 null 并以
          // reason:null 写入 turn/end，回放时子代理投影读 `reason.kind` 即 fatal
          // （2026-10-29 事故：guard fail-closed → 整个 DSH 退出）。
          target.cancel({ kind: 'disposed' })
          cancelled = true
        }
      } catch (cancelError) {
        logger.error(`取消未绑定的子代理失败：${cancelError?.message ?? cancelError}`)
      }

      // F14：外部 backend（非 spawn）不触发本地 `agent/created`，`cancel` 够不到它，
      // 只能关掉 activation 句柄——否则那个子代理会带着**未施加**的策略继续跑。
      if (!cancelled) {
        try {
          const dispose = /** @type {any} */ (activation)?.dispose
          if (typeof dispose === 'function') {
            await dispose()
            cancelled = true
            logger.error(
              `子代理 ${String(childId)} 没有本地 agent（外部 backend），已通过 dispose 关闭该 activation`,
            )
          }
        } catch (disposeError) {
          logger.error(`dispose 未绑定的 activation 失败：${disposeError?.message ?? disposeError}`)
        }
      }

      logger.error(
        `子代理 ${String(childId)} 没有消费到委派策略（策略未生效）；` +
          (cancelled
            ? '已取消该子代理，本次委派失败（fail-closed）'
            : '**未能确认取消**（agents 服务或该 agent 不可用）——请人工检查是否有未受约束的子代理仍在运行'),
      )
      // 诊断必须随错误回到调用方：`ctx.logger` 在本机不落盘，失败现场一旦
      // 取消子代理就没了，没有这几项就只能猜。
      const diag = [
        `登记键=${claimTrace.registeredParent ?? '(无)'}`,
        `子代理的 parentSession=${claimTrace.childParentSession ?? '(未触发 agent/created)'}`,
        `认领=${claimTrace.matched === true ? '命中' : '未命中'}`,
        `绑定=${claimTrace.bound === true ? '成功' : claimTrace.bound === false ? '失败' : '未执行'}`,
        ...(claimTrace.foreignCreated === true
          ? ['窗口内另有未认领的子代理先落地（官方 subagent？），本次诊断未被它覆盖']
          : []),
        ...(claimTrace.error === undefined ? [] : [`原因=${claimTrace.error}`]),
      ].join('；')
      throw new Error(
        (cancelled
          ? 'dsh-subagent-guard: 子代理未能绑定工具面与 prompt，已取消本次委派（fail-closed）'
          : 'dsh-subagent-guard: 子代理未能绑定工具面与 prompt，且**无法确认已取消**（fail-closed）——请人工检查') +
          ` [诊断：${diag}]`,
      )
    }

    if (typeof childId === 'string') consumed.delete(childId)

    return {
      kind: 'delegation',
      subagentId: String(childId),
      ...(policy.allowTools === undefined ? {} : { tools: [...policy.allowTools] }),
      toolsSource: policy.toolsSource,
      personaApplied: policy.personaApplied,
    }
  }

  const definition = {
    name: config.toolName,
    description:
      'Delegate one self-contained task to a subagent with an explicit prompt and tool scope. ' +
      'The child starts independently, keeps no parent context, and inherits only the tools you list. ' +
      'Omit `tools` to inherit the parent tool surface (the deployment cap only narrows it when `enforceMaxTools` is on). ' +
      'The runtime notifies you when it finishes.',
    parameters: parametersToJsonSchema({
      description: {
        type: 'string',
        required: true,
        description: 'A short (3-5 word) description of the delegated task, for display.',
      },
      prompt: {
        type: 'string',
        required: true,
        description: "The complete task for the subagent. It does not share this conversation's context.",
      },
      persona: {
        type: 'string',
        description:
          'System prompt for the child: who it is, what it must not do, how it should report. ' +
          'This is a real system-prompt section, not a message prefix.',
      },
      tools: {
        type: 'array',
        items: { type: 'string' },
        description:
          'Exact tool names the child may call. Omit to inherit the parent tool surface. ' +
          'The deployment cap always narrows this list; the child cannot ask for more.',
      },
      cwd: {
        type: 'string',
        description: 'Initial child working directory. Relative paths use your current directory.',
      },
    }),
    output: {
      // DSH 的 JSON Schema 子集不接受属性级 `required: true`（宿主会抛
      // `unsupported JSON schema: schema.properties.<name>.required`），
      // 必填项一律写成顶层 `required` 数组。
      schema: {
        type: 'object',
        additionalProperties: false,
        required: ['kind', 'subagentId', 'toolsSource', 'personaApplied'],
        properties: {
          kind: { type: 'string', const: 'delegation' },
          subagentId: { type: 'string' },
          tools: {
            type: 'array',
            items: { type: 'string' },
            description: 'The tool scope actually applied to the child.',
          },
          toolsSource: {
            type: 'string',
            enum: ['inherit', 'cap-default', 'requested'],
            description:
              'Where the scope came from: inherited parent surface, the deployment cap by default, or the caller’s own list.',
          },
          personaApplied: { type: 'boolean' },
        },
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            `started subagent ${value.subagentId}` +
            `（工具：${
              value.toolsSource === 'inherit'
                ? '继承父面'
                : value.toolsSource === 'cap-default'
                  ? `未收窄 —— 子代理获得了全部 ${value.tools.length} 个白名单工具`
                  : value.tools.length === 0
                    ? '无（子代理拿不到任何工具）'
                    : `${value.tools.length} 个：${value.tools.join(', ')}`
            }` +
            `，persona：${value.personaApplied ? '已设置' : '未设置'}）`,
        },
      ],
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      // F2（2026-10-31 red-3c）：绑定必须串行，**没有例外**。认领只按父会话 id +
      // FIFO 匹配，而 `agent/created` 的触发顺序由宿主决定；一旦允许两路并发
      // （`serializeBind: false`），乱序出生就会把 A 的策略绑到 B 的子代理上——
      // 那是权限串号，不是性能问题。这个闸只覆盖「登记 → 创建 → 核对」这一小段，
      // 子代理真正跑起来的并发不受影响，所以关掉它的收益本来就不存在。
      if (!config.serializeBind) {
        warnOnce(
          'serialize-bind-ignored',
          'serializeBind: false 已被忽略：并发绑定无法保证策略归属（会串号），绑定阶段一律串行',
        )
      }
      return bindMutex.run(() => runDelegation(args, exec))
    },
  }

  // 等 `subagents` 就绪再注册工具。它已经就绪时回调会**同步**执行，所以行为与
  // 直接注册一致；尚未就绪时就等它，而不是永久跳过（F16）。
  ctx.inject(['subagents'], (subCtx) => {
    const live = /** @type {any} */ (subCtx).subagents
    if (typeof live?.startActivation !== 'function') {
      logger.warn(
        'subagents 服务缺少 startActivation：闸三的委派工具不注册（闸一、闸二照常工作）',
      )
      return
    }
    subagents = live
    // 重新注册：认领监听只在工具挂上之后才有意义，但 `agent/created` 的认领
    // 逻辑已在外层注册（它不依赖工具存在），这里只补工具注册与启用日志。
    ctx.effect(() => ctx.tools.register(definition))
    logger.info(`闸三已启用：委派工具 ${config.toolName}（provider ${config.provider || '自动'}）`)
  })
}
