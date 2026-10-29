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
  DEFAULT_SECTION_ORDER,
  buildPolicy,
  dropPending,
  normalizeCap,
  pushPending,
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
  /** 脚本内容检查的体积上限（字节）。超过就只告警不读。 */
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
  const extraTools = new Set(config.shellTools)
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
  const sandboxPolicy = /** @type {any} */ (ctx).get?.('sandboxPolicy')

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

    // 服务缺失：读不到当前档位 = 不知道它有多宽，按最宽处理直接压到上限。
    if (sandboxPolicy === undefined) {
      hardCap(agent.session, config.subagentSandboxCap, 'sandboxPolicy 服务不可用', logger)
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
    // F1：未登记的档位名不再静默放过，先告警再按最宽处理。
    if (typeof effective === 'string' && !isKnownSandboxMode(effective)) {
      warnOnce(
        `unknown-mode:${effective}`,
        `读到未登记的沙箱档位 ${JSON.stringify(effective)}（宿主可能新增了档位）——按最宽处理并压到 ${config.subagentSandboxCap}`,
      )
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
   * 读脚本文件内容；失败返回 `undefined`（放行但告警）。
   *
   * 这里刻意不是 fail-closed：读不到通常意味着路径写错或文件不存在，那种情况
   * 脚本根本执行不起来。为一个执行不了的命令拦住整个调用，误伤远大于收益。
   */
  const readScript = (rawPath, cwd) => {
    const candidates = [rawPath]
    if (!isAbsolute(rawPath)) {
      if (typeof cwd === 'string' && cwd.length > 0) candidates.push(resolvePath(cwd, rawPath))
      candidates.push(resolvePath(process.cwd(), rawPath))
    }
    for (const candidate of candidates) {
      try {
        const stat = statSync(candidate)
        if (!stat.isFile()) continue
        if (stat.size > config.maxScriptBytes) {
          warnOnce(
            `big:${candidate}`,
            `脚本 ${candidate} 超过 ${config.maxScriptBytes} 字节，跳过内容检查`,
          )
          return undefined
        }
        return readFileSync(candidate, 'utf8')
      } catch {
        // 换下一个候选路径
      }
    }
    warnOnce(`unread:${rawPath}`, `无法读取脚本 ${rawPath}，内容未检查`)
    return undefined
  }

  // ---- 闸二：命令黑名单（单调门，不可被放行） ------------------------------
  ctx.effect(() =>
    ctx.tools.guard((exec) => {
      if (!config.enabled) return undefined
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

      // F8：认领只按 `parentSession` 匹配，而官方 `subagent` / `subagent_fork`
      // 派出的子代理同样带着这个 parentSession —— 它若先创建，就会把本次委派
      // 的策略领走（官方那个被误收窄、真正的委派方认领失败被取消）。
      // 委派窗口只有一次 startActivation 那么长，窗口内先不接受另一路委派。
      if (pending.size > 0 && (exec.name === 'subagent' || exec.name === 'subagent_fork')) {
        return (
          'dsh-subagent-guard：一次 delegate 委派正在进行（策略尚未认领），' +
          '此时不接受官方 subagent 委派，以免两路策略串号。请稍后重试。'
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
        for (const scriptPath of scriptPathsOf(command)) {
          const content = readScript(
            scriptPath,
            // `exec.cwd` 在宿主的 ToolRunContext 里不存在（2026-10-28 审计 F6）：
            // 相对脚本路径必须以**会话工作目录**为基准，否则会落到进程 cwd 上。
            /** @type {any} */ (exec)?.agent?.session?.header?.cwd,
          )
          if (content === undefined) continue
          const scriptHit = matchCommand(content, rules)
          if (scriptHit !== undefined) {
            logger.warn(`拒绝 ${exec.name} 调用（脚本 ${scriptPath} 命中规则 ${scriptHit}）`)
            return denyText(
              `间接执行的脚本 ${JSON.stringify(scriptPath)} 命中破坏性命令规则 ${JSON.stringify(scriptHit)}`,
            )
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
   * @type {{ registeredParent?: string, childParentSession?: string, claimedSid?: string, appliedSid?: string, matched?: boolean, bound?: boolean, error?: string }}
   */
  const claimTrace = {}
  /** 绑定序列的串行闸（见 Config.serializeBind）。 */
  const bindMutex = createMutex()

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
      let remaining = allow
      /** 从 restrict 里剔除的（scoped 注册或根本不存在），只影响 diagnostics。 */
      let scopedOnly = []
      let narrowed = false
      // 注意 `restrict({ allow: [] })` 是**合法**的（`restrict({})` 才抛 no-op）：
      // 空集表示把全局继承面整个 mask 掉，正是「一个工具都不给」要的效果。
      // 所以剩余集合变空时不能跳过这一调用。
      for (let attempt = 0; attempt < 3 && narrowed === false; attempt += 1) {
        try {
          childCtx.tools.restrict({ allow: remaining })
          narrowed = true
        } catch (error) {
          const text = String(error?.message ?? error)
          const unknown = [...text.matchAll(/"([^"]+)"/g)]
            .map((match) => match[1])
            .filter((name) => allow.includes(name) && !scopedOnly.includes(name))
          if (unknown.length === 0) {
            // 不是「名字不认识」这类可降级的错误：策略没落地，必须让调用方知道。
            logger.error(`子代理 ${sidOf(childAgent) ?? '未知'} 工具面收窄失败：${text}`)
            claimTrace.error = `tools.restrict 失败：${text}（allow=${JSON.stringify(allow)}）`
            return false
          }
          scopedOnly = [...scopedOnly, ...unknown]
          remaining = remaining.filter((name) => !unknown.includes(name))
        }
      }
      if (!narrowed) {
        claimTrace.error = `tools.restrict 连续三次被拒（allow=${JSON.stringify(allow)}）`
        return false
      }
      if (scopedOnly.length > 0) {
        logger.info(
          `子代理 ${sidOf(childAgent) ?? '未知'} 的 ${scopedOnly.length} 个工具不是全局可收窄面` +
            `（${scopedOnly.join(', ')}），交给 guard 把关`,
        )
      }
      claimTrace.scopedOnly = scopedOnly.length > 0 ? scopedOnly : undefined
      claimTrace.restricted = remaining

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
      const SAFE_SCOPED_TOOLS = new Set(['list_subagent_models'])
      const allowed = new Set([...policy.allowTools, ...SAFE_SCOPED_TOOLS])
      // 另存一份给插件 ctx 上的全局 guard：scoped 注册活不过冷恢复（详见 `pinned`）。
      // 键必须走 `sidOf`：Agent 上没有 `sessionId` 属性，照名字取会得到 undefined，
      // 于是这张表存进一个字面量 "undefined" 键、兜底层全部放行（2026-10-29 实测）。
      const childSid = sidOf(childAgent)
      pinned.set(String(childSid), allowed)
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
    claimTrace.childParentSession = typeof parentSessionId === 'string' ? parentSessionId : String(parentSessionId)
    if (typeof parentSessionId !== 'string') return

    const policy = takePending(pending, parentSessionId)
    claimTrace.matched = policy !== undefined
    claimTrace.claimedSid = sidOf(childAgent) ?? String(childAgent?.id)
    if (policy === undefined) return

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
      personaApplied: policy.sectionText !== undefined,
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
        required: ['kind', 'subagentId', 'personaApplied'],
        properties: {
          kind: { type: 'string', const: 'delegation' },
          subagentId: { type: 'string' },
          tools: {
            type: 'array',
            items: { type: 'string' },
            description: 'The tool scope actually applied to the child.',
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
              value.tools === undefined
                ? '未收窄 —— 子代理获得了全部白名单工具'
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
      // 串行化「登记 → 创建 → 核对」：并发派发时策略按父会话 FIFO 认领，
      // 不串行就可能把 A 的策略绑到 B 的子代理上。
      return config.serializeBind
        ? bindMutex.run(() => runDelegation(args, exec))
        : runDelegation(args, exec)
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
