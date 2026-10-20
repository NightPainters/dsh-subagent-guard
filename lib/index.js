/**
 * dsh-subagent-guard — 子代理权限守卫（两道闸）
 *
 * 背景：DSH 在创建子代理时捕获父会话的权限快照（`@deepseek-ai/dsh-subagent` 的
 * `captureDelegatedPolicyOverrides`）：approval 恒为 `never`、沙箱只继承父会话的
 * 显式 override。父会话是 `danger-full-access` 时子代理同档且不套沙箱——子代理
 * 因此可能在缺乏全局观的情况下执行破坏性命令（2026-10-18：批量删除卷影副本）。
 *
 * 闸一「沙箱档位硬顶」：子代理创建时（`agent/created`）把生效档位压到配置上限，
 * 只降不升。
 * 闸二「命令黑名单」：`ctx.tools.guard()` 是单调门——它在 `tools/pre-execute`
 * 瀑布之后**强制**运行（`@deepseek-ai/dsh-tools/lib/index.js:3337`），返回字符串
 * 即拒绝，任何插件都无法再把它放行，也没有 `ask` 档位可以绕过。
 *
 * 两道闸都只走公开扩展点，不碰内核。
 */
import Schema from '@deepseek-ai/schemastery'
import {
  DEFAULT_DENY_PATTERNS,
  DENY_SCOPES,
  SANDBOX_CAPS,
  commandOf,
  compileRules,
  delegationDepthOf,
  matchCommand,
  setSessionSandboxMode,
  shouldCapSandbox,
  skipByScope,
} from './rules.js'

export const name = 'dsh-subagent-guard'

/** 需要 `tools`（注册 guard）与 `sandboxPolicy`（读写会话档位）。 */
export const inject = ['tools', 'sandboxPolicy']

export const Config = Schema.object({
  /** 总开关。关掉后两道闸都不生效。 */
  enabled: Schema.boolean().default(true),
  /** 子代理的沙箱档位硬顶；`inherit` 表示不干预。 */
  subagentSandboxCap: Schema.string().default('workspace-write'),
  /** 受命令黑名单约束的工具名。 */
  shellTools: Schema.array(Schema.string()).default(['bash', 'pwsh']),
  /** 命令黑名单（正则源串）。空数组 = 不拦任何命令。 */
  denyPatterns: Schema.array(Schema.string()).default([...DEFAULT_DENY_PATTERNS]),
  /** `all` = 父会话与子代理都拦；`subagent` = 只拦子代理。 */
  denyScope: Schema.string().default('all'),
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

  const rules = compileRules(config.denyPatterns)
  const logger = ctx.logger('subagent-guard')
  const shellTools = new Set(config.shellTools)

  // ---- 闸一：子代理沙箱档位硬顶 ------------------------------------------
  ctx.on('agent/created', ({ agent }) => {
    if (!config.enabled) return
    if (config.subagentSandboxCap === 'inherit') return
    if (depthOf(agent) <= 0) return

    let effective
    try {
      effective = ctx.sandboxPolicy.overrideOf(agent.session) ?? ctx.sandboxPolicy.defaultMode
    } catch (error) {
      logger.warn(`读取子代理沙箱档位失败，跳过封顶：${error?.message ?? error}`)
      return
    }
    if (!shouldCapSandbox(effective, config.subagentSandboxCap)) return

    try {
      setSessionSandboxMode(agent.session, config.subagentSandboxCap)
      logger.info(
        `子代理 ${agent.sessionId} 沙箱档位 ${effective} → ${config.subagentSandboxCap}（硬顶）`,
      )
    } catch (error) {
      logger.warn(`子代理 ${agent.sessionId} 封顶失败：${error?.message ?? error}`)
    }
  })

  // ---- 闸二：命令黑名单（单调门，不可被放行） ------------------------------
  ctx.effect(() =>
    ctx.tools.guard((exec) => {
      if (!config.enabled) return undefined
      if (rules.length === 0) return undefined
      if (!shellTools.has(exec.name)) return undefined

      const command = commandOf(exec.arguments)
      if (command === undefined) return undefined

      if (skipByScope(config.denyScope, depthOf(exec.agent))) return undefined

      const hit = matchCommand(command, rules)
      if (hit === undefined) return undefined

      logger.warn(
        `拒绝 ${exec.name} 调用（会话 ${exec.agent?.sessionId ?? '未知'}，命中规则 ${hit}）`,
      )
      return [
        `命令被 dsh-subagent-guard 拒绝：命中破坏性命令规则 ${JSON.stringify(hit)}。`,
        '这条规则保护卷影副本、还原点、分区表、引导配置与宿主可用性，无法在本会话内绕过。',
        '如果确实需要执行，请由人工确认后操作，或修改 profile 里 dsh-subagent-guard 的 denyPatterns。',
      ].join('')
    }),
  )
}
