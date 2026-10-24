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
 *
 * 2026-10-24 外部审计后的修法（见 docs/research/2026-10-24-external-audit.md）：
 * 1. 闸二改为**按参数形状**判定命令类工具，不再用工具名白名单枚举——枚举必然
 *    漏掉第三方 shell（`win_bash` 就是这么漏的）。
 * 2. 闸一读档位失败时**补压到 `read-only`**，不再 warn 一句就放行（fail-closed）。
 * 3. schema 与 bundle patch 的 `denyScope` 默认值对齐，避免"装完比文档更松"。
 * 4. `pwsh -File x.ps1` 这类间接执行，读脚本内容再过一遍同一套规则。
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
  matchCommand,
  scriptPathOf,
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
  /**
   * 携带命令文本的参数名。闸二按**参数形状**识别命令类工具：
   * 任何工具的参数里有这个字段，都会被纳入检查，与它注册叫什么名字无关。
   */
  commandArg: Schema.string().default('command'),
  /**
   * 额外纳入的工具名。**不是全集**——命令类工具靠 `commandArg` 自动识别，
   * 这里只用于参数名不叫 `command` 的特殊 shell 工具。
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
function hardCap(session, mode, why, logger) {
  try {
    setSessionSandboxMode(session, mode)
    logger.error(`子代理档位无法读取（${why}），已兜底压到 ${mode}`)
    return true
  } catch (error) {
    logger.error(
      `子代理档位兜底失败（${why}）：${error?.message ?? error}——这个子代理的权限未被约束`,
    )
    return false
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
  if (!Number.isFinite(config.maxScriptBytes) || config.maxScriptBytes <= 0) {
    throw new Error(
      `dsh-subagent-guard: maxScriptBytes 必须是正数，收到 ${JSON.stringify(config.maxScriptBytes)}`,
    )
  }

  const rules = compileRules(config.denyPatterns)
  const logger = ctx.logger('subagent-guard')
  const extraTools = new Set(config.shellTools)
  /** 每个提示键只输出一次，避免刷屏。 */
  const warned = new Set()

  const warnOnce = (key, message) => {
    if (warned.has(key)) return
    warned.add(key)
    logger.warn(message)
  }

  // 生效配置打一行：默认值不一致这类问题，运维一眼能看出来。
  logger.info(
    `生效配置：subagentSandboxCap=${config.subagentSandboxCap} denyScope=${config.denyScope} ` +
      `commandArg=${config.commandArg} 规则=${rules.length} 条 scriptInspection=${config.scriptInspection}`,
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
    .catch(() => {
      // 包不在是正常情况（profile 里通常没有它），静默跳过。
    })

  // ---- 闸一：子代理沙箱档位硬顶 ------------------------------------------
  ctx.on('agent/created', ({ agent }) => {
    if (!config.enabled) return
    if (config.subagentSandboxCap === 'inherit') return

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

    let effective
    try {
      effective = ctx.sandboxPolicy.overrideOf(agent.session) ?? ctx.sandboxPolicy.defaultMode
    } catch (error) {
      // fail-closed：读不到当前档位 = 不知道它有多宽，直接压到最严。
      hardCap(agent.session, 'read-only', `读取生效档位失败：${error?.message ?? error}`, logger)
      return
    }
    if (!shouldCapSandbox(effective, config.subagentSandboxCap)) return

    try {
      setSessionSandboxMode(agent.session, config.subagentSandboxCap)
      logger.info(
        `子代理 ${agent.sessionId} 沙箱档位 ${effective} → ${config.subagentSandboxCap}（硬顶）`,
      )
    } catch (error) {
      // 写不进去就只能报错——此时子代理带着 `effective` 那一档在跑，必须让人看见。
      logger.error(
        `子代理 ${agent.sessionId} 封顶失败（当前仍在 ${effective}）：${error?.message ?? error}`,
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

      if (skipByScope(config.denyScope, depthOf(exec.agent))) return undefined

      const hit = matchCommand(command, rules)
      if (hit !== undefined) {
        logger.warn(`拒绝 ${exec.name} 调用（会话 ${exec.agent?.sessionId ?? '未知'}，命中规则 ${hit}）`)
        return denyText(`命中破坏性命令规则 ${JSON.stringify(hit)}`)
      }

      // 间接执行：`pwsh -File x.ps1` 的命令行里看不到脚本内容。
      if (config.scriptInspection) {
        const scriptPath = scriptPathOf(command)
        if (scriptPath !== undefined) {
          const content = readScript(scriptPath, exec.cwd)
          if (content !== undefined) {
            const scriptHit = matchCommand(content, rules)
            if (scriptHit !== undefined) {
              logger.warn(`拒绝 ${exec.name} 调用（脚本 ${scriptPath} 命中规则 ${scriptHit}）`)
              return denyText(
                `间接执行的脚本 ${JSON.stringify(scriptPath)} 命中破坏性命令规则 ${JSON.stringify(scriptHit)}`,
              )
            }
          }
        }
      }

      return undefined
    }),
  )
}

/**
 * 拒绝文案。三段：命中什么、为什么拦、怎么改。
 * @param {string} what
 * @returns {string}
 */
function denyText(what) {
  return [
    `命令被 dsh-subagent-guard 拒绝：${what}。`,
    '这条规则保护卷影副本、还原点、分区表、引导配置与宿主可用性，无法在本会话内绕过。',
    '如果确实需要执行，请由人工确认后操作，或修改 profile 里 dsh-subagent-guard 的 denyPatterns。',
  ].join('')
}
