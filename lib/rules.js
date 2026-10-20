/**
 * dsh-subagent-guard 的纯规则层：不 import 任何 DSH 包，可脱离宿主单测。
 * 接线（agent/created、tools.guard、setSandboxMode）在 index.js。
 */

/** 沙箱档位强弱序；数值越大越宽。 */
export const SANDBOX_RANK = Object.freeze({
  'read-only': 0,
  'workspace-write': 1,
  'danger-full-access': 2,
})

/** `subagentSandboxCap` 的合法取值（`inherit` = 不改子代理档位）。 */
export const SANDBOX_CAPS = Object.freeze([
  'inherit',
  'read-only',
  'workspace-write',
  'danger-full-access',
])

/** `denyScope` 的合法取值。 */
export const DENY_SCOPES = Object.freeze(['all', 'subagent'])

/**
 * 默认命令黑名单（正则源串，不区分大小写）。
 *
 * 取舍：只拦「删了就要靠外部介质才能恢复」的东西——卷影副本、还原点、分区表、
 * 引导配置，以及会让宿主离线的关机/重启。故意不拦 `Remove-Item`、`del`、
 * `rmdir` 这类日常操作（那会把正常开发一起打死）。
 * `format` 只匹配「format + 盘符 + 冒号」，不会误伤 `Format-Table`。
 */
export const DEFAULT_DENY_PATTERNS = Object.freeze([
  String.raw`\bvssadmin\b[^\r\n]*\b(?:delete|resize|revert)\b`,
  String.raw`\bwmic\b[^\r\n]*\bshadowcopy\b`,
  String.raw`\bshadowcopy\b[^\r\n]*\bdelete\b`,
  String.raw`\bGet-WmiObject\b[^\r\n]*\bWin32_ShadowCopy\b[^\r\n]*\bDelete\b`,
  String.raw`\bRemove-ComputerRestorePoint\b`,
  String.raw`\bDisable-ComputerRestore\b`,
  String.raw`\bdiskpart\b`,
  String.raw`\bFormat-Volume\b`,
  String.raw`\bClear-Disk\b`,
  String.raw`\bInitialize-Disk\b`,
  String.raw`\bRemove-Partition\b`,
  String.raw`\bformat\s+[A-Za-z]:`,
  String.raw`\bbcdedit\b`,
  String.raw`\breg(?:\.exe)?\s+delete\s+["']?HKLM`,
  String.raw`\b(?:Stop|Restart)-Computer\b`,
  String.raw`\bshutdown(?:\.exe)?\s+\/[a-zA-Z]`,
])

/**
 * 编译正则规则。非法正则必须在加载期响亮失败——静默跳过等于留了一条假规则。
 * @param {readonly string[]} patterns 正则源串
 * @returns {{ source: string, re: RegExp }[]}
 */
export function compileRules(patterns) {
  return patterns.map((source) => {
    try {
      return { source, re: new RegExp(source, 'i') }
    } catch (error) {
      throw new Error(
        `dsh-subagent-guard: 非法的 denyPatterns 正则 ${JSON.stringify(source)}：${error.message}`,
      )
    }
  })
}

/**
 * 在一条命令串上找第一条命中的规则。
 * @param {string} command 完整命令文本
 * @param {readonly { source: string, re: RegExp }[]} rules 已编译规则
 * @returns {string | undefined} 命中的规则源串
 */
export function matchCommand(command, rules) {
  if (typeof command !== 'string' || command.length === 0) return undefined
  for (const rule of rules) {
    if (rule.re.test(command)) return rule.source
  }
  return undefined
}

/**
 * 取出工具调用里的命令文本。`pwsh`/`bash` 的参数名都是 `command`。
 * @param {unknown} args 已解析的工具参数
 * @returns {string | undefined}
 */
export function commandOf(args) {
  if (args === null || typeof args !== 'object') return undefined
  const command = /** @type {{ command?: unknown }} */ (args).command
  return typeof command === 'string' && command.trim().length > 0 ? command : undefined
}

/**
 * 子代理的当前档位是否需要被压到硬顶。
 * @param {string} effective 当前生效档位
 * @param {string} cap 硬顶
 * @returns {boolean}
 */
export function shouldCapSandbox(effective, cap) {
  const from = SANDBOX_RANK[effective]
  const to = SANDBOX_RANK[cap]
  if (from === undefined || to === undefined) return false
  return from > to
}

/**
 * 这条规则是否只作用于子代理之外的调用时放行。
 * @param {'all' | 'subagent'} scope 配置的作用域
 * @param {number} depth 调用方的 delegation 深度
 * @returns {boolean} true = 这条调用不受黑名单约束
 */
export function skipByScope(scope, depth) {
  return scope === 'subagent' && depth <= 0
}

/**
 * 切换会话沙箱档位的写路径。
 *
 * 这是 `@deepseek-ai/dsh-sandbox-policy` 里 `setSandboxMode` 的同义实现：
 * 会话日志是唯一的存储，切档就是追加一条 `sandbox/mode` 事件，没有别的状态
 * 需要改。**故意不 import 官方包** —— profile 的 `node_modules` 里不一定有
 * 兄弟 `@deepseek-ai/dsh-*` 包（本机只有 `schemastery`），静态 import 会让插件
 * 在加载期就解析失败。
 *
 * @param {{ append: (type: string, data: unknown) => void }} session
 * @param {'read-only' | 'workspace-write' | 'danger-full-access'} mode
 */
export function setSessionSandboxMode(session, mode) {
  session.append('sandbox/mode', { mode })
}

/**
 * 读一次委派深度。
 *
 * 这是 `@deepseek-ai/dsh-subagent` 里 `delegationDepthOf` 的同义实现：会话头是
 * 权威且单调的（运行时 options 只能加深，不能降低），所以取两者最大值。同样
 * 不 import 官方包，理由见上。
 *
 * 刻意不做可选链兜底：结构与官方一致，坏输入要抛出去，让调用方决定是
 * fail-closed 还是 fail-open（守卫选择 fail-closed，当作子代理处理）。
 *
 * @param {{ options: { subagentDepth?: number }, session: { header: { delegationDepth?: number } } }} agent
 * @returns {number}
 * @throws 运行时深度不是非负安全整数、或 agent 结构不完整时
 */
export function delegationDepthOf(agent) {
  const runtime = agent.options.subagentDepth
  if (
    runtime !== undefined &&
    (!Number.isSafeInteger(runtime) || runtime < 0 || Object.is(runtime, -0))
  ) {
    throw new TypeError('agent subagentDepth must be a non-negative safe integer')
  }
  return Math.max(agent.session.header.delegationDepth ?? 0, runtime ?? 0)
}
