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
  // 不可恢复的数据擦除：安全删除与空闲空间擦写。
  String.raw`\bcipher(?:\.exe)?\s+\/w`,
  String.raw`\bsdelete(?:\.exe)?\b`,
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
 * 取出工具调用里的命令文本。
 *
 * 默认参数名是 `command`（`pwsh`/`bash`/第三方 `win_bash` 都是这个名字）。
 * **按参数形状而不是按工具名判断**：只要某个工具的参数里有这个字段，它就是
 * 命令执行类工具，不管它注册叫什么名字——这是 2026-10-24 外部审计指出的
 * 「白名单枚举必然漏掉第三方 shell」的修法。
 *
 * @param {unknown} args 已解析的工具参数
 * @param {string} [argName='command'] 承载命令的参数名
 * @returns {string | undefined}
 */
export function commandOf(args, argName = 'command') {
  if (args === null || typeof args !== 'object') return undefined
  const command = /** @type {Record<string, unknown>} */ (args)[argName]
  return typeof command === 'string' && command.trim().length > 0 ? command : undefined
}

/**
 * 从一条命令里认出「执行一个脚本文件」的目标路径。
 *
 * 闸二只看命令行文本，所以 `pwsh -File evil.ps1` 里脚本内容是不可见的。
 * 这里把目标路径抠出来，交给调用方读文件后再匹配一遍同一套规则。
 *
 * 只认**明确的脚本执行形式**，不猜测：`-File`/`-f`、`bash|sh|zsh|source`、
 * 以及 `& 'x.ps1'` / `.\x.ps1` / `/x.ps1`。返回的是原样路径（可能带引号），
 * 由调用方去解析引号与相对路径。
 *
 * @param {string} command 完整命令文本
 * @returns {string | undefined} 脚本路径（去引号前的原文），认不出就别管
 */
export function scriptPathOf(command) {
  if (typeof command !== 'string' || command.length === 0) return undefined

  /** 一个能被引号包裹的非空白片段。 */
  const arg = String.raw`("[^"]+"|'[^']+'|[^\s"']+)`

  const patterns = [
    // pwsh -File x.ps1 / powershell.exe -File "x.ps1" / -f x.ps1
    String.raw`(?:^|[\s;&|(])(?:pwsh|powershell)(?:\.exe)?\b[^\r\n]*?\s-(?:File|f)\s+${arg}`,
    // bash x.sh / sh ./x.sh / zsh x.zsh / source x.sh / . x.sh
    String.raw`(?:^|[\s;&|(])(?:bash|sh|zsh|dash|source|\.)\s+${arg}`,
    // & 'x.ps1' / .\x.ps1 / ./x.sh / /path/x.ps1
    String.raw`(?:^|[\s;&|(])(?:&\s*)?(${arg})`,
  ]

  for (const source of patterns) {
    const re = new RegExp(source, 'i')
    const hit = re.exec(command)
    const raw = hit?.[1]
    if (raw === undefined) continue
    const path = raw.replace(/^["']|["']$/g, '').trim()
    if (path.length === 0) continue
    // 只接受看起来像脚本文件的路径；纯词（例如 `bash -c` 里的 `-c`）跳过。
    if (!/\.(?:ps1|psm1|bat|cmd|sh|bash|zsh|py|js|mjs|cjs|vbs|wsf)$/i.test(path)) continue
    return path
  }

  return undefined
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
