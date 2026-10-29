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
  const names = Array.isArray(argName) ? argName.filter((n) => typeof n === 'string' && n.length > 0) : [argName]
  const found = []
  for (const name of names) collectCommand(args, name, found, 0)
  if (found.length === 0) return undefined
  // 多条命令拼成一串：黑名单是「任一命中即拦」，拼接不会放过任何一条。
  return found.join('\n')
}

/**
 * 递归收集某个名字的命令字段。
 *
 * 2026-10-28 审计的 F4：原来的实现只认**顶层精确字符串**，于是
 * `{ command: ['a','b'] }`、`{ input: { command: 'x' } }`、
 * `{ script: 'x' }`（配 `commandArg: 'script'`）全都是漏的。
 * 这里覆盖这三种形状；深度上限 3 是为了不把整棵参数树当命令扫。
 *
 * @param {unknown} value
 * @param {string} name
 * @param {string[]} out
 * @param {number} depth
 */
function collectCommand(value, name, out, depth) {
  if (depth > 3 || value === null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) collectCommand(item, name, out, depth + 1)
    return
  }
  for (const [key, raw] of Object.entries(value)) {
    if (key === name) {
      if (typeof raw === 'string' && raw.trim().length > 0) out.push(raw)
      else if (Array.isArray(raw)) {
        for (const item of raw) {
          if (typeof item === 'string' && item.trim().length > 0) out.push(item)
        }
      }
      continue
    }
    if (raw !== null && typeof raw === 'object') collectCommand(raw, name, out, depth + 1)
  }
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
  const all = scriptPathsOf(command)
  return all.length === 0 ? undefined : all[0]
}

/**
 * 一条命令里**全部**要执行的脚本路径。
 *
 * 2026-10-28 审计的 F5：原实现只返回第一个命中，于是
 * `pwsh -File clean.ps1; pwsh -File evil.ps1` 的第二个脚本永远不被检查。
 *
 * @param {string} command 完整命令文本
 * @returns {string[]} 去引号后的脚本路径（去重，保持出现顺序）
 */
export function scriptPathsOf(command) {
  if (typeof command !== 'string' || command.length === 0) return []

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

  const out = []
  for (const source of patterns) {
    const re = new RegExp(source, 'gi')
    let hit
    while ((hit = re.exec(command)) !== null) {
      const raw = hit[1]
      if (raw === undefined) continue
      // 非空白片段会把紧邻的 `;` `&` `|` `)` 一起吃进来：`pwsh -File a.ps1;` 里
      // 抓到的是 `a.ps1;`。先剥掉引号，再剥掉尾随的语句分隔符，否则扩展名判定失败。
      const path = raw
        .replace(/^["']|["']$/g, '')
        .trim()
        .replace(/[;,&|()]+$/, '')
      if (path.length === 0) continue
      // 只接受看起来像脚本文件的路径；纯词（例如 `bash -c` 里的 `-c`）跳过。
      if (!/\.(?:ps1|psm1|bat|cmd|sh|bash|zsh|py|js|mjs|cjs|vbs|wsf)$/i.test(path)) continue
      if (!out.includes(path)) out.push(path)
    }
  }
  return out
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
  if (to === undefined) return false
  // 2026-10-28 审计的 F1：读到**未登记**的档位名时，原实现返回 false（不压、
  // 也不告警）——那等于"宿主加了新档位，这个插件就静默失效"。方向反过来：
  // 不知道它多宽就按最宽处理，压到 cap；调用方负责 warn 出这个未知值。
  if (from === undefined) return true
  return from > to
}

/**
 * 判断一个档位名是否在已知表里。调用方用它决定要不要告警。
 * @param {string} mode
 * @returns {boolean}
 */
export function isKnownSandboxMode(mode) {
  return SANDBOX_RANK[mode] !== undefined
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
