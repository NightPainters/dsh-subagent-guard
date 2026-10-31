/**
 * dsh-delegate-policy 的纯逻辑层：不 import 任何 DSH 包，可脱离宿主单测。
 *
 * 三件事：校验部署上限、算出子代理真正能拿到的工具面、把 persona 渲染成
 * 一段 system prompt。接线（delegate 工具、agent/created、restrict）在 index.js。
 */

/** 段落默认顺序：排在首位指导语之后、工具说明之前。 */
export const DEFAULT_SECTION_ORDER = 120

/** 允许出现在 `tools` 里的名字形状（工具名都是小写加下划线/短横）。 */
const TOOL_NAME_RE = /^[A-Za-z][A-Za-z0-9_-]*$/

/**
 * 校验并规范化部署级上限。
 *
 * `enforce: false` 表示不设上限（`null`）。开启上限时必须是工具名数组——
 * 空数组是合法且有意义的：它表示**子代理一个工具都拿不到**。
 *
 * @param {boolean} enforce
 * @param {readonly string[]} list
 * @returns {readonly string[] | null}
 */
export function normalizeCap(enforce, list) {
  if (!enforce) return null
  if (!Array.isArray(list)) {
    throw new TypeError('dsh-delegate-policy: maxTools 必须是字符串数组')
  }
  return list.map((name) => assertToolName(name, 'maxTools'))
}

/**
 * 校验单个工具名。
 * @param {unknown} name
 * @param {string} where 出错时指认来源
 * @returns {string}
 */
export function assertToolName(name, where) {
  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError(`dsh-delegate-policy: ${where} 里的工具名必须是非空字符串，收到 ${JSON.stringify(name)}`)
  }
  if (!TOOL_NAME_RE.test(name)) {
    throw new TypeError(`dsh-delegate-policy: ${where} 里的工具名 ${JSON.stringify(name)} 形状非法`)
  }
  return name
}

/**
 * 由宿主动态 scoped 注册、**永远不属于授权面**的派生工具。
 *
 * 子代理能调用它们，就等于能派生一个**不受本策略约束**的孙代理：
 * `dsh-tool-subagent` 把 `subagent` 以 agent-scoped 方式装进子代理，绕开
 * `tools.restrict()`（2026-10-31 对抗审计 R1-01，🔴 阻断）。
 *
 * 2026-10-31 异质红队 opus T2：`enforceMaxTools: false`（默认）时上限为 null，
 * `delegate(tools: ['subagent'])` 会原样落到授权面。入口处直接拒绝，
 * `renderSection` 因此也不会写出「可用工具：subagent」这种假声明。
 *
 * 与 `index.js` 里的 `DERIVED_SCOPED_TOOLS` 必须保持同一份名单：那边是
 * 冷恢复/第二道过滤用的，这边是纯逻辑层的入口校验。
 */
export const DERIVED_TOOL_NAMES = Object.freeze(['subagent', 'subagent_fork'])

/**
 * 算出子代理最终的 allow 集合。
 *
 * - `requested === undefined`：调用方没指定 → 继承父面；若部署设了上限，
 *   就退化成上限本身（上限是继承面的上界）。
 * - `requested` 是数组：与上限取交集。**模型不能借参数绕开部署上限**。
 *
 * 返回 `undefined` 表示"不施加 restrict"。
 *
 * @param {readonly string[] | undefined} requested 模型传的 tools
 * @param {readonly string[] | null} cap 部署上限
 * @returns {readonly string[] | undefined}
 */
export function resolveAllowedTools(requested, cap) {
  if (requested !== undefined) {
    const list = [...new Set(requested.map((name) => assertToolName(name, 'delegate 的 tools')))]
    // T2：派生工具不是「工具」而是「派生通道」，授予它等于绕过整个闸三。
    // 必须在算上限之前拒绝：默认部署（`enforceMaxTools: false`）上限为 null，
    // 走到下面就直接返回了。
    const derived = list.filter((name) => DERIVED_TOOL_NAMES.includes(name))
    if (derived.length > 0) {
      throw new Error(
        `dsh-subagent-guard: delegate 的 tools 不能包含派生工具 ` +
          `（${derived.map((name) => JSON.stringify(name)).join(', ')}）——` +
          '子代理能调用它就能派生一个不受策略约束的孙代理。需要继续派生请回父会话操作。',
      )
    }
    if (cap === null) return list
    const capped = new Set(cap)
    // 不在部署上限里的名字必须响亮失败。
    //
    // 静默过滤的代价（2026-10-29 实测）：打错一个字 ⇒ allow 变空集 ⇒
    // `restrict({ allow: [] })` 移空全部全局工具，而 scoped 注册的
    // `subagent` / `list_subagent_models` 移不掉，子代理于是变成「什么都没法做、
    // 却挂着一个看起来能派代理的工具」。调用方还以为它按自己说的配置在跑。
    const rejected = list.filter((name) => !capped.has(name))
    if (rejected.length > 0) {
      throw new Error(
        `dsh-subagent-guard: delegate 的 tools 里有 ${rejected.length} 个名字不在部署上限里 ` +
          `（${rejected.map((name) => JSON.stringify(name)).join(', ')}）；` +
          `不传 tools 可得全部 ${cap.length} 个白名单工具，传 tools: [] 表示零工具。`,
      )
    }
    return list
  }
  return cap === null ? undefined : [...cap]
}

/**
 * 渲染交给子代理的那段 system prompt。
 *
 * 只做拼接与首尾裁剪，不做任何模板替换——persona 是调用方（父模型）写的自由
 * 文本，里面有 `{{…}}` 也应当原样保留。
 *
 * @param {{ persona?: string, allowTools?: readonly string[], label?: string }} policy
 * @returns {string | undefined} 空内容时返回 undefined（不注册段落）
 */
/** 子代理侧恒缺的通道：说明段落要主动声明，否则系统提示里提到的名字会让它误判。 */
export const ABSENT_CHANNELS_NOTE =
  '本会话没有 subagent / subagent_fork / delegate 等派生通道，也没有 task_board_run 这类宿主级执行入口；' +
  '系统提示里若提到它们，属于主会话机制，与你无关。'

/**
 * 渲染交给子代理的那段 system prompt。
 *
 * 只做拼接与首尾裁剪，不做任何模板替换——persona 是调用方（父模型）写的自由
 * 文本，里面有 `{{…}}` 也应当原样保留。
 *
 * **说明段落与 persona 解耦**：只传 `tools` 不传 `persona` 时同样要注册。
 * 2026-10-29 实测：旧实现把整段挂在 `persona` 非空这个条件上，于是
 * `delegate(tools: ['read'])` 的子代理上下文里没有任何「可用工具」文字，
 * 只能自己从函数表猜边界——它把 scoped 注册的 `subagent` 也算成了可用工具。
 *
 * @param {{ persona?: string, allowTools?: readonly string[], label?: string }} policy
 * @returns {string | undefined} 无内容可写时返回 undefined（不注册段落）
 */
export function renderSection({ persona, allowTools, label }) {
  const head = typeof persona === 'string' ? persona.trim() : ''
  if (head.length === 0 && allowTools === undefined) return undefined

  const lines = []
  if (head.length > 0) lines.push(head)
  if (allowTools !== undefined) {
    const list = allowTools.length === 0 ? '（无可用工具）' : allowTools.join(', ')
    if (lines.length > 0) lines.push('')
    lines.push(`可用工具：${list}。你没有其他工具；需要超出范围的操作用文字说明交回父会话。`)
    lines.push('')
    lines.push(ABSENT_CHANNELS_NOTE)
  } else if (typeof label === 'string' && label.trim().length > 0) {
    if (lines.length > 0) lines.push('')
    lines.push(`本次委派：${label.trim()}`)
  }
  return lines.length === 0 ? undefined : lines.join('\n')
}

/**
 * 组装要在 `agent/created` 里施加的完整策略。
 *
 * @param {{ persona?: string, tools?: readonly string[], label?: string }} input 模型传来的参数
 * @param {readonly string[] | null} cap 部署上限
 * @returns {{ allowTools: readonly string[] | undefined, sectionText: string | undefined, label: string | undefined }}
 */
export function buildPolicy(input, cap) {
  const allowTools = resolveAllowedTools(input.tools, cap)
  const label = typeof input.label === 'string' && input.label.trim().length > 0 ? input.label.trim() : undefined
  const sectionText = renderSection({ persona: input.persona, allowTools, label })
  // `personaApplied` 必须看**调用方是否真的给了 persona**，不能看 `sectionText`
  // 是否存在——说明段落现在与 persona 解耦，只传 tools 时也会注册 section，
  // 拿 sectionText 判定会把「没给人设」报成「已设置」（2026-10-29 实测）。
  const personaApplied = typeof input.persona === 'string' && input.persona.trim().length > 0
  // 工具面来源三态：调用方没传且无上限（继承父面）/ 调用方没传但有部署上限
  // （默认全集——调用方并没有主动收窄）/ 调用方显式传了。
  const toolsSource =
    allowTools === undefined ? 'inherit' : input.tools === undefined ? 'cap-default' : 'requested'
  return { allowTools, sectionText, label, personaApplied, toolsSource }
}

/**
 * 在一条 FIFO 队列里取出属于某个父会话的下一条策略。
 *
 * 队列按插入顺序消费：委派是"我先登记、再创建"，同一个父会话里拿到的一定是
 * 最早那条没被认领的。取走即删除。
 *
 * @param {Map<string, object[]>} map 父会话 id → 待认领策略队列
 * @param {string} parentSessionId
 * @returns {object | undefined}
 */
export function takePending(map, parentSessionId) {
  const queue = map.get(parentSessionId)
  if (queue === undefined || queue.length === 0) return undefined
  const policy = queue.shift()
  if (queue.length === 0) map.delete(parentSessionId)
  return policy
}

/**
 * 往队列尾部登记一条策略。
 * @param {Map<string, object[]>} map
 * @param {string} parentSessionId
 * @param {object} policy
 */
export function pushPending(map, parentSessionId, policy) {
  const queue = map.get(parentSessionId)
  if (queue === undefined) map.set(parentSessionId, [policy])
  else queue.push(policy)
}

/**
 * 撤下一条**未被认领**的策略。
 *
 * `takePending` 只在 `agent/created` 里调用：若那个回调因为时序变化没触发，
 * 策略会留在队列里，被**下一次**同父委派领走——把上一次的工具面与 prompt
 * 施加到另一个子代理上。所以每条失败退出路径都必须显式撤下。
 *
 * @param {Map<string, object[]>} map
 * @param {string} parentSessionId
 * @param {object} policy
 * @returns {boolean} 是否真的撤下了一条
 */
export function dropPending(map, parentSessionId, policy) {
  const queue = map.get(parentSessionId)
  if (queue === undefined || queue.length === 0) return false
  const index = queue.indexOf(policy)
  if (index < 0) return false
  queue.splice(index, 1)
  if (queue.length === 0) map.delete(parentSessionId)
  return true
}
