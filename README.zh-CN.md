# dsh-subagent-guard

给 [DeepSeek Harness][dsh] 的子代理上三道闸：**沙箱档位硬顶** + **破坏性命令黑名单** + **可精确设定工具面与 prompt 的委派工具**。

> English: [README.md](./README.md)

[dsh]: https://github.com/deepseek-ai/deepseek-harness

## 为什么需要

DSH 在创建子代理时捕获父会话的权限**快照**（`@deepseek-ai/dsh-subagent` 的
`captureDelegatedPolicyOverrides`）：

- 子代理的 approval 策略**恒为 `never`**：需要审批的操作在子代理内自动拒绝，
  不会转人工；
- 子代理的沙箱档位**只继承父会话的显式 override**：父会话是 `danger-full-access`
  时，子代理同档且不套沙箱；
- 模型侧没有任何放宽通道。

这是官方的[设计决定][note]，不是 bug：*"Snapshot-at-delegation is the semantic:
the child keeps the policy it was handed."* 后果是——子代理拿到的是父会话在
派发那一刻交出去的那份权限，而它没有主人的全局观、记忆和判断力。

本插件在那份快照之上再加一层运营者可调的**天花板**，也就是 harness 刻意不提供
的那一层。

[note]: https://github.com/jasonkneen/deepseek-harness-plus/blob/master/.agents/notes/implemented/feature/2026-07-25-subagent-policy-inheritance.md

## 三道闸

### 闸一：沙箱档位硬顶（`agent/created`）

子代理创建时读自己的生效档位（会话 override 或部署默认），比
`subagentSandboxCap` 宽就追加一条 `sandbox/mode` 事件把它压下去。**只降不升**：
`read-only` 的子代理不会被抬到 `workspace-write`。

**读不到当前档位时**，直接把子代理压到 `read-only` 并记一条 error（fail-closed）。
这条重要：在很多部署里，闸一是子代理与 `danger-full-access` 之间唯一的一道线。

只对**插件加载之后创建**的子代理生效。

### 闸二：命令黑名单（`ctx.tools.guard`）

`ctx.tools.guard()` 是**单调门**：它在 `tools/pre-execute` 瀑布之后运行，任何插件
都**无法再把它放行**。返回字符串即拒绝；没有 `ask` 档位可以绕过，任何审批策略
（包括 `never`）也绕不过。

**检查哪些工具？** 任何参数里带命令串的工具，参数名由 `commandArg` 指定（默认
`command`）。这**刻意不是**工具名白名单——早期版本用
`shellTools: [bash, pwsh]` 枚举，结果第三方 shell（例如 `win_bash`）注册成别的
名字就被静默跳过。工具名逐部署而变，参数形状不变。

默认拦这些（删了就要靠外部介质才能恢复的）：

| 类别 | 例子 |
|---|---|
| 卷影副本 | `vssadmin delete shadows`、`wmic shadowcopy delete`、`Get-WmiObject Win32_ShadowCopy … Delete` |
| 还原点 | `Remove-ComputerRestorePoint`、`Disable-ComputerRestore` |
| 磁盘/分区 | `diskpart`、`Format-Volume`、`Clear-Disk`、`Initialize-Disk`、`Remove-Partition`、`format C:` |
| 引导配置 | `bcdedit`、`reg delete HKLM…` |
| 宿主可用性 | `Stop-Computer`、`Restart-Computer`、`shutdown /…` |
| 不可恢复擦除 | `cipher /w`、`sdelete` |

**故意不拦** `Remove-Item`、`del`、`rmdir` 这类日常操作——全拦等于把 agent 废掉。
需要更严的话自己往 `denyPatterns` 里加。

#### 间接执行

`pwsh -File build.ps1` 的命令行里没有危险字样。开着 `scriptInspection: true`
（默认）时，插件会把明确的脚本执行形式（`-File` / `-f`、`bash|sh|zsh|source`、
`& 'x.ps1'`、`.\x.ps1`）的目标路径抠出来，读文件内容再过一遍同一套规则。

读不到或超过 `maxScriptBytes` 时**放行并告警**。这是有意的：读不到通常就是路径
写错，那种脚本本来也执行不起来。只查一层——脚本里再调脚本，不跟。

### 闸三：委派策略（`delegate` 工具）

DSH 0.2 关掉了 `persona` / `toolFilter` 两个参数
（`dsh-tool-subagent/lib/index.js:355` 明文拒绝），只剩 `agentPreset` 一条路能改
子代理的组合。但 harness 自己在**冷恢复**路径上仍然用着这两个机制
（`dsh-subagent/lib/types/child-agent.js:153-167`）：

```js
childCtx.systemPrompt.section(...)   // 遮蔽同名的全局段落
childCtx.tools.restrict(...)         // 移除继承面工具
```

闸三把这条路接回**新派发**：注册一个 `delegate` 工具，参数是 `prompt` +
可选的 `persona` + 可选的 `tools`：

1. 先把策略登记在**父会话 id** 下，再创建任何东西；
2. `subagents.startActivation()` 创建子代理；
3. `agent/created`（serial，且 await 在排队输入之前）里按父会话认领策略并施加到
   子代理自己的上下文；
4. `startActivation` 返回后**核对子代理确实消费了策略**——没消费就取消它并抛错。

第 4 步是 fail-closed 的落点：**收不住工具面的子代理，不许它带着未知权限跑**。

#### 为什么必须两层，而不是一层

`restrict()` 只遮**继承面**。它自己的文档
（`dsh-tools/lib/index.js:2985-2987`）写着：*"Restrictions intersect; scoped
registrations remain visible"*。而官方 `dsh-tool-subagent:605-607` 会在
`agent/created` 里把 `subagent`、`list_subagent_models` 直接注册到子代理自己的
上下文上。

修复前在真机实测到的形状：一个只被授予 **`read`** 的子代理调用 `subagent`，
派出一个孙代理，孙代理带着 `delegationDepth: 2` 和 **97 个工具**（含 `pwsh`、
`write`、`edit`、`workflow`）跑起来了——因为孙代理不是 `delegate` 派发的，策略
从未施加。

所以闸三两层的分工：

| 层 | 机制 | 覆盖 |
|---|---|---|
| 可见面 | `childCtx.tools.restrict({ allow })` | 继承来的工具 |
| 执行面 | agent-scoped `childCtx.tools.guard()` | `restrict` 看不见的 scoped 工具 |

第二层对任何不在白名单里的工具都拒绝：
`工具 "subagent" 不在该子代理的授权工具面内（delegate 策略）；可用工具：read`。

#### 部署级上限

`tools` 是模型传的，不能当上限信任。开 `enforceMaxTools: true` 后：

```
子代理最终工具面 = 模型传的 tools ∩ 部署的 maxTools
```

模型只能收窄，永远不能放宽。`maxTools: []` 配 `enforceMaxTools: true` 等于
一个工具都不给。

#### 并发

策略按父会话认领，而 `maxActiveSubagents` 默认 50。两次 `delegate` 交错就可能把
A 的策略绑到 B 的子代理上——正是这道闸要防的事。所以「登记 → 创建 → 核对」整段
串行化（`serializeBind`，默认开）。

## 安装

```bash
dsh plugin add dsh-subagent-guard
```

或者在 profile 里声明为 `file:` / `link:` 依赖，并把 `dsh-subagent-guard` 加进
`dsh.profile.bundles`。bundle 自带 `cordis.patch.yml`，注册行会自动插入。

## 配置

写在 bundle 的 `cordis.patch.yml` 里，或在 profile 里按 `id` 覆盖：

```yaml
- insert:
    - id: dsh-subagent-guard
      name: dsh-subagent-guard
      config:
        enabled: true
        # 子代理沙箱硬顶：inherit | read-only | workspace-write | danger-full-access
        subagentSandboxCap: workspace-write
        # all = 父会话与子代理都拦；subagent = 只拦子代理
        denyScope: subagent
        # 承载命令的参数名（按参数形状识别命令类工具）
        commandArg: command
        # 额外纳入的工具名——识别靠参数形状，这里不是全集
        shellTools: [bash, pwsh, win_bash]
        # 对 `pwsh -File x.ps1` 读目标文件内容再检查一遍
        scriptInspection: true
        maxScriptBytes: 262144
        # 自定义规则（正则源串，**整体替换**默认值，不是追加）
        denyPatterns:
          # ⚠️ 这里必须用**双引号**。YAML 单引号里的反斜杠是字面量，
          # '\\bvssadmin' 会编译成「匹配一个反斜杠加 bvssadmin」的正则，
          # 规则从此一条都匹配不上，而且没有任何告警。
          - "\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b"
          - "\\bdiskpart\\b"
```

启动时会打一行**生效配置**（`生效配置：subagentSandboxCap=… denyScope=… 规则=18 条 …`），
所以"文档默认值"与"实际部署值"不一致会当场可见，而不是静默降级。

非法配置（未知档位、未知作用域、编译不过的正则、非正的体积上限）在**加载期抛错**，
不会静默失效。

## 已知边界

- **文本匹配，不是系统调用沙箱。** `run_code`、`node -e`、内联求值（`pwsh -c "…"`）、
  多层脚本链都不在检查范围——闸一（沙箱档位）才是这层的兜底。
- **正则不是沙箱。** 拆成多行、base64 解码后执行、做混淆，这些拦不住。这道闸是
  用来挡事故和随手失误的，不是挡对手的。
- **策略层挡不住内核层。** [CVE-2026-82533][cve]（`0.1.2-alpha.1` 已修）曾让 agent
  从沙箱内访问未认证的本地 API，把自己提权到 `danger-full-access`。任何停在策略层
  的插件，对一个能任意执行代码的进程都是可绕过的。建议配合非管理员账户和可快照的
  宿主一起用。
- `denyScope: subagent` 依赖 `delegationDepthOf`；它抛错时按「是子代理」处理
  （fail-closed）。反过来说，如果它**对父会话**也抛错，父会话自己的命令同样会被拦。
- **闸三只保护它自己注册的 `delegate` 工具。** 不在委派窗口内时，父会话里官方的
  `subagent` / `subagent_fork` 仍然可用。模型改用它们、而不是 `delegate`，拿到的子代理
  **工具面没有被收窄**——正是本插件针对的那个 97 工具形状。此时闸一仍会压它的沙箱，
  所以这是「收窄面缺失」，不是提权。**委派窗口内**这两个工具会被直接拒绝：认领按
  `parentSession` 匹配，窗口里冒出来的官方子代理会把待认领的策略抢走。要连窗口外也堵，
  得自己禁掉官方那两个工具。
- **闸三依赖 `subagents` 服务。** 它如果始终不出现，`delegate` 不注册，闸一闸二照常
  工作。这个降级会记一条日志，但从模型视角看就是**闸三没了**。
- **冷恢复会把工具面重新放大。** `restrict()` 以及注册在子代理自己 `agent.ctx` 上的
  guard 都不熬过 `agents.resume()`：被 `send_message` 唤醒的闲置子代理，会带着接近
  完整的继承面回来——实测一个只被授予 `read` 的子代理，唤醒后自报 91 个工具，并成功
  派出了一个孙代理。这个**可见性**去不掉（`dsh-tools` 没有注销 scoped 工具的 API），
  所以本插件把每次授予的工具面钉在一张侧表里，并在**自己的** ctx 上注册兜底 guard，
  那个 ctx 不随子代理重建而销毁。实际后果：冷恢复后工具仍然**列在**模型眼前，只在调用
  时被拒。已验证——唤醒后的子代理调用 `subagent` 得到
  `工具 "subagent" 不在该子代理的授权工具面内（delegate 策略，冷恢复兜底）`，且没有
  产生孙代理。**如果你打算跟一个被收窄的子代理多轮对话，就一开始把工具面给全**，
  别指望收窄能跨过冷恢复。
- **未登记的沙箱档位按最宽处理**，并压到 `read-only` 加一条告警。宿主新增档位对本插件
  是一次迁移事件：否则闸一会把它当成"本来就不宽"而放过去。
- 改写子代理档位靠追加 `sandbox/mode` 事件（会话日志是唯一存储），重启后可通过
  replay 复现；子代理会话被归档后不再重放。

[cve]: https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape/

## 兼容性

已核对到 `@deepseek-ai/dsh-*` **0.2.1-rc.2**（0.3.3，2026-10-29——闸一闸二在一台真实的
`danger-full-access` 父会话上验过，闸三在测试台与同一台真机上都验过）。插件**复制**了
两小段官方实现，而不是 import 兄弟 `dsh-*` 包——因为 profile 的 `node_modules` 通常只有
`schemastery`，静态 import 会在加载期解析失败。代价是：如果 DSH 改了 `subagentDepth`、
`delegationDepth` 或 `sandbox/mode` 事件，这两份副本会**静默失配**。插件会在运行时尝试
`import()` 官方包做比对，不一致时告警——但这个检查只在官方包恰好可解析时才生效。

## 测试

```bash
npm test   # 六个套件，90 条用例，全部脱离宿主
```

| 套件 | 条数 | 覆盖面 |
|---|---|---|
| `guard.test.mjs` | 13 | 规则层：正则、脚本路径、深度、档位强弱 |
| `policy.test.mjs` | 20 | 委派策略：上限裁剪、段落渲染、待认领队列 |
| `apply.test.mjs` | 20 | 接线：闸一闸二（假 ctx） |
| `delegate.test.mjs` | 21 | 闸三接线、并发、fail-closed 认领 |
| `regressions.test.mjs` | 7 | YAML 引号、pending 清理、上限交集 |
| `audit-20261028.test.mjs` | 9 | 审计发现里凡能脱离宿主钉住的部分 |

## 外部审计

- [2026-10-24 拦截面缺口审计](./docs/research/2026-10-24-external-audit.md)：
  真实部署上的用户报告了五条缺口，附维护者逐条裁定，以及 0.2.0 落地的修法。
- **2026-10-28 内部对抗审计**（三路红队、埋 8 枚金丝雀、召回 8/8）：五类共 22 条发现
  （静默失效 / 记账说谎 / 边界翻转 / 修复不成立 / 门与旁路）。修法落在 0.3.1 与 0.3.2；
  **0.3.3 来自测试台**——它抓到了 0.3.1 那次修复自己引入的回退。记录保存在维护者私有
  工作区，不随本仓库分发。

## 许可证

MIT — 见 [LICENSE](./LICENSE)。
