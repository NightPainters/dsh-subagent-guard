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
派发那一刻交出去的那份权限，而它没有运营者的全局观、记忆和判断力。

本插件在那份快照之上再加一层运营者可调的**天花板**，也就是 harness 刻意不提供
的那一层。

[note]: https://github.com/jasonkneen/deepseek-harness-plus/blob/master/.agents/notes/implemented/feature/2026-07-25-subagent-policy-inheritance.md

## 三道闸

### 闸一：沙箱档位硬顶（`agent/created`）

子代理创建时读自己的生效档位（会话 override 或部署默认），比
`subagentSandboxCap` 宽就追加一条 `sandbox/mode` 事件把它压下去。**只降不升**：
`read-only` 的子代理不会被抬到 `workspace-write`。

**档位在 `agent/created` 触发时才读**，不在插件 `apply()` 时读。0.4.2 及更早版本在
`apply()` 里取 `sandboxPolicy` 服务的快照——那一刻服务往往还没注册（真机探针实测
apply 时相关服务全为 `undefined`，约 300ms 后才可见），于是快照恒为空，每次都走
fail-closed 分支，把**更窄**的子代理抬到 cap。安全方向相反，0.4.3 起改为事件内取服务。

**事件发生时仍读不到当前档位**，直接把子代理压到 `subagentSandboxCap` 并记一条
error（fail-closed）。这条重要：在很多部署里，闸一是子代理与 `danger-full-access`
之间唯一的一道线。

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

匹配之前先把命令文本**归一化**：折掉 PowerShell 的「反引号 + 换行」、cmd 的「caret +
换行」、bash 的「反斜杠 + 换行」，剥掉引号，把空白与换行压成单个空格（0.4.5）。于是
同一个动作的不同写法落在同一套规则上：`shutdown` 后跟换行再 `/s`、
`"C:\Windows\System32\shutdown.exe" /s`、`Start-Process shutdown -ArgumentList "-s"`
都按「shutdown 且带关机开关」命中；`format.com C:`、`reg delete HKEY_LOCAL_MACHINE\…`
分别与 `format C:`、`HKLM` 等价。关机开关按真实字母集合匹配（`/s` `/r` `/g` `/p` `/h`
`/l` `/a`，破折号同理），`Get-Help shutdown -examples`、`shutdown /?` 不受影响。

**故意不拦** `Remove-Item`、`del`、`rmdir` 这类日常操作——全拦等于把 agent 废掉。
需要更严的话自己往 `denyPatterns` 里加。

#### 间接执行

`pwsh -File build.ps1` 的命令行里没有危险字样。开着 `scriptInspection: true`
（默认）时，插件会把明确的脚本执行形式（`-File` / `-f`、`bash|sh|zsh|source`、
`& 'x.ps1'`、`.\x.ps1`）的目标路径抠出来，读文件内容再过一遍同一套规则。

0.4.5 补齐了四处 fail-open：

- **一条命令里的**全部**脚本都要查**：先按 `;` `&` `|` 与换行切段（不要求分隔符两侧
  有空格），再逐段解析。`pwsh -File a.ps1;pwsh -File b.ps1` 以前只查到 `b.ps1`。
- **按 BOM 解码**：`FF FE` → UTF-16LE、`FE FF` → UTF-16BE（手工换序）、`EF BB BF` →
  去 BOM 的 UTF-8；无 BOM 时若 NUL 字节比例高，按 UTF-16LE 再试一次。固定 `utf8`
  解码会把 UTF-16 脚本读成夹着 `\u0000` 的乱码，规则全部失配。
- **会话 cwd 优先，且所有存在的候选文件都查**：相对路径先按子代理会话的 `cwd` 解析，
  再按进程 cwd、最后按原样；任一候选命中规则即拒绝。以前是「读到第一个就查那一个」，
  进程 cwd 下的同名文件可以遮蔽真正会被执行的那份。
- **显式解释器的无扩展名目标也要查**：`bash ./payload`、`sh /opt/run` 这类没有已知
  扩展名的目标，只要形如路径（含 `/` `\` 或以 `.` 开头）就读进去检查。

读不到时**放行并告警**（通常就是路径写错，那种脚本本来也执行不起来）；但文件
超过 `maxScriptBytes`（默认 256 KiB）时**拒绝执行**——内容没看过的脚本不能放过，
确实需要跑就调大这个值。路径里的尾随点（`evil.ps1.`，Windows 会忽略）会先归一化
再判定与读取。只查一层——脚本里再调脚本，不跟。

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

策略按父会话认领，而 `maxActiveSubagents` 默认 8。两次 `delegate` 交错就可能把
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

## 版本警告

**`0.3.6` 及更早版本有可能把整个宿主进程一起带走。**

它们在 `delegate` 的 fail-closed 路径上用裸字符串
（`target.cancel('delegation-policy-unbound')`）取消子代理，而不是一个完整的
`AgentCancelCause`。这个坏值会被写成会话日志里的 `turn/end { reason: null }`；下次
回放该会话时，代码在 `null` 上读 `reason.kind` 抛错，导致**整个** DSH 进程 fatal
——同一个 Job Object 里的兄弟进程全部陪葬，死的不是一个子代理。

触发条件很窄：`delegate` 调用的工具绑定失败（例如工具名不在你配置的 `maxTools`
里），然后重启、让会话被回放。日常委派走不到这条路径。

**`0.3.7` 修掉了这个成因。** 在你真正在意的宿主上启用闸三之前，请先升级。
完整复盘：[`docs/incidents/2026-10-29-cancel-cause-fatal.md`](docs/incidents/2026-10-29-cancel-cause-fatal.md)。

暂时无法升级的话，保持 `enforceMaxTools: false` 且不要给 `delegate` 传 `tools`
——绑定就不会失败，那条路径也就进不去。

## 已知边界

- **文本匹配，不是系统调用沙箱。** `run_code`、`node -e`、内联求值（`pwsh -c "…"`）、
  多层脚本链都不在检查范围——闸一（沙箱档位）才是这层的兜底。
- **间接执行是尽力而为。** 0.4.7 起路径提取也能认出 `cmd /c "pwsh -File x.ps1"`、
  `Start-Process pwsh -ArgumentList "-File x.ps1"` 以及 `'-NoProfile','-File','x.ps1'`
  数组形态，脚本**内容**会按同一套规则匹配。参数在运行时拼接的写法
  （`Start-Process -ArgumentList @('-File', $p)`、`Invoke-Expression`、变量）无法从文本解析，
  不做检查。
- **`serializeBind: false` 已弃用并被忽略（0.4.7）。** 策略认领按父会话 FIFO，而
  `agent/created` 的触发顺序由宿主决定；允许两个绑定窗口重叠，就会让子代理领走另一次调用的
  策略。现在绑定一律串行，这个闸只覆盖「登记 → 创建 → 核对」窗口，子代理执行的并发不受影响。
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
- **冷恢复按会话日志重建工具面（0.4.3，0.4.4 修正授权面来源）。** `restrict()` 以及注册在
  子代理自己 `agent.ctx` 上的 guard 都不熬过 `agents.resume()`：被 `send_message` 唤醒的
  闲置子代理会带着接近完整的继承面回来——实测一个只被授予 `read` 的子代理，唤醒后自报
  91 个工具；宿主重启后连插件侧那张兜底表（纯内存）也一起消失，子代理于是真的用 `pwsh`
  写出了文件（0.4.2 及更早版本的真实缺陷）。0.4.3 起，`agent/created` 发现没有待认领策略
  时，会从**子会话自己的日志**重建：
  - `system/message` 里出现固定说明段落 ⇒ 这个子代理是本插件派的、且当时**显式给了
    工具面**（没给 `tools` 的委派没有可恢复的策略）；
  - 段落里那行 `可用工具：<list>`（本插件自己写的）⇒ **授权面**。这是 0.4.4 的修正：
    0.4.3 用的是最早一条 `request/header` 的 `tools`，但那是**模型可见面**——官方
    `dsh-tool-subagent` 以 agent-scoped 方式装上的 `subagent` / `subagent_fork` 会绕开
    `restrict()` 进入 header，于是被钉死的子代理在冷恢复后能再派生**不受约束的孙代理**
    （2026-10-31 对抗审计 R1-01，阻断级）。只有日志里没有这一行的旧版本，才退回请求头，
    并剔除那两个 scoped 派生工具。

  据此重新 `restrict`、重新注册说明段落、重新填充兜底表。DSH 没有给第三方插件写自定义
  会话事件的入口（未知类型未带 `ignorable` 会让**整条会话打不开**），所以这是唯一不新增
  状态、又能跨进程生效的路径。

  0.4.5 又收了三处：解析锚定到固定说明段落（只认标记**之前、最靠后**的那行
  `可用工具：`，宿主 order 1000+ 的段落文本排在标记之后，不能拿来顶替）；段落面与
  `request/header` 面**取交集**——任一来源说不许就不许，`subagent` / `subagent_fork`
  这类宿主 scoped 装上的派生工具在两侧都被剔除，父会话也无法再把它们写进 `tools`
  让子代理派无约束孙代理；拿不到子会话 id 的子代理**不登记**兜底表，绑定直接
  fail-closed（否则会写进一个 `"undefined"` 字面量键，等于整个兜底层放行）。

  已知边界：调用方自定义的 `persona` 无法从同一条 `system/message` 里分离，恢复后的段落
  只含工具面说明；**有标记**但既没有 `可用工具` 行也没有请求头时按空面 fail-closed。
  反过来，**连标记都没有**的子代理（第一回合之前就死了、没跑过任何请求）认不出是本插件
  派的，不恢复、继续继承父面——这个窗口很窄（它一回合都没跑过），真实委派里样本为 0。
  取交集是安全方向，但可能**过度收窄**：若某个 agent-scoped 注册的工具没有出现在当时
  那条请求头里，它会被交集剔掉（工具变少，不是变多）。
- **冷恢复的触发点只有 `agent/created`。** 宿主哪天在 `agents.resume()` 时不再派发它，
  整条兜底链会静默放行。插件在启动期只做一次廉价探测（`agents` 服务没有 `resume` 就告警），
  更深的验证只能靠真机回归；`0.2.1-rc.2` 实测会在恢复后首个请求之前派发。
- **闸二拦不住动态构造的命令。** 字符串拼接、base64 / `-EncodedCommand`、变量路径、
  无扩展名的解释器目标（不形如路径时）、`node -e` 内联求值、脚本里再调脚本——静态正则
  做不到语义等价，这些是明确边界（2026-10-31 异质红队 A2/A5/A7 同结论）。
- **闸二也拦审计者自己。** 只读的子代理去 `Get-Help shutdown` 这类查询不会中，但真正跑
  敏感命令的审计脚本会被拒绝；这是预期行为，不给豁免——豁免逻辑本身就是绕过面。
- **`provider: 'fork'` 的子代理按父历史的段落面恢复**，可能比它实际该有的更窄
  （过度限制，非放宽）。
- **`serializeBind: false` 时两路并发委派可能互换策略**（DoS 形态，非越权）；默认 `true`。
- **兜底表（`pinned`）是进程内闭包 Map**，只覆盖本插件派的子代理：其他插件或官方
  `subagent` 派出的子代理不在其中，它们靠闸一压沙箱。
- **未登记的沙箱档位按最宽处理**，并压到 `read-only`（与「读不到档位」一致）。**不能**压到
  `subagentSandboxCap`：那个 cap 默认是 `workspace-write`，宿主若新增一个比它更严格的档位，
  压到 cap 反而是一次放宽。
  加一条告警。宿主新增档位对本插件是一次迁移事件：否则闸一会把它当成"本来就不宽"而放过去。
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
npm test   # 六个套件，123 条用例，全部脱离宿主
```

| 套件 | 条数 | 覆盖面 |
|---|---|---|
| `guard.test.mjs` | 19 | 规则层：正则、命令归一化、脚本路径（含引号内分隔符与 `cmd /c` 子命令）、深度、档位强弱 |
| `policy.test.mjs` | 21 | 委派策略：上限裁剪、派生工具拒绝、段落渲染、待认领队列 |
| `apply.test.mjs` | 27 | 接线：闸一闸二（假 ctx，含 F-A、R3、R5、BOM、会话 cwd、F-06 未知档位回归） |
| `delegate.test.mjs` | 39 | 闸三接线、并发、fail-closed 认领、F-B/R1-01/C1/T1 冷恢复、F1 派生通道过滤、F2 强制串行、F8 窗口 |
| `regressions.test.mjs` | 7 | YAML 引号、pending 清理、上限交集 |
| `audit-20261028.test.mjs` | 10 | 审计发现里凡能脱离宿主钉住的部分 |

## 外部审计

- [2026-10-24 拦截面缺口审计](./docs/research/2026-10-24-external-audit.md)：
  真实部署上的用户报告了五条缺口，附维护者逐条裁定，以及 0.2.0 落地的修法。
- **2026-10-28 自建对抗审计**（三路红队、埋 8 枚金丝雀、召回 8/8）：五类共 22 条发现
  （静默失效 / 记账说谎 / 边界翻转 / 修复不成立 / 门与旁路）。修法落在 0.3.1 与 0.3.2；
  **0.3.3 来自测试台**——它抓到了 0.3.1 那次修复自己引入的回退。记录保存在维护者私有
  工作区，不随本仓库分发。

## 许可证

MIT — 见 [LICENSE](./LICENSE)。
