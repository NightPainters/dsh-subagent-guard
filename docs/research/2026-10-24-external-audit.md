# 外部审计报告：拦截面缺口（2026-10-24）

> 本文件是一份**外部用户提交的审计报告**的归档（路径与可识别信息已脱敏），
> 后附维护者的逐条回应与处理记录。保留原文措辞，便于日后核对当时的判断依据。
>
> - 报告版本：针对 `dsh-subagent-guard@0.1.0`
> - 宿主版本：`@deepseek-ai/dsh-*@0.2.1-rc.2`（Windows 10 22H2，Node 22.x）
> - 归档日期：2026-10-24
> - 处理结果：见文末「维护者回应」，修复版本 `0.2.0`

---

## 摘要

这份报告不是来否定插件的。它的两道闸在本机**确实挡住了 2026-10-18 那类事故**（子代理批量删除卷影副本），闸二 `ctx.tools.guard()` 作为单调门的选型也是对的。以下五条是在这台机器上核对出的**拦截面缺口**，按严重度排序：

| # | 缺口 | 严重度 | 性质 |
|---|---|---|---|
| 1 | 闸二的 `shellTools` 白名单不含 `win_bash`，该工具被完整放行 | **P0** | 配置覆盖面 |
| 2 | 闸二只检查命令文本，"写脚本再执行"可完整绕过 | **P0** | 设计边界（README 已自述） |
| 3 | 闸一自身失败时**开门**（fail-open），与"不可放行"的设计意图相反 | P1 | 失败方向 |
| 4 | schema 默认 `denyScope: 'all'`，bundle patch 默认 `'subagent'`，安装即吃宽松档 | P1 | 静默降级 |
| 5 | 复制官方实现（`delegationDepthOf` / `setSessionSandboxMode`），版本迁移会静默失配 | P2 | 可维护性 |

每条都带**证据等级**：`[静态]` = 读源码可证；`[实测]` = 本机跑过；`[记载]` = 来自本机配置注释或历史记录，未复测。

---

## 环境与生效配置

| 项 | 值 |
|---|---|
| DSH 运行时 | 0.2.1-rc.2 |
| guard 生效配置 | `subagentSandboxCap: workspace-write`、`denyScope: subagent`、`shellTools: [bash, pwsh]`、`denyPatterns` 用内置 16 条 |
| 安装方式 | bundle：`package.json` 的 `dsh.profile.bundles` 第 17 项 + 包内 `cordis.patch.yml` |
| 同机 shell 插件 | `@linxin666/dsh-win-bash@0.4.7`，`replacePwsh: false` |

---

## 一、先说它拦住了什么

三条正面结论，避免后续建议被误读成"推倒重来"：

1. **闸二挂在正确的扩展点上。** `ctx.tools.guard()` 在 `tools/pre-execute` 瀑布之后**单调**运行，返回字符串即拒绝，任何插件不能再放行，也没有 `ask` 档位绕过的余地。10/18 事故里的 `vssadmin delete shadows` 命中规则 1，这类命令确实被掐死。
2. **闸一的深度判定与派发通道无关。** 核对了 `@deepseek-ai/dsh-subagent/lib/index.js:279-284`：`childDepth = delegationDepthOf(parent) + 1` 对 spawn / fork / workflow 三条通道一致。`workflow` 的 `startChild` 虽然不传 `maxDepth`，但"不传"只表示"不设上限"，深度照样递增。所以闸一**会**作用于 workflow 子代理。
3. **`delegationDepthOf` 抛错时返回 1（当作子代理）是 fail-closed**，方向正确。

---

## 二、缺口 1（P0）：`win_bash` 不在白名单，闸二对它零覆盖

### 事实链 `[静态]`

DSH 在 Windows 上跑 bash 时，本机用的是第三方插件提供的 `win_bash` 工具，而不是内置 `bash`：

**① profile 挂载了它**：

```yaml
- id: web-ui-win-bash
  name: '@linxin666/dsh-web-all/win-bash'
  config:
    plugin: '@linxin666/dsh-win-bash'
    replacePwsh: false
```

**② 这个插件注册的工具名就叫 `win_bash`**（`lib/index.js`）：

```js
const WIN_BASH_TOOL = "win_bash";        // L2287
...
name: WIN_BASH_TOOL,                     // L2456  defineTool({...})
```

**③ 而 guard 的白名单只有两条**（`lib/index.js` 与包内 `cordis.patch.yml`）：

```js
shellTools: Schema.array(Schema.string()).default(['bash', 'pwsh'])
```

**④ 闸二的第一道门正好是名字白名单**：

```js
if (!shellTools.has(exec.name)) return undefined   // 放行
```

`exec.name === 'win_bash'` ⇒ `shellTools.has('win_bash') === false` ⇒ **无论命令内容是什么，闸二一律放行**。

### 为什么目前没有立刻炸

`subagentSandboxCap: workspace-write` 把子代理压进受限沙箱，而 win_bash 依赖的 MSYS2 bash 在受限 token 下起不来（`SANDBOX_UNSUPPORTED`），子代理只能退回 `pwsh`，闸二于是又生效了。`[记载]`

**这层遮挡是偶然的，不是设计。** 两个方向都会让它失效：

- `subagentSandboxCap` 的合法取值包含 `inherit`。一旦改成 `inherit`，闸一不压档，子代理继承父会话的 `danger-full-access`，`win_bash` 可用，闸二对主力 shell 彻底失效；
- profile 自己的注释写着 "danger-full-access 下 win_bash 仍优先" —— 也就是说**在最需要被管的全权会话里，win_bash 恰是首选 shell**。

### 建议

1. **不要用具体工具名做白名单全集。** 改为"能力发现"：启动时遍历已注册工具的 `parameters`，把含 `command`（或其他命令类参数）的工具都纳入闸二；`shellTools` 退化为"额外补充"或"排除项"。
2. 至少加一条**启动自检**：把"注册表里参数含 `command` 的工具名"与 `shellTools` 求差集，非空就 `logger.warn` 列出。
3. README 里点明 `shellTools` 是"精确工具名"而非"shell 类别"，并给出 `win_bash` 这类第三者插件的配置样例。

---

## 三、缺口 2（P0）：闸二只做文本匹配，写脚本即绕过

README 的 Known limits 已经自述（"Shell tools only. `run_code`、`node -e`、或先写脚本再执行永远不经过它"）。这里补的是一个**具体可达的路径**：它在本机不是理论问题。

### 路径 `[静态]`

DSH 的 `workflow` 通道在创建子代理时**不传 `agentPreset`**（`dsh-workflow-ptc/lib/index.js:327-348` 的 `startChild` 参数里只有 prompt / provider / model / schema）。而 `applyChildComposition` 在 `composition.agentPreset === undefined` 时走 `composeFrom(childCtx, parent.ctx)`（`dsh-subagent/lib/types/child-agent.js:140-152`）—— 子代理**继承父会话的完整工具组合**，`write` / `edit` 必然在手。

于是：

```
1) write  →  C:\...\x.ps1     内容: vssadmin delete shadows /all /quiet
2) bash   →  pwsh -File x.ps1
```

闸二看到的 `command` 是 `pwsh -File x.ps1`，默认规则**零命中**。

这不是 `win_bash` 独有的问题——即使 shellTools 修好了，文本匹配依然看不到脚本内容。

### 建议

1. **脚本旁路检查**：当 `command` 匹配到 `-File <path>`、`-f <path>`、`bash <path>`、`& <path>`、`./<path>` 等形式时，读取目标文件内容再过一遍同一套规则。读失败时**不放行**（或至少 `logger.error`），否则等于给了一条"读不到就通行"的通道。
2. **在拒绝文案里如实说明兜底。** 现在闸一压档后子代理的沙箱是 `workspace-write`，脚本绕过也只能拿到 `workspace-write` 的权限。把这句写进文档，能显著降低误判风险——但**不能把它当防护**：`workspace-write` 本身允许改工作区里的构建脚本，而构建脚本通常会被后续流程执行。
3. 长期方案是把"命令类工具"统一到一条 `pre-execute` 钩子上做 **argv 级**检查（拆词后再匹配），而不是对整条命令行做正则。正则对 `vssadmin  delete`（多空格）、`vssadmin /delete`（参数换序）、`& {vssadmin} delete` 这类变体都不稳。

---

## 四、缺口 3（P1）：两道闸的失败方向不一致，闸一自身失败即放行

`[静态]` 逐点核对：

| 位置 | 出错情形 | 实际行为 | 期望 |
|---|---|---|---|
| `index.js:91-96` | 读子代理沙箱档位抛错 | `logger.warn` + `return` → **放行** | fail-closed，或升 `error` |
| `index.js:99-106` | 写沙箱档位抛错 | `logger.warn` + `return` → **放行**（子代理已在跑） | 同上 |
| `index.js:116-117` | `arguments.command` 非字符串 | `return undefined` → **放行** | 至少 `warn` |
| `index.js:113` | `rules.length === 0`（配置清空） | 静默放行 | 启动时 `warn` |
| `index.js:56-62` | `delegationDepthOf` 抛错 | 返回 `1` → **当作子代理（拦截）** | ✅ 唯一 fail-closed |

闸一是这台机器上唯一阻止"子代理拿到 danger-full-access"的机制。它自己失败时**开门**，与"闸二是单调门、不可放行"的整体设计意图相反：**同一份配置里，闸二比闸一更可信**。

### 建议

- 增加 `onFailure: 'open' | 'closed'`，默认 `closed`；闸一读取失败时拒绝该子代理创建（或至少不创建），而不是让它带着未知权限跑起来。
- 把这两处 `logger.warn` 提到 `logger.error`，并用 `session.append('guard/error', {...})` 留痕——现在只有控制台日志，父会话审计看不到。

---

## 五、缺口 4（P1）：两套默认值，安装即吃宽松档

`[静态]`

- `lib/index.js:46` —— schema 默认 `denyScope: 'all'`（父会话 + 子代理都拦）
- `cordis.patch.yml:15` —— 包内 patch 写死 `denyScope: 'subagent'`（只拦子代理）

bundle 安装走的是 patch，所以用户实际拿到的是 **`subagent`**：父会话执行 `vssadmin delete shadows` **不拦**。

10/18 那次事故是子代理干的，所以 `subagent` 这个默认取向可以理解；但两处默认值不一致、README 没有点明，属于**静默降级**。看 schema 文档的人会以为装完是 `all`。

### 建议

- schema 默认与 patch 对齐（都写 `subagent`，或都写 `all`）；
- 启动时用 `logger.info` 打出**生效值**（`subagentSandboxCap` / `denyScope` / `shellTools` 实际集合），一行即可，运维排查成本会低一个数量级。

---

## 六、缺口 5（P2）：复制官方实现，版本迁移会静默失配

`[静态]` `rules.js` 里有两份"同义实现"：

- `delegationDepthOf`（L132-155）复制自 `@deepseek-ai/dsh-subagent`；
- `setSessionSandboxMode`（L116-130）复制自 `@deepseek-ai/dsh-sandbox-policy`。

复制的**理由成立**，注释也写清楚了（`rules.js:119-123`：profile 的 `node_modules` 里不一定有兄弟 `dsh-*` 包，静态 import 会让插件在加载期就解析失败）。本机确实如此——`profiles/web/node_modules` 里只有 `schemastery`。

代价是：DSH 一旦改字段（`options.subagentDepth` / `session.header.delegationDepth`）或改事件名（`sandbox/mode`），这两处**不会报错，只会静默失配**。可能的后果有两个方向，而且都不受控：

- 漏拦：深度恒为 0，闸一跳过所有子代理；
- 误伤：`delegationDepthOf` 抛错被 `depthOf` 捕获后返回 1，**父会话**也会被当成子代理压档。

### 建议

- 启动自检：若官方包可 resolve，对同一 agent 做一次 `delegationDepthOf` 比对，不一致 `logger.error`；
- README 标注"已核对到 DSH 0.2.1-rc.2"，并给出升级核对清单（事件名、字段名、`sandbox/mode` 载荷）。

---

## 七、可选（P3）：黑名单覆盖的取舍

默认 16 条覆盖卷影副本 / 还原点 / 分区表 / 引导 / 关机重启，取舍写得很明确："只拦删了就要靠外部介质才能恢复的东西，故意不拦 `Remove-Item`/`del`/`rmdir`"。这条线认为立得住，不应扩大。

按同一标准，下面几个**符合"不可恢复"却没进表**，可考虑补 2-3 条：

| 命令 | 为什么符合 |
|---|---|
| `robocopy <src> <dst> /mir` | 镜像模式会删除目标端多余文件，等同批量删除 |
| `cipher /w:<drive>` | 擦除空闲空间，数据不可恢复 |
| `sdelete` / `fsutil usn deletejournal` | 安全删除与 USN 日志删除 |
| `mountvol` | 可卸载/删除卷挂载点 |

不建议加的：`Remove-Item -Recurse -Force`（会把正常开发打死）。

---

## 附录 A：证据锚点

| 断言 | 文件 | 行 |
|---|---|---|
| 闸一挂 `agent/created` | `dsh-subagent-guard/lib/index.js` | 85-107 |
| 闸二白名单门 | 同上 | 110-133（门在 114） |
| `depthOf` fail-closed | 同上 | 56-62 |
| schema 默认 `denyScope: all` | 同上 | 46 |
| 默认 `shellTools: [bash, pwsh]` | 同上 | 42 |
| 包内 patch `denyScope: subagent` | `dsh-subagent-guard/cordis.patch.yml` | 15 |
| 包内 patch `shellTools` | 同上 | 17-19 |
| `delegationDepthOf` 同义实现 | `dsh-subagent-guard/lib/rules.js` | 132-155 |
| `setSessionSandboxMode` 同义实现 | 同上 | 116-130 |
| 16 条默认规则 | 同上 | 32-49 |
| `win_bash` 工具名常量 | `@linxin666/dsh-win-bash/lib/index.js` | 2287 |
| `defineTool({ name: WIN_BASH_TOOL })` | 同上 | 2456 |
| workflow `startChild` 不传 `agentPreset` | `dsh-workflow-ptc/lib/index.js` | 327-348 |
| 缺省 preset 继承父工具组合 | `dsh-subagent/lib/types/child-agent.js` | 140-152 |
| 深度与通道无关 | `dsh-subagent/lib/index.js` | 279-284 |

## 附录 B：复现步骤（均可静态复现，不需触发真实破坏）

**B1 — `win_bash` 放行**
1. 读 profile 的 `cordis.patch.yml`，确认 `@linxin666/dsh-win-bash` 已挂载；
2. 读该插件 `lib/index.js:2287`，确认工具名 `win_bash`；
3. 读 `dsh-subagent-guard/lib/index.js:42` 与 `cordis.patch.yml:17-19`，确认集合为 `{bash, pwsh}`；
4. 结论：`shellTools.has('win_bash') === false`，名字白名单直接放行。**无需实际执行命令**。

**B2 — 脚本绕过**
1. 在 `workflow` 或 `subagent` 子代理内 `write` 一个 `.ps1`，内容任意命中规则 1 的命令；
2. 用 `pwsh -File` 执行；
3. 观察 `commandOf(exec.arguments)` 只拿到 `pwsh -File <path>`，对默认规则零命中。
   *注意：第 2 步会真实执行，切勿用 `vssadmin delete` 之类做验证；用 `echo` 假命令验证"脚本内容不被检查"即可。*

**B3 — 闸一 fail-open**
1. 构造使 `sandboxPolicy.overrideOf` 或 `setSessionSandboxMode` 抛错的输入（例如传入结构不完整的 session）；
2. 观察走 `logger.warn` + `return`，子代理继续创建。

**B4 — 默认值**
1. `dump-config` 或加载日志里查 `dsh-subagent-guard` 的生效 `denyScope`；
2. 与 schema 默认的 `all` 对比，确认实际为 `subagent`。

---
---

# 维护者回应（2026-10-24）

逐条复核过报告里的 `文件:行` 引用（抽查 12 处），**全部与磁盘一致**，包括"16 条默认规则"这类细节（维护者此前口头汇报误记为 17 条，报告是对的）。这份报告的质量高于预期，五条缺口里有四条是维护者自己代码的真实行为。

## 裁定

| # | 裁定 | 说明 |
|---|---|---|
| 1 | **成立，已修** | 白名单枚举必然漏第三方 shell。改为**按参数形状**判定：任何工具的参数里有 `command` 字段就纳入检查。`shellTools` 降级为"额外补充"。同时加了自动纳入的可见告警。 |
| 2 | **成立，已部分修** | 加了脚本旁路检查（`-File` / `bash x.sh` / `& x.ps1` 等）。**未采纳"读失败不放行"**：读不到通常意味着路径写错，脚本根本执行不起来，为此拦住整个调用误伤大于收益。改为告警放行，理由写进代码注释。 |
| 3 | **成立，已修；但报告的修法技术上不成立** | 详情见下。 |
| 4 | **成立，已修** | schema 默认改为 `subagent` 与 patch 对齐；启动时 `logger.info` 打一行生效配置。 |
| 5 | **成立，部分采纳** | 加了后台可选 `import()` 官方包比对，不一致时 `logger.error`。**未采纳"静态 import"**：那会让插件在 profile 无该包时加载期就失败。 |

## 对缺口 3 修法的反驳

报告建议"闸一读取失败时**拒绝该子代理创建**（或至少不创建）"。

**这在技术上做不到。** `agent/created` 是**创建之后**发出的事件——事件到达时子代理已经存在并在运行。在这个扩展点上没有任何"拒绝创建"的语义。

可行的 fail-closed 只能是：**读不到当前档位时，立即把该会话压到最严档（`read-only`）并 `logger.error` 留痕**。已按此实现。这比原来的 `warn` + 放行严格，但达不到报告期望的"拦下创建"——那是内核层的语义，插件层拿不到。

## 报告未提到的连带风险

`depthOf()` 抛错返回 `1`（当作子代理）确实是 fail-closed，但**对父会话是反向的**：

| `denyScope` | 父会话深度读错时的后果 |
|---|---|
| `all` | 无害（本来全拦） |
| `subagent` | **父会话的命令也会被拦**（误伤） |

报告缺口 5 提到"父会话会被压档"这个方向，没提"父会话命令被拦"。同一根因，已记入 README 的 Known limits。

## 关于 P3 的取舍

采纳 `cipher /w` 与 `sdelete` 两条，**不采纳**：

- `robocopy /mir` —— 镜像同步是常见合法操作，误伤率高；
- `mountvol` —— 偏卷管理，且多数用法是只读查看。

## 修复版本

`0.2.0`。行动清单与验证记录见 [../../CHANGELOG.md](../../CHANGELOG.md)。
