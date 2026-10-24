# dsh-subagent-guard

给 [DeepSeek Harness][dsh] 的子代理上两道闸：**沙箱档位硬顶** + **破坏性命令黑名单**。

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

## 两道闸

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
          - '\\bvssadmin\\b[^\\r\\n]*\\b(?:delete|resize|revert)\\b'
          - '\\bdiskpart\\b'
```

启动时会打一行**生效配置**（`生效配置：subagentSandboxCap=… denyScope=… 规则=16 条 …`），
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
- 改写子代理档位靠追加 `sandbox/mode` 事件（会话日志是唯一存储），重启后可通过
  replay 复现；子代理会话被归档后不再重放。

[cve]: https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape/

## 兼容性

已核对到 `@deepseek-ai/dsh-*` **0.2.1-rc.2**（2026-10-24）。插件**复制**了两小段官方
实现，而不是 import 兄弟 `dsh-*` 包——因为 profile 的 `node_modules` 通常只有
`schemastery`，静态 import 会在加载期解析失败。代价是：如果 DSH 改了
`subagentDepth`、`delegationDepth` 或 `sandbox/mode` 事件，这两份副本会**静默失配**。
插件会在运行时尝试 `import()` 官方包做比对，不一致时告警——但这个检查只在官方包
恰好可解析时才生效。

## 测试

```bash
node tests/guard.test.mjs    # 纯规则层，不依赖宿主
node tests/apply.test.mjs    # 接线层，假 ctx 驱动
```

33 条用例，全部脱离宿主：`lib/rules.js` 不 import 任何 DSH 包。

## 外部审计

- [2026-10-24 拦截面缺口审计](./docs/research/2026-10-24-external-audit.md)：
  真实部署上的用户报告了五条缺口，附维护者逐条裁定，以及 0.2.0 落地的修法。

## 许可证

MIT — 见 [LICENSE](./LICENSE)。
