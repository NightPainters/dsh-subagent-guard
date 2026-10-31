# AGENTS.md — 给 Agent 的配置说明

这个文件写给**读仓库的 Agent**（也就是「你」），不是写给终端用户的。用户的文档在
`README.md` / `README.zh-CN.md`。

## 一句话分工

- **人只碰两个开关**：插件页那张卡片上的「工具面拦截」「权限拦截」。
- **其余配置由 Agent 改文件**：`cordis.patch.yml`（本包默认层）或 profile 的
  `cordis.patch.yml`（部署覆盖层）。

## 两个开关（人用，别替人改）

| 字段 | 默认 | 关掉之后 |
|---|---|---|
| `enforceToolFace` | `true` | 父 Agent 传给 `delegate` 的 `tools` 不再收窄子代理（显式 `tools: []` 仍照办）。无部署上限时子代理继承父会话完整工具面；有 `enforceMaxTools: true` 时仍压到部署白名单。`persona` 与说明段落照常施加。**副带影响**：只有在没有部署上限时，`subagent` / `subagent_fork` 的派生封锁才一起失效。 |
| `enforceSandbox` | `true` | 沙箱硬顶（`subagentSandboxCap`）整个跳过，子代理完全跟随父会话档位。 |

这两个字段是 `.volatile()`：运行时是 `Volatile<T>` 引用，读值必须走 `.get()`。插件内部统一
用 `flagOf()` 读，**不要**再写 `config.xxx === false`。

## Agent 可以改的（配置文件层）

profile patch 里的覆盖写法：

```yaml
- id: dsh-subagent-guard
  config:
    denyPatterns: [...]      # 整体替换，不是追加；漏写的规则等于删掉
    denyScope: subagent      # all = 连父会话一起拦
    scriptInspection: true
    maxScriptBytes: 262144
    subagentSandboxCap: workspace-write
```

要改之前先确认目标文件：

- 部署覆盖层：`<DSH_HOME>/profiles/<profile>/cordis.patch.yml`
- 本包默认层：`node_modules/dsh-subagent-guard/cordis.patch.yml`（会被升级覆盖，别改这里）

改完不用重启：Loader 会重新组合该 entry（配置类改动）。

**布尔字段必须写裸 `true` / `false`**：带引号的 `"false"` 会让 schema 在 `apply` 之前就拒绝，
插件整个不激活——三道闸一起消失（界面上该插件会显示失败，但没人看就等于没拦）。

## 不要做的事

1. **不要往会话日志里追加自定义事件类型**——第三方插件拿不到 `ignorable` 标记，整条会话会
   变成「打不开」。
2. **不要试图取消子代理的 `subagent` 过滤**来恢复递归：那份过滤是 R1-01 的修法，取消等于让
   被收窄的子代理派生出不受约束的孙代理。要递归就别把这个插件装到那一层。
3. **不要为了「让它别拦我」去改人的开关**：那两个开关是用户的决定，不是 Agent 的。确实被
   规则误伤时，改 `denyPatterns` 并在回复里说明改了哪条。

## 自查命令

```bash
npm test                     # 129 例
node tools/...               # 本仓库没有额外的工具脚本；测试即全部自检
```

装到真机上之后，想确认生效值：设置 `DSH_GUARD_CONFIG_DUMP=<path>` 再启动 DSH，插件会把
**实际收到的配置**写到该文件（排障用，默认不写）。

