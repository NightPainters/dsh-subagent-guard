# 事故复盘：cancel 参数契约违规导致 DSH 整体 fatal

- 日期：2026-10-29 20:53
- 组件：`dsh-subagent-guard` 0.3.6 / `@deepseek-ai/dsh-agent-loop` / `@deepseek-ai/dsh-subagent`
- 影响：整个 DSH 进程退出；同 Job Object 内的子进程（含 CapsWriter 语音输入）被连带终止
- 严重度：高（进程级 fatal，非静默降级）
- 状态：已修复并验证

## TL;DR

**一句话**：guard 取消子代理时传了裸字符串而非 `{kind}` 对象 → DSH 内部把这次取消记成 `reason: null` → 回放日志时读 `null.kind` 抛 TypeError → 整个进程 fatal 退出。

**三层缺陷**（缺任一层都不会崩）：

| 层 | 位置 | 问题 |
|---|---|---|
| 触发 | `dsh-subagent-guard/lib/index.js:755` | `cancel('delegation-policy-unbound')`，契约要求 `{ kind }` |
| 污染 | `dsh-agent-loop/lib/index.js:731` | `abortedCancelCause` 读 `null.kind` 抛错，`turnEnds` 停在 `null` 后被 finally 写进日志 |
| 爆点 | `dsh-subagent/lib/index.js:2668` | 回放时 `reason.kind` 无 null 防护 |

**修复**：三处均已打补丁（`{kind:'disposed'}` + 非对象兜底 + 可选链），脏帧已清理，981 个会话 / 2936 条 `turn/end` 全量回归无异常。

**教训**：`tests/delegate.test.mjs:269` 原本把那个非法字符串断言成了期望值 —— 测试不但没拦住 bug，还把它固化成了"既定行为"。回归测试必须断言**契约形状**，不能只断言当前实现。

**注意**：agent-loop 与 subagent 两处补丁在 `node_modules`，整包升级会被覆盖，需重打（原件在 `_cw_recon\patch_backup_20261029\`）。

## 一、现象

20:53:33，DSH 终端打印：

```
dsh: fatal load failure: TypeError: Cannot read properties of null (reading 'kind')
    at Object.apply (dsh-subagent/lib/index.js:2668:42)
    at Object.apply (dsh-session-projection/lib/index.js:74:40)
    at Proxy.advanceCell (dsh-session-projection/lib/index.js:391:21)
    ...
```

进程以 code 1 退出。终端窗口留给用户阅读错误 10 分钟后自动关闭。

## 二、根因：三层缺陷叠加

### ① 触发源 —— 本插件传错 cancel 参数

`lib/index.js`（修改前第 755 行）：

```js
target.cancel('delegation-policy-unbound')   // 裸字符串
```

`agent.cancel(cause)` 的契约是 `AgentCancelCause = { kind: 'user' | 'parent' | 'disposed' | 'hook' }`。
DSH 官方全部调用点（`dsh-agent`、`dsh-subagent` 三处、`dsh-agent-loop`）一律传 `{ kind: ... }` 对象。

`ReactLoopAgent.cancel` 的实现是直通：

```js
cancel(cause, options = {}) {
  if (!options.keepInbox) { ... }
  if (this.phase.kind !== "idle") this.phase.abort.abort(cause);   // reason 变成那个字符串
}
```

于是 `signal.reason` 成了一个字符串。

### ② 污染源 —— DSH 的 `abortedCancelCause` 不容错，异常发生在 catch 块内

`dsh-agent-loop/lib/index.js`（修改前 731-745 行）：

```js
function abortedCancelCause(signal) {
  if (!signal.aborted) return void 0;
  const cause = signal.reason;      // 'delegation-policy-unbound'
  switch (cause.kind) {             // undefined → 落到 default
    case "user": ...
    default: return assertNever(cause);   // 抛错
  }
}
```

它被 `turn()` 的 **catch 块**调用（1011 行）：

```js
} catch (error) {
  const cause = abortedCancelCause(signal);   // ← 这里抛
  if (cause !== void 0) { turnEnds = { kind: "aborted", reason: cause }; throw error; }
  turnEnds = { kind: "error", ... };
  this.throwError(error);
} finally {
  this.session.append("turn/end", { turn, reason: turnEnds });   // turnEnds 仍是 null
}
```

`abortedCancelCause` 抛出后，`turnEnds`（950 行初始为 `null`）**永远不会被赋值**，
`finally` 无条件把 `reason: null` 写进会话日志。

### ③ 爆点 —— 投影层无 null 防护

`dsh-subagent/lib/index.js:2668`：

```js
lastTurnCompleted: event.data.reason.kind === "completed"
```

`turn/end` 事件回放时 `data.reason` 为 null → `TypeError`。
该 apply 由 `dsh-session-projection` 在 `stateOf → materializeCells → cellFor → advanceCell`
路径上调用，异常无人捕获 → 进程 fatal。

### 为什么是子代理会话

`turn/end` 的 reason 只在这个 `turn()` 的 finally 里写一次。中毒的文件是
`6cd33003-5a58-457d-90a1-b4e2af528eaf`（`origin: "subagent"`、`delegationDepth: 1`、
label `冷恢复探针A`、父会话 `session-672711cc`），只有 1703 B、3 帧，事件序列为：

```
subagent/descriptor → sandbox/mode(danger-full-access, delegation) → approval/policy
→ permission/preset → sandbox/mode(workspace-write) → subagent/model-selection-policy
→ agent/inbox/spliced（探针 prompt）→ turn/start(turn:1)
→ agent/inbox/spliced(removedCount:1) → turn/end(turn:1, reason:null)   ← 脏
```

即：guard 在 `agent/created` 之后发现策略没绑定成功（`claimed !== policy || policy.bound !== true`），
走 fail-closed 分支取消该子代理；子代理刚 `turn/start` 就被 abort，abort 的 cause 是那个裸字符串，
随后上述链条成立。

## 三、证据

| 环节 | 证据 |
|---|---|
| 崩溃时刻 | `E:\DSH-Portable\logs\last-start-error.txt` = `2026/10/29 20:53:33.28 DSH START FAILED` |
| 脏事件存在 | 全量扫描 981 个当前代（v4）会话日志、2936 个 `turn/end`，**仅此 1 处** `reason: null` |
| 脏事件位置 | 文件 `frame:2`、字节区间 `[546,1703)`、帧内第 5 行（0-based） |
| 正常形态 | 同会话其余 `turn/end` 全部为 `{"kind":"completed"}` |
| 用户侧对应 | 该会话 UI 显示 `dsh-subagent-guard: 子代理未能绑定工具面与 prompt，已取消本次委派（fail-closed）` |
| 连带伤亡 | CapsWriter 由 DSH 的 Windows Job Object 管理，DSH 退出时被整组终止（20:53:16 先死、20:53:33 DSH 退出） |

## 四、修复

### 本插件

```diff
-          target.cancel('delegation-policy-unbound')
+          target.cancel({ kind: 'disposed' })
```

`disposed` 而非 `user`：这是系统主动销毁未受约束的子代理，语义正确；且
`ReactLoopAgent.wakeDriver` / `runMaintenance` 中对 `?.kind !== "disposed"` 的判断能正确配合。

### DSH 侧（本地补丁，非上游）

`dsh-agent-loop/lib/index.js`，`abortedCancelCause` 内增加：

```js
if (cause === null || typeof cause !== "object") return { kind: "disposed" };
```

`dsh-subagent/lib/index.js:2668`：

```diff
- lastTurnCompleted: event.data.reason.kind === "completed"
+ lastTurnCompleted: event.data?.reason?.kind === "completed"
```

两处均为防未来第三方插件/调用方再传非法 cause，属于纵深防御。

### 数据修复

将中毒帧的 `"reason":null` 替换为 `"reason":{"kind":"disposed"}`，仅重压该单帧、
其余帧原样拼接。原文件已备份为 `session.v4.jsonl.zstd.orig`。

## 五、验证

1. 三个改过的 `lib/index.js` 复制为 `.mjs` 后 `node --check` 全部通过（ESM 必须用 `.mjs`，
   否则 `node --check` 按 CJS 解析会误报）。
2. 修复脚本自检 `nullReasonsLeft === 0`，并用**独立的**批量扫描器复扫同一文件：
   `turnEnds=1 nullReasons=0`。
3. 全量回归：981 个当前代会话日志 / 2936 个 `turn/end` → `nullReasons=0`，
   `turnEnds` 总数与修复前一致（排除误删帧造成的静默损失）。

## 六、教训

- **真实机上跑出来的问题，单测覆盖不到是常态，但没有覆盖的唯一可执行结论是“补测试”，
  不是“下次注意”。** 这条路径（fail-closed 取消 → 非法 cause → catch 内抛错 → 写 null reason）
  在测试台从未走通；现有测试只验证了“策略未绑定时会抛错”，没验证“抛错之后会话日志写成什么”。
- **`cancel()` 的 cause 是跨包契约**，本项目在 0.3.6 里已经吃过一次“子代理续跑后守卫失效”
  （见 CHANGELOG 0.3.6），同属“只在真机探针上暴露的集成缺陷”，应视为同一类问题域。
- **日志持久化层的容错优先级**：`turn/end` 是每次 turn 必然写入的收尾事件，其 reason 为 null
  会让整个会话永久不可加载。这一层应该对非法输入做兜底，而不是让异常穿透 finally。

## 七、回滚

| 对象 | 备份 |
|---|---|
| 本插件源码 | `_cw_recon\patch_backup_20261029\dsh-subagent-guard__index.js` |
| `dsh-agent-loop` | `_cw_recon\patch_backup_20261029\dsh-agent-loop__index.js` |
| `dsh-subagent` | `_cw_recon\patch_backup_20261029\dsh-subagent__index.js` |
| 会话日志 | `_cw_recon\patch_backup_20261029\session.v4.jsonl.zstd.orig` |

注意：DSH 侧两处补丁位于 `node_modules`，**下次整包升级会被覆盖**，升级后需重新打。
