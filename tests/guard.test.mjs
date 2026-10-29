/**
 * 纯规则层单测：不加载 DSH 宿主，只 import lib/rules.js。
 * 跑法：node tests/guard.test.mjs
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_DENY_PATTERNS,
  commandOf,
  compileRules,
  matchCommand,
  scriptPathOf,
  shouldCapSandbox,
  skipByScope,
} from '../lib/rules.js'

const rules = compileRules(DEFAULT_DENY_PATTERNS)

/** @param {string} cmd */
const hit = (cmd) => matchCommand(cmd, rules)

test('默认黑名单拦住批量删除卷影副本的命令', () => {
  assert.ok(hit('vssadmin delete shadows /all /quiet'), 'vssadmin delete shadows 必须被拦')
  assert.ok(hit('vssadmin.exe delete shadows /for=C: /oldest'))
  assert.ok(hit('vssadmin resize shadowstorage /for=C: /on=D: /maxsize=10GB'))
  assert.ok(hit('vssadmin revert shadow'))
})

test('默认黑名单拦住还原点、分区表、引导配置、关机', () => {
  for (const cmd of [
    'Remove-ComputerRestorePoint -RestorePoint 12',
    'Disable-ComputerRestore -Drive "C:\\"',
    'Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }',
    'wmic shadowcopy delete',
    'diskpart /s clean.txt',
    'Format-Volume -DriveLetter D -FileSystem NTFS',
    'Clear-Disk -Number 1 -RemoveData',
    'Initialize-Disk -Number 1',
    'Remove-Partition -DriveLetter D',
    'format C: /q',
    'bcdedit /set {default} recoveryenabled No',
    'reg delete HKLM\\SOFTWARE\\Foo /f',
    'Stop-Computer -Force',
    'shutdown /r /t 0',
  ]) {
    assert.ok(hit(cmd), `应拦：${cmd}`)
  }
})

test('不误伤日常命令', () => {
  for (const cmd of [
    'Get-ChildItem D:\\work',
    'vssadmin list shadows',
    'Remove-Item .\\tmp\\a.txt',
    'del /q build\\*.obj',
    'Get-Process | Format-Table -AutoSize',      // 关键：不能被 format 规则误伤
    'git status',
    'node tests/guard.test.mjs',
    'Get-Volume | Select-Object DriveLetter,SizeRemaining',
    'wevtutil qe System',
  ]) {
    assert.equal(hit(cmd), undefined, `不应拦：${cmd}`)
  }
})

test('默认黑名单拦住不可恢复的数据擦除', () => {
  // 2026-10-24 外部审计建议：按"不可恢复"这同一把尺子补的两条。
  assert.ok(hit('cipher /w:C'), 'cipher /w 擦除空闲空间')
  assert.ok(hit('cipher.exe /w:C:\\'), 'cipher.exe 形式')
  assert.ok(hit('sdelete -p 3 C:\\secret'), 'sdelete 安全删除')
  assert.equal(hit('cipher /e file.txt'), undefined, '普通加密不该被拦')
})

test('多行命令里命中任意一行即拒绝', () => {
  const cmd = ['Get-Date', 'Write-Host "backup"', 'vssadmin delete shadows /all /quiet'].join('\n')
  assert.ok(hit(cmd))
})

test('大小写不敏感', () => {
  assert.ok(hit('VSSADMIN DELETE SHADOWS /ALL /QUIET'))
  assert.ok(hit('DISKPART /s clean.txt'))
})

test('commandOf 只认非空字符串 command', () => {
  assert.equal(commandOf({ command: 'whoami' }), 'whoami')
  assert.equal(commandOf({ command: '   ' }), undefined)
  assert.equal(commandOf({ command: 42 }), undefined)
  assert.equal(commandOf({ cmd: 'whoami' }), undefined)
  assert.equal(commandOf(null), undefined)
  assert.equal(commandOf('whoami'), undefined)
})

test('shouldCapSandbox 只降不升', () => {
  assert.equal(shouldCapSandbox('danger-full-access', 'workspace-write'), true)
  assert.equal(shouldCapSandbox('workspace-write', 'read-only'), true)
  assert.equal(shouldCapSandbox('workspace-write', 'workspace-write'), false)
  assert.equal(shouldCapSandbox('read-only', 'workspace-write'), false, '不能给子代理升档')
  assert.equal(shouldCapSandbox('read-only', 'read-only'), false)
  // 2026-10-28 审计 F1：**未登记**的档位名按「不知道它多宽」处理 ⇒ 压。
  // 原实现返回 false（不压也不告警），宿主一加新档位这个插件就静默失效。
  assert.equal(shouldCapSandbox('unknown-mode', 'read-only'), true)
  assert.equal(shouldCapSandbox('danger-full-access', 'unknown-cap'), false)
})

test('skipByScope：subagent 档只放过顶层', () => {
  assert.equal(skipByScope('subagent', 0), true)
  assert.equal(skipByScope('subagent', 1), false)
  assert.equal(skipByScope('subagent', 2), false)
  assert.equal(skipByScope('all', 0), false)
  assert.equal(skipByScope('all', 3), false)
})

test('非法正则加载期响亮失败', () => {
  assert.throws(() => compileRules(['vssadmin(']), /非法的 denyPatterns 正则/)
})

test('空规则表不拦任何命令', () => {
  assert.equal(matchCommand('vssadmin delete shadows /all /quiet', []), undefined)
})

test('commandOf 支持自定义参数名（第三方 shell 的参数可能不叫 command）', () => {
  assert.equal(commandOf({ script: 'whoami' }, 'script'), 'whoami')
  assert.equal(commandOf({ script: 'whoami' }, 'command'), undefined)
})

test('scriptPathOf 只从明确的脚本执行形式里抠路径', () => {
  assert.equal(scriptPathOf('pwsh -File C:\\tmp\\x.ps1'), 'C:\\tmp\\x.ps1')
  assert.equal(scriptPathOf('pwsh -File "C:\\my dir\\x.ps1"'), 'C:\\my dir\\x.ps1')
  assert.equal(scriptPathOf('powershell.exe -f .\\run.ps1'), '.\\run.ps1')
  assert.equal(scriptPathOf('bash ./deploy.sh'), './deploy.sh')
  assert.equal(scriptPathOf('& "C:\\x\\y.ps1"'), 'C:\\x\\y.ps1')

  // 认不出就不管，交给命令行文本那一层
  assert.equal(scriptPathOf('Get-Date'), undefined)
  assert.equal(scriptPathOf('pwsh -c "Get-Date"'), undefined)
  assert.equal(scriptPathOf('bash -c whoami'), undefined, '`-c` 不是脚本文件')
  assert.equal(scriptPathOf('echo vssadmin delete shadows'), undefined)
})
