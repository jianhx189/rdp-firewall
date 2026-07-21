# wry合金防护 计划任务注册脚本
# [FIX 2026-07-04] 改为幂等模式：先删同名任务再创建，避免重复任务
# 以管理员身份运行 PowerShell 执行此脚本
# 注册为 SYSTEM 用户，开机自启动，不依赖 qclaw

$TaskName = "wry合金防护"
$TaskNameReport = "wry合金防护日报"
$WorkDir = "C:\Users\jianh\.qclaw\workspace\rdp-firewall"

# 解析 Node 路径：优先 QClaw 任意版本自带 node（升级自动跟随），回退到稳定安装 D:\app\nodejs\node.exe
$qclawBase = "C:\Program Files\QClaw"
$NodePath = $null
if (Test-Path $qclawBase) {
    $versions = Get-ChildItem $qclawBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object Name -Descending
    foreach ($v in $versions) {
        $cand = Join-Path $v.FullName "resources\node\node.exe"
        if (Test-Path $cand) { $NodePath = $cand; break }
    }
}
if (-not $NodePath -or -not (Test-Path $NodePath)) { $NodePath = "D:\app\nodejs\node.exe" }
if (-not (Test-Path $NodePath)) { $NodePath = "node" }
Write-Host "使用 Node 路径: $NodePath" -ForegroundColor Cyan

# [FIX] 幂等处理：先删除所有同名旧任务（防止重复）
$AllTaskNames = @(
    $TaskName,
    "$TaskNameWeb",
    "$TaskNameReport",
    "wry合金防护Web守护",
    "wry鍚堥噕闃叉姢Web"
)
foreach ($tname in $AllTaskNames) {
    $existing = Get-ScheduledTask -TaskName $tname -ErrorAction SilentlyContinue
    if ($existing) {
        try {
            Unregister-ScheduledTask -TaskName $tname -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "已删除旧任务: $tname" -ForegroundColor Gray
        } catch {}
    }
}

Write-Host "=== 注册 wry合金防护 计划任务 ===" -ForegroundColor Cyan
$ActionGuard = New-ScheduledTaskAction -Execute "$NodePath" -Argument "`"$WorkDir\rdp-guard.js`"" -WorkingDirectory "$WorkDir"
$TriggerGuard = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1).ToString("HH:mm") -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)

# 每天 8:00 执行上午报告
$ActionReport8 = New-ScheduledTaskAction -Execute "$NodePath" -Argument "`"$WorkDir\send-report-html.js`"" -WorkingDirectory "$WorkDir"
$TriggerReport8 = New-ScheduledTaskTrigger -Daily -At "08:00"

# 每天 20:00 执行下午报告
$ActionReport20 = New-ScheduledTaskAction -Execute "$NodePath" -Argument "`"$WorkDir\send-report-html.js`"" -WorkingDirectory "$WorkDir"
$TriggerReport20 = New-ScheduledTaskTrigger -Daily -At "20:00"

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

# 注册 guard 任务（每分钟）
Register-ScheduledTask -TaskName "$TaskName" -Action $ActionGuard -Trigger $TriggerGuard -Principal $Principal -Settings $Settings -Force

# 注册 Web 守护任务（每分钟 watchdog）
$ActionWebWatchdog = New-ScheduledTaskAction -Execute "$NodePath" -Argument "`"$WorkDir\wry-web-watchdog.js`""
$TriggerWebWatchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1).ToString("HH:mm") -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
Register-ScheduledTask -TaskName "wry合金防护Web守护" -Action $ActionWebWatchdog -Trigger $TriggerWebWatchdog -Principal $Principal -Settings $Settings -Force

# 注册日报任务（多个触发器）
$domain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $env:COMPUTERNAME }
$PrincipalReport = New-ScheduledTaskPrincipal -UserId "$domain\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "$TaskNameReport" -Action $ActionReport8 -Trigger @($TriggerReport8, $TriggerReport20) -Principal $PrincipalReport -Settings $Settings -Force

Write-Host "计划任务已注册："
Get-ScheduledTask -TaskName "$TaskName*" | Select-Object TaskName, State, NextRunTime
