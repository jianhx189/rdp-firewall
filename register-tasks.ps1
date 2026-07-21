# wry RDP guard - scheduled task registration (ASCII safe, no QClaw dependency)
# Must run elevated. Registers all 3 tasks as SYSTEM.
$TaskGuard  = "wry-rdp-guard"
$TaskWeb    = "wry-rdp-web"
$TaskReport = "wry-rdp-report"
$WorkDir    = "C:\Users\jianh\.qclaw\workspace\rdp-firewall"

$StableNode = "D:\app\nodejs\node.exe"
$NodePath = $StableNode
if (-not (Test-Path $NodePath)) { $NodePath = "node" }
Write-Host "Node path: $NodePath"

# Cleanup any previous wry* tasks (covers legacy Chinese-named tasks too)
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like "wry*" } | ForEach-Object {
    try {
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed old task: $($_.TaskName)"
    } catch {}
}

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable:$false -ExecutionTimeLimit (New-TimeSpan -Minutes 2)

# Guard: one-shot, runs every minute
$ActionGuard = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$WorkDir\rdp-guard.js`"" -WorkingDirectory $WorkDir
$TriggerGuard = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
Register-ScheduledTask -TaskName $TaskGuard -Action $ActionGuard -Trigger $TriggerGuard -Principal $Principal -Settings $Settings -Force
Write-Host "Registered $TaskGuard"

# Web watchdog: one-shot, runs every minute, spawns web if port not listening
$ActionWeb = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$WorkDir\wry-web-watchdog.js`"" -WorkingDirectory $WorkDir
$TriggerWeb = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
Register-ScheduledTask -TaskName $TaskWeb -Action $ActionWeb -Trigger $TriggerWeb -Principal $Principal -Settings $Settings -Force
Write-Host "Registered $TaskWeb"

# Daily report at 08:00 and 20:00
$ActionReport = New-ScheduledTaskAction -Execute $NodePath -Argument "`"$WorkDir\send-report-html.js`"" -WorkingDirectory $WorkDir
$TriggerReport = @(
    (New-ScheduledTaskTrigger -Daily -At "08:00"),
    (New-ScheduledTaskTrigger -Daily -At "20:00")
)
Register-ScheduledTask -TaskName $TaskReport -Action $ActionReport -Trigger $TriggerReport -Principal $Principal -Settings $Settings -Force
Write-Host "Registered $TaskReport"

Write-Host "DONE"
Get-ScheduledTask -TaskName "wry-rdp-*" | Select-Object TaskName, State, @{n='Node';e={$_.Actions[0].Execute}} | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
