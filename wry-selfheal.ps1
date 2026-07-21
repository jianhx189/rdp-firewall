# wry-selfheal.ps1 — non-elevated watchdog for RDP Guard engine + web dashboard
# Relaunches processes via WMI using the real system node, independent of exec sessions.
# Scheduled tasks currently point to a dead QClaw node path (post-update) and need admin to fix;
# this script is the non-elevated safety net.

$ErrorActionPreference = 'SilentlyContinue'

# 解析 Node 路径：优先稳定安装 D:\app\nodejs\node.exe，其次 QClaw 任意版本自带 node，最后退回 PATH
$node = 'node'
if (Test-Path 'D:\app\nodejs\node.exe') { $node = 'D:\app\nodejs\node.exe' }
else {
    $qclawBase = 'C:\Program Files\QClaw'
    if (Test-Path $qclawBase) {
        $versions = Get-ChildItem $qclawBase -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object Name -Descending
        foreach ($v in $versions) {
            $cand = Join-Path $v.FullName 'resources\node\node.exe'
            if (Test-Path $cand) { $node = $cand; break }
        }
    }
}
$work   = 'C:\Users\jianh\.qclaw\workspace\rdp-firewall'
$webJs  = Join-Path $work 'wry-web.js'
$guardJs= Join-Path $work 'rdp-guard.js'
$webLog = Join-Path $work 'wry-web.log'
$snap   = 'C:\Users\jianh\Documents\rdp_snapshots.json'
$report = @()

function Start-Detached($script, $log) {
  # 使用 ProcessStartInfo 而非 WMI/Win32_Process，避免弹窗
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $node
  $psi.Arguments = "`"$script`""
  $psi.WorkingDirectory = $work
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  # 异步输出写入日志文件
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  [System.Threading.Tasks.Task]::WhenAll($outTask, $errTask).ContinueWith({
    $content = $outTask.Result
    if ($errTask.Result) { $content += "`n" + $errTask.Result }
    if ($content.Trim()) {
      try { Add-Content -Path $log -Value $content -ErrorAction SilentlyContinue } catch {}
    }
  }) | Out-Null
  $p.Dispose()
}

# 1) Web dashboard: must be LISTENING on 19888
$listening = Get-NetTCPConnection -State Listen -LocalPort 19888 -ErrorAction SilentlyContinue
if (-not $listening) {
  Start-Detached $webJs $webLog
  $report += 'WEB_RESTARTED'
} else {
  $report += 'WEB_OK'
}

# 2) Engine: rdp-guard.js is one-shot; run it every cycle to refresh the snapshot.
Start-Detached $guardJs (Join-Path $work 'rdp-guard.log')
if (Test-Path $snap) {
  $age = ((Get-Date) - (Get-Item $snap).LastWriteTime).TotalMinutes
  $report += ('ENGINE_RAN (prev_age={0:N1}m)' -f $age)
} else {
  $report += 'ENGINE_RAN (no_prev_snap)'
}

($report -join ' | ')
