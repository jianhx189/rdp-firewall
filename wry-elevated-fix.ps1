# wry elevated fix - runs in admin context (launched via -Verb RunAs)
$log = "C:\Users\jianh\Documents\wry-fix-result.log"
function Log($m){ $m | Out-File -Append -FilePath $log -Encoding ascii }
Log "=== wry elevated fix started $(Get-Date) ==="

# 1) Kill anything still listening on 19888 (old 0.0.0.0 web panel)
$listeners = Get-NetTCPConnection -LocalPort 19888 -State Listen -ErrorAction SilentlyContinue
if ($listeners) {
    $listeners | ForEach-Object {
        try { Stop-Process -Id $_.OwningProcess -Force -ErrorAction Stop; Log "Killed PID $($_.OwningProcess) holding 19888" }
        catch { Log "Kill PID $($_.OwningProcess) failed: $($_.Exception.Message)" }
    }
} else { Log "19888 not held by any process" }
Start-Sleep -Seconds 1
$a = Get-NetTCPConnection -LocalPort 19888 -State Listen -ErrorAction SilentlyContinue
if ($a) { Log "WARN 19888 still held by PID $($a.OwningProcess) on $($a.LocalAddress)" } else { Log "19888 is FREE" }

# 2) Re-register all 3 tasks (D:\app\nodejs, no QClaw)
Log "--- running register-tasks.ps1 ---"
& "C:\Users\jianh\.qclaw\workspace\rdp-firewall\register-tasks.ps1" 2>&1 | ForEach-Object { Log $_ }

# 3) Start guard + web tasks immediately
try { Start-ScheduledTask -TaskName "wry-rdp-guard" -ErrorAction Stop; Log "Started wry-rdp-guard" }
catch { Log "Start guard failed: $($_.Exception.Message)" }
try { Start-ScheduledTask -TaskName "wry-rdp-web" -ErrorAction Stop; Log "Started wry-rdp-web" }
catch { Log "Start web failed: $($_.Exception.Message)" }

# 4) Wait for watchdog to spawn web, then verify
Start-Sleep -Seconds 12
$b = Get-NetTCPConnection -LocalPort 19888 -State Listen -ErrorAction SilentlyContinue
if ($b) { Log "19888 listening at $($b.LocalAddress):$($b.LocalPort) PID=$($b.OwningProcess)" } else { Log "ERROR 19888 NOT listening after start" }

$r = Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
Log "RDP enabled rules count: $($r.Count)"

# 5) Confirm guard actually ran (new snapshot within last 2 min)
$snapFile = "C:\Users\jianh\Documents\rdp_snapshots.json"
try {
    $snaps = Get-Content $snapFile -Raw -ErrorAction Stop | ConvertFrom-Json
    $last = $snaps[-1]
    $ageMin = [math]::Round(([DateTimeOffset]::Now.ToUnixTimeMilliseconds() - $last.ts)/60000, 1)
    Log "Last guard snapshot age: $ageMin min (total=$($last.total))"
} catch { Log "Snapshot check failed: $_" }

Log "=== wry elevated fix finished $(Get-Date) ==="
