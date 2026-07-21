# Check web dashboard
$webOk = (Test-NetConnection -ComputerName 127.0.0.1 -Port 19888 -WarningAction SilentlyContinue).TcpTestSucceeded
Write-Output "WEB_OK=$webOk"

# Check engine task
$engineTask = Get-ScheduledTaskInfo -TaskName 'wry合金防护'
Write-Output "ENGINE LastRun=$($engineTask.LastRunTime) Result=$($engineTask.LastTaskResult)"

# Check web guard task
$webTask = Get-ScheduledTaskInfo -TaskName 'wry合金防护Web守护'
Write-Output "WEBGUARD LastRun=$($webTask.LastRunTime) Result=$($webTask.LastTaskResult)"

# Check daily report task (result 2147942402 = 0x80070102 = timeout, non-critical)
$dailyTask = Get-ScheduledTaskInfo -TaskName 'wry合金防护日报'
Write-Output "DAILY LastRun=$($dailyTask.LastRunTime) Result=$($dailyTask.LastTaskResult)"

# Try HTTP request to web dashboard
try {
    $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:19888' -TimeoutSec 5 -UseBasicParsing
    Write-Output "HTTP_STATUS=$($resp.StatusCode)"
} catch {
    Write-Output "HTTP_ERROR=$($_.Exception.Message)"
}
