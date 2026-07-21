# Check web dashboard
$webOk = $false
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect('127.0.0.1', 19888)
    $webOk = $true
    $tcp.Close()
} catch {
    $webOk = $false
}

# Check rdp-guard process
$engine = Get-Process -Name 'node' -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*rdp-guard*' -or $_.Path -like '*node*' }
$nodeProcs = Get-Process -Name 'node' -ErrorAction SilentlyContinue
$wryWeb = Get-Process -Name 'node' -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like '*wry*' }

Write-Output "WEB_LISTENING=$webOk"
Write-Output "NODE_PROCS=$($nodeProcs.Count)"

# Check recent RDP data file
$dataFile = Get-ChildItem 'C:\Users\jianh\Documents\rdp_*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if($dataFile){
    $age = (Get-Date) - $dataFile.LastWriteTime
    Write-Output ("DATA_FILE=" + $dataFile.Name + " | AGE_MIN=" + [math]::Round($age.TotalMinutes))
} else {
    Write-Output "DATA_FILE=NONE"
}
