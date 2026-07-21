$tasks = Get-ScheduledTask
foreach($t in $tasks){
    if($t.TaskName -like '*RDP*' -or $t.TaskName -like '*Guard*'){
        Write-Output ($t.TaskName + ' | ' + $t.State)
    }
}
