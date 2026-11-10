<#
.SYNOPSIS
    Create (or remove) a Windows Task Scheduler task that scans this PC on a schedule
    and opens the change report.

.PARAMETER Every
    Weekly (default) or Monthly.

.PARAMETER DayOfWeek
    For weekly scans: the day to run. Default Sunday.

.PARAMETER Day
    For monthly scans: the day of the month to run (1-28). Default 1.

.PARAMETER Time
    Time of day, 24-hour HH:mm. Default 00:00 (midnight at the start of that day). If the PC
    is off or asleep then, the scan runs as soon as possible afterwards.

.PARAMETER Elevated
    Run the scan with administrator rights so protected folders (other user profiles,
    some system folders) are included. Run this script from an administrator PowerShell
    when you use this switch.

.PARAMETER Remove
    Delete the scheduled task.

.PARAMETER DryRun
    Show the task definition without registering it.

.EXAMPLE
    .\Install-ScheduledScan.ps1                                  # every Sunday at 00:00
    .\Install-ScheduledScan.ps1 -DayOfWeek Saturday -Time 09:30
    .\Install-ScheduledScan.ps1 -Every Monthly -Day 1 -Time 12:00
    .\Install-ScheduledScan.ps1 -Remove
#>
param(
    [ValidateSet('Weekly', 'Monthly')][string]$Every = 'Weekly',
    [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
    [string]$DayOfWeek = 'Sunday',
    [ValidateRange(1, 28)][int]$Day = 1,
    [ValidatePattern('^([01]?\d|2[0-3]):[0-5]\d$')][string]$Time = '00:00',
    [switch]$Elevated,
    [switch]$Remove,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Computer Mapper - scheduled scan'
$LegacyTaskNames = @('Computer Mapper - monthly scan')

if ($Remove) {
    $found = $false
    foreach ($name in @($TaskName) + $LegacyTaskNames) {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "Removed the scheduled task '$name'."
            $found = $true
        }
    }
    if (-not $found) { Write-Host "There is no Computer Mapper scheduled task." }
    return
}

if ($Elevated) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "-Elevated needs an administrator PowerShell. Right-click PowerShell, choose 'Run as administrator', and run this again."
    }
}

$here = $PSScriptRoot
$scan = Join-Path $here 'Scan-Computer.ps1'
$x = { param($s) [Security.SecurityElement]::Escape($s) }
$h, $m = $Time.Split(':')
$start = (Get-Date).Date.AddHours([int]$h).AddMinutes([int]$m).ToString('yyyy-MM-ddTHH:mm:ss')
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$runLevel = if ($Elevated) { 'HighestAvailable' } else { 'LeastPrivilege' }

if ($Every -eq 'Weekly') {
    $schedule = "<ScheduleByWeek><DaysOfWeek><$DayOfWeek /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>"
    $when = "every $DayOfWeek at $Time"
} else {
    $months = (1..12 | ForEach-Object { '<' + [Globalization.CultureInfo]::InvariantCulture.DateTimeFormat.GetMonthName($_) + ' />' }) -join ''
    $schedule = "<ScheduleByMonth><DaysOfMonth><Day>$Day</Day></DaysOfMonth><Months>$months</Months></ScheduleByMonth>"
    $when = "on day $Day of every month at $Time"
}

$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>$(& $x "Maps every file, folder and program on this PC $when and opens a report of what changed since the previous scan. Installed from $here.")</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>$start</StartBoundary>
      <Enabled>true</Enabled>
      $schedule
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$(& $x $user)</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>$runLevel</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>$(& $x "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$scan`" -Scheduled")</Arguments>
      <WorkingDirectory>$(& $x $here)</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

[xml]$xml | Out-Null   # fail early if the definition is malformed
if ($DryRun) {
    Write-Host "Dry run: this task definition would be registered as '$TaskName':"
    Write-Output $xml
    return
}

foreach ($name in $LegacyTaskNames) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "Replaced the older task '$name'."
    }
}
Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
$next = (Get-ScheduledTaskInfo -TaskName $TaskName).NextRunTime
Write-Host "Scheduled '$TaskName': $when$(if ($Elevated) { ' (as administrator)' })."
Write-Host "Next run: $next"
Write-Host "Run it now with:  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Remove it with:   .\Install-ScheduledScan.ps1 -Remove"
