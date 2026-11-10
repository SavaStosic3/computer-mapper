<#
.SYNOPSIS
    Map every file, folder and program on this PC, compare with the previous scan,
    and open a report of what changed.

.DESCRIPTION
    Saves a snapshot in data\snapshots and a report in reports\. Usually takes under a minute.
    Run it from an administrator PowerShell to include folders that need admin rights.

.PARAMETER NoOpen
    Don't open the report in the browser when the scan finishes.

.PARAMETER Scheduled
    Used by the scheduled task: logs failures and shows a pop-up if the scan fails.
#>
param(
    [switch]$NoOpen,
    [switch]$Scheduled
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'mapper\find-python.ps1')
Set-Location $PSScriptRoot

try {
    $python = Find-MapperPython
    $scanArgs = @('-m', 'mapper', 'scan')
    if ($NoOpen) { $scanArgs += '--no-open' }
    & $python @scanArgs
    if ($LASTEXITCODE -ne 0) { throw "The scan stopped with exit code $LASTEXITCODE. See data\logs for details." }
}
catch {
    $msg = "Computer Mapper scan failed: $($_.Exception.Message)"
    Write-Host $msg -ForegroundColor Red
    if ($Scheduled) {
        $logDir = Join-Path $PSScriptRoot 'data\logs'
        New-Item -ItemType Directory -Force $logDir | Out-Null
        Add-Content -Path (Join-Path $logDir 'scheduled-errors.log') -Value "$(Get-Date -Format s) $msg"
        (New-Object -ComObject WScript.Shell).Popup($msg, 0, 'Computer Mapper', 0x30) | Out-Null
    }
    exit 1
}
