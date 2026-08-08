#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stops and removes the Aegis Defense Windows Service.

.PARAMETER KeepData
    If set, leaves %ProgramData%\AegisDefense (database, logs, keys) in place. By default
    the script only removes the service registration - data is preserved unless -PurgeData
    is also specified, since deleting the event/alert database is rarely what an operator
    doing routine maintenance actually wants.

.PARAMETER PurgeData
    Also deletes %ProgramData%\AegisDefense entirely (database, logs, trusted keys). This is
    destructive and cannot be undone - forensic evidence and audit logs are lost.
#>
[CmdletBinding()]
param(
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"
$ServiceName = "AegisDefenseService"

$existing = sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Service '$ServiceName' is not installed - nothing to do." -ForegroundColor Yellow
} else {
    Write-Host "Stopping service '$ServiceName'..." -ForegroundColor Cyan
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "Removing service '$ServiceName'..." -ForegroundColor Cyan
    sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with exit code $LASTEXITCODE." }
}

if ($PurgeData) {
    $root = Join-Path $env:ProgramData "AegisDefense"
    if (Test-Path $root) {
        Write-Host "Purging data directory '$root'..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $root
    }
} else {
    Write-Host "Data directory under %ProgramData%\AegisDefense was left in place. Re-run with -PurgeData to remove it." -ForegroundColor Cyan
}

Write-Host "Done." -ForegroundColor Green
