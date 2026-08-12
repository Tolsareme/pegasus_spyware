#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-shot dev loop for validating AegisDefense on Windows: pulls the latest branch (if
    this is a git checkout), does a full clean rebuild, launches the service and GUI each in
    their own elevated window, then tails the service log in this window so events can be
    watched flowing live without a manual Get-Content round trip.

.NOTES
    Run this from an elevated PowerShell prompt. It expects to live at
    <repo>\AegisDefense\scripts\dev-loop.ps1 and finds the AegisDefense root relative to
    itself, so it works no matter where the repo checkout is on disk.

    Each launched process pops a UAC consent prompt (Start-Process -Verb RunAs) - that's
    expected, click Yes on both. The service and GUI windows stay open after this script's
    own window is closed; re-run the script any time to pick up new fixes and restart both
    cleanly.
#>
[CmdletBinding()]
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "=== AegisDefense dev loop ===" -ForegroundColor Cyan
Write-Host "Root: $root" -ForegroundColor DarkGray

# 1. Pull latest if this is a git checkout (AegisDefense is a subfolder of the repo root).
$repoRoot = Split-Path -Parent $root
if (Test-Path (Join-Path $repoRoot ".git")) {
    Write-Host "`n--- git pull ---" -ForegroundColor Cyan
    Push-Location $repoRoot
    git pull
    Pop-Location
} else {
    Write-Host "`n(Not a git checkout - skipping pull. Re-download the branch ZIP first if you need the latest fixes.)" -ForegroundColor Yellow
}

# 2. Stop any running instances so the rebuild isn't blocked by locked files.
Write-Host "`n--- Stopping any running AegisDefense processes ---" -ForegroundColor Cyan
Get-Process -Name "AegisDefenseService", "AegisDefenseConsole" -ErrorAction SilentlyContinue | Stop-Process -Force

# 3. Clean + release build-server locks + restore + build.
Write-Host "`n--- Clean (bin/obj) ---" -ForegroundColor Cyan
Get-ChildItem -Path $root -Recurse -Directory -Include bin, obj -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n--- dotnet build-server shutdown (releases stale file locks) ---" -ForegroundColor Cyan
dotnet build-server shutdown

Write-Host "`n--- Restore ---" -ForegroundColor Cyan
dotnet restore "$root\AegisDefense.sln"
if ($LASTEXITCODE -ne 0) { throw "Restore failed - see errors above." }

Write-Host "`n--- Build ($Configuration) ---" -ForegroundColor Cyan
dotnet build "$root\AegisDefense.sln" -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "Build failed - see errors above." }

# 4. Launch service + GUI, each elevated, each in its own window.
$servicePath = Join-Path $root "src\Aegis.Service\bin\$Configuration\net48\AegisDefenseService.exe"
$guiPath     = Join-Path $root "src\Aegis.Gui\bin\$Configuration\net48\AegisDefenseConsole.exe"

Write-Host "`n--- Launching service (console mode) - approve the UAC prompt ---" -ForegroundColor Cyan
Start-Process -FilePath $servicePath -ArgumentList "--console" -Verb RunAs

Start-Sleep -Seconds 3

Write-Host "--- Launching GUI - approve the UAC prompt ---" -ForegroundColor Cyan
Start-Process -FilePath $guiPath -Verb RunAs

# 5. Tail today's log in this window so events/errors are visible live.
Start-Sleep -Seconds 2
$logPath = "$env:ProgramData\AegisDefense\logs\aegis-$(Get-Date -Format yyyy-MM-dd).log"
Write-Host "`n--- Tailing $logPath (Ctrl+C stops watching; service/GUI keep running) ---" -ForegroundColor Cyan
if (Test-Path $logPath) {
    Get-Content -Path $logPath -Wait -Tail 20
} else {
    Write-Host "Log file not found yet - the service may still be starting. Wait a few seconds, then run:" -ForegroundColor Yellow
    Write-Host "  Get-Content `"$logPath`" -Wait -Tail 20"
}
