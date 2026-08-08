#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Aegis Defense Windows Service.

.DESCRIPTION
    Registers AegisDefenseService.exe as a Windows Service running as LocalSystem, set to
    start automatically, with a delayed-auto-start so it doesn't compete with other
    autostart services during boot. Uses sc.exe rather than New-Service so this works
    unmodified on PowerShell 2.0 (Windows 7) through the latest PowerShell 7 (Server 2025) -
    New-Service's -StartupType Automatic (Delayed) option isn't available on older
    PowerShell, but sc.exe's syntax has been stable for the whole target range.

.PARAMETER BinaryPath
    Path to AegisDefenseService.exe. Defaults to the published output next to this script.

.EXAMPLE
    .\install-service.ps1
.EXAMPLE
    .\install-service.ps1 -BinaryPath "C:\Program Files\AegisDefense\AegisDefenseService.exe"
#>
[CmdletBinding()]
param(
    [string]$BinaryPath = (Join-Path $PSScriptRoot "..\src\Aegis.Service\bin\Release\net48\AegisDefenseService.exe")
)

$ErrorActionPreference = "Stop"
$ServiceName = "AegisDefenseService"
$DisplayName = "Aegis Autonomous Defense Service"
$Description = "Behavioral detection, attack-state estimation, deception and policy-bounded automated response for this host. See docs/ARCHITECTURE.md."

$BinaryPath = (Resolve-Path $BinaryPath -ErrorAction Stop).Path
if (-not (Test-Path $BinaryPath)) {
    throw "Service binary not found at '$BinaryPath'. Build the solution in Release first (dotnet build -c Release), or pass -BinaryPath explicitly."
}

$existing = sc.exe query $ServiceName 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Service '$ServiceName' already exists - stopping and removing it first for a clean reinstall." -ForegroundColor Yellow
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "Registering service '$ServiceName'..." -ForegroundColor Cyan
# binPath= (with the trailing space before '=') is mandatory sc.exe syntax - do not remove the spaces.
sc.exe create $ServiceName binPath= "`"$BinaryPath`"" start= delayed-auto obj= "LocalSystem" DisplayName= $DisplayName
if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with exit code $LASTEXITCODE." }

sc.exe description $ServiceName $Description | Out-Null

# Restart policy: auto-recover from crashes without operator intervention, but back off so a
# persistently crashing service doesn't hot-loop.
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null

Write-Host "Provisioning ProgramData layout..." -ForegroundColor Cyan
$root = Join-Path $env:ProgramData "AegisDefense"
foreach ($sub in @("data", "logs", "keys")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root $sub) | Out-Null
}

Write-Host ""
Write-Host "Service installed but NOT started automatically by this script." -ForegroundColor Green
Write-Host "Before starting it:"
Write-Host "  1. Provision a policy-signing trust key: run the Aegis Defense Console (Aegis.Gui), use"
Write-Host "     'Generate New Signing Key' then 'Export Public Key for Service Install', and copy the"
Write-Host "     exported file to: $root\keys\policy-trusted-public.xml"
Write-Host "  2. Then start the service:  Start-Service $ServiceName"
Write-Host ""
Write-Host "Without step 1 the service still runs (telemetry, detection, alerting all work), it will" -ForegroundColor Yellow
Write-Host "just reject any policy changes pushed from the console until a trust key is installed." -ForegroundColor Yellow
