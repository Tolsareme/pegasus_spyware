#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Publishes the service + console and builds AegisDefense.msi. Run on Windows with the
    .NET SDK, the Windows Desktop workload (for Aegis.Gui), and the WiX Toolset installed
    (`dotnet tool install --global wix --version 5.0.2` then
    `wix extension add WixToolset.UI.wixext/5.0.2`).

.PARAMETER Configuration
    Build configuration to publish (default Release).
#>
[CmdletBinding()]
param(
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$installerDir = $PSScriptRoot

Write-Host "Publishing Aegis.Service..." -ForegroundColor Cyan
dotnet publish "$root\src\Aegis.Service\Aegis.Service.csproj" -c $Configuration -r win-x64 --self-contained false -o "$installerDir\publish\service"
if ($LASTEXITCODE -ne 0) { throw "Publishing Aegis.Service failed." }

Write-Host "Publishing Aegis.Gui..." -ForegroundColor Cyan
dotnet publish "$root\src\Aegis.Gui\Aegis.Gui.csproj" -c $Configuration -r win-x64 --self-contained false -o "$installerDir\publish\gui"
if ($LASTEXITCODE -ne 0) { throw "Publishing Aegis.Gui failed." }

Write-Host "Building installer..." -ForegroundColor Cyan
dotnet build "$installerDir\AegisDefense.Installer.wixproj" -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "WiX build failed." }

Write-Host "Done - MSI is under installer\bin\$Configuration\." -ForegroundColor Green
