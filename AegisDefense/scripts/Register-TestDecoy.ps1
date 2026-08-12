#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers a decoy (canary) resource against a running Aegis.Service instance, over a raw
    connection to the control pipe. This exists because there's no GUI form for RegisterDecoy
    yet (registration is IPC-only today - see docs/ARCHITECTURE.md) - useful for validation
    testing without writing a throwaway C# client.

.DESCRIPTION
    Sends a RegisterDecoy request matching Aegis.Ipc.Contracts' wire format directly, then
    reports the service's response and confirms whether the decoy artifact actually got
    created on disk (v2.1's WindowsDecoyMaterializer). After running this, touch/open the
    file at -Location - if object-access auditing is enabled
    (auditpol /set /subcategory:"File System" /success:enable /failure:enable) the access
    should show up as a CanaryAccess alert in the console within one refresh cycle.

.PARAMETER Id
    Unique id for the decoy.
.PARAMETER Location
    Full path where the decoy file should be created.
.PARAMETER Description
    Human-readable description stored with the decoy.
#>
[CmdletBinding()]
param(
    [string]$Id = "test-decoy-$(Get-Random)",
    [string]$Location = "$env:USERPROFILE\Documents\passwords-backup.xlsx",
    [string]$Description = "Validation test decoy - registered via Register-TestDecoy.ps1"
)

$ErrorActionPreference = "Stop"

# DecoyType enum (Aegis.Core.Deception.DecoyType): File=0, Directory=1, ServiceIdentity=2, HoneyCredential=3, Share=4, Api=5
$decoy = [ordered]@{
    Id          = $Id
    Type        = 0
    Location    = $Location
    Description = $Description
    HostIdScope = $null
}
$envelope = [ordered]@{
    RequestId   = [guid]::NewGuid().ToString()
    MessageType = "RegisterDecoy"
    Payload     = [ordered]@{ Decoy = $decoy }
}
$json = $envelope | ConvertTo-Json -Depth 6 -Compress

Write-Host "Connecting to Aegis Defense control pipe..." -ForegroundColor Cyan
$pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
    ".", "AegisDefense.Control.v1",
    [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None,
    [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
$pipe.Connect(5000)

# No-BOM UTF8, matching AegisPipeClient/AegisPipeServer exactly - a BOM here would corrupt
# the first line the server reads.
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($pipe, $utf8NoBom)
$writer.AutoFlush = $true
$reader = [System.IO.StreamReader]::new($pipe, $utf8NoBom)

Write-Host "Sending RegisterDecoy request (Id=$Id, Location=$Location)..." -ForegroundColor Cyan
$writer.WriteLine($json)

$responseLine = $reader.ReadLine()
Write-Host "`nRaw response:" -ForegroundColor DarkGray
Write-Host $responseLine

$response = $responseLine | ConvertFrom-Json
if ($response.Error) {
    Write-Host "`nRegistration FAILED: $($response.Error)" -ForegroundColor Red
} else {
    Write-Host "`nDecoy registered." -ForegroundColor Green
    Start-Sleep -Milliseconds 500
    if (Test-Path $Location) {
        Write-Host "Artifact confirmed created on disk at: $Location" -ForegroundColor Green
        Write-Host "`nNext: touch it (e.g. 'Get-Content `"$Location`"' or open it in Notepad)," -ForegroundColor Cyan
        Write-Host "then check the console's Alerts tab for a CanaryAccess alert." -ForegroundColor Cyan
    } else {
        Write-Host "WARNING: artifact was not found on disk at $Location - check the service log for a WindowsDecoyMaterializer warning." -ForegroundColor Yellow
    }
}

$writer.Dispose()
$reader.Dispose()
$pipe.Dispose()
