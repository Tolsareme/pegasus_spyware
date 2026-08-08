<#
.SYNOPSIS
    Generates (or replaces) this account's Aegis policy-signing key pair, for headless/
    server-side provisioning without running the WPF console (Aegis.Gui already offers the
    same action from its Policy & Autonomy tab - use whichever is convenient).

.DESCRIPTION
    Mirrors Aegis.Gui.Services.PolicySigningKeyManager exactly: a 2048-bit RSA key pair is
    generated, the private key is DPAPI-protected (CurrentUser scope) at
    %AppData%\AegisDefense\policy-signing-key.protected, and the public key is exported in
    the classic XML key-interchange format that Aegis.Service's PolicyTrustStore expects.
    Uses only .NET Framework BCL types available to PowerShell 5.1+ - no extra module.

.PARAMETER PublicKeyOutputPath
    Where to write the exported public key XML. Copy this file to the service host's
    %ProgramData%\AegisDefense\keys\policy-trusted-public.xml to complete provisioning.

.EXAMPLE
    .\New-PolicySigningKey.ps1 -PublicKeyOutputPath .\policy-trusted-public.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublicKeyOutputPath
)

$ErrorActionPreference = "Stop"

$keyDir = Join-Path $env:APPDATA "AegisDefense"
$protectedKeyPath = Join-Path $keyDir "policy-signing-key.protected"
New-Item -ItemType Directory -Force -Path $keyDir | Out-Null

if (Test-Path $protectedKeyPath) {
    $confirm = Read-Host "A signing key already exists at '$protectedKeyPath'. Replacing it invalidates trust with any service that already has the old public key installed. Continue? (y/N)"
    if ($confirm -ne "y") { Write-Host "Aborted." -ForegroundColor Yellow; exit 1 }
}

Add-Type -AssemblyName System.Security

$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
try {
    $privateXml = $rsa.ToXmlString($true)
    $privateBytes = [System.Text.Encoding]::UTF8.GetBytes($privateXml)
    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $privateBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($protectedKeyPath, $protectedBytes)

    $publicXml = $rsa.ToXmlString($false)
    $resolvedOutput = [System.IO.Path]::GetFullPath($PublicKeyOutputPath)
    New-Item -ItemType Directory -Force -Path (Split-Path $resolvedOutput -Parent) | Out-Null
    [System.IO.File]::WriteAllText($resolvedOutput, $publicXml, [System.Text.Encoding]::UTF8)
}
finally {
    $rsa.Dispose()
}

Write-Host "Signing key generated and protected at: $protectedKeyPath" -ForegroundColor Green
Write-Host "Public key exported to: $resolvedOutput" -ForegroundColor Green
Write-Host "Copy the public key file to the service host as: %ProgramData%\AegisDefense\keys\policy-trusted-public.xml" -ForegroundColor Cyan
