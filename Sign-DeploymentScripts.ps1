#Requires -Version 5.1

<#
.SYNOPSIS
    Signs PowerShell deployment scripts and configuration files with Authenticode signatures

.DESCRIPTION
    This script signs all PowerShell (.ps1) files in the deployment system with Authenticode signatures.
    It replaces the previous catalog-based signing approach with direct script signature validation.

    Signed files:
    - Scripts/Deploy-Bootstrap/Deploy-Bootstrap.ps1
    - Scripts/Deploy-Windows/Deploy-Windows.ps1
    - Config/Examples/*.ps1 (all example configuration files)

.PARAMETER CertificateThumbprint
    Thumbprint of the code signing certificate to use.
    If not specified, the first available code signing certificate will be used.

.PARAMETER FilePath
    Optional: Sign a specific file instead of all deployment scripts.
    Must be a .ps1 file.

.PARAMETER TimestampServer
    Timestamp server URL for signing.
    Default: http://timestamp.digicert.com

.EXAMPLE
    .\Sign-DeploymentScripts.ps1
    Signs all deployment scripts using the first available code signing certificate

.EXAMPLE
    .\Sign-DeploymentScripts.ps1 -CertificateThumbprint "A1B2C3D4E5F6..."
    Signs all deployment scripts using a specific certificate

.EXAMPLE
    .\Sign-DeploymentScripts.ps1 -FilePath "Config\Examples\deployment-iso-example-config.ps1"
    Signs a specific configuration file

.NOTES
    Author: Windows Deployment Automation
    Requires: Code signing certificate in CurrentUser\My or LocalMachine\My
    Certificate Requirements: Must have Code Signing EKU (1.3.6.1.5.5.7.3.3)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "File not found: $_"
        }
        if ($_ -notmatch '\.ps1$') {
            throw "File must be a PowerShell script (.ps1): $_"
        }
        return $true
    })]
    [string]$FilePath,

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

# Set script root
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Get signing certificate
function Get-SigningCertificate {
    [CmdletBinding()]
    param(
        [string]$Thumbprint
    )

    if ($Thumbprint) {
        Write-Host "Looking for certificate with thumbprint: $Thumbprint" -ForegroundColor Cyan

        # Search CurrentUser\My
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Thumbprint -eq $Thumbprint }

        # Search LocalMachine\My if not found
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Where-Object { $_.Thumbprint -eq $Thumbprint }
        }

        if (-not $cert) {
            throw "Certificate with thumbprint $Thumbprint not found in CurrentUser\My or LocalMachine\My"
        }
    }
    else {
        Write-Host "Looking for first available code signing certificate..." -ForegroundColor Cyan

        # Get first code signing cert from CurrentUser\My
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

        # Try LocalMachine\My if not found
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
        }

        if (-not $cert) {
            throw "No code signing certificate found in CurrentUser\My or LocalMachine\My"
        }
    }

    return $cert
}

# Sign a PowerShell file
function Sign-PowerShellFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Certificate,

        [Parameter(Mandatory = $true)]
        [string]$TimestampServer
    )

    Write-Host "  Signing: $Path" -ForegroundColor Yellow

    try {
        $signature = Set-AuthenticodeSignature `
            -FilePath $Path `
            -Certificate $Certificate `
            -TimestampServer $TimestampServer `
            -ErrorAction Stop

        if ($signature.Status -eq 'Valid') {
            Write-Host "    ✓ Signed successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "    ✗ Signature status: $($signature.Status)" -ForegroundColor Red
            Write-Host "      $($signature.StatusMessage)" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "    ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main script
try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Sign Deployment Scripts" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Get certificate
    $cert = Get-SigningCertificate -Thumbprint $CertificateThumbprint

    Write-Host "Using certificate:" -ForegroundColor Cyan
    Write-Host "  Subject: $($cert.Subject)" -ForegroundColor White
    Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
    Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor White
    Write-Host ""

    # Check certificate expiration
    if ($cert.NotAfter -lt (Get-Date)) {
        throw "Certificate has expired: $($cert.NotAfter)"
    }

    # Collect files to sign
    $filesToSign = @()

    if ($FilePath) {
        # Sign specific file
        $filesToSign += Get-Item $FilePath
    }
    else {
        # Sign all deployment scripts and config examples
        Write-Host "Collecting PowerShell files to sign..." -ForegroundColor Cyan

        # Main deployment scripts
        $deployBootstrap = Join-Path $ScriptRoot "Scripts\Deploy-Bootstrap\Deploy-Bootstrap.ps1"
        $deployWindows = Join-Path $ScriptRoot "Scripts\Deploy-Windows\Deploy-Windows.ps1"

        if (Test-Path $deployBootstrap) {
            $filesToSign += Get-Item $deployBootstrap
        }

        if (Test-Path $deployWindows) {
            $filesToSign += Get-Item $deployWindows
        }

        # Configuration examples
        $configExamplesPath = Join-Path $ScriptRoot "Config\Examples"
        if (Test-Path $configExamplesPath) {
            $filesToSign += Get-ChildItem -Path $configExamplesPath -Filter "*.ps1" -File
        }

        Write-Host "  Found $($filesToSign.Count) files to sign" -ForegroundColor White
        Write-Host ""
    }

    # Sign files
    Write-Host "Signing files..." -ForegroundColor Cyan
    Write-Host ""

    $successCount = 0
    $failCount = 0

    foreach ($file in $filesToSign) {
        if (Sign-PowerShellFile -Path $file.FullName -Certificate $cert -TimestampServer $TimestampServer) {
            $successCount++
        }
        else {
            $failCount++
        }
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Signing Complete" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Total files: $($filesToSign.Count)" -ForegroundColor White
    Write-Host "  Successful: $successCount" -ForegroundColor Green
    Write-Host "  Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "White" })
    Write-Host ""

    if ($failCount -gt 0) {
        throw "Some files failed to sign. See errors above."
    }

    Write-Host "All files signed successfully!" -ForegroundColor Green
    Write-Host ""

    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Signing Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    exit 1
}
