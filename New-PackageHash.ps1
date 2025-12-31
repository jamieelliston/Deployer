#Requires -Version 5.1

<#
.SYNOPSIS
    Generates and automatically signs a hash file for deployment package validation

.DESCRIPTION
    This script calculates the hash of a deployment package ZIP file, creates a PowerShell
    script containing the hash information, and automatically signs it if a code signing
    certificate is available.

    The generated hash script is used by Deploy-Bootstrap.ps1 to validate package integrity
    before extraction.

    Signing is automatic - if a code signing certificate is found, the hash file will be signed.
    Use -NoSign to skip signing.

    Security Chain:
    1. This script calculates ZIP hash and creates hash.ps1
    2. Automatically signs hash.ps1 with Authenticode (if certificate available)
    3. Deploy-Bootstrap.ps1 downloads and verifies hash.ps1 signature
    4. Deploy-Bootstrap.ps1 downloads ZIP and verifies hash matches
    5. Deploy-Bootstrap.ps1 extracts and verifies Deploy-Windows.ps1 signature

.PARAMETER ZipPath
    Path to the deployment package ZIP file to hash

.PARAMETER OutputPath
    Optional: Path where the hash script should be saved.
    Default: Same directory as ZIP file, named "deployment-package-hash.ps1"

.PARAMETER Algorithm
    Hash algorithm to use. Default: SHA256
    Supported: SHA1, SHA256, SHA384, SHA512, MD5

.PARAMETER NoSign
    Skip signing even if a code signing certificate is available

.PARAMETER CertificateThumbprint
    Thumbprint of the code signing certificate to use for signing.
    If not specified, the first available code signing certificate will be used.

.PARAMETER TimestampServer
    Timestamp server URL for signing.
    Default: http://timestamp.digicert.com

.EXAMPLE
    .\New-PackageHash.ps1 -ZipPath "C:\Deploy\DeploymentPackage.zip"
    Creates deployment-package-hash.ps1 and automatically signs if certificate available

.EXAMPLE
    .\New-PackageHash.ps1 -ZipPath ".\Package.zip" -NoSign
    Creates hash file without signing

.EXAMPLE
    .\New-PackageHash.ps1 -ZipPath ".\Package.zip" -CertificateThumbprint "A1B2C3D4..."
    Creates and signs package hash using specific certificate

.EXAMPLE
    .\New-PackageHash.ps1 -ZipPath ".\Package.zip" -Algorithm SHA512
    Uses SHA512 algorithm and automatically signs

.NOTES
    Author: Windows Deployment Automation
    One-step hash generation and signing for deployment packages
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "ZIP file not found: $_"
        }
        if ($_ -notmatch '\.zip$') {
            throw "File must be a ZIP archive (.zip): $_"
        }
        return $true
    })]
    [string]$ZipPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5')]
    [string]$Algorithm = 'SHA256',

    [Parameter(Mandatory = $false)]
    [switch]$NoSign,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

# Get signing certificate
function Get-SigningCertificate {
    [CmdletBinding()]
    param(
        [string]$Thumbprint,
        [switch]$Required
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
        Write-Host "Looking for code signing certificate..." -ForegroundColor Cyan

        # Get first code signing cert from CurrentUser\My
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

        # Try LocalMachine\My if not found
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert | Select-Object -First 1
        }

        if (-not $cert) {
            if ($Required) {
                throw "No code signing certificate found in CurrentUser\My or LocalMachine\My"
            }
            else {
                Write-Host "  No code signing certificate found - hash file will not be signed" -ForegroundColor Yellow
                return $null
            }
        }
    }

    return $cert
}

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Generate Deployment Package Hash" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Resolve full path
    $zipFullPath = Resolve-Path -Path $ZipPath -ErrorAction Stop
    $zipFile = Get-Item -Path $zipFullPath

    Write-Host "ZIP File: $($zipFile.FullName)" -ForegroundColor White
    Write-Host "  Size: $([math]::Round($zipFile.Length / 1MB, 2)) MB" -ForegroundColor Gray
    Write-Host ""

    # Determine output path - use ZIP's base name with .ps1 extension
    if (-not $OutputPath) {
        $zipDirectory = Split-Path -Path $zipFullPath -Parent
        $zipBaseName = [System.IO.Path]::GetFileNameWithoutExtension($zipFile.Name)
        $OutputPath = Join-Path $zipDirectory "$zipBaseName.ps1"
    }

    $outputFullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    Write-Host "Calculating $Algorithm hash..." -ForegroundColor Yellow

    # Calculate hash
    $hashResult = Get-FileHash -Path $zipFullPath -Algorithm $Algorithm -ErrorAction Stop

    Write-Host "  Hash: $($hashResult.Hash)" -ForegroundColor Green
    Write-Host ""

    # Create hash script content
    $hashScriptContent = @"
#Requires -Version 5.1

<#
.SYNOPSIS
    Deployment package hash for integrity validation

.DESCRIPTION
    This file contains the cryptographic hash of the deployment package ZIP file.
    It is used by Deploy-Bootstrap.ps1 to verify package integrity before extraction.

    This file should be signed with Authenticode signatures to ensure the hash
    itself has not been tampered with.

    Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Algorithm: $Algorithm
    Source ZIP: $($zipFile.Name)
    ZIP Size: $($zipFile.Length) bytes ($([math]::Round($zipFile.Length / 1MB, 2)) MB)

.NOTES
    Do not modify this file manually. Regenerate using New-PackageHash.ps1
#>

return @{
    fileName = "$($zipFile.Name)"
    algorithm = "$Algorithm"
    hash = "$($hashResult.Hash)"
    sizeBytes = $($zipFile.Length)
    sizeMB = $([math]::Round($zipFile.Length / 1MB, 2))
    generatedDate = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    generatedBy = "$($env:USERNAME)@$($env:COMPUTERNAME)"
}
"@

    # Write hash script
    Write-Host "Creating hash script..." -ForegroundColor Yellow
    Set-Content -Path $outputFullPath -Value $hashScriptContent -Encoding UTF8 -ErrorAction Stop

    Write-Host "  Output: $outputFullPath" -ForegroundColor Green
    Write-Host ""

    # Auto-sign hash file unless -NoSign specified
    $signed = $false
    if (-not $NoSign) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Signing Hash File" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""

        # Get certificate (returns $null if not found)
        $cert = Get-SigningCertificate -Thumbprint $CertificateThumbprint

        if ($cert) {
            Write-Host "Using certificate:" -ForegroundColor Cyan
            Write-Host "  Subject: $($cert.Subject)" -ForegroundColor White
            Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
            Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor White
            Write-Host ""

            # Check certificate expiration
            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Host "  WARNING: Certificate has expired: $($cert.NotAfter)" -ForegroundColor Red
                Write-Host "  Hash file will not be signed" -ForegroundColor Yellow
                Write-Host ""
            }
            else {
                Write-Host "Signing hash file..." -ForegroundColor Yellow

                try {
                    $signature = Set-AuthenticodeSignature `
                        -FilePath $outputFullPath `
                        -Certificate $cert `
                        -TimestampServer $TimestampServer `
                        -ErrorAction Stop

                    if ($signature.Status -eq 'Valid') {
                        Write-Host "  ✓ Signed successfully" -ForegroundColor Green
                        $signed = $true
                    }
                    else {
                        Write-Host "  ✗ Signature status: $($signature.Status)" -ForegroundColor Red
                        if ($signature.StatusMessage) {
                            Write-Host "    $($signature.StatusMessage)" -ForegroundColor Red
                        }
                        Write-Host "  Hash file created but not signed" -ForegroundColor Yellow
                    }
                }
                catch {
                    Write-Host "  ✗ Failed to sign: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Host "  Hash file created but not signed" -ForegroundColor Yellow
                }

                Write-Host ""
            }
        }
        else {
            Write-Host ""
        }
    }
    else {
        Write-Host "Signing skipped (-NoSign specified)" -ForegroundColor Gray
        Write-Host ""
    }

    # Display next steps
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Hash File Created Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Upload both files to your deployment source:" -ForegroundColor White
    Write-Host "   - ZIP: $($zipFile.Name)" -ForegroundColor Cyan
    Write-Host "   - Hash: $($outputFullPath | Split-Path -Leaf)$(if ($signed) { ' (SIGNED)' } else { ' (NOT SIGNED)' })" -ForegroundColor Cyan
    Write-Host ""

    if (-not $signed) {
        Write-Host "2. IMPORTANT: Sign the hash file for production use:" -ForegroundColor Yellow
        Write-Host "   .\Sign-DeploymentScripts.ps1 -FilePath `"$outputFullPath`"" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "3. Bootstrap will auto-discover hash file (same name as ZIP with .ps1)" -ForegroundColor White
    }
    else {
        Write-Host "2. Bootstrap will auto-discover hash file (same name as ZIP with .ps1)" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "Note: packageHashUrl is optional - if not specified, bootstrap will" -ForegroundColor Gray
    Write-Host "      automatically look for $($zipBaseName).ps1 in the same location" -ForegroundColor Gray

    Write-Host ""

    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Hash Generation Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    exit 1
}
