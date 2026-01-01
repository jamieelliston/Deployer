#Requires -Version 5.1

<#
.SYNOPSIS
    Creates a signed catalog (.cat) file for a ZIP archive

.DESCRIPTION
    This script automates the creation of a signed catalog file for validating ZIP archive integrity.
    It creates a ZIP from a folder, generates a catalog file using New-FileCatalog, and signs it with Authenticode.

    This uses the CATALOG-based validation approach (not the newer hash file .ps1 approach).
    For hash file approach, use New-PackageHash.ps1 instead.

    Workflow:
    1. Create ZIP archive from folder contents (contents only, not folder wrapper)
    2. Generate catalog file (.cat) using New-FileCatalog cmdlet (Version 2.0)
    3. Sign the catalog file with Authenticode (auto-sign if certificate available)

    Catalog vs Hash File:
    - Catalog (.cat): Windows catalog infrastructure using New-FileCatalog/Test-FileCatalog
    - Hash File (.ps1): PowerShell script with hash, simpler, cross-platform friendly

.PARAMETER FolderPath
    Path to the folder containing files to ZIP and catalog.
    The ZIP will contain the folder CONTENTS at root, not the folder itself.

.PARAMETER OutputPath
    Optional: Directory where ZIP and CAT files will be saved.
    Default: Same directory as the source folder (parent directory)

.PARAMETER ZipName
    Optional: Custom name for the ZIP and catalog files (without extension).
    Default: Source folder name
    Example: "Production-v1.2" creates Production-v1.2.zip and Production-v1.2.cat

.PARAMETER CompressionLevel
    Optional: ZIP compression level.
    Default: Optimal (balanced speed/size)
    Options: Optimal, Fastest, NoCompression

.PARAMETER NoSign
    Skip signing even if a code signing certificate is available.
    Use for testing or when signing will be done separately.

.PARAMETER CertificateThumbprint
    Thumbprint of the code signing certificate to use for signing.
    If not specified, the first available code signing certificate will be used.

.PARAMETER TimestampServer
    Timestamp server URL for signing.
    Default: http://timestamp.digicert.com

.EXAMPLE
    .\New-SignedZipCatalog.ps1 -FolderPath "C:\Deploy\Package"
    Creates Package.zip and Package.cat (signed) in C:\Deploy

.EXAMPLE
    .\New-SignedZipCatalog.ps1 -FolderPath "C:\Source\Package" -OutputPath "C:\Build" -ZipName "Production-v1.2"
    Creates Production-v1.2.zip and Production-v1.2.cat in C:\Build

.EXAMPLE
    .\New-SignedZipCatalog.ps1 -FolderPath "C:\Deploy\Package" -NoSign
    Creates Package.zip and Package.cat (unsigned) for testing

.EXAMPLE
    .\New-SignedZipCatalog.ps1 -FolderPath "C:\Deploy\Package" -CertificateThumbprint "A1B2C3D4..."
    Creates and signs with specific certificate

.EXAMPLE
    .\New-SignedZipCatalog.ps1 -FolderPath "C:\Deploy\Large" -CompressionLevel Fastest
    Uses fastest compression for large packages

.NOTES
    Author: Windows Deployment Automation
    Requires: PowerShell 5.1+ (for New-FileCatalog cmdlet)
    Certificate Requirements: Code Signing EKU (1.3.6.1.5.5.7.3.3)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Container)) {
            throw "Folder not found: $_"
        }
        return $true
    })]
    [string]$FolderPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and ($_ -match '[<>:"/\\|?*]')) {
            throw "ZipName contains invalid filename characters: $_"
        }
        return $true
    })]
    [string]$ZipName,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Optimal', 'NoCompression', 'Fastest')]
    [string]$CompressionLevel = 'Optimal',

    [Parameter(Mandatory = $false)]
    [switch]$NoSign,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

#region Helper Functions

function Get-SigningCertificate {
    <#
    .SYNOPSIS
        Finds and returns a code signing certificate
    .PARAMETER Thumbprint
        Optional certificate thumbprint to search for
    .PARAMETER Required
        If set, throws error when certificate not found. Otherwise returns $null.
    #>
    [CmdletBinding()]
    param(
        [string]$Thumbprint,
        [switch]$Required
    )

    if ($Thumbprint) {
        Write-Host "Looking for certificate with thumbprint: $Thumbprint" -ForegroundColor Cyan

        # Search CurrentUser\My
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $Thumbprint }

        # Search LocalMachine\My if not found
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Where-Object { $_.Thumbprint -eq $Thumbprint }
        }

        if (-not $cert) {
            throw "Certificate with thumbprint $Thumbprint not found in CurrentUser\My or LocalMachine\My"
        }
    }
    else {
        Write-Host "Looking for code signing certificate..." -ForegroundColor Cyan

        # Get first code signing cert from CurrentUser\My
        $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
            Select-Object -First 1

        # Try LocalMachine\My if not found
        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }

        if (-not $cert) {
            if ($Required) {
                throw "No code signing certificate found in CurrentUser\My or LocalMachine\My"
            }
            else {
                Write-Host "  No code signing certificate found - catalog file will not be signed" -ForegroundColor Yellow
                return $null
            }
        }
    }

    return $cert
}

#endregion

#region Main Script

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Create Signed ZIP Catalog" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # =====================================================================
    # PHASE 1: Input Validation and Path Resolution
    # =====================================================================

    Write-Host "Validating inputs..." -ForegroundColor Yellow

    # Resolve full path to source folder
    $folderFullPath = Resolve-Path -Path $FolderPath -ErrorAction Stop
    $folderItem = Get-Item -Path $folderFullPath

    Write-Host "  Source Folder: $folderFullPath" -ForegroundColor White

    # Determine output directory
    if (-not $OutputPath) {
        $OutputPath = Split-Path -Path $folderFullPath -Parent
    }

    # Validate output directory exists (create if needed)
    if (-not (Test-Path $OutputPath -PathType Container)) {
        Write-Host "  Creating output directory: $OutputPath" -ForegroundColor Cyan
        New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $outputFullPath = Resolve-Path -Path $OutputPath -ErrorAction Stop

    # Determine ZIP/catalog base name
    if (-not $ZipName) {
        $ZipName = $folderItem.Name
    }

    # Construct file paths
    $zipFileName = "$ZipName.zip"
    $catFileName = "$ZipName.cat"

    $zipPath = Join-Path $outputFullPath $zipFileName
    $catPath = Join-Path $outputFullPath $catFileName

    Write-Host "  Output Directory: $outputFullPath" -ForegroundColor White
    Write-Host "  ZIP File: $zipFileName" -ForegroundColor White
    Write-Host "  Catalog File: $catFileName" -ForegroundColor White

    # Check for existing files (warn but allow overwrite)
    if (Test-Path $zipPath) {
        $existingSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-Host ""
        Write-Host "  WARNING: Existing ZIP will be overwritten" -ForegroundColor Yellow
        Write-Host "    Path: $zipPath" -ForegroundColor Gray
        Write-Host "    Size: $existingSize MB" -ForegroundColor Gray
    }

    if (Test-Path $catPath) {
        Write-Host "  WARNING: Existing catalog will be overwritten" -ForegroundColor Yellow
        Write-Host "    Path: $catPath" -ForegroundColor Gray
    }

    Write-Host ""

    # =====================================================================
    # PHASE 2: Create ZIP Archive
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Creating ZIP Archive" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Compressing folder contents (this may take several minutes for large folders)..." -ForegroundColor Yellow
    Write-Host "  Compression Level: $CompressionLevel" -ForegroundColor White
    Write-Host ""

    # Create ZIP from folder CONTENTS (not folder itself)
    # Using "$folderFullPath\*" ensures contents are at root of ZIP
    Compress-Archive `
        -Path "$folderFullPath\*" `
        -DestinationPath $zipPath `
        -CompressionLevel $CompressionLevel `
        -Force `
        -ErrorAction Stop

    # Get ZIP file info
    $zipFile = Get-Item -Path $zipPath
    $zipSizeMB = [math]::Round($zipFile.Length / 1MB, 2)

    Write-Host "  ✓ ZIP created successfully" -ForegroundColor Green
    Write-Host "    Size: $zipSizeMB MB ($($zipFile.Length) bytes)" -ForegroundColor Gray
    Write-Host "    Path: $zipPath" -ForegroundColor Gray

    # Check for empty ZIP and warn
    try {
        $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        if ($zipArchive.Entries.Count -eq 0) {
            Write-Host ""
            Write-Host "  WARNING: ZIP archive is empty (source folder contains no files)" -ForegroundColor Yellow
        }
        $zipArchive.Dispose()
    }
    catch {
        # Non-fatal - continue even if we can't check ZIP contents
    }

    Write-Host ""

    # =====================================================================
    # PHASE 3: Create Catalog File
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Creating Catalog File" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Generating catalog using New-FileCatalog..." -ForegroundColor Yellow
    Write-Host "  Catalog Version: 2.0" -ForegroundColor White
    Write-Host ""

    # Use New-FileCatalog to create the catalog
    # Catalog the ZIP file directly (no CDF needed)
    New-FileCatalog -Path $zipPath -CatalogFilePath $catPath -CatalogVersion 2.0 -ErrorAction Stop

    # Verify catalog was created
    if (-not (Test-Path $catPath)) {
        throw "Catalog file was not created by New-FileCatalog"
    }

    Write-Host "  ✓ Catalog file created: $catPath" -ForegroundColor Green
    Write-Host "  Catalog Version: 2.0" -ForegroundColor Gray
    Write-Host ""

    # =====================================================================
    # PHASE 5: Sign Catalog File
    # =====================================================================

    $signed = $false

    if (-not $NoSign) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "  Signing Catalog File" -ForegroundColor Cyan
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
                Write-Host "  Catalog file will not be signed" -ForegroundColor Yellow
                Write-Host ""
            }
            else {
                Write-Host "Signing catalog..." -ForegroundColor Yellow

                try {
                    $signature = Set-AuthenticodeSignature `
                        -FilePath $catPath `
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
                        Write-Host "  Catalog created but not signed" -ForegroundColor Yellow
                    }
                }
                catch {
                    # Check for timestamp-specific errors
                    if ($_.Exception.Message -match "timestamp") {
                        Write-Host "  ✗ Timestamp server unavailable: $TimestampServer" -ForegroundColor Red
                        Write-Host "    The catalog is signed but lacks a timestamp." -ForegroundColor Yellow
                        Write-Host "    Signature will expire when certificate expires." -ForegroundColor Yellow
                        Write-Host ""
                        Write-Host "  Consider retrying with different timestamp server:" -ForegroundColor Yellow
                        Write-Host "    -TimestampServer http://timestamp.sectigo.com" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "  ✗ Failed to sign: $($_.Exception.Message)" -ForegroundColor Red
                    }
                    Write-Host "  Catalog created but not signed" -ForegroundColor Yellow
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

    # =====================================================================
    # PHASE 6: Cleanup
    # =====================================================================

    # No cleanup needed - New-FileCatalog doesn't create temporary files
    # (Unlike the old makecat.exe approach which created CDF files)

    # =====================================================================
    # PHASE 7: Summary and Next Steps
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ZIP Catalog Created Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    Write-Host "OUTPUT FILES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ZIP: $zipPath" -ForegroundColor White
    Write-Host "    Size: $zipSizeMB MB" -ForegroundColor Gray
    Write-Host "    Structure: Contains folder contents at root (no wrapper folder)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Catalog: $catPath$(if ($signed) { ' (SIGNED)' } else { ' (NOT SIGNED)' })" -ForegroundColor White
    Write-Host ""

    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Upload both files to your deployment source:" -ForegroundColor White
    Write-Host "   - ZIP: $zipFileName" -ForegroundColor Cyan
    Write-Host "   - Catalog: $catFileName$(if ($signed) { ' (SIGNED)' } else { '' })" -ForegroundColor Cyan
    Write-Host ""

    if (-not $signed) {
        Write-Host "2. IMPORTANT: Sign the catalog file for production use:" -ForegroundColor Yellow
        Write-Host "   .\Sign-DeploymentScripts.ps1 -FilePath `"$catPath`"" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "3. Update bootstrap configuration with catalog URL:" -ForegroundColor White
        Write-Host ""
    }
    else {
        Write-Host "2. Update bootstrap configuration with catalog URL:" -ForegroundColor White
        Write-Host ""
    }

    Write-Host "CATALOG VALIDATION:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Test catalog integrity with PowerShell:" -ForegroundColor White
    Write-Host "  `$result = Test-FileCatalog -Path `"$zipPath`" -CatalogFilePath `"$catPath`" -Detailed" -ForegroundColor Cyan
    Write-Host "  if (`$result.Status -eq 'Valid') {" -ForegroundColor Cyan
    Write-Host "    Write-Host 'Catalog is valid' -ForegroundColor Green" -ForegroundColor Cyan
    Write-Host "  } else {" -ForegroundColor Cyan
    Write-Host "    Write-Host 'Catalog validation failed' -ForegroundColor Red" -ForegroundColor Cyan
    Write-Host "    `$result.CatalogItems | Where-Object Status -ne 'Valid'" -ForegroundColor Cyan
    Write-Host "  }" -ForegroundColor Cyan
    Write-Host ""

    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Catalog Creation Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    # Provide contextual help for common errors
    if ($_.Exception.Message -match "Access.*denied|permission") {
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "  1. Verify you have write permissions to output directory" -ForegroundColor White
        Write-Host "  2. Run PowerShell as Administrator if needed" -ForegroundColor White
        Write-Host "  3. Choose different output location with -OutputPath parameter" -ForegroundColor White
        Write-Host ""
    }

    exit 1
}

#endregion
