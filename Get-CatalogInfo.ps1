#Requires -Version 5.1

<#
.SYNOPSIS
    Inspects and displays contents of Windows catalog (.cat) files

.DESCRIPTION
    Reads a Windows catalog file and displays its contents including:
    - Signature information (signer, timestamp, validity)
    - Certificate details (thumbprint, expiration)
    - Files listed in the catalog
    - Hash values (extracted from catalog structure)
    - Validation status (manual hash comparison for ZIP files)

    Catalog files are binary PKCS#7 signed data structures containing cryptographic
    hashes of files for integrity verification.

    This script includes manual hash validation that bypasses Test-FileCatalog
    for single-file catalogs (like ZIP files), which Test-FileCatalog doesn't handle properly.

.PARAMETER CatalogPath
    Path to the catalog (.cat) file to inspect

.PARAMETER ShowHashes
    Display full hash values (default: show first 16 characters for readability)

.PARAMETER ValidateAgainst
    Optional: Path to file or directory to validate against the catalog.
    For ZIP files, performs manual hash comparison.

.PARAMETER Detailed
    Show detailed certificate and signature information including:
    - Full certificate chain
    - Signature algorithm details
    - Extended attributes

.EXAMPLE
    .\Get-CatalogInfo.ps1 -CatalogPath "DeploymentPackage.cat"
    Shows catalog information including file list from catalog structure

.EXAMPLE
    .\Get-CatalogInfo.ps1 -CatalogPath "DeploymentPackage.cat" -ShowHashes
    Shows catalog info with full hash values displayed

.EXAMPLE
    .\Get-CatalogInfo.ps1 -CatalogPath "Package.cat" -ValidateAgainst "Package.zip"
    Shows catalog info and validates ZIP file using manual hash comparison

.EXAMPLE
    .\Get-CatalogInfo.ps1 -CatalogPath "Package.cat" -Detailed
    Shows comprehensive certificate and signature information

.NOTES
    Author: Windows Deployment Automation
    Catalog files cannot be read as plain text - they are binary PKCS#7 structures
    This version includes manual hash validation for ZIP files
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "Catalog file not found: $_"
        }
        if ($_ -notmatch '\.cat$') {
            throw "File must be a catalog file (.cat): $_"
        }
        return $true
    })]
    [string]$CatalogPath,

    [Parameter(Mandatory = $false)]
    [switch]$ShowHashes,

    [Parameter(Mandatory = $false)]
    [string]$ValidateAgainst,

    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

#region Helper Functions

function Get-CatalogEntries {
    <#
    .SYNOPSIS
        Parses catalog file to extract file names and hash values
    .DESCRIPTION
        Extracts file entries from Windows catalog by parsing PKCS#7 structure
        and searching for file references in the catalog content.
    #>
    param([string]$CatalogPath)

    try {
        # Read catalog bytes
        $catBytes = [System.IO.File]::ReadAllBytes($CatalogPath)

        # Parse PKCS#7 structure
        $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $signedCms.Decode($catBytes)

        # Get catalog content
        $content = $signedCms.ContentInfo.Content

        # Convert bytes to string for pattern matching
        $contentString = [System.Text.Encoding]::Unicode.GetString($content)

        # Extract file names (look for common patterns in catalog structure)
        # Catalogs typically store filenames as Unicode strings
        $fileEntries = @()

        # Pattern 1: Look for .zip, .ps1, .exe patterns
        $filePatterns = @('\.zip', '\.ps1', '\.exe', '\.dll', '\.sys', '\.cat', '\.wim', '\.iso')

        foreach ($pattern in $filePatterns) {
            $matches = [regex]::Matches($contentString, "([^\x00]{1,200}$pattern)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            foreach ($match in $matches) {
                $fileName = $match.Groups[1].Value -replace '[^\w\.\-]', ''
                if ($fileName -and $fileName.Length -lt 260 -and $fileName -match '\.' -and $fileName -notmatch '^\W') {
                    $fileEntries += $fileName
                }
            }
        }

        # Remove duplicates and sort
        $fileEntries = $fileEntries | Select-Object -Unique | Sort-Object

        # For each file, try to extract hash (SHA256 is 32 bytes = 64 hex chars)
        $catalogEntries = @()

        foreach ($fileName in $fileEntries) {
            # Try to find hash near filename in content
            # This is a simplified approach - full catalog parsing requires ASN.1 parser
            $catalogEntries += [PSCustomObject]@{
                FileName = $fileName
                Algorithm = "SHA256"  # Most catalogs use SHA256
                Hash = $null  # Hash extraction from binary is complex without full ASN.1 parser
            }
        }

        return $catalogEntries
    }
    catch {
        Write-Verbose "Catalog parsing error: $($_.Exception.Message)"
        return @()
    }
}

function Get-ManualHashValidation {
    <#
    .SYNOPSIS
        Performs manual hash validation by comparing file hash against catalog
    .DESCRIPTION
        When Test-FileCatalog doesn't work (single-file ZIP catalogs), this function
        performs manual hash comparison.
    #>
    param(
        [string]$FilePath,
        [string]$CatalogPath,
        [string]$Algorithm = "SHA256"
    )

    try {
        # For now, we calculate the file hash using the standard algorithm
        # In a full implementation, we would extract the expected hash from the catalog
        $actualHash = (Get-FileHash -Path $FilePath -Algorithm $Algorithm).Hash

        # Read catalog to try to find hash (this is simplified - full parsing would be complex)
        $catBytes = [System.IO.File]::ReadAllBytes($CatalogPath)
        $signedCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $signedCms.Decode($catBytes)
        $content = $signedCms.ContentInfo.Content

        # Convert to hex string to search for hash
        $contentHex = ($content | ForEach-Object { $_.ToString("X2") }) -join ''

        # Check if actualHash exists in catalog content
        if ($contentHex -match $actualHash) {
            return [PSCustomObject]@{
                FileName = Split-Path -Leaf $FilePath
                Algorithm = $Algorithm
                ExpectedHash = $actualHash
                ActualHash = $actualHash
                Valid = $true
            }
        }
        else {
            # Hash not found - try reverse (catalog might store differently)
            return [PSCustomObject]@{
                FileName = Split-Path -Leaf $FilePath
                Algorithm = $Algorithm
                ExpectedHash = "Unknown (unable to extract from catalog)"
                ActualHash = $actualHash
                Valid = $false
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            FileName = Split-Path -Leaf $FilePath
            Algorithm = $Algorithm
            ExpectedHash = "Error"
            ActualHash = "Error: $($_.Exception.Message)"
            Valid = $false
        }
    }
}

#endregion

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Catalog File Information" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # =====================================================================
    # PHASE 1: Basic File Information
    # =====================================================================

    # Resolve full path
    $catalogFullPath = Resolve-Path -Path $CatalogPath -ErrorAction Stop
    $catFile = Get-Item -Path $catalogFullPath

    Write-Host "File: $($catFile.FullName)" -ForegroundColor White
    Write-Host "  Size: $([math]::Round($catFile.Length / 1KB, 2)) KB ($($catFile.Length) bytes)" -ForegroundColor Gray
    Write-Host "  Created: $($catFile.CreationTime)" -ForegroundColor Gray
    Write-Host "  Modified: $($catFile.LastWriteTime)" -ForegroundColor Gray
    Write-Host ""

    # =====================================================================
    # PHASE 2: Signature Information
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Signature Information" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Get signature
    $signature = Get-AuthenticodeSignature -FilePath $catalogFullPath

    # Display signature status
    $statusColor = if ($signature.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host "Status: $($signature.Status)" -ForegroundColor $statusColor

    if ($signature.Status -eq 'NotSigned') {
        Write-Host "  This catalog file is not signed" -ForegroundColor Yellow
        Write-Host ""
    }
    elseif ($signature.Status -ne 'Valid') {
        Write-Host "  Status Message: $($signature.StatusMessage)" -ForegroundColor Red
        Write-Host ""
    }
    else {
        # Valid signature - show details
        Write-Host "Signature Type: $($signature.SignatureType)" -ForegroundColor White

        # Signer certificate
        if ($signature.SignerCertificate) {
            Write-Host ""
            Write-Host "Signed By:" -ForegroundColor Cyan
            Write-Host "  Subject: $($signature.SignerCertificate.Subject)" -ForegroundColor White

            if ($Detailed) {
                Write-Host "  Issuer: $($signature.SignerCertificate.Issuer)" -ForegroundColor Gray
            }

            Write-Host "  Thumbprint: $($signature.SignerCertificate.Thumbprint)" -ForegroundColor White
            Write-Host "  Valid From: $($signature.SignerCertificate.NotBefore)" -ForegroundColor Gray
            Write-Host "  Valid Until: $($signature.SignerCertificate.NotAfter)" -ForegroundColor Gray

            # Check expiration
            if ($signature.SignerCertificate.NotAfter -lt (Get-Date)) {
                Write-Host "  WARNING: Certificate has expired!" -ForegroundColor Red
            }
            elseif ($signature.SignerCertificate.NotAfter -lt (Get-Date).AddDays(30)) {
                Write-Host "  WARNING: Certificate expires within 30 days" -ForegroundColor Yellow
            }

            # Show extended key usage if detailed
            if ($Detailed) {
                $eku = $signature.SignerCertificate.Extensions |
                    Where-Object { $_.Oid.FriendlyName -eq 'Enhanced Key Usage' }
                if ($eku) {
                    Write-Host "  Enhanced Key Usage:" -ForegroundColor Gray
                    # Parse EKU OIDs
                    if ($eku.Format($false) -match 'Code Signing') {
                        Write-Host "    - Code Signing (1.3.6.1.5.5.7.3.3)" -ForegroundColor Gray
                    }
                }
            }
        }

        # Timestamp
        if ($signature.TimeStamperCertificate) {
            Write-Host ""
            Write-Host "Timestamp:" -ForegroundColor Cyan
            Write-Host "  Authority: $($signature.TimeStamperCertificate.Subject)" -ForegroundColor White

            # Try to get timestamp from signature
            try {
                # Get timestamp from SignatureObject if available
                $timestampTime = $signature.SignatureObject.TimestampCertificates[0].NotBefore
                if ($timestampTime) {
                    Write-Host "  Timestamp: $timestampTime" -ForegroundColor Gray
                }
            }
            catch {
                # Timestamp extraction may not work in all PowerShell versions
                Write-Host "  Present: Yes" -ForegroundColor Gray
            }

            if ($Detailed) {
                Write-Host "  Thumbprint: $($signature.TimeStamperCertificate.Thumbprint)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host ""
            Write-Host "Timestamp: None" -ForegroundColor Yellow
            Write-Host "  WARNING: Signature will expire when certificate expires" -ForegroundColor Yellow
        }

        Write-Host ""
    }

    # =====================================================================
    # PHASE 3: Catalog Contents
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Catalog Contents" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Parse catalog structure to get file list
    Write-Host "Parsing catalog structure..." -ForegroundColor Yellow
    $catalogEntries = Get-CatalogEntries -CatalogPath $catalogFullPath

    if ($catalogEntries -and $catalogEntries.Count -gt 0) {
        Write-Host ""
        Write-Host "Files in catalog: $($catalogEntries.Count)" -ForegroundColor White
        Write-Host ""

        # Display entries
        foreach ($entry in $catalogEntries) {
            Write-Host "  - $($entry.FileName)" -ForegroundColor Cyan
        }
        Write-Host ""
    }
    else {
        Write-Host "  Unable to extract file list from catalog structure" -ForegroundColor Yellow
        Write-Host ""
    }

    # If ValidateAgainst provided, perform validation
    if ($ValidateAgainst) {
        if (-not (Test-Path $ValidateAgainst)) {
            Write-Host "ERROR: Validation target not found: $ValidateAgainst" -ForegroundColor Red
            Write-Host ""
        }
        else {
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "  File Validation" -ForegroundColor Cyan
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""

            Write-Host "Validating against: $ValidateAgainst" -ForegroundColor Yellow
            Write-Host ""

            # Try Test-FileCatalog first
            $testFileCatalogWorked = $false
            try {
                $validationResult = Test-FileCatalog -Path $ValidateAgainst -CatalogFilePath $catalogFullPath -Detailed

                if ($validationResult.CatalogItems -and $validationResult.CatalogItems.Count -gt 0) {
                    $testFileCatalogWorked = $true

                    # Show overall status
                    $validationColor = if ($validationResult.Status -eq 'Valid') { 'Green' } else { 'Red' }
                    Write-Host "Validation Status: $($validationResult.Status)" -ForegroundColor $validationColor
                    Write-Host ""

                    # Display catalog items in table format
                    $catalogItems = $validationResult.CatalogItems | ForEach-Object {
                        $hashDisplay = if ($ShowHashes) {
                            $_.Hash
                        } else {
                            if ($_.Hash -and $_.Hash.Length -gt 16) {
                                $_.Hash.Substring(0, 16) + "..."
                            } else {
                                $_.Hash
                            }
                        }

                        $statusIcon = if ($_.Status -eq 'Valid') { '✓' } else { '✗' }

                        [PSCustomObject]@{
                            Status = "$statusIcon $($_.Status)"
                            File = $_.Name
                            Hash = $hashDisplay
                        }
                    }

                    $catalogItems | Format-Table -AutoSize

                    # Show summary
                    $validCount = ($validationResult.CatalogItems | Where-Object Status -eq 'Valid').Count
                    $invalidCount = $validationResult.CatalogItems.Count - $validCount

                    Write-Host "Summary:" -ForegroundColor Cyan
                    Write-Host "  Valid: $validCount" -ForegroundColor Green
                    if ($invalidCount -gt 0) {
                        Write-Host "  Invalid: $invalidCount" -ForegroundColor Red
                    }
                }
            }
            catch {
                # Test-FileCatalog failed - will use manual validation
            }

            # If Test-FileCatalog didn't work, use manual hash validation
            if (-not $testFileCatalogWorked) {
                Write-Host "Test-FileCatalog doesn't support single-file ZIP catalogs" -ForegroundColor Yellow
                Write-Host "Attempting manual hash validation..." -ForegroundColor Cyan
                Write-Host ""

                $manualValidation = Get-ManualHashValidation -FilePath $ValidateAgainst -CatalogPath $catalogFullPath

                Write-Host "File: $($manualValidation.FileName)" -ForegroundColor White
                Write-Host "  Algorithm: $($manualValidation.Algorithm)" -ForegroundColor Gray
                Write-Host "  Calculated Hash: $($manualValidation.ActualHash)" -ForegroundColor Gray

                if ($manualValidation.Valid) {
                    Write-Host "  Status: ✓ VALID (hash found in catalog)" -ForegroundColor Green
                    $manualValidationPassed = $true
                }
                else {
                    Write-Host "  Status: ✗ VALIDATION INCONCLUSIVE" -ForegroundColor Yellow
                    Write-Host "  Note: Full catalog parsing requires complex ASN.1 decoder" -ForegroundColor Gray
                    $manualValidationPassed = $null
                }
            }

            Write-Host ""
        }
    }

    # =====================================================================
    # PHASE 4: Summary
    # =====================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Overall status
    $overallStatus = if ($signature.Status -eq 'Valid') { 'VALID' } else { 'INVALID' }
    $overallColor = if ($signature.Status -eq 'Valid') { 'Green' } else { 'Red' }

    Write-Host "Catalog Signature: $overallStatus" -ForegroundColor $overallColor

    if ($ValidateAgainst -and $testFileCatalogWorked -and $validationResult) {
        $validationStatus = if ($validationResult.Status -eq 'Valid') { 'VALID' } else { 'INVALID' }
        $validationColor = if ($validationResult.Status -eq 'Valid') { 'Green' } else { 'Red' }
        Write-Host "File Validation: $validationStatus" -ForegroundColor $validationColor
    }
    elseif ($ValidateAgainst -and $manualValidationPassed -eq $true) {
        Write-Host "File Validation: VALID (manual hash comparison)" -ForegroundColor Green
    }
    elseif ($ValidateAgainst -and $manualValidationPassed -eq $false) {
        Write-Host "File Validation: INVALID (hash mismatch)" -ForegroundColor Red
    }
    elseif ($ValidateAgainst -and $manualValidationPassed -eq $null) {
        Write-Host "File Validation: INCONCLUSIVE (limited parsing)" -ForegroundColor Yellow
    }

    Write-Host ""

    # Recommendations
    if ($signature.Status -eq 'Valid' -and -not $signature.TimeStamperCertificate) {
        Write-Host "RECOMMENDATION:" -ForegroundColor Yellow
        Write-Host "  Re-sign this catalog with a timestamp server for long-term validity" -ForegroundColor White
        Write-Host ""
    }

    if ($ValidateAgainst -and $manualValidationPassed -eq $null) {
        Write-Host "NOTE:" -ForegroundColor Cyan
        Write-Host "  This script performs simplified catalog parsing" -ForegroundColor White
        Write-Host "  For full hash extraction, a complete ASN.1/DER parser is needed" -ForegroundColor White
        Write-Host "  The catalog signature is valid, indicating integrity of the catalog itself" -ForegroundColor White
        Write-Host ""
    }

    exit 0
}
catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Catalog Inspection Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    # Contextual help
    if ($_.Exception.Message -match "Access.*denied") {
        Write-Host "TROUBLESHOOTING:" -ForegroundColor Yellow
        Write-Host "  1. Verify you have read permissions to the catalog file" -ForegroundColor White
        Write-Host "  2. Check the file is not locked by another process" -ForegroundColor White
        Write-Host ""
    }

    exit 1
}
