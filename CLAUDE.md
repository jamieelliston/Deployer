# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Deployer** is a Windows deployment automation system designed for zero-touch deployment scenarios in WinPE/WinRE environments. It provides configuration-driven image deployment with Azure Blob Storage integration, supporting ISO, FFU, and WIM formats with comprehensive offline customization capabilities.

**Technology Stack:**
- PowerShell 5.1+ (WinPE/WinRE compatible)
- Azure Blob Storage for image and package distribution
- PowerShell configuration files with Authenticode signature validation
- DISM for offline image servicing
- UEFI/GPT partitioning (no BIOS/MBR support)

## Development Commands

### Configuration Validation
```powershell
# Test loading a deployment configuration
$config = & "Config/Examples/deployment-iso-example-config.ps1"
$config | Format-List

# Test loading a bootstrap configuration
$config = & "Config/Examples/bootstrap-example-config.ps1"
$config | Format-List

# Sign all deployment scripts and configurations
.\Sign-DeploymentScripts.ps1

# Verify signature of a specific file
Get-AuthenticodeSignature -FilePath "Scripts\Deploy-Windows\Deploy-Windows.ps1"
```

### PowerShell Script Testing
```powershell
# Test syntax of a script file
Get-Command -Syntax -Name "Scripts/Functions/Web-Functions.ps1"

# Dot-source functions for manual testing (simulates deployment script behavior)
. ./Scripts/Functions/Utility-Functions.ps1
. ./Scripts/Functions/Validation-Functions.ps1
. ./Scripts/Functions/Web-Functions.ps1
. ./Scripts/Functions/SMB-Functions.ps1

# Test a specific function
Test-WinPEEnvironment
```

### PowerShell Script Analysis
```powershell
# Analyze script with PSScriptAnalyzer (if available)
Invoke-ScriptAnalyzer -Path "Scripts/Functions/" -Recurse
```

**Note:** This project currently has no automated build system, test suite, or linting configuration. Scripts are designed to run directly in WinPE/WinRE environments.

## Architecture & Code Structure

### Configuration System

The deployment system is entirely **configuration-driven** using PowerShell .ps1 files that return hashtables:

- **Bootstrap Configuration**: Defines package download from Azure Blob/SMB, Deploy-Windows.ps1 script signature validation, and extraction settings for the bootstrap phase
- **Deployment Configuration**: Comprehensive deployment configuration including image source, disk partitioning, and customizations

Configuration files are PowerShell scripts that return a hashtable using `return @{...}` syntax. This allows them to be code-signed with Authenticode signatures.

Example configurations in `Config/Examples/`:
- `bootstrap-example-config.ps1` - Bootstrap phase with signature verification and trusted publishers
- `bootstrap-blob-sas-config.ps1` - Bootstrap with SAS token authentication
- `bootstrap-smb-example-config.ps1` - Bootstrap from SMB network share
- `deployment-iso-example-config.ps1` - Full Windows 11 Pro deployment with drivers, registry mods, Autopilot, and Unattend.xml
- `deployment-ffu-example-config.ps1` - Fast FFU deployment with minimal customization
- `deployment-smb-example-config.ps1` - Deployment with image from SMB share

Configuration validation is performed by `Test-BootstrapConfigurationStructure` and `Test-DeploymentConfigurationStructure` functions, which replace the previous JSON Schema validation.

### Function Library Design

**Critical: Functions are DOT-SOURCED, not imported as modules.** This is intentional due to WinPE/WinRE environment constraints where full PowerShell module support is limited.

Main deployment scripts load functions via:
```powershell
# Bootstrap (web downloads only)
. ./Scripts/Functions/Validation-Functions.ps1
. ./Scripts/Functions/Web-Functions.ps1
. ./Scripts/Functions/Utility-Functions.ps1

# Main deployment (web + SMB support)
. ./Scripts/Functions/Validation-Functions.ps1
. ./Scripts/Functions/Web-Functions.ps1
. ./Scripts/Functions/SMB-Functions.ps1
. ./Scripts/Functions/Utility-Functions.ps1
```

### Deployment Phases

1. **Bootstrap Phase** (optional)
   - **Self-update check**: Download Deploy-Bootstrap.ps1 directly, compare versions
   - If newer version available, validate signature and re-execute updated script
   - Download deployment package from Azure Blob Storage or SMB share
   - Validate Deploy-Windows.ps1 script signature (no catalog validation for bootstrap)
   - Extract deployment package to target location

2. **Validation Phase**
   - Verify WinPE/UEFI environment (`Test-WinPEEnvironment`)
   - Validate configuration JSON against schema (`Test-DeploymentConfig`)
   - Check disk requirements and readiness (`Test-DiskRequirements`)
   - Test network connectivity for Azure downloads (`Test-NetworkConnectivity`)

3. **Preparation Phase**
   - Download Windows image (ISO/FFU/WIM) from Azure or local path
   - Create temporary working directories (`Get-TemporaryPath`)
   - Prepare target disk (clean/partition with GPT)

4. **Deployment Phase**
   - Install Windows from image source
   - Create GPT partitions: EFI (100MB), MSR (16MB), Recovery (1024MB), Windows (remaining)

5. **Customization Phase**
   - Inject drivers (offline DISM operations)
   - Apply registry modifications (offline hive loading)
   - Copy files to deployed image
   - Apply Windows Autopilot configuration
   - Apply Unattend.xml

6. **Cleanup Phase**
   - Dismount all mounted images
   - Unload registry hives
   - Remove temporary files and directories
   - Copy deployment logs to deployed system (`Copy-DeploymentLogsToImage`)

### Module Organization

**`Scripts/Functions/Validation-Functions.ps1`** (360 lines)
- `Test-WinPEEnvironment` - Validates WinPE/RE environment, UEFI boot, PowerShell version, RAM, scratch space
- `Test-DeploymentConfig` - Validates JSON configuration structure and settings
- `Test-DiskRequirements` - Checks target disk size, online status, and existing partitions
- `Test-NetworkConnectivity` - Verifies network access for Azure Blob downloads

**`Scripts/Functions/Web-Functions.ps1`** (~350 lines)
- `Get-AzureBlobAnonymous` - Download from Azure Blob without authentication (BITS or WebClient)
- `Get-AzureBlobWithSAS` - Download with SAS token authentication
- `Test-AzureBlobConnection` - Test connectivity and retrieve blob metadata
- `Get-DeploymentFile` - Unified function for web, SMB, or local file operations (auto-detects source type)

**`Scripts/Functions/SMB-Functions.ps1`** (~290 lines)
- `Get-SMBFile` - Download from SMB/UNC path with optional credentials and drive mapping
- `Test-SMBConnection` - Test SMB share connectivity with optional credentials

**`Scripts/Functions/Utility-Functions.ps1`** (448 lines)
- **Logging**: `Initialize-DeploymentLogging`, `Write-DeploymentLog` (with levels: Verbose, Info, Warning, Error)
- **UI/Display**: `Show-DeploymentProgress`, `Show-DeploymentStatus`, `Show-DeploymentError`
- **Resource Management**: `Get-TemporaryPath`, `Invoke-CleanupDeployment`, `Copy-DeploymentLogsToImage`

## Key Technical Patterns

### Logging System

**All functions must use the centralized logging system:**

```powershell
# Initialize logging at script start
Initialize-DeploymentLogging -LogPath "X:\Deploy\Logs" -LogLevel "Info"

# Write log entries with levels
Write-DeploymentLog "Starting deployment validation" -Level Info
Write-DeploymentLog "WARNING: Disk has existing partitions" -Level Warning
Write-DeploymentLog "ERROR: Failed to download image" -Level Error
Write-DeploymentLog "Detailed debug information" -Level Verbose
```

Features:
- Automatic log rotation (10MB max file size by default)
- Color-coded console output
- Log level filtering
- Timestamp headers

### Resource Tracking and Cleanup

**Critical pattern: Track all mounted images, loaded registry hives, and temp paths in a `$DeploymentState` hashtable for cleanup:**

```powershell
# Initialize state tracker
$DeploymentState = @{
    MountedImages = @()
    LoadedHives = @()
    TempPaths = @()
}

# Track mounted image
$DeploymentState.MountedImages += $mountPath

# Track loaded registry hive
$DeploymentState.LoadedHives += "HKLM\DEPLOYER_SOFTWARE"

# Track temp directory
$DeploymentState.TempPaths += $tempDir

# Cleanup (always call in finally block or on error)
Invoke-CleanupDeployment -State $DeploymentState
```

### Error Handling

**All deployment operations use try-catch with detailed logging:**

```powershell
try {
    Write-DeploymentLog "Starting operation..." -Level Info
    # Perform operation
    Write-DeploymentLog "Operation completed successfully" -Level Info
}
catch {
    Write-DeploymentLog "ERROR: Operation failed: $($_.Exception.Message)" -Level Error
    # Cleanup resources
    Invoke-CleanupDeployment -State $DeploymentState
    throw
}
```

### Offline Image Customization

**Registry modifications use offline hive loading:**

```powershell
# Load registry hive from offline image
reg load "HKLM\DEPLOYER_SOFTWARE" "$mountPath\Windows\System32\config\SOFTWARE"
$DeploymentState.LoadedHives += "HKLM\DEPLOYER_SOFTWARE"

# Make modifications
Set-ItemProperty -Path "HKLM:\DEPLOYER_SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" `
    -Name "Manufacturer" -Value "Contoso"

# Unload in cleanup
reg unload "HKLM\DEPLOYER_SOFTWARE"
```

**Driver injection uses DISM:**

```powershell
Add-WindowsDriver -Path $mountPath -Driver $driverPath -Recurse
```

### Azure Authentication Patterns

**Three source types supported:**

```powershell
# Azure Blob - Anonymous access (public blobs)
Get-AzureBlobAnonymous -BlobUrl $url -Destination $dest -ShowProgress

# Azure Blob - SAS token authentication
Get-AzureBlobWithSAS -BlobUrl $url -SasToken $token -Destination $dest -ShowProgress

# SMB/Network Share - With credentials
$securePassword = ConvertTo-SecureString -String "password" -AsPlainText -Force
Get-SMBFile -UncPath "\\server\share\file.iso" -Destination $dest -Username "domain\user" -Password $securePassword -ShowProgress

# SMB/Network Share - Current user context (no credentials)
Get-SMBFile -UncPath "\\server\share\file.iso" -Destination $dest -ShowProgress
```

### Configuration Validation

**PowerShell configuration loading and validation:**

```powershell
# Load configuration from PowerShell script
try {
    $config = & $configPath

    if ($null -eq $config) {
        throw "Configuration script returned null. Ensure the script returns a hashtable using 'return @{...}'"
    }

    if ($config -isnot [hashtable]) {
        throw "Configuration script must return a hashtable. Got: $($config.GetType().Name)"
    }
}
catch {
    throw "Failed to load configuration from $configPath : $_"
}

# Validate configuration structure
$validation = Test-DeploymentConfigurationStructure -Config $config
if (-not $validation.Passed) {
    throw "Configuration validation failed: " + ($validation.Issues -join "; ")
}
```

### Script Signing and Signature Validation

**All PowerShell deployment scripts and configuration files can be signed with Authenticode signatures.** This replaces the previous catalog-based validation approach.

**Signing Scripts:**

Use `Sign-DeploymentScripts.ps1` to sign all deployment files:

```powershell
# Sign all deployment scripts using first available code signing certificate
.\Sign-DeploymentScripts.ps1

# Sign using a specific certificate thumbprint
.\Sign-DeploymentScripts.ps1 -CertificateThumbprint "A1B2C3D4E5F6..."

# Sign a specific file
.\Sign-DeploymentScripts.ps1 -FilePath "Config\Examples\deployment-iso-example-config.ps1"
```

**Signature Validation:**

Deploy-Bootstrap.ps1 validates the Deploy-Windows.ps1 script signature directly when signature checking is enabled:

```powershell
# Bootstrap configuration with signature validation
return @{
    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "Thumbprint:A1B2C3D4E5F6..."  # Exact thumbprint match
            "CN:Contoso Corporation"       # Certificate CN contains match
        )
        requireValidSignature = $true      # Fail if signature invalid
    }
}
```

**Trusted Publisher Formats:**
- `"Thumbprint:<40-hex-chars>"` - Exact certificate thumbprint match
- `"CN:<common-name>"` - Certificate subject CN contains the specified text

**Signature Validation Flow:**
1. Bootstrap downloads and extracts deployment package to temporary location
2. Validates Deploy-Windows.ps1 signature using `Get-AuthenticodeSignature`
3. Checks signature status (must be "Valid")
4. Verifies signer is in trustedPublishers list (Thumbprint or CN match)
5. Moves validated package to target location

### Package Hash Validation

**Package integrity can be validated using cryptographic hashes before extraction.** This adds an additional security layer by verifying the deployment package ZIP file has not been tampered with or corrupted.

**Generating Package Hash:**

Use `New-PackageHash.ps1` to create and auto-sign a hash file for your deployment package:

```powershell
# Generate hash file - automatically signs if certificate available
.\New-PackageHash.ps1 -ZipPath ".\DeploymentPackage.zip"
# Creates: DeploymentPackage.ps1 (same name as ZIP, .ps1 extension)

# Use specific certificate
.\New-PackageHash.ps1 -ZipPath ".\DeploymentPackage.zip" -CertificateThumbprint "A1B2C3D4..."

# Use different algorithm
.\New-PackageHash.ps1 -ZipPath ".\DeploymentPackage.zip" -Algorithm SHA512

# Skip signing (not recommended)
.\New-PackageHash.ps1 -ZipPath ".\DeploymentPackage.zip" -NoSign

# Upload both files to deployment source
# - DeploymentPackage.zip
# - DeploymentPackage.ps1 (auto-signed if certificate found)
```

**Auto-Discovery:** Bootstrap automatically looks for a .ps1 file with the same name as the ZIP file. No need to specify `packageHashUrl` unless the hash file has a different name or location.

**Enabling Hash Validation:**

Hash validation is automatic if a matching .ps1 file exists. Optionally specify `packageHashUrl` for custom locations:

```powershell
# Option 1: Auto-discovery (recommended)
return @{
    packageSource = @{
        blobUrl = "https://.../DeploymentPackage.zip"
        # packageHashUrl is optional - will auto-discover DeploymentPackage.ps1
        authType = "Anonymous"
    }
    validation = @{
        enableSignatureCheck = $true  # Also validates hash file signature
        trustedPublishers = @("CN=Contoso Corporation")
        requireValidSignature = $true
    }
}

# Option 2: Explicit hash URL (for custom naming or location)
return @{
    packageSource = @{
        blobUrl = "https://.../DeploymentPackage.zip"
        packageHashUrl = "https://.../custom-hash-name.ps1"  # Override auto-discovery
        authType = "Anonymous"
    }
}
```

**Hash Validation Flow:**

Deploy-Bootstrap.ps1 automatically performs these steps:

1. **Download Package**: Downloads deployment ZIP file from configured source
2. **Auto-Discover Hash**: Looks for hash file with same name as ZIP but .ps1 extension
   - If `packageHashUrl` specified: Uses that URL
   - Otherwise: Replaces .zip with .ps1 in package URL
3. **Download Hash File**: Downloads the signed hash script (warns if not found, continues without validation)
4. **Verify Hash Signature**: Validates hash file signature against trustedPublishers (if signature checking enabled)
5. **Load Expected Hash**: Executes hash script to retrieve expected hash value
6. **Calculate Actual Hash**: Computes hash of downloaded ZIP file
7. **Compare Hashes**: Verifies actual hash matches expected hash
8. **Fail or Continue**: Throws error if mismatch, continues to script validation if match

**Hash File Format:**

The hash file is a PowerShell script that returns a hashtable:

```powershell
return @{
    fileName = "DeploymentPackage.zip"
    algorithm = "SHA256"
    hash = "A1B2C3D4E5F6..."
    sizeBytes = 104857600
    sizeMB = 100.0
    generatedDate = "2025-01-15 10:30:00"
    generatedBy = "admin@buildserver"
}
```

**Security Chain:**

The complete validation chain provides defense in depth:

1. **Hash File Signature** → Proves hash value is from trusted source
2. **ZIP Hash Match** → Proves package hasn't been tampered with
3. **Deploy-Windows.ps1 Signature** → Proves deployment script is authentic

All three layers must pass for deployment to proceed when fully configured.

### Bootstrap Version Checking and Self-Update

**Deploy-Bootstrap.ps1 downloads and executes updated versions of itself directly** - no ZIP extraction required. This provides faster updates and simpler architecture.

**How It Works:**

1. **Version Comparison**: Bootstrap compares `$BOOTSTRAP_VERSION` with remote version file
2. **Direct Download**: If newer version available, downloads Deploy-Bootstrap.ps1 directly
3. **Version Extraction**: Uses `Get-ScriptVersion` function to parse version from downloaded file
4. **Signature Validation**: Validates script signature if `enableSignatureCheck` enabled
5. **Re-execution**: If valid and newer, executes downloaded script with same parameters

**Key Function: Get-ScriptVersion**

```powershell
function Get-ScriptVersion {
    param([string]$ScriptPath)

    # Parses $BOOTSTRAP_VERSION = "1.2.0" using regex
    $content = Get-Content -Path $ScriptPath -Raw
    if ($content -match '\$BOOTSTRAP_VERSION\s*=\s*"([^"]+)"') {
        return $matches[1]
    }
    return $null
}
```

**Configuration Schema:**

```powershell
return @{
    bootstrapUpdate = @{
        enabled = $true
        # Direct .ps1 script URL (not ZIP)
        scriptUrl = "https://.../Deploy-Bootstrap.ps1"
        # Version file URL (optional - auto-derived)
        versionFileUrl = "https://.../DeployBootstrap-version.ps1"
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @("CN:YourOrg")
        requireValidSignature = $true
    }
}
```

**Version File Format:**

```powershell
# DeployBootstrap-version.ps1
return @{
    version = "1.3.0"
    releaseDate = "2026-01-04"
    minimumPSVersion = "5.1"
    changes = @(
        "Direct script download (no ZIP extraction)"
        "Get-ScriptVersion function for version parsing"
        "40-50% faster update process"
    )
    breaking = $false
}
```

**Update Flow:**

```
Deploy-Bootstrap.ps1 (v1.2.0) starts
│
├─→ Download DeployBootstrap-version.ps1
│   └─→ Compare versions: 1.2.0 vs 1.3.0
│
├─→ Download Deploy-Bootstrap.ps1 directly
│   └─→ Save to temp: C:\Temp\BootstrapUpdate_xxx\Deploy-Bootstrap.ps1
│
├─→ Extract version from downloaded file
│   └─→ Get-ScriptVersion: Found version "1.3.0"
│
├─→ Validate signature (if enabled)
│   └─→ Get-AuthenticodeSignature + trusted publisher check
│
└─→ Re-execute new script
    └─→ & $newScriptPath -ConfigPath $config -TestMode:$TestMode
    └─→ exit 0 (current script terminates)
```

**Auto-Discovery:**

- `scriptUrl`: Required in config (points to .ps1 file)
- `versionFileUrl`: Optional - auto-derives by replacing `.ps1` → `-version.ps1`
- If download fails or same/older version: continues with current script (non-fatal)

**Benefits:**

- **40-50% faster**: No ZIP extraction overhead
- **Simpler**: Single file download instead of package
- **Bandwidth efficient**: Only downloads if version check indicates update
- **Non-breaking**: Update failures are graceful (continues with current version)

**Important Notes:**

- Bootstrap does NOT use catalog validation (.cat files) for self-update
- Deploy-Windows.ps1 signature IS validated after extraction from deployment package
- Version checking uses semantic versioning (Major.Minor.Patch comparison)

### Deploy-Windows Version Tracking

**Deploy-Windows.ps1 now includes version tracking** for future self-update capability:

```powershell
# Deploy-Windows.ps1 (line 63)
$DEPLOYMENT_VERSION = "1.0.0"
```

**Purpose:**
- Tracks the deployment script version
- Enables future catalog-based self-update feature
- Allows version comparison for deployment package updates

**Future Enhancement (Planned):**

Deploy-Windows will support self-update via catalog validation:
1. Download DeploymentPackage.cat before downloading package
2. Validate catalog signature
3. Compare catalog signing timestamp with current script
4. If catalog is newer, download and extract package
5. Re-execute updated Deploy-Windows.ps1

**Status**: Version variable added (v1.0.0), self-update logic pending implementation.

## Important Constraints

### Environment Requirements

- **WinPE/WinRE only**: Designed specifically for Windows Preinstallation Environment
- **PowerShell 5.1+**: Minimum required version
- **UEFI boot mode**: BIOS/Legacy boot not supported
- **GPT partitioning**: MBR not supported
- **Elevated privileges**: Must run as administrator
- **Network connectivity**: Required for Azure Blob downloads

### Partitioning Constraints

**Only GPT partition style is supported with this fixed layout:**
- EFI System Partition (default 100MB, configurable)
- MSR (Microsoft Reserved) Partition (default 16MB, configurable)
- Recovery Partition (default 1024MB, configurable)
- Windows Partition (remaining space, or configurable size)

### Image Source Flexibility

**Supports three image formats:**
- **ISO**: Multi-edition support with imageIndex selection
- **FFU**: Fast Flash Update format for rapid deployment (placeholder)
- **WIM**: Windows Imaging format

**Source locations:**
- **Azure Blob Storage**: Anonymous or SAS token authentication
- **SMB/Network Shares**: UNC paths with optional credentials (\\server\share\image.iso)
- **Local file paths**: For pre-downloaded or offline scenarios

### Function Design Philosophy

- Functions use PowerShell comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.OUTPUTS`)
- All functions assume they're dot-sourced into the calling script's scope
- Functions depend on shared logging (`Write-DeploymentLog`) and utility functions
- No module manifests or `Export-ModuleMember` directives

## Bootable ISO Builder (`Build-BootableISO.ps1`)

The Build-BootableISO.ps1 script creates bootable WinPE/WinRE ISOs with embedded deployment scripts.

**Key Features:**
- Extracts WinRE from Windows ISO for lighter, faster boot images
- Customizes boot.wim with deployment scripts and packages
- Supports driver injection
- Creates bootable ISO with oscdimg

**Usage:**
```powershell
# Build WinRE-based ISO from Windows installation media
.\Build-BootableISO.ps1 -UseWinRE -WinREISOPath "C:\ISOs\Win11.iso"

# Build standard WinPE ISO
.\Build-BootableISO.ps1 -Architecture amd64

# Custom output location
.\Build-BootableISO.ps1 -UseWinRE -WinREISOPath "C:\ISOs\Win11.iso" -OutputPath "C:\Output\Deployer.iso"
```

**Administrator Requirement:**
The script **MUST** be run as Administrator due to DISM operations requiring elevated privileges. The script includes an explicit check at startup and will fail early with clear instructions if not elevated.

### ADK Environment Initialization

**copype.cmd requires ADK environment variables to be set up before execution:**

```powershell
# CRITICAL: copype.cmd depends on environment variables like %WinPERoot%, %DISMRoot%, and %OSCDImgRoot%
# These are set by DandISetEnv.bat and MUST be initialized in the same cmd session

$dandISetEnvPath = Join-Path $adkPath "Deployment Tools\DandISetEnv.bat"
$copypeArgs = "$Architecture `"$workingPath`""

# Run both DandISetEnv.bat and copype.cmd in the same cmd session using &&
$combinedCommand = "`"`"$dandISetEnvPath`" && `"$copypePath`" $copypeArgs`""
$copypeResult = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $combinedCommand" -Wait -NoNewWindow -PassThru
```

**Why:** `copype.cmd` checks for the existence of `%WinPERoot%\<arch>` (line 32 of copype.cmd). Without running `DandISetEnv.bat` first, these variables are undefined and copype.cmd fails with "ERROR: The following processor architecture was not found".

### WinRE vs WinPE Package Requirements

**WinRE already includes essential components built-in** - do NOT install packages unnecessarily:

```powershell
# Add essential packages (only needed for WinPE, WinRE has them built-in)
if (-not $UseWinRE) {
    # Install WinPE-WMI, WinPE-PowerShell, WinPE-NetFx, WinPE-StorageWMI, WinPE-DismCmdlets
} else {
    # Skip - WinRE already includes these components
}
```

**Why:** WinRE (Windows Recovery Environment) is based on WinPE but includes PowerShell, WMI, wireless support (WinPE-WiFi), and other components by default. Installing packages that already exist:
- Wastes 5-10 minutes of build time
- May cause conflicts or warnings
- Doesn't follow Microsoft's recommended approach ([reference](https://msendpointmgr.com/2018/03/06/build-a-winpe-with-wireless-support/))

**WinRE only requires:** Adding `dmcmnutils.dll` and `mdmregistration.dll` for wireless support in Windows 10 1607+ (handled by `-EnableWireless` flag).

### Boot Prompt Control (-PAK Parameter)

**Control the "Press Any Key to Boot" prompt** using the `-PAK` parameter:

```powershell
# Default: NO boot prompt (automatic boot)
.\Build-BootableISO.ps1 -UseWinRE -WinREISOPath "C:\ISOs\Win11.iso"

# With -PAK: WITH boot prompt
.\Build-BootableISO.ps1 -UseWinRE -WinREISOPath "C:\ISOs\Win11.iso" -PAK
```

**Implementation:**
- **Default (no `-PAK`)**: Uses `efisys_noprompt_EX.bin` - boots automatically without key press
- **With `-PAK` flag**: Uses `efisys_EX.bin` - displays "Press any key to boot from CD or DVD..."
- Uses Windows UEFI CA 2023 signatures (\_EX files) with fallback to standard signatures
- Bypasses `MakeWinPEMedia.cmd` and calls `oscdimg.exe` directly for full control

**Why:** Automated deployments and VM testing benefit from immediate boot without manual intervention. The `-PAK` flag is available when the prompt is needed for physical media or user choice scenarios.

### Critical DISM Invocation Pattern

**NEVER use `Start-Process` with dism.exe** - it causes hanging with complex console applications:

```powershell
# ❌ WRONG - Will hang indefinitely
$dismResult = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru
if ($dismResult.ExitCode -ne 0) {
    throw "Failed"
}

# ✅ CORRECT - Direct invocation
dism.exe /Mount-Image /ImageFile:"$imagePath" /Index:1 /MountDir:"$mountPath"
$dismExitCode = $LASTEXITCODE
if ($dismExitCode -ne 0) {
    throw "Failed to mount. Exit code: $dismExitCode"
}
```

**Why:** `Start-Process -Wait` with `-NoNewWindow` doesn't reliably return control when used with DISM, which outputs progress bars and formatted text. Direct invocation works correctly.

### WIM File Attribute Handling

**Files copied from read-only DISM mounts must have attributes corrected:**

```powershell
# After copying WIM file from read-only mount
Copy-Item -Path $sourceWim -Destination $bootWimPath -Force

# CRITICAL: Remove read-only attribute for subsequent DISM operations
Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction Stop
```

**Why:** WIM files copied from read-only mounted images retain restrictive permissions that prevent DISM from mounting them read-write, causing "Access Denied" errors (exit code 5).

### Enhanced Error Reporting Pattern

**Provide contextual error messages for common DISM failures:**

```powershell
dism.exe /Mount-Image /ImageFile:"$wimPath" /Index:1 /MountDir:"$mountPath"
$dismExitCode = $LASTEXITCODE

# Check for specific error codes and provide actionable guidance
if ($dismExitCode -eq 5) {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ACCESS DENIED ERROR" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  1. Antivirus software blocking DISM" -ForegroundColor Cyan
    Write-Host "  2. File permissions issue" -ForegroundColor Cyan
    Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
    Write-Host "  1. Check DISM log: C:\WINDOWS\Logs\DISM\dism.log" -ForegroundColor Cyan
    Write-DeploymentLog "DISM mount failed with ACCESS DENIED (exit code 5)" -Level Error
}

if ($dismExitCode -ne 0) {
    throw "Failed to mount. Exit code: $dismExitCode"
}
```

### Contextual Cleanup Messages

**Cleanup phases should clearly indicate WHY they're running:**

```powershell
finally {
    Write-Host ""

    # Determine cleanup reason
    if ($_.Exception) {
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  CLEANUP: Error Recovery" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
    }
    else {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  CLEANUP: WinRE Extraction Complete" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
    }

    # Perform cleanup...

    # Indicate completion
    if (-not $_.Exception) {
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  CLEANUP COMPLETED - Continuing Build" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
    }
}
```

**Why:** Users need to understand whether cleanup is happening due to success, error, or leftover resources from previous runs.

### Background Job Pattern for Long Operations

**For operations without native progress reporting, use background jobs with periodic updates:**

```powershell
# Start operation as background job
$copyJob = Start-Job -ScriptBlock {
    param($Source, $Dest)
    Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
} -ArgumentList $sourcePath, $destPath

# Monitor and report progress
$expectedSize = (Get-Item $sourcePath).Length
$updateCounter = 0

while ($copyJob.State -eq 'Running') {
    Start-Sleep -Seconds 10
    $updateCounter++

    if ($updateCounter -ge 3) {  # Report every 30 seconds
        if (Test-Path $destPath) {
            $currentSize = (Get-Item $destPath).Length
            $percentComplete = [math]::Round(($currentSize / $expectedSize) * 100, 1)
            Write-Host "  Still copying... $percentComplete% complete" -ForegroundColor Cyan
        }
        $updateCounter = 0
    }
}

# Get result and cleanup job
$result = Receive-Job -Job $copyJob -Wait
Remove-Job -Job $copyJob
```

**Why:** Large file operations (600MB+ WIM files) can take 10-30 minutes with no native progress indication. Background jobs with monitoring prevent the appearance of hanging.

## Configuration is King

**All deployment logic is driven by PowerShell configuration files.** When modifying deployment behavior:

1. Check if the desired behavior can be configured via PowerShell hashtables
2. Review existing example configurations in `Config/Examples/` for patterns
3. Update `Test-BootstrapConfigurationStructure` or `Test-DeploymentConfigurationStructure` if adding new required fields
4. Provide example configurations in `Config/Examples/` as .ps1 files
5. Sign configuration files with `Sign-DeploymentScripts.ps1` for production use
