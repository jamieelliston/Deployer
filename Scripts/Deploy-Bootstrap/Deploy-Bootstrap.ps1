#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Bootstrap deployment script with embedded functions

.DESCRIPTION
    Self-contained bootstrap script for code signing compatibility.
    All function libraries are embedded in this file.

    This script handles the bootstrap phase of Windows deployment automation:
    - Loads and validates bootstrap configuration from PowerShell .ps1 file
    - Downloads deployment package (ZIP) from Azure Blob Storage
    - Validates Deploy-Windows.ps1 script signature directly
    - Extracts package to target location
    - Optionally launches main deployment script

    Functions included:
    - Utility-Functions: Logging, resource management, UI
    - Validation-Functions: Environment and config validation
    - Web-Functions: Azure Blob downloads

.PARAMETER ConfigPath
    Path to bootstrap configuration PowerShell script (.ps1 file)
    Must return a hashtable with required configuration sections
    Default: bootstrap-config.ps1 in script directory

.PARAMETER LaunchDeployment
    Automatically launch Deploy-Windows.ps1 after successful extraction

.PARAMETER DeploymentConfigPath
    Path to deployment config to pass to Deploy-Windows.ps1
    Only used if -LaunchDeployment is specified

.EXAMPLE
    .\Deploy-Bootstrap.ps1
    Uses default bootstrap-config.ps1 from script directory

.EXAMPLE
    .\Deploy-Bootstrap.ps1 -ConfigPath "X:\Deploy\Config\bootstrap-config.ps1"

.EXAMPLE
    .\Deploy-Bootstrap.ps1 -LaunchDeployment -DeploymentConfigPath "X:\Deploy\Config\deployment-config.ps1"
    Uses default bootstrap-config.ps1 and launches main deployment

.NOTES
    This is a consolidated version for code signing.
    Original modular version: Scripts/Deploy-Bootstrap.ps1

    Author: Windows Deployment Automation
    Requires: PowerShell 5.1+, Administrator privileges
    Environment: WinPE/WinRE
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
            throw "Configuration file not found: $_"
        }
        if ($_ -and $_ -notmatch '\.ps1$') {
            throw "Configuration file must be a PowerShell script (.ps1): $_"
        }
        return $true
    })]
    [string]$ConfigPath,

    [Parameter(Mandatory = $false)]
    [switch]$LaunchDeployment,

    [Parameter(Mandatory = $false)]
    [string]$DeploymentConfigPath,

    [Parameter(Mandatory = $false)]
    [switch]$TestMode
)

# Set script root
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Store test mode in script scope for embedded functions to access
$script:TestMode = $TestMode.IsPresent

# Bootstrap Script Version
$BOOTSTRAP_VERSION = "1.0.0"

# Default to bootstrap-config.ps1 in script directory if not specified
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $ScriptRoot "bootstrap-config.ps1"
    Write-Host "No config path specified, using default: $ConfigPath" -ForegroundColor Cyan
}

# Validate config file exists
if (-not (Test-Path $ConfigPath -PathType Leaf)) {
    Write-Host "ERROR: Configuration file not found: $ConfigPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please either:" -ForegroundColor Yellow
    Write-Host "  1. Create bootstrap-config.ps1 in the script directory: $ScriptRoot" -ForegroundColor White
    Write-Host "  2. Specify -ConfigPath parameter with path to your bootstrap configuration (.ps1 file)" -ForegroundColor White
    exit 1
}

#region Embedded Functions

#region Utility Functions

# Script-level variables for logging configuration
$script:LogConfig = @{
    LogPath = if ($script:TestMode) { "C:\DeploymentTest\Deploy\Logs\Deployment.log" } else { "X:\Deploy\Logs\Deployment.log" }
    LogLevel = "Info"
    MaxLogSizeMB = 10
    EnableConsole = $true
}

# Initialize logging system
function Initialize-DeploymentLogging {
    <#
    .SYNOPSIS
        Initialize deployment logging system
    .PARAMETER LogPath
        Path to log file
    .PARAMETER LogLevel
        Minimum log level (Verbose, Info, Warning, Error)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = $(if ($script:TestMode) { "C:\DeploymentTest\Deploy\Logs\Deployment.log" } else { "X:\Deploy\Logs\Deployment.log" }),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Verbose', 'Info', 'Warning', 'Error')]
        [string]$LogLevel = 'Info'
    )

    # Create log directory if it doesn't exist
    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Initialize log file with header
    $header = @"
========================================
Windows Deployment Log
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
PowerShell Version: $($PSVersionTable.PSVersion)
Computer: $env:COMPUTERNAME
========================================

"@

    $header | Out-File -FilePath $LogPath -Encoding UTF8

    # Update script-level configuration
    $script:LogConfig.LogPath = $LogPath
    $script:LogConfig.LogLevel = $LogLevel

    Write-Host "Logging initialized: $LogPath" -ForegroundColor Green
}

# Write log entry
function Write-DeploymentLog {
    <#
    .SYNOPSIS
        Write log entry to file and console
    .PARAMETER Message
        Log message
    .PARAMETER Level
        Log level (Verbose, Info, Warning, Error)
    .PARAMETER LogPath
        Optional override log path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Verbose', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $script:LogConfig.LogPath
    )

    # Check if message level meets minimum log level
    $levels = @('Verbose', 'Info', 'Warning', 'Error')
    $currentLevelIndex = $levels.IndexOf($script:LogConfig.LogLevel)
    $messageLevelIndex = $levels.IndexOf($Level)

    if ($messageLevelIndex -lt $currentLevelIndex) {
        return
    }

    # Format log entry
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Write to file
    try {
        $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }

    # Write to console with color coding
    if ($script:LogConfig.EnableConsole) {
        $color = switch ($Level) {
            'Verbose' { 'Gray' }
            'Info' { 'White' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
        }

        Write-Host $logEntry -ForegroundColor $color
    }

    # Check if log rotation needed
    if (Test-Path $LogPath) {
        $logSize = (Get-Item $LogPath).Length / 1MB
        if ($logSize -gt $script:LogConfig.MaxLogSizeMB) {
            $archivePath = $LogPath -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
            try {
                Move-Item -Path $LogPath -Destination $archivePath -Force -ErrorAction Stop
                Write-Host "Log file rotated to: $archivePath" -ForegroundColor Gray
            }
            catch {
                Write-Warning "Failed to rotate log file: $_"
            }
        }
    }
}

# Helper function to safely check if a drive exists
function Test-DriveExists {
    <#
    .SYNOPSIS
        Safely check if a drive exists without throwing errors
    .PARAMETER DriveLetter
        Drive letter to check (without colon)
    .OUTPUTS
        Boolean indicating if drive exists
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DriveLetter
    )

    try {
        $null = Get-PSDrive -Name $DriveLetter -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# Get temporary path
function Get-TemporaryPath {
    <#
    .SYNOPSIS
        Create and return a temporary directory path
    .PARAMETER Prefix
        Prefix for temporary directory name
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Prefix = "Deploy"
    )

    # In test mode, use C:\DeploymentTest\Deploy\Temp
    # In WinPE, use X:\Deploy\Temp
    # Otherwise, use system temp
    $tempBase = if ($script:TestMode) {
        "C:\DeploymentTest\Deploy\Temp"
    } elseif (Test-DriveExists -DriveLetter "X") {
        "X:\Deploy\Temp"
    } else {
        $env:TEMP
    }

    # Create base temp directory if it doesn't exist
    if (-not (Test-Path $tempBase)) {
        New-Item -Path $tempBase -ItemType Directory -Force | Out-Null
    }

    # Create unique temp directory
    $tempName = "{0}_{1}" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $tempPath = Join-Path $tempBase $tempName

    New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

    Write-DeploymentLog "Created temporary directory: $tempPath" -Level Verbose

    return $tempPath
}

# Download a file from any supported URL type
function Get-BootstrapFile {
    <#
    .SYNOPSIS
        Download a file from any supported URL type
    .PARAMETER Url
        Source URL (Azure Blob, HTTP/HTTPS, SMB/UNC, Local path)
    .PARAMETER Destination
        Local destination file path
    .PARAMETER AuthType
        Authentication type: "Anonymous", "SAS", "None"
    .PARAMETER SasToken
        SAS token if AuthType is "SAS"
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [string]$AuthType = "Anonymous",

        [Parameter(Mandatory = $false)]
        [string]$SasToken = $null
    )

    try {
        # Detect URL type and route to appropriate download method
        if ($Url -match '^https?://.*\.blob\.core\.windows\.net/') {
            # Azure Blob Storage
            Write-DeploymentLog "  Downloading from Azure Blob Storage..." -Level Verbose

            if ($AuthType -eq "SAS") {
                # Extract or use provided SAS token
                $token = if ($Url -match '\?(.+)$') { $matches[1] } else { $SasToken }
                Get-AzureBlobWithSAS -BlobUrl $Url -SasToken $token -Destination $Destination
            }
            else {
                # Anonymous
                Get-AzureBlobAnonymous -BlobUrl $Url -Destination $Destination
            }
        }
        elseif ($Url -match '^https?://') {
            # Generic HTTP/HTTPS
            Write-DeploymentLog "  Downloading from HTTP/HTTPS..." -Level Verbose

            # Use Invoke-WebRequest for generic HTTP downloads
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
            $ProgressPreference = 'Continue'
        }
        elseif ($Url -match '^\\\\' -or $Url -match '^[A-Za-z]:') {
            # UNC path or local path
            Write-DeploymentLog "  Copying from local/UNC path..." -Level Verbose

            if (Test-Path $Url) {
                Copy-Item -Path $Url -Destination $Destination -Force -ErrorAction Stop
            }
            else {
                throw "Source file not found: $Url"
            }
        }
        else {
            throw "Unsupported URL format: $Url"
        }

        # Verify download
        if (Test-Path $Destination) {
            Write-DeploymentLog "  Download successful: $([math]::Round((Get-Item $Destination).Length / 1KB, 2)) KB" -Level Verbose
            return $true
        }
        else {
            Write-DeploymentLog "  Download failed - file not created" -Level Error
            return $false
        }
    }
    catch {
        Write-DeploymentLog "  Download failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Compare two semantic version strings
function Compare-SemanticVersion {
    <#
    .SYNOPSIS
        Compare two semantic version strings
    .PARAMETER Version1
        First version (e.g., "1.0.0")
    .PARAMETER Version2
        Second version (e.g., "1.1.0")
    .OUTPUTS
        Returns: -1 if Version1 < Version2
                  0 if Version1 = Version2
                  1 if Version1 > Version2
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Version1,

        [Parameter(Mandatory = $true)]
        [string]$Version2
    )

    # Parse versions
    $v1Parts = $Version1 -split '\.'
    $v2Parts = $Version2 -split '\.'

    # Ensure 3 parts (Major.Minor.Patch)
    while ($v1Parts.Count -lt 3) { $v1Parts += "0" }
    while ($v2Parts.Count -lt 3) { $v2Parts += "0" }

    # Compare each part
    for ($i = 0; $i -lt 3; $i++) {
        $v1Num = [int]$v1Parts[$i]
        $v2Num = [int]$v2Parts[$i]

        if ($v1Num -lt $v2Num) { return -1 }
        if ($v1Num -gt $v2Num) { return 1 }
    }

    return 0  # Equal
}

# Check if a newer bootstrap version is available
function Test-BootstrapUpdate {
    <#
    .SYNOPSIS
        Check if a newer bootstrap version is available
    .PARAMETER Config
        Bootstrap configuration hashtable
    .PARAMETER CurrentVersion
        Current bootstrap version
    .PARAMETER BootstrapUrl
        URL to bootstrap package
    .PARAMETER AuthType
        Authentication type
    .PARAMETER SasToken
        SAS token if using SAS authentication
    .OUTPUTS
        Hashtable with update information
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [string]$CurrentVersion,

        [Parameter(Mandatory = $true)]
        [string]$BootstrapUrl,

        [Parameter(Mandatory = $false)]
        [string]$AuthType = "Anonymous",

        [Parameter(Mandatory = $false)]
        [string]$SasToken = $null
    )

    $result = @{
        UpdateAvailable = $false
        NewVersion = $null
        VersionFileUrl = $null
        BootstrapZipUrl = $null
        VersionMetadata = $null
    }

    Write-DeploymentLog "Checking for bootstrap updates..." -Level Info
    Write-DeploymentLog "  Current version: $CurrentVersion" -Level Info
    Write-DeploymentLog "  Package URL: $BootstrapUrl" -Level Info

    $result.BootstrapZipUrl = $BootstrapUrl

    # Determine version file location
    $versionFileUrl = if ($Config.bootstrapUpdate -and $Config.bootstrapUpdate.versionFileUrl) {
        $Config.bootstrapUpdate.versionFileUrl
    } else {
        # Auto-construct: replace .zip with -version.ps1
        $BootstrapUrl -replace '\.zip$', '-version.ps1'
    }

    Write-DeploymentLog "  Version file: $versionFileUrl" -Level Verbose
    $result.VersionFileUrl = $versionFileUrl

    # Download version file
    $versionFile = Get-TemporaryPath -Prefix "BootstrapVersion_"
    $versionFile = "$versionFile.ps1"

    try {
        # Use universal download helper
        $downloadSuccess = Get-BootstrapFile -Url $versionFileUrl -Destination $versionFile -AuthType $AuthType -SasToken $SasToken

        if (-not $downloadSuccess -or -not (Test-Path $versionFile)) {
            Write-DeploymentLog "Version file not found - assuming no update available" -Level Verbose
            return $result
        }

        # Load version metadata
        try {
            $versionMetadata = & $versionFile
            $result.VersionMetadata = $versionMetadata
            $newVersion = $versionMetadata.version

            Write-DeploymentLog "  Available version: $newVersion" -Level Info

            # Compare versions
            $comparison = Compare-SemanticVersion -Version1 $CurrentVersion -Version2 $newVersion

            if ($comparison -lt 0) {
                # Current version is older
                Write-DeploymentLog "Newer bootstrap version available: $newVersion" -Level Info
                $result.UpdateAvailable = $true
                $result.NewVersion = $newVersion
            }
            elseif ($comparison -eq 0) {
                Write-DeploymentLog "Bootstrap is up to date" -Level Info
            }
            else {
                Write-DeploymentLog "Current version is newer than available version" -Level Warning
            }
        }
        catch {
            Write-DeploymentLog "Failed to parse version file: $($_.Exception.Message)" -Level Verbose
            return $result
        }
    }
    catch {
        Write-DeploymentLog "Failed to check version file: $($_.Exception.Message)" -Level Verbose
        return $result
    }
    finally {
        # Cleanup version file
        if (Test-Path $versionFile) {
            Remove-Item -Path $versionFile -Force -ErrorAction SilentlyContinue
        }
    }

    return $result
}

# Download and apply bootstrap update
function Update-Bootstrap {
    <#
    .SYNOPSIS
        Download and apply bootstrap update
    .PARAMETER Config
        Bootstrap configuration hashtable
    .PARAMETER UpdateInfo
        Update information from Test-BootstrapUpdate
    .OUTPUTS
        Path to new bootstrap script, or $null if update failed
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config,

        [Parameter(Mandatory = $true)]
        [hashtable]$UpdateInfo
    )

    Write-DeploymentLog "Downloading bootstrap update..." -Level Info
    Write-DeploymentLog "  Version: $($UpdateInfo.NewVersion)" -Level Info

    # Create temp directory for update
    $updateDir = Get-TemporaryPath -Prefix "BootstrapUpdate_"
    if (-not (Test-Path $updateDir)) {
        New-Item -Path $updateDir -ItemType Directory -Force | Out-Null
    }

    $bootstrapZip = Join-Path $updateDir "DeployBootstrap.zip"
    $catalogFile = Join-Path $updateDir "DeployBootstrap.cat"

    try {
        # Determine authentication method
        $authType = if ($Config.bootstrapUpdate.authType) {
            $Config.bootstrapUpdate.authType
        } else {
            "Anonymous"
        }

        $sasToken = $Config.bootstrapUpdate.sasToken

        # =====================================================================
        # PHASE 1: Catalog Download and Signature Validation (BEFORE .zip)
        # =====================================================================

        Write-DeploymentLog "Preparing catalog validation..." -Level Info

        # Derive catalog URL from package URL
        $catalogFileUrl = $UpdateInfo.BootstrapZipUrl -replace '\.zip$', '.cat'

        Write-DeploymentLog "Downloading catalog file..." -Level Info
        Write-DeploymentLog "  Catalog URL: $catalogFileUrl" -Level Verbose

        $catDownload = Get-BootstrapFile -Url $catalogFileUrl -Destination $catalogFile -AuthType $authType -SasToken $sasToken

        if (-not $catDownload -or -not (Test-Path $catalogFile)) {
            throw "Catalog file not found at: $catalogFileUrl. Catalog validation is required."
        }

        Write-DeploymentLog "Catalog file downloaded" -Level Info

        # Validate catalog signature
        if ($Config.validation.enableSignatureCheck) {
            Write-DeploymentLog "Verifying catalog signature..." -Level Info

            $catalogSignature = Get-AuthenticodeSignature -FilePath $catalogFile -ErrorAction Stop

            if ($catalogSignature.Status -ne "Valid") {
                throw "Catalog signature invalid: $($catalogSignature.Status). Bootstrap package download aborted."
            }

            # Verify signer is in trusted publishers list
            $signerCert = $catalogSignature.SignerCertificate
            $isTrustedSigner = $false

            foreach ($trustedPublisher in $Config.validation.trustedPublishers) {
                if ($trustedPublisher -match '^Thumbprint:(.+)$') {
                    $thumbprint = $matches[1]
                    if ($signerCert.Thumbprint -eq $thumbprint) {
                        $isTrustedSigner = $true
                        Write-DeploymentLog "Catalog signed by trusted thumbprint: $thumbprint" -Level Verbose
                        break
                    }
                }
                elseif ($trustedPublisher -match '^CN:(.+)$') {
                    $cnPattern = $matches[1]
                    if ($signerCert.Subject -like "*CN=$cnPattern*") {
                        $isTrustedSigner = $true
                        Write-DeploymentLog "Catalog signed by trusted CN: $cnPattern" -Level Verbose
                        break
                    }
                }
            }

            if (-not $isTrustedSigner) {
                throw "Catalog signer not in trusted publishers list. Bootstrap package download aborted.`n  Signer: $($signerCert.Subject)"
            }

            Write-DeploymentLog "Catalog signature validated successfully" -Level Info
        }

        Write-DeploymentLog "Catalog validated - proceeding with package download..." -Level Info

        # =====================================================================
        # PHASE 2: Package Download (AFTER catalog validation)
        # =====================================================================

        Write-DeploymentLog "Downloading bootstrap package..." -Level Info
        Write-DeploymentLog "  Package URL: $($UpdateInfo.BootstrapZipUrl)" -Level Verbose

        $downloadSuccess = Get-BootstrapFile -Url $UpdateInfo.BootstrapZipUrl -Destination $bootstrapZip -AuthType $authType -SasToken $sasToken

        if (-not $downloadSuccess -or -not (Test-Path $bootstrapZip)) {
            Write-DeploymentLog "Failed to download bootstrap update" -Level Error
            return $null
        }

        Write-DeploymentLog "Bootstrap package downloaded: $([math]::Round((Get-Item $bootstrapZip).Length / 1MB, 2)) MB" -Level Info

        # =====================================================================
        # PHASE 3: Package Validation Against Catalog
        # =====================================================================

        Write-DeploymentLog "Validating bootstrap package against catalog..." -Level Info

        $catalogResult = Test-FileCatalog -Path $bootstrapZip `
                                         -CatalogFilePath $catalogFile `
                                         -Detailed `
                                         -ErrorAction Stop

        if ($catalogResult.Status -ne "Valid") {
            Write-DeploymentLog "Bootstrap package catalog validation FAILED: $($catalogResult.Status)" -Level Error

            # Show validation details
            if ($catalogResult.CatalogItems) {
                foreach ($item in $catalogResult.CatalogItems) {
                    if ($item.Status -ne "Valid") {
                        Write-DeploymentLog "  Invalid: $($item.FileName) - $($item.Status)" -Level Error
                    }
                }
            }

            throw "Bootstrap package validation against catalog FAILED"
        }

        Write-DeploymentLog "Bootstrap package catalog validation PASSED" -Level Info

        # Cleanup catalog file
        if (Test-Path $catalogFile) {
            Remove-Item $catalogFile -Force -ErrorAction SilentlyContinue
        }

        # Extract bootstrap package
        Write-DeploymentLog "Extracting bootstrap update..." -Level Info
        $extractPath = Join-Path $updateDir "Extracted"

        try {
            Expand-Archive -Path $bootstrapZip -DestinationPath $extractPath -Force
        }
        catch {
            Write-DeploymentLog "Failed to extract bootstrap package: $($_.Exception.Message)" -Level Error
            return $null
        }

        # Find new Deploy-Bootstrap.ps1
        $newBootstrapScript = Get-ChildItem -Path $extractPath -Filter "Deploy-Bootstrap.ps1" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $newBootstrapScript) {
            Write-DeploymentLog "Deploy-Bootstrap.ps1 not found in update package" -Level Error
            return $null
        }

        Write-DeploymentLog "Bootstrap update extracted successfully" -Level Info
        return $newBootstrapScript.FullName
    }
    catch {
        Write-DeploymentLog "Bootstrap update failed: $($_.Exception.Message)" -Level Error
        return $null
    }
}

# Show deployment progress
function Show-DeploymentProgress {
    <#
    .SYNOPSIS
        Display deployment progress
    .PARAMETER Activity
        Activity description
    .PARAMETER Status
        Current status
    .PARAMETER PercentComplete
        Percentage complete (0-100)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = -1
    )

    if ($PercentComplete -ge 0) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
    else {
        Write-Progress -Activity $Activity -Status $Status
    }

    Write-DeploymentLog "$Activity - $Status" -Level Info
}

# Show deployment status screen
function Show-DeploymentStatus {
    <#
    .SYNOPSIS
        Display full-screen deployment status
    .PARAMETER Phase
        Current deployment phase
    .PARAMETER Status
        Status message
    .PARAMETER PercentComplete
        Optional percentage complete
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Phase,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = -1
    )

    # Display header (without clearing screen to preserve logs)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    Windows Deployment in Progress     " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Display current phase
    Write-Host "Current Phase: " -NoNewline
    Write-Host $Phase -ForegroundColor Yellow
    Write-Host ""

    # Display status
    Write-Host "Status: " -NoNewline
    Write-Host $Status -ForegroundColor Green
    Write-Host ""

    # Display progress bar if percentage provided
    if ($PercentComplete -ge 0) {
        $barLength = 40
        $filledLength = [int](($PercentComplete / 100) * $barLength)
        $emptyLength = $barLength - $filledLength

        $bar = "[" + ("=" * $filledLength) + (" " * $emptyLength) + "]"
        Write-Host "$bar $PercentComplete%" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "Please do not power off the system..." -ForegroundColor Red
}

# Show deployment error
function Show-DeploymentError {
    <#
    .SYNOPSIS
        Display deployment error screen with options
    .PARAMETER ErrorMessage
        Error message to display
    .PARAMETER AdditionalInfo
        Additional information to display
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage,

        [Parameter(Mandatory = $false)]
        [string]$AdditionalInfo
    )

    # Display error (without clearing screen to preserve logs)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "    Deployment Error Occurred          " -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: " -NoNewline
    Write-Host $ErrorMessage -ForegroundColor Yellow
    Write-Host ""

    if ($AdditionalInfo) {
        Write-Host $AdditionalInfo -ForegroundColor Gray
        Write-Host ""
    }
}

# Cleanup deployment resources
function Invoke-CleanupDeployment {
    <#
    .SYNOPSIS
        Clean up deployment resources (mounted images, loaded hives, temp files)
    .PARAMETER State
        Hashtable tracking deployment state
    .PARAMETER PreserveLogsOnly
        Only preserve log files, remove everything else
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$State,

        [Parameter(Mandatory = $false)]
        [switch]$PreserveLogsOnly
    )

    Write-DeploymentLog "Starting deployment cleanup..." -Level Info

    # Dismount any mounted images
    if ($State -and $State.MountedImages) {
        foreach ($mount in $State.MountedImages) {
            try {
                Write-DeploymentLog "Dismounting image: $($mount.ImagePath)" -Level Info

                if ($mount.Type -eq 'ISO') {
                    Dismount-DiskImage -ImagePath $mount.ImagePath -ErrorAction SilentlyContinue
                }
                elseif ($mount.Type -eq 'WIM') {
                    Dismount-WindowsImage -Path $mount.MountPath -Discard -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-DeploymentLog "Failed to dismount image: $_" -Level Warning
            }
        }
    }

    # Unload any loaded registry hives
    if ($State -and $State.LoadedHives) {
        foreach ($hive in $State.LoadedHives) {
            try {
                Write-DeploymentLog "Unloading registry hive: $($hive.MountPoint)" -Level Info

                $result = Start-Process -FilePath "reg.exe" -ArgumentList "unload", $hive.MountPoint -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue

                if ($result.ExitCode -ne 0) {
                    # Retry after garbage collection
                    Start-Sleep -Seconds 2
                    [System.GC]::Collect()
                    Start-Sleep -Seconds 1
                    Start-Process -FilePath "reg.exe" -ArgumentList "unload", $hive.MountPoint -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-DeploymentLog "Failed to unload hive: $_" -Level Warning
            }
        }
    }

    # Remove temporary paths
    if ($State -and $State.TempPaths) {
        foreach ($tempPath in $State.TempPaths) {
            try {
                if (Test-Path $tempPath) {
                    Write-DeploymentLog "Removing temporary path: $tempPath" -Level Verbose
                    Remove-Item -Path $tempPath -Recurse -Force -ErrorAction Stop
                }
            }
            catch {
                Write-DeploymentLog "Failed to remove temporary path: $_" -Level Warning
            }
        }
    }

    # Force garbage collection to free memory in WinPE
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    Write-DeploymentLog "Deployment cleanup completed" -Level Info
}

# Copy logs to deployed image
function Copy-DeploymentLogsToImage {
    <#
    .SYNOPSIS
        Copy deployment logs to deployed Windows image
    .PARAMETER LogPath
        Source log file path
    .PARAMETER WindowsPartitionPath
        Windows partition root path (e.g., W:\)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [string]$WindowsPartitionPath
    )

    try {
        # Create log directory in deployed image
        $destLogDir = Join-Path $WindowsPartitionPath "Windows\Logs\Deployment"
        if (-not (Test-Path $destLogDir)) {
            New-Item -Path $destLogDir -ItemType Directory -Force | Out-Null
        }

        # Copy log file
        $logFileName = Split-Path -Path $LogPath -Leaf
        $destLogPath = Join-Path $destLogDir $logFileName

        Copy-Item -Path $LogPath -Destination $destLogPath -Force -ErrorAction Stop

        Write-DeploymentLog "Deployment logs copied to: $destLogPath" -Level Info
        return $true
    }
    catch {
        Write-DeploymentLog "Failed to copy logs to image: $_" -Level Warning
        return $false
    }
}

#endregion

#region Validation Functions

# Validate bootstrap configuration structure
function Test-BootstrapConfigurationStructure {
    <#
    .SYNOPSIS
        Validate bootstrap configuration hashtable structure
    .DESCRIPTION
        Validates PowerShell configuration hashtable for required fields and types.
        Replaces JSON Schema validation for .ps1 config files.
    .PARAMETER Config
        Configuration hashtable to validate
    .OUTPUTS
        Hashtable with Passed (bool) and Issues (array) properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )

    $results = @{
        Passed = $true
        Issues = @()
    }

    # Validate packageSource section
    if (-not $Config.packageSource) {
        $results.Issues += "Missing 'packageSource' section"
        $results.Passed = $false
    }
    else {
        $ps = $Config.packageSource

        # Must have exactly one source type
        $sourceCount = 0
        if ($ps.blobUrl) { $sourceCount++ }
        if ($ps.uncPath) { $sourceCount++ }
        if ($ps.localPath) { $sourceCount++ }

        if ($sourceCount -eq 0) {
            $results.Issues += "packageSource must specify one of: blobUrl, uncPath, or localPath"
            $results.Passed = $false
        }
        elseif ($sourceCount -gt 1) {
            $results.Issues += "packageSource must specify only one source type (blobUrl, uncPath, or localPath)"
            $results.Passed = $false
        }

        # Validate authType
        if ($ps.authType -and $ps.authType -notin @('Anonymous', 'SAS', 'SMB')) {
            $results.Issues += "Invalid authType: $($ps.authType). Must be Anonymous, SAS, or SMB"
            $results.Passed = $false
        }

        # If SAS auth, require sasToken
        if ($ps.authType -eq 'SAS' -and -not $ps.sasToken) {
            $results.Issues += "sasToken required when authType is SAS"
            $results.Passed = $false
        }
    }

    # Validate validation section
    if (-not $Config.validation) {
        $results.Issues += "Missing 'validation' section"
        $results.Passed = $false
    }
    else {
        $val = $Config.validation

        if ($null -eq $val.enableSignatureCheck) {
            $results.Issues += "validation.enableSignatureCheck is required (must be true or false)"
            $results.Passed = $false
        }
        elseif ($val.enableSignatureCheck -isnot [bool]) {
            $results.Issues += "validation.enableSignatureCheck must be boolean (use `$true or `$false)"
            $results.Passed = $false
        }

        # Validate trustedPublishers format if specified
        if ($val.trustedPublishers) {
            if ($val.trustedPublishers -isnot [array]) {
                $results.Issues += "validation.trustedPublishers must be an array"
                $results.Passed = $false
            }
            else {
                foreach ($publisher in $val.trustedPublishers) {
                    if ($publisher -notmatch '^(Thumbprint:[0-9A-Fa-f]{40}|CN:.+)$') {
                        $results.Issues += "Invalid trusted publisher format: '$publisher'. Must use 'Thumbprint:<40-hex>' or 'CN:<name>'"
                        $results.Passed = $false
                    }
                }
            }
        }
    }

    # Validate extraction section (optional, but validate if present)
    if ($Config.extraction) {
        if ($Config.extraction.targetPath -and $Config.extraction.targetPath -isnot [string]) {
            $results.Issues += "extraction.targetPath must be a string"
            $results.Passed = $false
        }

        if ($null -ne $Config.extraction.cleanupOnFailure -and $Config.extraction.cleanupOnFailure -isnot [bool]) {
            $results.Issues += "extraction.cleanupOnFailure must be boolean"
            $results.Passed = $false
        }
    }

    # Validate logging section (optional, but validate if present)
    if ($Config.logging) {
        if ($Config.logging.logLevel -and $Config.logging.logLevel -notin @('Verbose', 'Info', 'Warning', 'Error')) {
            $results.Issues += "Invalid logging.logLevel: $($Config.logging.logLevel)"
            $results.Passed = $false
        }
    }

    # Validate bootstrapUpdate section (optional, but validate if present)
    # Note: Update check always runs, so this section is entirely optional
    if ($Config.bootstrapUpdate) {
        # All fields are optional - only validate types if present
        if ($Config.bootstrapUpdate.packageUrl -and $Config.bootstrapUpdate.packageUrl -isnot [string]) {
            $results.Issues += "bootstrapUpdate.packageUrl must be a string"
            $results.Passed = $false
        }

        if ($Config.bootstrapUpdate.authType -and $Config.bootstrapUpdate.authType -isnot [string]) {
            $results.Issues += "bootstrapUpdate.authType must be a string"
            $results.Passed = $false
        }

        if ($null -ne $Config.bootstrapUpdate.requireValidSignature -and $Config.bootstrapUpdate.requireValidSignature -isnot [bool]) {
            $results.Issues += "bootstrapUpdate.requireValidSignature must be a boolean"
            $results.Passed = $false
        }

        if ($null -ne $Config.bootstrapUpdate.enableVersionCheck -and $Config.bootstrapUpdate.enableVersionCheck -isnot [bool]) {
            $results.Issues += "bootstrapUpdate.enableVersionCheck must be a boolean"
            $results.Passed = $false
        }

        if ($null -ne $Config.bootstrapUpdate.forceUpdate -and $Config.bootstrapUpdate.forceUpdate -isnot [bool]) {
            $results.Issues += "bootstrapUpdate.forceUpdate must be a boolean"
            $results.Passed = $false
        }
    }

    return $results
}

# Test if running in WinPE/RE environment
function Test-WinPEEnvironment {
    <#
    .SYNOPSIS
        Validate that script is running in WinPE or WinRE environment
    .DESCRIPTION
        Checks for WinPE, validates UEFI boot mode, PowerShell version, and available resources
    .OUTPUTS
        Hashtable with validation results
    #>
    [CmdletBinding()]
    param()

    Write-DeploymentLog "Validating WinPE/RE environment..." -Level Info

    $results = @{
        IsWinPE = $false
        IsUEFI = $false
        PowerShellVersion = $PSVersionTable.PSVersion
        AvailableRAM_GB = 0
        ScratchSpace_GB = 0
        Passed = $false
        Issues = @()
    }

    # Check if running in WinPE
    $isWinPE = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT"
    $results.IsWinPE = $isWinPE

    if (-not $isWinPE) {
        $results.Issues += "Not running in Windows PE/RE environment"
        Write-DeploymentLog "WARNING: Not running in WinPE/RE - this may be a test environment" -Level Warning
    }

    # Verify PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $results.Issues += "PowerShell 5.1 or later required (current: $($PSVersionTable.PSVersion))"
        Write-DeploymentLog "ERROR: PowerShell version check failed" -Level Error
    }
    else {
        Write-DeploymentLog "PowerShell version: $($PSVersionTable.PSVersion)" -Level Info
    }

    # Check UEFI boot mode
    try {
        $isUEFI = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        $results.IsUEFI = $isUEFI

        if (-not $isUEFI) {
            $results.Issues += "System is not in UEFI boot mode (only UEFI/GPT supported)"
            Write-DeploymentLog "ERROR: Not in UEFI boot mode" -Level Error
        }
        else {
            Write-DeploymentLog "UEFI boot mode confirmed" -Level Info
        }
    }
    catch {
        $results.Issues += "Failed to detect boot mode: $_"
        Write-DeploymentLog "ERROR: Failed to detect boot mode: $_" -Level Error
    }

    # Check available RAM
    try {
        $totalRAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
        $results.AvailableRAM_GB = [math]::Round($totalRAM, 2)
        Write-DeploymentLog "Available RAM: $($results.AvailableRAM_GB) GB" -Level Info

        if ($totalRAM -lt 2) {
            $results.Issues += "Low RAM detected ($($results.AvailableRAM_GB) GB) - deployment may be slow"
            Write-DeploymentLog "WARNING: Low RAM - deployment may be slow" -Level Warning
        }
    }
    catch {
        Write-DeploymentLog "WARNING: Failed to check RAM: $_" -Level Warning
    }

    # Check scratch space (X: drive in WinPE)
    try {
        if (Test-DriveExists -DriveLetter "X") {
            $scratchSpace = (Get-PSDrive X -ErrorAction SilentlyContinue).Free / 1GB
            $results.ScratchSpace_GB = [math]::Round($scratchSpace, 2)
            Write-DeploymentLog "Scratch space on X:\ = $($results.ScratchSpace_GB) GB" -Level Info

            if ($scratchSpace -lt 1) {
                $results.Issues += "Insufficient scratch space on X:\ ($($results.ScratchSpace_GB) GB)"
                Write-DeploymentLog "ERROR: Insufficient scratch space" -Level Error
            }
        }
    }
    catch {
        Write-DeploymentLog "WARNING: Failed to check scratch space: $_" -Level Warning
    }

    # Determine if validation passed
    $criticalIssues = $results.Issues | Where-Object { $_ -like "ERROR:*" -or $_ -like "*required*" -or $_ -like "*UEFI*" }
    $results.Passed = ($criticalIssues.Count -eq 0)

    if ($results.Passed) {
        Write-DeploymentLog "WinPE environment validation PASSED" -Level Info
    }
    else {
        Write-DeploymentLog "WinPE environment validation FAILED" -Level Error
        foreach ($issue in $results.Issues) {
            Write-DeploymentLog "  - $issue" -Level Error
        }
    }

    return $results
}

# Test deployment configuration
function Test-DeploymentConfig {
    <#
    .SYNOPSIS
        Validate deployment configuration
    .PARAMETER Config
        Configuration object (from JSON)
    .OUTPUTS
        Hashtable with validation results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    Write-DeploymentLog "Validating deployment configuration..." -Level Info

    $results = @{
        Passed = $true
        Issues = @()
    }

    # Validate required sections
    if (-not $Config.deploymentInfo) {
        $results.Issues += "Missing 'deploymentInfo' section"
        $results.Passed = $false
    }

    if (-not $Config.imageSource) {
        $results.Issues += "Missing 'imageSource' section"
        $results.Passed = $false
    }

    if (-not $Config.diskConfiguration) {
        $results.Issues += "Missing 'diskConfiguration' section"
        $results.Passed = $false
    }

    # Validate image source
    if ($Config.imageSource) {
        if (-not $Config.imageSource.type) {
            $results.Issues += "Missing image type"
            $results.Passed = $false
        }
        elseif ($Config.imageSource.type -notin @('ISO', 'FFU', 'WIM')) {
            $results.Issues += "Invalid image type: $($Config.imageSource.type)"
            $results.Passed = $false
        }

        if (-not $Config.imageSource.location) {
            $results.Issues += "Missing image location"
            $results.Passed = $false
        }
    }

    # Validate disk configuration
    if ($Config.diskConfiguration) {
        if ($Config.diskConfiguration.partitionStyle -ne 'GPT') {
            $results.Issues += "Only GPT partition style is supported"
            $results.Passed = $false
        }

        if ($null -eq $Config.diskConfiguration.diskNumber -or $Config.diskConfiguration.diskNumber -lt 0) {
            $results.Issues += "Invalid disk number"
            $results.Passed = $false
        }
    }

    # Validate customization settings
    if ($Config.customization) {
        # Check driver settings
        if ($Config.customization.drivers -and $Config.customization.drivers.enabled) {
            if (-not $Config.customization.drivers.sources -or $Config.customization.drivers.sources.Count -eq 0) {
                $results.Issues += "Driver injection enabled but no driver sources specified"
                $results.Passed = $false
            }
        }

        # Check autopilot settings
        if ($Config.customization.autopilot -and $Config.customization.autopilot.enabled) {
            if (-not $Config.customization.autopilot.configurationFile) {
                $results.Issues += "Autopilot enabled but no configuration file specified"
                $results.Passed = $false
            }
        }

        # Check unattend settings
        if ($Config.customization.unattend -and $Config.customization.unattend.enabled) {
            if (-not $Config.customization.unattend.unattendFile) {
                $results.Issues += "Unattend enabled but no unattend file specified"
                $results.Passed = $false
            }
        }
    }

    if ($results.Passed) {
        Write-DeploymentLog "Configuration validation PASSED" -Level Info
    }
    else {
        Write-DeploymentLog "Configuration validation FAILED" -Level Error
        foreach ($issue in $results.Issues) {
            Write-DeploymentLog "  - $issue" -Level Error
        }
    }

    return $results
}

# Test disk requirements
function Test-DiskRequirements {
    <#
    .SYNOPSIS
        Validate disk exists and meets requirements
    .PARAMETER DiskNumber
        Disk number to validate
    .PARAMETER RequiredSizeGB
        Minimum required disk size in GB (default: 32GB)
    .OUTPUTS
        Hashtable with validation results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,

        [Parameter(Mandatory = $false)]
        [int]$RequiredSizeGB = 32
    )

    Write-DeploymentLog "Validating disk $DiskNumber..." -Level Info

    $results = @{
        DiskExists = $false
        DiskOnline = $false
        DiskSize_GB = 0
        MeetsRequirements = $false
        Issues = @()
    }

    try {
        # Get disk
        $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
        $results.DiskExists = $true

        # Check if disk is online
        $results.DiskOnline = ($disk.OperationalStatus -eq 'Online')
        if (-not $results.DiskOnline) {
            $results.Issues += "Disk $DiskNumber is not online (status: $($disk.OperationalStatus))"
            Write-DeploymentLog "WARNING: Disk is not online" -Level Warning

            # Try to bring disk online
            try {
                Set-Disk -Number $DiskNumber -IsOffline $false -ErrorAction Stop
                $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
                $results.DiskOnline = ($disk.OperationalStatus -eq 'Online')

                if ($results.DiskOnline) {
                    Write-DeploymentLog "Disk brought online successfully" -Level Info
                    $results.Issues = $results.Issues | Where-Object { $_ -notlike "*not online*" }
                }
            }
            catch {
                Write-DeploymentLog "ERROR: Failed to bring disk online: $_" -Level Error
            }
        }

        # Check disk size
        $diskSizeGB = $disk.Size / 1GB
        $results.DiskSize_GB = [math]::Round($diskSizeGB, 2)
        Write-DeploymentLog "Disk size: $($results.DiskSize_GB) GB" -Level Info

        if ($diskSizeGB -lt $RequiredSizeGB) {
            $results.Issues += "Disk is too small ($($results.DiskSize_GB) GB, minimum: $RequiredSizeGB GB)"
            Write-DeploymentLog "ERROR: Disk too small" -Level Error
        }

        # Check if disk is read-only
        if ($disk.IsReadOnly) {
            $results.Issues += "Disk is read-only"
            Write-DeploymentLog "ERROR: Disk is read-only" -Level Error
        }

        # Check if disk has existing data (warn only)
        if ($disk.PartitionStyle -ne 'RAW' -and $disk.NumberOfPartitions -gt 0) {
            $results.Issues += "Disk has existing partitions ($($disk.NumberOfPartitions) partitions) - will be cleaned if cleanDisk is enabled"
            Write-DeploymentLog "WARNING: Disk has existing data" -Level Warning
        }

        # Determine if requirements met
        $results.MeetsRequirements = ($results.DiskExists -and $results.DiskOnline -and $diskSizeGB -ge $RequiredSizeGB -and -not $disk.IsReadOnly)

        if ($results.MeetsRequirements) {
            Write-DeploymentLog "Disk validation PASSED" -Level Info
        }
        else {
            Write-DeploymentLog "Disk validation FAILED" -Level Error
        }
    }
    catch {
        $results.Issues += "Failed to access disk $DiskNumber : $_"
        Write-DeploymentLog "ERROR: Disk validation failed: $_" -Level Error
    }

    return $results
}

# Test network connectivity
function Test-NetworkConnectivity {
    <#
    .SYNOPSIS
        Test network connectivity (required for Azure Blob access)
    .PARAMETER TestUrl
        URL to test connectivity
    .OUTPUTS
        Boolean indicating connectivity status
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TestUrl = "https://www.msftconnecttest.com/connecttest.txt"
    )

    Write-DeploymentLog "Testing network connectivity to $TestUrl..." -Level Verbose

    try {
        $response = Invoke-WebRequest -Uri $TestUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        Write-DeploymentLog "Network connectivity test PASSED" -Level Info
        return $true
    }
    catch {
        Write-DeploymentLog "Network connectivity test FAILED: $_" -Level Error
        return $false
    }
}

#endregion

#region Web Functions

# Download from Azure Blob (anonymous access)
function Get-AzureBlobAnonymous {
    <#
    .SYNOPSIS
        Download file from Azure Blob Storage without authentication
    .PARAMETER BlobUrl
        Azure Blob Storage URL
    .PARAMETER Destination
        Local destination file path
    .PARAMETER ShowProgress
        Show download progress
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BlobUrl,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )

    Write-DeploymentLog "Downloading from blob (anonymous): $BlobUrl" -Level Info

    try {
        # Create destination directory if it doesn't exist
        $destDir = Split-Path -Path $Destination -Parent
        if ($destDir -and -not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }

        # Detect GitHub raw URLs and force simple download (BITS/WebClient incompatible)
        if ($BlobUrl -match 'raw\.githubusercontent\.com|github\.com/.*/(raw|blob)/') {
            Write-DeploymentLog "Detected GitHub URL - using Invoke-WebRequest for compatibility" -Level Verbose
            Invoke-WebRequest -Uri $BlobUrl -OutFile $Destination -UseBasicParsing -ErrorAction Stop

            # Verify download
            if (Test-Path $Destination) {
                $fileSize = (Get-Item $Destination).Length
                Write-DeploymentLog "Download complete: $Destination ($([math]::Round($fileSize / 1MB, 2)) MB)" -Level Info
                return $true
            }
            else {
                Write-DeploymentLog "ERROR: File not created after download" -Level Error
                return $false
            }
        }

        # Download with progress if requested
        if ($ShowProgress) {
            # Use BITS if available (faster for large files)
            if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
                Start-BitsTransfer -Source $BlobUrl -Destination $Destination -DisplayName "Downloading from Azure Blob" -Description $BlobUrl
            }
            else {
                # Fallback to WebClient with progress
                $webClient = New-Object System.Net.WebClient

                # Register progress event
                $progressEventId = "Download_$(Get-Random)"
                Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -SourceIdentifier $progressEventId -Action {
                    $percent = $EventArgs.ProgressPercentage
                    $received = $EventArgs.BytesReceived / 1MB
                    $total = $EventArgs.TotalBytesToReceive / 1MB
                    Write-Progress -Activity "Downloading from Azure Blob" -Status "$([math]::Round($received, 2)) MB / $([math]::Round($total, 2)) MB" -PercentComplete $percent
                } | Out-Null

                try {
                    $webClient.DownloadFile($BlobUrl, $Destination)
                }
                finally {
                    Unregister-Event -SourceIdentifier $progressEventId -ErrorAction SilentlyContinue
                    $webClient.Dispose()
                }
            }
        }
        else {
            # Simple download without progress
            Invoke-WebRequest -Uri $BlobUrl -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        }

        # Verify download
        if (Test-Path $Destination) {
            $fileSize = (Get-Item $Destination).Length
            Write-DeploymentLog "Download complete: $Destination ($([math]::Round($fileSize / 1MB, 2)) MB)" -Level Info
            return $true
        }
        else {
            Write-DeploymentLog "ERROR: File not created after download" -Level Error
            return $false
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Download failed: $_" -Level Error
        return $false
    }
}

# Download from Azure Blob with SAS token
function Get-AzureBlobWithSAS {
    <#
    .SYNOPSIS
        Download file from Azure Blob Storage with SAS token
    .PARAMETER BlobUrl
        Azure Blob Storage URL (without SAS token)
    .PARAMETER SASToken
        SAS token for authentication
    .PARAMETER Destination
        Local destination file path
    .PARAMETER ShowProgress
        Show download progress
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BlobUrl,

        [Parameter(Mandatory = $true)]
        [string]$SASToken,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )

    # Build full URI with SAS token
    $separator = if ($BlobUrl -like "*?*") { "&" } else { "?" }
    $fullUri = "$BlobUrl$separator$SASToken"

    Write-DeploymentLog "Downloading from blob (SAS): $BlobUrl" -Level Info

    try {
        # Create destination directory if it doesn't exist
        $destDir = Split-Path -Path $Destination -Parent
        if ($destDir -and -not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }

        # Download (cannot use BITS with SAS tokens easily, use WebClient)
        if ($ShowProgress) {
            $webClient = New-Object System.Net.WebClient

            # Register progress event
            $progressEventId = "Download_$(Get-Random)"
            Register-ObjectEvent -InputObject $webClient -EventName DownloadProgressChanged -SourceIdentifier $progressEventId -Action {
                $percent = $EventArgs.ProgressPercentage
                $received = $EventArgs.BytesReceived / 1MB
                $total = $EventArgs.TotalBytesToReceive / 1MB
                Write-Progress -Activity "Downloading from Azure Blob" -Status "$([math]::Round($received, 2)) MB / $([math]::Round($total, 2)) MB" -PercentComplete $percent
            } | Out-Null

            try {
                $webClient.DownloadFile($fullUri, $Destination)
            }
            finally {
                Unregister-Event -SourceIdentifier $progressEventId -ErrorAction SilentlyContinue
                $webClient.Dispose()
            }
        }
        else {
            # Simple download without progress
            Invoke-WebRequest -Uri $fullUri -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        }

        # Verify download
        if (Test-Path $Destination) {
            $fileSize = (Get-Item $Destination).Length
            Write-DeploymentLog "Download complete: $Destination ($([math]::Round($fileSize / 1MB, 2)) MB)" -Level Info
            return $true
        }
        else {
            Write-DeploymentLog "ERROR: File not created after download" -Level Error
            return $false
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Download failed: $_" -Level Error
        return $false
    }
}

# Test Azure Blob connectivity
function Test-AzureBlobConnection {
    <#
    .SYNOPSIS
        Test connectivity to Azure Blob and get metadata
    .PARAMETER BlobUrl
        Azure Blob Storage URL
    .PARAMETER SASToken
        Optional SAS token
    .OUTPUTS
        Hashtable with connectivity status and blob metadata
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BlobUrl,

        [Parameter(Mandatory = $false)]
        [string]$SASToken
    )

    Write-DeploymentLog "Testing connection to blob: $BlobUrl" -Level Verbose

    $result = @{
        Connected = $false
        BlobExists = $false
        ContentLength = 0
        LastModified = $null
        ErrorMessage = ""
    }

    try {
        # Build URI with SAS token if provided
        $uri = if ($SASToken) {
            $separator = if ($BlobUrl -like "*?*") { "&" } else { "?" }
            "$BlobUrl$separator$SASToken"
        }
        else {
            $BlobUrl
        }

        # Make HEAD request to get metadata without downloading
        $response = Invoke-WebRequest -Uri $uri -Method Head -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop

        $result.Connected = $true
        $result.BlobExists = ($response.StatusCode -eq 200)

        if ($result.BlobExists) {
            # Get blob metadata
            if ($response.Headers.'Content-Length') {
                $result.ContentLength = [long]$response.Headers.'Content-Length'[0]
            }

            if ($response.Headers.'Last-Modified') {
                $result.LastModified = [datetime]$response.Headers.'Last-Modified'[0]
            }

            $sizeMB = [math]::Round($result.ContentLength / 1MB, 2)
            Write-DeploymentLog "Blob exists: $sizeMB MB, Last modified: $($result.LastModified)" -Level Info
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
        Write-DeploymentLog "ERROR: Blob connection test failed: $($result.ErrorMessage)" -Level Error
    }

    return $result
}

# Download file from blob, SMB share, or local path (unified function)
function Get-DeploymentFile {
    <#
    .SYNOPSIS
        Download file from Azure Blob, SMB share, or copy from local path
    .PARAMETER SourcePath
        Source path (blob URL, UNC path, or local file path)
    .PARAMETER Destination
        Destination file path
    .PARAMETER AuthType
        Authentication type (Anonymous, SAS, or SMB)
    .PARAMETER SASToken
        SAS token (required if AuthType is SAS)
    .PARAMETER Username
        Username for SMB authentication (optional, use domain\username)
    .PARAMETER Password
        Password for SMB authentication (optional, SecureString)
    .PARAMETER ShowProgress
        Show download/copy progress
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Anonymous', 'SAS', 'SMB')]
        [string]$AuthType = 'Anonymous',

        [Parameter(Mandatory = $false)]
        [string]$SASToken,

        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [SecureString]$Password,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )

    # Determine source type
    $isUrl = $SourcePath -match '^https?://'
    $isUncPath = $SourcePath -match '^\\\\[^\\]+\\[^\\]+'

    if ($isUrl) {
        # Download from Azure Blob
        Write-DeploymentLog "Source type: Azure Blob Storage" -Level Info

        if ($AuthType -eq 'SAS' -and $SASToken) {
            return Get-AzureBlobWithSAS -BlobUrl $SourcePath -SASToken $SASToken -Destination $Destination -ShowProgress:$ShowProgress
        }
        else {
            return Get-AzureBlobAnonymous -BlobUrl $SourcePath -Destination $Destination -ShowProgress:$ShowProgress
        }
    }
    elseif ($isUncPath) {
        # Download from SMB share
        Write-DeploymentLog "Source type: SMB/Network Share" -Level Info

        if ($Username -and $Password) {
            return Get-SMBFile -UncPath $SourcePath -Destination $Destination -Username $Username -Password $Password -ShowProgress:$ShowProgress
        }
        else {
            # Try without credentials (may use current user context)
            return Get-SMBFile -UncPath $SourcePath -Destination $Destination -ShowProgress:$ShowProgress
        }
    }
    else {
        # Copy from local path
        Write-DeploymentLog "Source type: Local file path" -Level Info

        try {
            if (-not (Test-Path $SourcePath)) {
                Write-DeploymentLog "ERROR: Source file not found: $SourcePath" -Level Error
                return $false
            }

            # Create destination directory if needed
            $destDir = Split-Path -Path $Destination -Parent
            if ($destDir -and -not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }

            Copy-Item -Path $SourcePath -Destination $Destination -Force -ErrorAction Stop

            $fileSize = (Get-Item $Destination).Length
            Write-DeploymentLog "File copied: $Destination ($([math]::Round($fileSize / 1MB, 2)) MB)" -Level Info
            return $true
        }
        catch {
            Write-DeploymentLog "ERROR: File copy failed: $_" -Level Error
            return $false
        }
    }
}

# SMB file download function (stub - Get-SMBFile called but not defined for bootstrap)
function Get-SMBFile {
    <#
    .SYNOPSIS
        Download file from SMB/UNC path (stub for bootstrap)
    .DESCRIPTION
        Bootstrap script does not support SMB for package downloads.
        For SMB/UNC sources, use the main deployment script (Deploy-Windows.ps1).
        Bootstrap phase only supports Azure Blob Storage (Anonymous or SAS authentication).

        This stub allows Get-DeploymentFile to function without errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UncPath,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [SecureString]$Password,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )

    Write-DeploymentLog "ERROR: SMB downloads not supported in bootstrap script" -Level Error
    Write-DeploymentLog "Please use Azure Blob Storage or local file path for bootstrap packages" -Level Error
    return $false
}

#endregion

#endregion Embedded Functions

#region Main Script Logic

# Initialize deployment state for resource tracking
$DeploymentState = @{
    MountedImages = @()
    LoadedHives = @()
    TempPaths = @()
}

# Initialize $logPath with default for error handling
# This ensures error messages can reference the correct log location
$logPath = if ($TestMode) { "C:\DeploymentTest\Deploy\Logs\Bootstrap" } else { "X:\Deploy\Logs\Bootstrap" }

try {
    #region Configuration Loading
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows Deployment Bootstrap" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Add test mode banner if enabled
    if ($TestMode) {
        Write-Host "========================================" -ForegroundColor Magenta
        Write-Host "  TEST MODE ENABLED" -ForegroundColor Magenta
        Write-Host "========================================" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Running in Windows test environment" -ForegroundColor Yellow
        Write-Host "Using C:\DeploymentTest\ instead of X:\" -ForegroundColor Yellow
        Write-Host ""
    }

    Write-Host "Loading bootstrap configuration..." -ForegroundColor Yellow

    # Load configuration from PowerShell script
    try {
        $config = & $ConfigPath

        if ($null -eq $config) {
            throw "Configuration script returned null. Ensure the script returns a hashtable using 'return @{...}'"
        }

        if ($config -isnot [hashtable]) {
            throw "Configuration script must return a hashtable. Got: $($config.GetType().Name)"
        }
    }
    catch {
        throw "Failed to load configuration from $ConfigPath : $($_.Exception.Message)"
    }

    # Initialize logging
    # Smart path transformation: In test mode, convert X:\ paths to C:\DeploymentTest\
    $logPath = if ($config.logging.logPath) {
        $configPath = $config.logging.logPath
        # In test mode, transform X:\ paths to C:\DeploymentTest\
        if ($TestMode -and $configPath -match '^X:\\(.*)') {
            "C:\DeploymentTest\$($matches[1])"
        } else {
            $configPath
        }
    } elseif ($TestMode) {
        "C:\DeploymentTest\Deploy\Logs\Bootstrap"
    } else {
        "X:\Deploy\Logs\Bootstrap"
    }
    $logLevel = if ($config.logging.logLevel) { $config.logging.logLevel } else { "Info" }

    Initialize-DeploymentLogging -LogPath $logPath -LogLevel $logLevel
    Write-DeploymentLog "Bootstrap script started" -Level Info
    Write-DeploymentLog "Configuration loaded from: $ConfigPath" -Level Info

    # Validate configuration structure
    Write-DeploymentLog "Validating configuration structure..." -Level Info
    $validationResult = Test-BootstrapConfigurationStructure -Config $config

    if (-not $validationResult.Passed) {
        Write-DeploymentLog "Configuration validation FAILED:" -Level Error
        foreach ($issue in $validationResult.Issues) {
            Write-DeploymentLog "  - $issue" -Level Error
        }
        throw "Configuration validation failed. See log for details."
    }
    Write-DeploymentLog "Configuration validation passed" -Level Info
    #endregion

    #region Bootstrap Self-Update Check
    Write-DeploymentLog "===== BOOTSTRAP UPDATE CHECK =====" -Level Info

    # Auto-discover update location
    $bootstrapUrl = $null

    # 1. Check config for explicit packageUrl
    if ($config.bootstrapUpdate -and $config.bootstrapUpdate.packageUrl) {
        $bootstrapUrl = $config.bootstrapUpdate.packageUrl
        Write-DeploymentLog "Using configured bootstrap URL: $bootstrapUrl" -Level Verbose
    }
    # 2. Auto-derive from packageSource
    elseif ($config.packageSource.blobUrl) {
        $bootstrapUrl = $config.packageSource.blobUrl -replace 'DeploymentPackage\.zip$', 'DeployBootstrap.zip'
        Write-DeploymentLog "Auto-derived bootstrap URL: $bootstrapUrl" -Level Verbose
    }
    elseif ($config.packageSource.uncPath) {
        $bootstrapUrl = $config.packageSource.uncPath -replace 'DeploymentPackage\.zip$', 'DeployBootstrap.zip'
        Write-DeploymentLog "Auto-derived bootstrap URL: $bootstrapUrl" -Level Verbose
    }

    if ($bootstrapUrl) {
        # Determine auth type
        $updateAuthType = if ($config.bootstrapUpdate -and $config.bootstrapUpdate.authType) {
            $config.bootstrapUpdate.authType
        } else {
            $config.packageSource.authType
        }

        $updateSasToken = if ($updateAuthType -eq "SAS") {
            if ($config.bootstrapUpdate -and $config.bootstrapUpdate.sasToken) {
                $config.bootstrapUpdate.sasToken
            }
            else {
                $config.packageSource.sasToken
            }
        } else {
            $null
        }

        # Attempt update check (non-fatal if fails)
        try {
            $updateInfo = Test-BootstrapUpdate -Config $config -CurrentVersion $BOOTSTRAP_VERSION -BootstrapUrl $bootstrapUrl -AuthType $updateAuthType -SasToken $updateSasToken

            if ($updateInfo.UpdateAvailable) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  Bootstrap Update Available" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Current version:   $BOOTSTRAP_VERSION" -ForegroundColor White
                Write-Host "Available version: $($updateInfo.NewVersion)" -ForegroundColor Cyan
                Write-Host ""

                # Download and apply update
                $newBootstrapScript = Update-Bootstrap -Config $config -UpdateInfo $updateInfo

                if ($newBootstrapScript) {
                    Write-Host "Bootstrap updated successfully!" -ForegroundColor Green
                    Write-Host "Restarting with new version..." -ForegroundColor Yellow
                    Write-Host ""

                    Write-DeploymentLog "Restarting with updated bootstrap: $newBootstrapScript" -Level Info

                    # Build new command line (preserve all parameters)
                    $newParams = @{
                        ConfigPath = $ConfigPath
                    }

                    if ($LaunchDeployment) {
                        $newParams.LaunchDeployment = $true
                    }

                    if ($DeploymentConfigPath) {
                        $newParams.DeploymentConfigPath = $DeploymentConfigPath
                    }

                    if ($TestMode) {
                        $newParams.TestMode = $true
                    }

                    # Execute new bootstrap script
                    & $newBootstrapScript @newParams

                    # Exit current script (new version is now running)
                    Write-DeploymentLog "Exiting current bootstrap version" -Level Info
                    exit 0
                }
                else {
                    Write-Host "Bootstrap update failed - continuing with current version" -ForegroundColor Yellow
                    Write-DeploymentLog "Update failed - continuing with version $BOOTSTRAP_VERSION" -Level Warning
                }
            } else {
                Write-DeploymentLog "No bootstrap update available" -Level Info
            }
        }
        catch {
            Write-DeploymentLog "Bootstrap update check failed (non-fatal): $($_.Exception.Message)" -Level Warning
            Write-DeploymentLog "Continuing with current version" -Level Info
        }
    } else {
        Write-DeploymentLog "No bootstrap update location found - skipping update check" -Level Verbose
    }
    #endregion

    #region Package Download
    Write-DeploymentLog "===== PACKAGE DOWNLOAD PHASE =====" -Level Info

    # Determine package source type
    $packageSource = if ($config.packageSource.blobUrl) {
        $config.packageSource.blobUrl
    }
    elseif ($config.packageSource.uncPath) {
        $config.packageSource.uncPath
    }
    elseif ($config.packageSource.localPath) {
        $config.packageSource.localPath
    }
    else {
        throw "No package source specified in configuration"
    }

    $authType = $config.packageSource.authType
    Write-DeploymentLog "Package source: $packageSource" -Level Info
    Write-DeploymentLog "Authentication: $authType" -Level Info

    # Create temp directory for package download
    $tempDir = Get-TemporaryPath -Prefix "BootstrapPackage"
    $DeploymentState.TempPaths += $tempDir

    $packageFile = Join-Path $tempDir "deployment-package.zip"
    $catalogFile = Join-Path $tempDir "deployment-package.cat"

    # =====================================================================
    # PHASE 1: Catalog Download and Signature Validation (BEFORE package)
    # =====================================================================

    Write-DeploymentLog "Preparing catalog validation..." -Level Info

    # Derive catalog URL from package URL
    $catalogUrl = $packageSource -replace '\.zip$', '.cat'

    Write-DeploymentLog "Downloading catalog file..." -Level Info
    Write-DeploymentLog "  Catalog URL: $catalogUrl" -Level Verbose

    # Download catalog based on auth type
    try {
        if ($authType -eq "SAS") {
            $catalogSasToken = if ($config.packageSource.catalogSasToken) {
                $config.packageSource.catalogSasToken
            } else {
                $config.packageSource.sasToken
            }
            Get-AzureBlobWithSAS -BlobUrl $catalogUrl -SasToken $catalogSasToken -Destination $catalogFile -ShowProgress:$false
        }
        elseif ($authType -eq "Anonymous") {
            Get-AzureBlobAnonymous -BlobUrl $catalogUrl -Destination $catalogFile -ShowProgress:$false
        }
        elseif ($authType -eq "SMB") {
            $securePassword = $null
            if ($config.packageSource.password) {
                $securePassword = ConvertTo-SecureString -String $config.packageSource.password -AsPlainText -Force
            }

            if ($config.packageSource.username -and $securePassword) {
                Get-SMBFile -UncPath $catalogUrl -Destination $catalogFile -Username $config.packageSource.username -Password $securePassword -ShowProgress:$false
            }
            else {
                Get-SMBFile -UncPath $catalogUrl -Destination $catalogFile -ShowProgress:$false
            }
        }
        else {
            # Auto-detect
            if ($catalogUrl -match '^\\\\') {
                Get-SMBFile -UncPath $catalogUrl -Destination $catalogFile -ShowProgress:$false
            }
            elseif ($catalogUrl -match '^https?://') {
                Get-AzureBlobAnonymous -BlobUrl $catalogUrl -Destination $catalogFile -ShowProgress:$false
            }
            else {
                Copy-Item -Path $catalogUrl -Destination $catalogFile -Force
            }
        }
    }
    catch {
        throw "Failed to download catalog file: $($_.Exception.Message)"
    }

    if (-not (Test-Path $catalogFile)) {
        throw "Catalog file not found at: $catalogUrl. Catalog validation is required."
    }

    Write-DeploymentLog "Catalog file downloaded" -Level Info

    # Validate catalog signature
    if ($config.validation.enableSignatureCheck) {
        Write-DeploymentLog "Verifying catalog file signature..." -Level Info

        $catalogSignature = Get-AuthenticodeSignature -FilePath $catalogFile -ErrorAction Stop

        if ($catalogSignature.Status -ne "Valid") {
            throw "Catalog signature invalid: $($catalogSignature.Status). Package download aborted."
        }

        # Verify signer is in trusted publishers list
        $signerCert = $catalogSignature.SignerCertificate
        $isTrustedSigner = $false

        foreach ($trustedPublisher in $config.validation.trustedPublishers) {
            if ($trustedPublisher -match '^Thumbprint:(.+)$') {
                $thumbprint = $matches[1]
                if ($signerCert.Thumbprint -eq $thumbprint) {
                    $isTrustedSigner = $true
                    Write-DeploymentLog "Catalog signed by trusted thumbprint: $thumbprint" -Level Verbose
                    break
                }
            }
            elseif ($trustedPublisher -match '^CN:(.+)$') {
                $cnPattern = $matches[1]
                if ($signerCert.Subject -like "*CN=$cnPattern*") {
                    $isTrustedSigner = $true
                    Write-DeploymentLog "Catalog signed by trusted CN: $cnPattern" -Level Verbose
                    break
                }
            }
        }

        if (-not $isTrustedSigner) {
            throw "Catalog signer not in trusted publishers list. Package download aborted.`n  Signer: $($signerCert.Subject)"
        }

        Write-DeploymentLog "Catalog signature validated successfully" -Level Info
    }

    Write-DeploymentLog "Catalog validated - proceeding with package download..." -Level Info

    # =====================================================================
    # PHASE 2: Package Download (AFTER catalog validation)
    # =====================================================================

    Write-DeploymentLog "Acquiring deployment package..." -Level Info
    Write-DeploymentLog "  Package URL: $packageSource" -Level Verbose

    if ($authType -eq "SAS") {
        if (-not $config.packageSource.sasToken) {
            throw "SAS token required but not provided in configuration"
        }
        Get-AzureBlobWithSAS -BlobUrl $packageSource -SasToken $config.packageSource.sasToken -Destination $packageFile -ShowProgress
    }
    elseif ($authType -eq "Anonymous") {
        Get-AzureBlobAnonymous -BlobUrl $packageSource -Destination $packageFile -ShowProgress:$false
    }
    elseif ($authType -eq "SMB") {
        # Convert password to SecureString if provided
        $securePassword = $null
        if ($config.packageSource.password) {
            $securePassword = ConvertTo-SecureString -String $config.packageSource.password -AsPlainText -Force
        }

        if ($config.packageSource.username -and $securePassword) {
            Get-SMBFile -UncPath $packageSource -Destination $packageFile -Username $config.packageSource.username -Password $securePassword -ShowProgress
        }
        else {
            # Try without credentials (current user context)
            Get-SMBFile -UncPath $packageSource -Destination $packageFile -ShowProgress
        }
    }
    else {
        # Local path or auto-detect
        if ($packageSource -match '^\\\\') {
            # UNC path
            Get-SMBFile -UncPath $packageSource -Destination $packageFile -ShowProgress
        }
        else {
            # Local file path
            Copy-Item -Path $packageSource -Destination $packageFile -Force
        }
    }

    if (-not (Test-Path $packageFile)) {
        throw "Failed to acquire package file"
    }

    Write-DeploymentLog "Package acquired successfully: $packageFile" -Level Info

    # =====================================================================
    # PHASE 3: Package Validation Against Catalog
    # =====================================================================

    Write-DeploymentLog "Validating package against catalog..." -Level Info

    $catalogResult = Test-FileCatalog -Path $packageFile `
                                     -CatalogFilePath $catalogFile `
                                     -Detailed `
                                     -ErrorAction Stop

    if ($catalogResult.Status -ne "Valid") {
        Write-DeploymentLog "Package catalog validation FAILED: $($catalogResult.Status)" -Level Error

        # Show validation details
        if ($catalogResult.CatalogItems) {
            foreach ($item in $catalogResult.CatalogItems) {
                if ($item.Status -ne "Valid") {
                    Write-DeploymentLog "  Invalid: $($item.FileName) - $($item.Status)" -Level Error
                }
            }
        }

        throw "Package validation against catalog FAILED"
    }

    Write-DeploymentLog "Package catalog validation PASSED" -Level Info

    # Cleanup catalog file
    if (Test-Path $catalogFile) {
        Remove-Item $catalogFile -Force -ErrorAction SilentlyContinue
    }
    #endregion

    #region Signature Validation
    $validatedExtraction = $null

    if ($config.validation.enableSignatureCheck) {
        Write-DeploymentLog "===== SIGNATURE VALIDATION PHASE =====" -Level Info
        Write-DeploymentLog "Signature validation enabled - validating Deploy-Windows.ps1 script signature" -Level Info

        # Extract to temporary location for validation
        $tempExtractPath = Get-TemporaryPath -Prefix "PackageValidation"
        $DeploymentState.TempPaths += $tempExtractPath

        Write-DeploymentLog "Extracting package for validation..." -Level Info
        Write-DeploymentLog "  Temporary extraction path: $tempExtractPath" -Level Verbose

        try {
            Expand-Archive -Path $packageFile -DestinationPath $tempExtractPath -Force -ErrorAction Stop
        }
        catch {
            throw "Failed to extract package for validation: $($_.Exception.Message)"
        }

        # Locate Deploy-Windows.ps1 in extracted package
        $deployScriptPath = Join-Path $tempExtractPath "Scripts\Deploy-Windows\Deploy-Windows.ps1"

        if (-not (Test-Path $deployScriptPath)) {
            # Try alternate location
            $deployScriptPath = Join-Path $tempExtractPath "Deploy-Windows.ps1"
        }

        if (-not (Test-Path $deployScriptPath)) {
            throw "Deploy-Windows.ps1 not found in package. Expected location: Scripts\Deploy-Windows\Deploy-Windows.ps1"
        }

        Write-DeploymentLog "Validating Deploy-Windows.ps1 signature..." -Level Info
        Write-DeploymentLog "  Script path: $deployScriptPath" -Level Verbose

        # Verify script signature
        $signature = Get-AuthenticodeSignature -FilePath $deployScriptPath

        if ($signature.Status -ne "Valid") {
            $errorMsg = "Deploy-Windows.ps1 signature validation failed: $($signature.Status)"
            Write-DeploymentLog $errorMsg -Level Error

            if ($config.validation.requireValidSignature) {
                throw $errorMsg
            }
            else {
                Write-DeploymentLog "Continuing despite invalid signature (requireValidSignature = false)" -Level Warning
            }
        }
        else {
            Write-DeploymentLog "Deploy-Windows.ps1 signature is valid" -Level Info
            Write-DeploymentLog "Signer: $($signature.SignerCertificate.Subject)" -Level Info

            # Check trusted publishers if specified
            if ($config.validation.trustedPublishers -and $config.validation.trustedPublishers.Count -gt 0) {
                $certSubject = $signature.SignerCertificate.Subject
                $certThumbprint = $signature.SignerCertificate.Thumbprint
                $certCN = if ($certSubject -match 'CN=([^,]+)') { $matches[1] } else { '' }

                $isTrusted = $false
                $matchedPublisher = $null

                foreach ($trustedPublisher in $config.validation.trustedPublishers) {
                    # Check for prefix-based validation
                    if ($trustedPublisher -like "Thumbprint:*") {
                        # Thumbprint validation (case-insensitive, exact match)
                        $expectedThumbprint = $trustedPublisher -replace '^Thumbprint:', ''
                        if ($certThumbprint -eq $expectedThumbprint) {
                            $isTrusted = $true
                            $matchedPublisher = $trustedPublisher
                            break
                        }
                    }
                    elseif ($trustedPublisher -like "CN:*") {
                        # Common Name validation (case-insensitive, contains match)
                        $expectedCN = $trustedPublisher -replace '^CN:', ''
                        if ($certCN -like "*$expectedCN*") {
                            $isTrusted = $true
                            $matchedPublisher = $trustedPublisher
                            break
                        }
                    }
                    else {
                        # Invalid format - reject
                        $errorMsg = "Invalid trusted publisher format: '$trustedPublisher'`n  Must use 'Thumbprint:<40-hex>' or 'CN:<common-name>' prefix"
                        Write-DeploymentLog $errorMsg -Level Error
                        throw $errorMsg
                    }
                }

                if (-not $isTrusted) {
                    $errorMsg = "Deploy-Windows.ps1 signed by untrusted publisher`n  Certificate Subject: $certSubject`n  Certificate CN: $certCN`n  Certificate Thumbprint: $certThumbprint"
                    Write-DeploymentLog $errorMsg -Level Error
                    throw $errorMsg
                }

                Write-DeploymentLog "Publisher is trusted: $matchedPublisher" -Level Info
                Write-DeploymentLog "  Certificate Subject: $certSubject" -Level Verbose
                Write-DeploymentLog "  Certificate Thumbprint: $certThumbprint" -Level Verbose
            }
        }

        # Validation passed - use validated extraction
        Write-DeploymentLog "Signature validation passed" -Level Info
        $validatedExtraction = $tempExtractPath
    }
    else {
        Write-DeploymentLog "Signature validation disabled" -Level Info
    }
    #endregion

    #region Package Extraction
    Write-DeploymentLog "===== PACKAGE EXTRACTION PHASE =====" -Level Info

    $extractionPath = $config.extraction.targetPath
    if (-not $extractionPath) {
        $extractionPath = if ($TestMode) { "C:\DeploymentTest\Deploy" } else { "X:\Deploy" }
    }

    Write-DeploymentLog "Extraction target: $extractionPath" -Level Info

    # Create extraction directory
    if (-not (Test-Path $extractionPath)) {
        Write-DeploymentLog "Creating extraction directory..." -Level Info
        New-Item -Path $extractionPath -ItemType Directory -Force | Out-Null
    }

    # If signature validation was enabled, move validated extraction
    # Otherwise, extract fresh
    if ($validatedExtraction) {
        Write-DeploymentLog "Moving validated package to target location..." -Level Info
        try {
            # Move contents from temp validation location to target
            Get-ChildItem -Path $validatedExtraction -Recurse | ForEach-Object {
                $targetPath = $_.FullName.Replace($validatedExtraction, $extractionPath)

                if ($_.PSIsContainer) {
                    if (-not (Test-Path $targetPath)) {
                        New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
                    }
                }
                else {
                    $targetDir = Split-Path $targetPath -Parent
                    if (-not (Test-Path $targetDir)) {
                        New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path $_.FullName -Destination $targetPath -Force
                }
            }
            Write-DeploymentLog "Validated package moved successfully" -Level Info
        }
        catch {
            $errorMsg = "Failed to move validated package: $($_.Exception.Message)"
            Write-DeploymentLog $errorMsg -Level Error
            throw $errorMsg
        }
    }
    else {
        # Extract without pre-validation
        Write-DeploymentLog "Extracting deployment package..." -Level Info

        try {
            Expand-Archive -Path $packageFile -DestinationPath $extractionPath -Force
            Write-DeploymentLog "Package extracted successfully" -Level Info
        }
        catch {
            $errorMsg = "Failed to extract package: $($_.Exception.Message)"
            Write-DeploymentLog $errorMsg -Level Error

            if ($config.extraction.cleanupOnFailure) {
                Write-DeploymentLog "Cleaning up extraction directory..." -Level Warning
                if (Test-Path $extractionPath) {
                    Remove-Item -Path $extractionPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }

            throw $errorMsg
        }
    }

    # List extracted contents
    Write-DeploymentLog "Extraction complete. Contents:" -Level Info
    Get-ChildItem -Path $extractionPath -Recurse | ForEach-Object {
        Write-DeploymentLog "  $($_.FullName)" -Level Verbose
    }
    #endregion

    #region Launch Deployment
    if ($LaunchDeployment) {
        Write-DeploymentLog "===== LAUNCHING MAIN DEPLOYMENT =====" -Level Info

        $deployScriptPath = Join-Path $extractionPath "Scripts\Deploy-Windows.ps1"

        if (-not (Test-Path $deployScriptPath)) {
            Write-DeploymentLog "Deploy-Windows.ps1 not found in extracted package: $deployScriptPath" -Level Warning
            Write-DeploymentLog "Skipping automatic deployment launch" -Level Warning
        }
        else {
            Write-DeploymentLog "Launching Deploy-Windows.ps1..." -Level Info

            if ($DeploymentConfigPath) {
                Write-DeploymentLog "Deployment config: $DeploymentConfigPath" -Level Info
                & $deployScriptPath -ConfigPath $DeploymentConfigPath
            }
            else {
                Write-DeploymentLog "No deployment config specified, attempting default..." -Level Info
                $defaultConfig = Join-Path $extractionPath "Config\deployment-config.ps1"
                if (Test-Path $defaultConfig) {
                    & $deployScriptPath -ConfigPath $defaultConfig
                }
                else {
                    throw "No deployment configuration specified and default not found: $defaultConfig"
                }
            }
        }
    }
    else {
        Write-DeploymentLog "Automatic deployment launch disabled" -Level Info
        Write-DeploymentLog "To manually launch deployment, run: $extractionPath\Scripts\Deploy-Windows.ps1" -Level Info
    }
    #endregion

    Write-DeploymentLog "Bootstrap completed successfully" -Level Info
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Bootstrap Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Extraction Path: $extractionPath" -ForegroundColor Cyan

    if (-not $LaunchDeployment) {
        Write-Host ""
        Write-Host "To launch deployment manually:" -ForegroundColor Yellow
        Write-Host "  $extractionPath\Scripts\Deploy-Windows.ps1 -ConfigPath <config.ps1>" -ForegroundColor White
    }

    exit 0
}
catch {
    Write-DeploymentLog "FATAL ERROR: $($_.Exception.Message)" -Level Error
    Write-DeploymentLog "Stack trace: $($_.ScriptStackTrace)" -Level Error

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Bootstrap Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the log file for details:" -ForegroundColor Yellow
    Write-Host "  $logPath" -ForegroundColor White

    Show-DeploymentError -ErrorMessage $_.Exception.Message -AdditionalInfo "Check logs at: $logPath"

    exit 1
}
finally {
    # Cleanup temporary files
    Write-DeploymentLog "Cleaning up temporary files..." -Level Info
    Invoke-CleanupDeployment -State $DeploymentState
}

#endregion
