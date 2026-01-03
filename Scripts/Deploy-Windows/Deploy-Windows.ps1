#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows deployment script with embedded functions

.DESCRIPTION
    Self-contained deployment script for code signing compatibility.
    All function libraries are embedded in this file.

    Functions included:
    - Utility-Functions: Logging, resource management, UI
    - Validation-Functions: Environment and config validation, Windows 11 compatibility
    - Web-Functions: Azure Blob downloads
    - SMB-Functions: Network share access

    Performs complete Windows deployment automation:
    - Validates WinPE environment and Windows 11 hardware compatibility
    - Downloads Windows image (ISO/FFU/WIM) from Azure or local
    - Partitions disk with GPT layout (EFI, MSR, Windows, Recovery at END)
    - Installs Windows image
    - Applies customizations (drivers, registry, files, Autopilot, Unattend.xml)
    - Configures bootloader and recovery environment

    Designed specifically for UEFI/GPT systems in WinPE/WinRE environments.

.PARAMETER ConfigPath
    Path to deployment configuration PowerShell .ps1 file
    Must return a hashtable with deployment configuration

.EXAMPLE
    .\Deploy-Windows.ps1 -ConfigPath "X:\Deploy\Config\deployment-config.ps1"

.NOTES
    This is a consolidated version for code signing.
    Original modular version: Scripts/Deploy-Windows.ps1
    Author: Windows Deployment Automation
    Requires: PowerShell 5.1+, Administrator privileges, UEFI boot mode
    Environment: WinPE/WinRE
    Partition Layout: EFI → MSR → Windows → Recovery (at END)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if (-not (Test-Path $_ -PathType Leaf)) {
            throw "Configuration file not found: $_"
        }
        if ($_ -notmatch '\.ps1$') {
            throw "Configuration file must be a PowerShell script (.ps1): $_"
        }
        return $true
    })]
    [string]$ConfigPath
)

# Set script root
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Deployment Script Version
$DEPLOYMENT_VERSION = "1.0.0"

#region Embedded Functions

#region Utility Functions

# Script-level variables for logging configuration
$script:LogConfig = @{
    LogPath = "X:\Deploy\Logs\Deployment.log"
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
        [string]$LogPath = "X:\Deploy\Logs\Deployment.log",

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

    # In WinPE, use X:\Temp or X:\Deploy\Temp
    $tempBase = if (Test-Path "X:\") { "X:\Deploy\Temp" } else { $env:TEMP }

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
    .PARAMETER CurrentPhase
        Current deployment phase
    .PARAMETER PercentComplete
        Optional percentage complete
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentPhase,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete = -1
    )

    # Display current phase
    Write-Host "Current Phase: " -NoNewline
    Write-Host $CurrentPhase -ForegroundColor Yellow
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
        [string]$AdditionalInfo = ""
    )

    Clear-Host
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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$State
    )

    Write-DeploymentLog "Starting deployment cleanup..." -Level Info

    # Dismount any mounted images
    if ($State -and $State.MountedImages) {
        foreach ($imagePath in $State.MountedImages) {
            try {
                Write-DeploymentLog "Dismounting image: $imagePath" -Level Info
                Dismount-DiskImage -ImagePath $imagePath -ErrorAction SilentlyContinue
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
                Write-DeploymentLog "Unloading registry hive: $hive" -Level Info

                $result = Start-Process -FilePath "reg.exe" -ArgumentList "unload", "HKLM\$hive" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue

                if ($result.ExitCode -ne 0) {
                    # Retry after garbage collection
                    Start-Sleep -Seconds 2
                    [System.GC]::Collect()
                    Start-Sleep -Seconds 1
                    Start-Process -FilePath "reg.exe" -ArgumentList "unload", "HKLM\$hive" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue
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
    .PARAMETER ImagePath
        Windows partition root path (e.g., W:\)
    .PARAMETER LogPath
        Source log file path
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImagePath,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    try {
        # Create log directory in deployed image
        $destLogDir = Join-Path $ImagePath "Windows\Logs\Deployment"
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

#endregion Utility Functions

#region Validation Functions

# Validate deployment configuration structure
function Test-DeploymentConfigurationStructure {
    <#
    .SYNOPSIS
        Validate deployment configuration hashtable structure
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

    # Validate deploymentInfo
    if (-not $Config.deploymentInfo) {
        $results.Issues += "Missing 'deploymentInfo' section"
        $results.Passed = $false
    }
    else {
        if (-not $Config.deploymentInfo.name) {
            $results.Issues += "deploymentInfo.name is required"
            $results.Passed = $false
        }
        if (-not $Config.deploymentInfo.version) {
            $results.Issues += "deploymentInfo.version is required"
            $results.Passed = $false
        }
    }

    # Validate imageSource
    if (-not $Config.imageSource) {
        $results.Issues += "Missing 'imageSource' section"
        $results.Passed = $false
    }
    else {
        if (-not $Config.imageSource.type) {
            $results.Issues += "imageSource.type is required"
            $results.Passed = $false
        }
        elseif ($Config.imageSource.type -notin @('ISO', 'FFU', 'WIM')) {
            $results.Issues += "Invalid imageSource.type: $($Config.imageSource.type). Must be ISO, FFU, or WIM"
            $results.Passed = $false
        }

        if (-not $Config.imageSource.location) {
            $results.Issues += "imageSource.location is required"
            $results.Passed = $false
        }
        else {
            $loc = $Config.imageSource.location

            # Must have exactly one location type
            $locCount = 0
            if ($loc.blobUrl) { $locCount++ }
            if ($loc.uncPath) { $locCount++ }
            if ($loc.localPath) { $locCount++ }

            if ($locCount -eq 0) {
                $results.Issues += "imageSource.location must specify one of: blobUrl, uncPath, or localPath"
                $results.Passed = $false
            }
            elseif ($locCount -gt 1) {
                $results.Issues += "imageSource.location must specify only one location type"
                $results.Passed = $false
            }
        }
    }

    # Validate diskConfiguration
    if (-not $Config.diskConfiguration) {
        $results.Issues += "Missing 'diskConfiguration' section"
        $results.Passed = $false
    }
    else {
        $disk = $Config.diskConfiguration

        if ($disk.partitionStyle -and $disk.partitionStyle -ne 'GPT') {
            $results.Issues += "Only GPT partition style is supported. Got: $($disk.partitionStyle)"
            $results.Passed = $false
        }

        if ($null -eq $disk.diskNumber -or $disk.diskNumber -lt 0) {
            $results.Issues += "diskConfiguration.diskNumber must be >= 0"
            $results.Passed = $false
        }
    }

    # Validate customization sections (all optional, but validate structure if present)
    if ($Config.customization) {
        $custom = $Config.customization

        # Validate drivers section
        if ($custom.drivers -and $custom.drivers.enabled -and $custom.drivers.sources) {
            if ($custom.drivers.sources -isnot [array]) {
                $results.Issues += "customization.drivers.sources must be an array"
                $results.Passed = $false
            }
        }

        # Validate registry section
        if ($custom.registry -and $custom.registry.enabled -and $custom.registry.modifications) {
            if ($custom.registry.modifications -isnot [array]) {
                $results.Issues += "customization.registry.modifications must be an array"
                $results.Passed = $false
            }
        }

        # Validate files section
        if ($custom.files -and $custom.files.enabled -and $custom.files.copyOperations) {
            if ($custom.files.copyOperations -isnot [array]) {
                $results.Issues += "customization.files.copyOperations must be an array"
                $results.Passed = $false
            }
        }
    }

    # Validate imageValidation section (optional, but validate structure if present)
    if ($Config.imageValidation) {
        $validation = $Config.imageValidation

        # enabled must be boolean
        if ($null -ne $validation.enabled -and $validation.enabled -isnot [bool]) {
            $results.Issues += "imageValidation.enabled must be a boolean"
            $results.Passed = $false
        }

        # requireValidCatalog must be boolean
        if ($null -ne $validation.requireValidCatalog -and $validation.requireValidCatalog -isnot [bool]) {
            $results.Issues += "imageValidation.requireValidCatalog must be a boolean"
            $results.Passed = $false
        }

        # enableSignatureCheck must be boolean
        if ($null -ne $validation.enableSignatureCheck -and $validation.enableSignatureCheck -isnot [bool]) {
            $results.Issues += "imageValidation.enableSignatureCheck must be a boolean"
            $results.Passed = $false
        }

        # trustedPublishers must be array
        if ($validation.trustedPublishers -and $validation.trustedPublishers -isnot [array]) {
            $results.Issues += "imageValidation.trustedPublishers must be an array"
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
        if (Test-Path "X:\") {
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
    .PARAMETER ConfigPath
        Path to configuration .ps1 file
    .PARAMETER SchemaPath
        (Deprecated - no longer used, kept for compatibility)
    .OUTPUTS
        Hashtable with validation results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $false)]
        [string]$SchemaPath
    )

    Write-DeploymentLog "Validating deployment configuration..." -Level Info

    # Load configuration
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
        $results = @{
            Passed = $false
            Issues = @("Failed to load configuration from $ConfigPath : $($_.Exception.Message)")
        }
        return $results
    }

    # Validate configuration structure using Test-DeploymentConfigurationStructure
    $results = Test-DeploymentConfigurationStructure -Config $config

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
        SizeGB = 0
        Passed = $false
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
        $results.SizeGB = [math]::Round($diskSizeGB, 2)
        Write-DeploymentLog "Disk size: $($results.SizeGB) GB" -Level Info

        if ($diskSizeGB -lt $RequiredSizeGB) {
            $results.Issues += "Disk is too small ($($results.SizeGB) GB, minimum: $RequiredSizeGB GB)"
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
        $results.Passed = ($results.DiskExists -and $results.DiskOnline -and $diskSizeGB -ge $RequiredSizeGB -and -not $disk.IsReadOnly)

        if ($results.Passed) {
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

function Invoke-ExternalCommand {
    <#
    .SYNOPSIS
        Executes external command with timeout protection

    .DESCRIPTION
        Runs command as PowerShell job with configurable timeout.
        Used for BIOS configuration tools that may hang.

    .PARAMETER Command
        The executable path to run

    .PARAMETER Arguments
        Array of arguments to pass to the command

    .PARAMETER TimeoutSeconds
        Maximum time to wait for command completion (default: 300 seconds)

    .OUTPUTS
        Hashtable with Success, Output, and ExitCode properties
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 300
    )

    Write-DeploymentLog "Executing command with timeout: $Command $($Arguments -join ' ')" -Level Verbose

    $job = Start-Job -ScriptBlock {
        param($cmd, $args)
        & $cmd $args 2>&1
    } -ArgumentList $Command, $Arguments

    $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds

    if ($completed) {
        $output = Receive-Job -Job $job
        Remove-Job -Job $job -Force
        Write-DeploymentLog "Command completed successfully" -Level Verbose
        return @{
            Success = $true
            Output = $output
            ExitCode = 0
        }
    }
    else {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        Write-DeploymentLog "Command timed out after $TimeoutSeconds seconds" -Level Warning
        return @{
            Success = $false
            Output = "Command timed out after $TimeoutSeconds seconds"
            ExitCode = -1
        }
    }
}

function Set-DellBIOSConfiguration {
    <#
    .SYNOPSIS
        Configures Dell BIOS settings for Windows 11 deployment

    .DESCRIPTION
        Uses Dell Command | Configure Toolkit (CCTK) to configure:
        - Storage controller mode (AHCI)
        - TPM enable and activation
        - SecureBoot enable

        If any settings are changed, prompts for reboot and exits script.

    .PARAMETER SystemInfo
        System information object from Get-CimInstance Win32_ComputerSystem

    .NOTES
        Requires CCTK at X:\Windows\System32\Dell\CCTK\cctk.exe or X:\Deploy\CTTK.zip
        Exits script if reboot required
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SystemInfo
    )

    Write-DeploymentLog "Starting Dell BIOS configuration..." -Level Info

    # Path where CCTK should be in WinPE
    $cttkExe = "X:\Windows\System32\Dell\CCTK\cctk.exe"

    # Fallback: Extract from deployment package
    if (-not (Test-Path $cttkExe)) {
        $cttkZip = "X:\Deploy\CTTK.zip"
        $cttkExtractPath = "X:\Windows\System32\Dell\CCTK"

        if (Test-Path $cttkZip) {
            Write-DeploymentLog "Extracting CTTK from deployment package..." -Level Info
            Expand-Archive -Path $cttkZip -DestinationPath $cttkExtractPath -Force
        }
        else {
            Write-DeploymentLog "CTTK not found - skipping Dell BIOS configuration" -Level Warning
            return
        }
    }

    # Verify CCTK exists after extraction
    if (-not (Test-Path $cttkExe)) {
        Write-DeploymentLog "CCTK executable not found after extraction - skipping Dell BIOS configuration" -Level Warning
        return
    }

    # Start WMI service (required for CCTK)
    Write-DeploymentLog "Starting WMI service for CCTK operations..." -Level Info
    Start-Service -Name "Winmgmt" -ErrorAction SilentlyContinue

    $requiresReboot = $false

    try {
        # Check and configure storage mode (AHCI)
        Write-DeploymentLog "Checking storage controller mode..." -Level Info
        $sataResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--embsataraid")

        if ($sataResult.Success -and $sataResult.Output -match "raid") {
            Write-DeploymentLog "RAID mode detected - switching to AHCI..." -Level Warning
            $ahciResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--embsataraid=ahci")

            if ($ahciResult.Success) {
                Write-DeploymentLog "AHCI mode configured successfully" -Level Info
                $requiresReboot = $true
            }
        }
        elseif ($sataResult.Success -and $sataResult.Output -match "ahci") {
            Write-DeploymentLog "Storage controller already set to AHCI" -Level Info
        }

        # Check and configure TPM
        Write-DeploymentLog "Checking TPM status..." -Level Info
        $tpmResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--tpm")

        if ($tpmResult.Success -and $tpmResult.Output -notmatch "on") {
            Write-DeploymentLog "Enabling TPM..." -Level Warning
            $tpmEnableResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--tpm=on")

            if ($tpmEnableResult.Success) {
                Write-DeploymentLog "TPM enabled - activating..." -Level Info
                Invoke-ExternalCommand -Command $cttkExe -Arguments @("--tpmactivation=activate") | Out-Null
                $requiresReboot = $true
            }
        }

        # Check and configure SecureBoot
        Write-DeploymentLog "Checking SecureBoot status..." -Level Info
        $secureBootResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--secureboot")

        if ($secureBootResult.Success -and $secureBootResult.Output -notmatch "enable") {
            Write-DeploymentLog "Enabling SecureBoot..." -Level Warning
            $sbEnableResult = Invoke-ExternalCommand -Command $cttkExe -Arguments @("--secureboot=enable")

            if ($sbEnableResult.Success) {
                Write-DeploymentLog "SecureBoot enabled successfully" -Level Info
                $requiresReboot = $true
            }
        }

        # Handle reboot if needed
        if ($requiresReboot) {
            Write-Host ""
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host "BIOS CONFIGURATION COMPLETE" -ForegroundColor Yellow
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "BIOS settings have been updated successfully!" -ForegroundColor Green
            Write-Host "A system reboot is REQUIRED for changes to take effect." -ForegroundColor Red
            Write-Host ""
            Write-Host "Press any key to reboot..." -ForegroundColor Cyan
            Write-Host ""

            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

            Write-DeploymentLog "Rebooting system for BIOS changes..." -Level Info
            & wpeutil reboot

            # Fallback reboot
            Start-Sleep -Seconds 2
            & shutdown /r /t 0 /f

            exit 0
        }

        Write-DeploymentLog "Dell BIOS configuration complete - no changes required" -Level Info

    }
    catch {
        Write-DeploymentLog "Error during Dell BIOS configuration: $($_.Exception.Message)" -Level Warning
        Write-DeploymentLog "Continuing with deployment despite BIOS configuration issues" -Level Warning
    }
}

function Set-HPBIOSConfiguration {
    <#
    .SYNOPSIS
        Configures HP BIOS settings for Windows 11 deployment

    .DESCRIPTION
        Uses HP BIOSConfigUtility64.exe to configure:
        - SecureBoot enable

        If settings are changed, prompts for reboot and exits script.

    .PARAMETER SystemInfo
        System information object from Get-CimInstance Win32_ComputerSystem

    .NOTES
        Requires HP BIOSConfigUtility64.exe at X:\Windows\System32\HP\BIOSConfigUtility\
        Exits script if reboot required or configuration fails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $SystemInfo
    )

    Write-DeploymentLog "Starting HP BIOS configuration..." -Level Info

    # Path where HP BIOSConfigUtility should be in WinPE
    $hpToolPath = "X:\Windows\System32\HP\BIOSConfigUtility\BIOSConfigUtility64.exe"

    if (-not (Test-Path $hpToolPath)) {
        Write-DeploymentLog "HP BIOSConfigUtility not found - skipping BIOS configuration" -Level Warning
        return
    }

    try {
        # Check SecureBoot status
        Write-DeploymentLog "Checking HP SecureBoot status..." -Level Info
        $secureBootResult = & $hpToolPath /getvalue:"Secure Boot" 2>&1
        $secureBootOutput = $secureBootResult -join " "
        Write-DeploymentLog "SecureBoot query result: $secureBootOutput" -Level Verbose

        # Parse XML response - look for *ENABLE indicating enabled status
        # Enabled: <VALUE><![CDATA[DISABLE,*ENABLE]]></VALUE>
        # Disabled: <VALUE><![CDATA[*DISABLE,ENABLE]]></VALUE>
        if ($secureBootOutput -notlike "*[DISABLE,``*ENABLE]*") {
            Write-DeploymentLog "SecureBoot is disabled - attempting to enable..." -Level Warning

            # Create temp directory
            if (-not (Test-Path "X:\Temp")) {
                New-Item -Path "X:\Temp" -ItemType Directory -Force | Out-Null
            }

            # Create SecureBoot configuration file (ASCII encoding required)
            $configContent = "Secure Boot=Enable"
            $configFile = "X:\Temp\EnableSecureBoot.txt"
            $configContent | Out-File -FilePath $configFile -Encoding ASCII

            Write-DeploymentLog "Applying SecureBoot configuration..." -Level Info
            $applyResult = & $hpToolPath /Set:"$configFile" 2>&1
            $applyOutput = $applyResult -join " "
            Write-DeploymentLog "SecureBoot enable result: $applyOutput" -Level Verbose

            # Clean up config file
            Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue

            # Check if successful
            if ($LASTEXITCODE -eq 0 -or $applyOutput -notlike "*error*") {
                Write-Host ""
                Write-Host "============================================" -ForegroundColor Yellow
                Write-Host "SECUREBOOT CONFIGURATION COMPLETE" -ForegroundColor Yellow
                Write-Host "============================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "SecureBoot has been enabled successfully!" -ForegroundColor Green
                Write-Host "A system reboot is REQUIRED for changes to take effect." -ForegroundColor Red
                Write-Host ""
                Write-Host "Press any key to reboot..." -ForegroundColor Cyan
                Write-Host ""

                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

                Write-DeploymentLog "Rebooting system for BIOS changes..." -Level Info
                & wpeutil reboot

                # Fallback reboot
                Start-Sleep -Seconds 2
                & shutdown /r /t 0 /f

                # Final fallback
                Start-Sleep -Seconds 5
                Write-DeploymentLog "All reboot methods failed - manual reboot required" -Level Error
                Write-Host "ERROR: Automatic reboot failed. Please manually restart." -ForegroundColor Red
                exit 1
            }
            else {
                # Auto-enable failed - provide manual instructions
                Write-Host ""
                Write-Host "============================================" -ForegroundColor Red
                Write-Host "SECUREBOOT AUTO-CONFIGURATION FAILED" -ForegroundColor Red
                Write-Host "============================================" -ForegroundColor Red
                Write-Host ""
                Write-Host "Could not enable SecureBoot automatically." -ForegroundColor Yellow
                Write-Host "SecureBoot must be enabled manually in BIOS." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Steps:" -ForegroundColor Cyan
                Write-Host "  1. Reboot and enter BIOS (F10 during boot)" -ForegroundColor Cyan
                Write-Host "  2. Navigate to Security settings" -ForegroundColor Cyan
                Write-Host "  3. Enable SecureBoot" -ForegroundColor Cyan
                Write-Host "  4. Save and exit" -ForegroundColor Cyan
                Write-Host "  5. Run deployment again" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Press any key to exit..." -ForegroundColor Cyan

                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

                Write-DeploymentLog "Manual SecureBoot configuration required - exiting" -Level Error
                exit 1
            }
        }
        else {
            Write-DeploymentLog "SecureBoot is already enabled" -Level Info
        }

        Write-DeploymentLog "HP BIOS configuration complete" -Level Info

    }
    catch {
        Write-DeploymentLog "Error during HP BIOS configuration: $($_.Exception.Message)" -Level Warning
        Write-DeploymentLog "Continuing with deployment despite BIOS configuration issues" -Level Warning
    }
}

function Test-Windows11Compatibility {
    <#
    .SYNOPSIS
        Validates system meets Windows 11 hardware requirements

    .DESCRIPTION
        Checks:
        - Secure Boot enabled
        - TPM 2.0+ present and enabled
        - Manufacturer-specific BIOS configuration (Dell or HP)

        Calls manufacturer-specific functions which may exit script if BIOS changes needed.

    .OUTPUTS
        None - exits script if requirements not met or BIOS reconfiguration needed
    #>
    [CmdletBinding()]
    param()

    Write-DeploymentLog "===== WINDOWS 11 COMPATIBILITY CHECK =====" -Level Info

    $failedChecks = @()

    # Get system information
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $systemInfo.Manufacturer

    Write-DeploymentLog "System manufacturer: $manufacturer" -Level Info
    Write-DeploymentLog "System model: $($systemInfo.Model)" -Level Info

    # Check manufacturer-specific BIOS settings FIRST (may exit script for reboot)
    if ($manufacturer -match "Dell") {
        Write-DeploymentLog "Dell system detected - checking BIOS configuration..." -Level Info
        Set-DellBIOSConfiguration -SystemInfo $systemInfo
        # If function returns, all BIOS settings are correct
    }
    elseif ($manufacturer -match "HP|Hewlett") {
        Write-DeploymentLog "HP system detected - checking BIOS configuration..." -Level Info
        Set-HPBIOSConfiguration -SystemInfo $systemInfo
        # If function returns, all BIOS settings are correct
    }
    else {
        Write-DeploymentLog "Manufacturer '$manufacturer' - no vendor-specific BIOS configuration available" -Level Warning
    }

    # Check Secure Boot
    try {
        $secureBoot = Confirm-SecureBootUEFI
        if ($secureBoot) {
            Write-DeploymentLog "Secure Boot: ENABLED" -Level Info
        }
        else {
            Write-DeploymentLog "Secure Boot: DISABLED" -Level Error
            $failedChecks += "Secure Boot is not enabled"
        }
    }
    catch {
        Write-DeploymentLog "Unable to check Secure Boot: $($_.Exception.Message)" -Level Error
        $failedChecks += "Unable to verify Secure Boot status: $($_.Exception.Message)"
    }

    # Check TPM
    try {
        $tpm = Get-Tpm
        if ($tpm) {
            Write-DeploymentLog "TPM Present: $($tpm.TpmPresent)" -Level Info
            Write-DeploymentLog "TPM Ready: $($tpm.TpmReady)" -Level Info
            Write-DeploymentLog "TPM Enabled: $($tpm.TpmEnabled)" -Level Info
            Write-DeploymentLog "TPM Activated: $($tpm.TpmActivated)" -Level Info
            Write-DeploymentLog "TPM Version: $($tpm.ManufacturerVersion)" -Level Info

            if (-not $tpm.TpmPresent) {
                $failedChecks += "TPM not present"
            }
            elseif (-not $tpm.TpmReady) {
                $failedChecks += "TPM not ready"
            }
            elseif ($tpm.ManufacturerVersion -notmatch "^2\.") {
                $failedChecks += "TPM version $($tpm.ManufacturerVersion) does not meet Windows 11 requirement (2.0+)"
            }
        }
        else {
            Write-DeploymentLog "Unable to query TPM" -Level Error
            $failedChecks += "Unable to query TPM"
        }
    }
    catch {
        Write-DeploymentLog "Error checking TPM: $($_.Exception.Message)" -Level Error
        $failedChecks += "Error checking TPM: $($_.Exception.Message)"
    }

    # Report results
    if ($failedChecks.Count -gt 0) {
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Red
        Write-Host "WINDOWS 11 COMPATIBILITY CHECK FAILED" -ForegroundColor Red
        Write-Host "============================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "The following requirements are not met:" -ForegroundColor Yellow
        foreach ($check in $failedChecks) {
            Write-Host "  - $check" -ForegroundColor Yellow
        }
        Write-Host ""

        $errorMsg = "Windows 11 compatibility check failed: " + ($failedChecks -join "; ")
        Write-DeploymentLog $errorMsg -Level Error
        throw $errorMsg
    }

    Write-DeploymentLog "Windows 11 compatibility check PASSED" -Level Info
    Write-Host "Windows 11 compatibility check: PASSED" -ForegroundColor Green
}

#endregion Validation Functions

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
    .PARAMETER SasToken
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
        [string]$SasToken,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress
    )

    # Build full URI with SAS token
    $separator = if ($BlobUrl -like "*?*") { "&" } else { "?" }
    $fullUri = "$BlobUrl$separator$SasToken"

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

#endregion Web Functions

#region SMB Functions

# Download from SMB/network share with optional authentication
function Get-SMBFile {
    <#
    .SYNOPSIS
        Download file from SMB/network share with optional authentication
    .PARAMETER UncPath
        UNC path to source file (e.g., \\server\share\file.iso)
    .PARAMETER Destination
        Local destination file path
    .PARAMETER Username
        Username for authentication (optional, use domain\username or username@domain)
    .PARAMETER Password
        Password for authentication (optional, SecureString)
    .PARAMETER ShowProgress
        Show copy progress
    .OUTPUTS
        Boolean indicating success
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

    Write-DeploymentLog "Downloading from SMB share: $UncPath" -Level Info

    try {
        # Validate UNC path format
        if ($UncPath -notmatch '^\\\\[^\\]+\\[^\\]+') {
            throw "Invalid UNC path format. Expected: \\server\share\file"
        }

        # Extract server and share from UNC path
        if ($UncPath -match '^\\\\([^\\]+)\\([^\\]+)') {
            $server = $Matches[1]
            $share = $Matches[2]
            $sharePath = "\\$server\$share"
        }
        else {
            throw "Failed to parse UNC path"
        }

        # Map network drive if credentials provided
        $driveMapped = $false
        $mappedDrive = $null

        if ($Username -and $Password) {
            Write-DeploymentLog "Authenticating to SMB share with credentials..." -Level Info

            # Find available drive letter
            $availableDrive = Get-ChildItem function:[d-z]: -Name |
                Where-Object { -not (Test-Path $_) } |
                Select-Object -First 1

            if (-not $availableDrive) {
                throw "No available drive letters for mapping"
            }

            $mappedDrive = $availableDrive.TrimEnd(':')

            # Convert SecureString to credential
            $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)

            # Map network drive
            try {
                New-PSDrive -Name $mappedDrive -PSProvider FileSystem -Root $sharePath -Credential $credential -ErrorAction Stop | Out-Null
                $driveMapped = $true
                Write-DeploymentLog "Network drive mapped: $mappedDrive`:" -Level Info

                # Update UNC path to use mapped drive
                $relativePath = $UncPath.Substring($sharePath.Length)
                $UncPath = "$mappedDrive`:$relativePath"
            }
            catch {
                Write-DeploymentLog "WARNING: Failed to map network drive: $_" -Level Warning
                Write-DeploymentLog "Attempting direct access (may prompt for credentials)..." -Level Warning
            }
        }

        # Verify source exists
        if (-not (Test-Path $UncPath)) {
            throw "Source file not found: $UncPath"
        }

        # Create destination directory if needed
        $destDir = Split-Path -Path $Destination -Parent
        if ($destDir -and -not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }

        # Copy file
        Write-DeploymentLog "Copying file from SMB share..." -Level Info

        if ($ShowProgress) {
            # Use robocopy for progress (better for large files)
            $sourceDir = Split-Path $UncPath -Parent
            $sourceFile = Split-Path $UncPath -Leaf
            $destDir = Split-Path $Destination -Parent

            $robocopyArgs = "`"$sourceDir`" `"$destDir`" `"$sourceFile`" /R:3 /W:10 /NFL /NDL"
            $robocopyResult = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -NoNewWindow -PassThru

            # Robocopy exit codes: 0-7 are success, >7 are errors
            if ($robocopyResult.ExitCode -gt 7) {
                throw "Robocopy failed with exit code: $($robocopyResult.ExitCode)"
            }

            # Move to final destination if robocopy used different name
            $tempDest = Join-Path $destDir $sourceFile
            if ($tempDest -ne $Destination) {
                Move-Item -Path $tempDest -Destination $Destination -Force
            }
        }
        else {
            # Simple copy
            Copy-Item -Path $UncPath -Destination $Destination -Force -ErrorAction Stop
        }

        # Verify copy
        if (Test-Path $Destination) {
            $fileSize = (Get-Item $Destination).Length
            Write-DeploymentLog "File copied successfully: $Destination ($([math]::Round($fileSize / 1MB, 2)) MB)" -Level Info
            return $true
        }
        else {
            Write-DeploymentLog "ERROR: File not created after copy" -Level Error
            return $false
        }
    }
    catch {
        Write-DeploymentLog "ERROR: SMB file download failed: $_" -Level Error
        return $false
    }
    finally {
        # Remove mapped drive if created
        if ($driveMapped -and $mappedDrive) {
            Write-DeploymentLog "Removing mapped network drive..." -Level Verbose
            Remove-PSDrive -Name $mappedDrive -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion SMB Functions

#endregion Embedded Functions

#region Main Script Logic

# Initialize deployment state for resource tracking
$DeploymentState = @{
    MountedImages = @()
    LoadedHives = @()
    TempPaths = @()
}

try {
    #region Initialization Phase
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Windows Deployment Automation" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Loading deployment configuration..." -ForegroundColor Yellow

    # Load configuration
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
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  Configuration Loading Failed!" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }

    # Initialize logging
    $logPath = if ($config.logging.logPath) { $config.logging.logPath } else { "X:\Deploy\Logs\Deployment" }
    $logLevel = if ($config.logging.logLevel) { $config.logging.logLevel } else { "Info" }

    Initialize-DeploymentLogging -LogPath $logPath -LogLevel $logLevel
    Write-DeploymentLog "========================================" -Level Info
    Write-DeploymentLog "Windows Deployment Script Started" -Level Info
    Write-DeploymentLog "========================================" -Level Info
    Write-DeploymentLog "Configuration: $ConfigPath" -Level Info
    Write-DeploymentLog "Deployment: $($config.deploymentInfo.name) v$($config.deploymentInfo.version)" -Level Info
    Write-DeploymentLog "Description: $($config.deploymentInfo.description)" -Level Info
    #endregion

    #region Validation Phase
    Write-DeploymentLog "===== VALIDATION PHASE =====" -Level Info
    Show-DeploymentStatus -CurrentPhase "Validation" -PercentComplete 5

    # Validate WinPE environment
    Write-DeploymentLog "Validating WinPE/RE environment..." -Level Info
    $envValidation = Test-WinPEEnvironment

    if (-not $envValidation.Passed) {
        $errorMsg = "Environment validation failed: " + ($envValidation.Issues -join "; ")
        Write-DeploymentLog $errorMsg -Level Error
        throw $errorMsg
    }

    Write-DeploymentLog "Environment validation passed" -Level Info
    Write-DeploymentLog "  WinPE: $($envValidation.IsWinPE)" -Level Info
    Write-DeploymentLog "  UEFI: $($envValidation.IsUEFI)" -Level Info
    Write-DeploymentLog "  PowerShell: $($envValidation.PowerShellVersion)" -Level Info
    Write-DeploymentLog "  RAM: $($envValidation.AvailableRAM_GB) GB" -Level Info

    # Validate Windows 11 hardware compatibility
    Write-Host ""
    Write-Host "Checking Windows 11 hardware requirements..." -ForegroundColor Cyan
    Test-Windows11Compatibility
    Write-Host ""

    # Validate configuration structure
    Write-DeploymentLog "Validating configuration structure..." -Level Info
    $configValidation = Test-DeploymentConfig -ConfigPath $ConfigPath

    if (-not $configValidation.Passed) {
        $errorMsg = "Configuration validation failed: " + ($configValidation.Issues -join "; ")
        Write-DeploymentLog $errorMsg -Level Error
        throw $errorMsg
    }

    Write-DeploymentLog "Configuration validation passed" -Level Info

    # Validate disk requirements
    $diskNumber = $config.diskConfiguration.diskNumber
    Write-DeploymentLog "Validating target disk $diskNumber..." -Level Info
    $diskValidation = Test-DiskRequirements -DiskNumber $diskNumber

    if (-not $diskValidation.Passed) {
        $errorMsg = "Disk validation failed: " + ($diskValidation.Issues -join "; ")
        Write-DeploymentLog $errorMsg -Level Error
        throw $errorMsg
    }

    Write-DeploymentLog "Disk validation passed" -Level Info
    Write-DeploymentLog "  Disk $diskNumber : $($diskValidation.SizeGB) GB" -Level Info

    # Validate network connectivity if using Azure
    $imageLocation = if ($config.imageSource.location.blobUrl) { $config.imageSource.location.blobUrl } else { $config.imageSource.location.localPath }
    if ($imageLocation -like "https://*") {
        Write-DeploymentLog "Validating network connectivity..." -Level Info
        $networkValidation = Test-NetworkConnectivity

        if (-not $networkValidation) {
            throw "Network connectivity test failed - cannot download from Azure"
        }

        Write-DeploymentLog "Network connectivity validated" -Level Info
    }

    Write-DeploymentLog "All validations passed successfully" -Level Info
    #endregion

    #region Image Acquisition Phase
    Write-DeploymentLog "===== IMAGE ACQUISITION PHASE =====" -Level Info
    Show-DeploymentStatus -CurrentPhase "Image Download" -PercentComplete 15

    # Detect image type from file extension
    $imageExtension = [System.IO.Path]::GetExtension($imageLocation).ToLower()

    $deploymentMode = switch ($imageExtension) {
        ".iso" { "ISO" }
        ".ffu" { "FFU" }
        ".wim" { "WIM" }
        default { throw "Unsupported image type: $imageExtension" }
    }

    Write-DeploymentLog "Detected deployment mode: $deploymentMode" -Level Info

    # Create temp directory for image download and validation
    $tempDir = Get-TemporaryPath -Prefix "DeploymentImage"
    $DeploymentState.TempPaths += $tempDir

    $imagePath = Join-Path $tempDir ([System.IO.Path]::GetFileName($imageLocation))
    $imageFileName = [System.IO.Path]::GetFileName($imageLocation)
    $catalogFileName = $imageFileName -replace '\.(iso|wim|ffu)$', '.cat'
    $catalogFile = Join-Path $tempDir $catalogFileName

    # =====================================================================
    # PHASE 1: Catalog Download and Signature Validation (BEFORE image)
    # =====================================================================

    if ($config.imageValidation -and $config.imageValidation.enabled) {
        Write-DeploymentLog "" -Level Info
        Write-DeploymentLog "========================================" -Level Info
        Write-DeploymentLog "  Pre-validating Catalog Signature" -Level Info
        Write-DeploymentLog "========================================" -Level Info
        Write-DeploymentLog "" -Level Info

        # Derive catalog URL
        $catalogUrl = $config.imageValidation.catalogUrl
        if (-not $catalogUrl) {
            $catalogUrl = $imageLocation -replace '\.(iso|wim|ffu)$', '.cat'
            Write-DeploymentLog "Auto-discovered catalog URL: $catalogUrl" -Level Verbose
        }

        Write-DeploymentLog "Downloading catalog for signature verification..." -Level Info
        Write-DeploymentLog "  Catalog URL: $catalogUrl" -Level Verbose

        # Download catalog based on source type
        try {
            if ($config.imageSource.location.blobUrl) {
                # Azure Blob download
                if ($config.imageSource.location.authType -eq "SAS") {
                    Get-AzureBlobWithSAS -BlobUrl $catalogUrl `
                                        -SasToken $config.imageSource.location.sasToken `
                                        -Destination $catalogFile `
                                        -ShowProgress:$false
                }
                else {
                    Get-AzureBlobAnonymous -BlobUrl $catalogUrl `
                                          -Destination $catalogFile `
                                          -ShowProgress:$false
                }
            }
            elseif ($config.imageSource.location.uncPath) {
                # SMB download
                $securePassword = $null
                if ($config.imageSource.location.password) {
                    $securePassword = ConvertTo-SecureString -String $config.imageSource.location.password -AsPlainText -Force
                }

                if ($config.imageSource.location.username -and $securePassword) {
                    Get-SMBFile -UncPath $catalogUrl `
                               -Destination $catalogFile `
                               -Username $config.imageSource.location.username `
                               -Password $securePassword `
                               -ShowProgress:$false
                }
                else {
                    Get-SMBFile -UncPath $catalogUrl `
                               -Destination $catalogFile `
                               -ShowProgress:$false
                }
            }
            elseif ($config.imageSource.location.localPath) {
                # Local file copy
                if (Test-Path $catalogUrl) {
                    Copy-Item -Path $catalogUrl -Destination $catalogFile -Force
                }
                else {
                    throw "Local catalog file not found: $catalogUrl"
                }
            }
        }
        catch {
            throw "Failed to download catalog: $($_.Exception.Message)"
        }

        if (-not (Test-Path $catalogFile)) {
            throw "Catalog file not found at: $catalogUrl. Image validation is required."
        }

        Write-DeploymentLog "Catalog downloaded successfully" -Level Info

        # Validate catalog signature
        if ($config.imageValidation.enableSignatureCheck) {
            Write-DeploymentLog "Verifying catalog signature..." -Level Info

            $catalogSignature = Get-AuthenticodeSignature -FilePath $catalogFile -ErrorAction Stop

            if ($catalogSignature.Status -ne "Valid") {
                throw "Catalog signature invalid: $($catalogSignature.Status). Image download aborted."
            }

            # Verify trusted publisher
            $signerCert = $catalogSignature.SignerCertificate
            $isTrusted = $false

            foreach ($publisher in $config.imageValidation.trustedPublishers) {
                if ($publisher -match '^Thumbprint:(.+)$') {
                    if ($signerCert.Thumbprint -eq $matches[1]) {
                        $isTrusted = $true
                        Write-DeploymentLog "Catalog signed by trusted thumbprint" -Level Verbose
                        break
                    }
                }
                elseif ($publisher -match '^CN:(.+)$') {
                    if ($signerCert.Subject -like "*CN=$($matches[1])*") {
                        $isTrusted = $true
                        Write-DeploymentLog "Catalog signed by trusted CN: $($matches[1])" -Level Verbose
                        break
                    }
                }
            }

            if (-not $isTrusted) {
                throw "Catalog signer not in trusted publishers list. Image download aborted.`n  Signer: $($signerCert.Subject)"
            }

            Write-DeploymentLog "Catalog signature validated successfully" -Level Info
        }

        Write-DeploymentLog "Catalog validated - proceeding with image download..." -Level Info
        Write-DeploymentLog "" -Level Info
    }

    # =====================================================================
    # PHASE 2: Image Download (AFTER catalog validation)
    # =====================================================================

    Write-DeploymentLog "Acquiring image: $imageLocation" -Level Info

    if ($config.imageSource.location.blobUrl) {
        # Azure Blob download
        $authType = $config.imageSource.location.authType
        $sasToken = $config.imageSource.location.sasToken

        Write-DeploymentLog "Source type: Azure Blob Storage" -Level Info
        Write-DeploymentLog "  Auth Type: $authType" -Level Info

        if ($authType -eq "SAS") {
            Get-AzureBlobWithSAS -BlobUrl $imageLocation -SasToken $sasToken -Destination $imagePath -ShowProgress
        }
        else {
            Get-AzureBlobAnonymous -BlobUrl $imageLocation -Destination $imagePath -ShowProgress
        }
    }
    elseif ($config.imageSource.location.uncPath) {
        # SMB/UNC path
        Write-DeploymentLog "Source type: SMB/Network Share" -Level Info

        # Convert password to SecureString if provided
        $securePassword = $null
        if ($config.imageSource.location.password) {
            $securePassword = ConvertTo-SecureString -String $config.imageSource.location.password -AsPlainText -Force
        }

        if ($config.imageSource.location.username -and $securePassword) {
            Write-DeploymentLog "  Using credentials: $($config.imageSource.location.username)" -Level Info
            Get-SMBFile -UncPath $imageLocation -Destination $imagePath -Username $config.imageSource.location.username -Password $securePassword -ShowProgress
        }
        else {
            Write-DeploymentLog "  Using current user context (no credentials provided)" -Level Info
            Get-SMBFile -UncPath $imageLocation -Destination $imagePath -ShowProgress
        }
    }
    else {
        # Local path
        Write-DeploymentLog "Source type: Local file path" -Level Info
        Copy-Item -Path $imageLocation -Destination $imagePath -Force
    }

    if (-not (Test-Path $imagePath)) {
        throw "Failed to acquire image file"
    }

    Write-DeploymentLog "Image acquired successfully: $imagePath" -Level Info
    $imageSize = (Get-Item $imagePath).Length / 1GB
    Write-DeploymentLog "Image size: $([math]::Round($imageSize, 2)) GB" -Level Info

    # =====================================================================
    # PHASE 3: Validate Image Against Catalog
    # =====================================================================

    if ($config.imageValidation -and $config.imageValidation.enabled) {
        Write-DeploymentLog "Validating image against catalog..." -Level Info

        $catalogResult = Test-FileCatalog -Path $imagePath `
                                         -CatalogFilePath $catalogFile `
                                         -Detailed `
                                         -ErrorAction Stop

        if ($catalogResult.Status -ne "Valid") {
            Write-DeploymentLog "Image catalog validation FAILED: $($catalogResult.Status)" -Level Error

            # Show validation details
            if ($catalogResult.CatalogItems) {
                foreach ($item in $catalogResult.CatalogItems) {
                    if ($item.Status -ne "Valid") {
                        Write-DeploymentLog "  Invalid: $($item.FileName) - $($item.Status)" -Level Error
                    }
                }
            }

            throw "Image validation against catalog FAILED"
        }

        Write-DeploymentLog "Image catalog validation PASSED" -Level Info

        # Cleanup catalog file
        if (Test-Path $catalogFile) {
            Remove-Item $catalogFile -Force -ErrorAction SilentlyContinue
        }
    }

    #endregion

    #region Disk Preparation Phase
    Write-DeploymentLog "===== DISK PREPARATION PHASE =====" -Level Info
    Show-DeploymentStatus -CurrentPhase "Disk Preparation" -PercentComplete 25

    $disk = Get-Disk -Number $diskNumber

    # Clean disk if requested
    if ($config.diskConfiguration.cleanDisk) {
        Write-DeploymentLog "Cleaning disk $diskNumber..." -Level Info
        Write-DeploymentLog "WARNING: All data on disk $diskNumber will be destroyed!" -Level Warning

        Clear-Disk -Number $diskNumber -RemoveData -RemoveOEM -Confirm:$false
        Write-DeploymentLog "Disk cleaned successfully" -Level Info
    }

    # Initialize as GPT
    Write-DeploymentLog "Initializing disk as GPT..." -Level Info
    Initialize-Disk -Number $diskNumber -PartitionStyle GPT -Confirm:$false
    Write-DeploymentLog "Disk initialized as GPT" -Level Info

    # Get partition sizes from config
    $efiSize = if ($config.diskConfiguration.partitions.efiSize) { $config.diskConfiguration.partitions.efiSize } else { 100 }
    $msrSize = if ($config.diskConfiguration.partitions.msrSize) { $config.diskConfiguration.partitions.msrSize } else { 16 }
    $recoverySize = if ($config.diskConfiguration.partitions.recoverySize) { $config.diskConfiguration.partitions.recoverySize } else { 1024 }

    Write-DeploymentLog "Partition sizes (MB): EFI=$efiSize, MSR=$msrSize, Recovery=$recoverySize" -Level Info

    # Calculate Windows partition size (Total - EFI - MSR - Recovery)
    $diskSizeMB = ($disk.Size / 1MB)
    $windowsSize = $diskSizeMB - $efiSize - $msrSize - $recoverySize - 100  # 100MB buffer

    Write-DeploymentLog "Creating GPT partition layout (Recovery at END)..." -Level Info

    # Create EFI System Partition (100MB)
    Write-DeploymentLog "Creating EFI System Partition ($efiSize MB)..." -Level Info
    $efiPartition = New-Partition -DiskNumber $diskNumber -Size ($efiSize * 1MB) -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $efiPartition | Format-Volume -FileSystem FAT32 -NewFileSystemLabel "System" -Confirm:$false | Out-Null
    $efiPartition | Set-Partition -NewDriveLetter S
    Write-DeploymentLog "EFI partition created: S:" -Level Info

    # Create MSR Partition (16MB)
    Write-DeploymentLog "Creating MSR Partition ($msrSize MB)..." -Level Info
    New-Partition -DiskNumber $diskNumber -Size ($msrSize * 1MB) -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
    Write-DeploymentLog "MSR partition created" -Level Info

    # Create Windows Partition (calculated size)
    Write-DeploymentLog "Creating Windows Partition ($([math]::Round($windowsSize / 1024, 2)) GB)..." -Level Info
    $windowsPartition = New-Partition -DiskNumber $diskNumber -Size ($windowsSize * 1MB) -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
    $windowsPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows" -Confirm:$false | Out-Null
    $windowsPartition | Set-Partition -NewDriveLetter W
    Write-DeploymentLog "Windows partition created: W:" -Level Info

    # Create Recovery Partition at END (1GB)
    Write-DeploymentLog "Creating Recovery Partition at END ($recoverySize MB)..." -Level Info
    $recoveryPartition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
    $recoveryPartition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "Recovery" -Confirm:$false | Out-Null
    $recoveryPartition | Set-Partition -NewDriveLetter R
    Write-DeploymentLog "Recovery partition created: R:" -Level Info

    Write-DeploymentLog "Partition layout created successfully" -Level Info
    Write-DeploymentLog "  EFI (S:) : $efiSize MB" -Level Info
    Write-DeploymentLog "  MSR      : $msrSize MB" -Level Info
    Write-DeploymentLog "  Windows (W:) : $([math]::Round($windowsSize / 1024, 2)) GB" -Level Info
    Write-DeploymentLog "  Recovery (R:) : $recoverySize MB (at END)" -Level Info
    #endregion

    #region Image Installation Phase
    Write-DeploymentLog "===== IMAGE INSTALLATION PHASE =====" -Level Info
    Write-DeploymentLog "Deployment mode: $deploymentMode" -Level Info

    if ($deploymentMode -eq "ISO") {
        Show-DeploymentStatus -CurrentPhase "Installing Windows (ISO)" -PercentComplete 35

        Write-DeploymentLog "Mounting ISO image..." -Level Info
        $mountedISO = Mount-DiskImage -ImagePath $imagePath -PassThru
        $DeploymentState.MountedImages += $imagePath
        $isoDrive = ($mountedISO | Get-Volume).DriveLetter

        Write-DeploymentLog "ISO mounted at drive $isoDrive`:" -Level Info

        # Locate Windows image in ISO
        $installWim = Join-Path "$isoDrive`:" "sources\install.wim"
        $installEsd = Join-Path "$isoDrive`:" "sources\install.esd"

        if (Test-Path $installWim) {
            $sourceImage = $installWim
            Write-DeploymentLog "Found install.wim" -Level Info
        }
        elseif (Test-Path $installEsd) {
            $sourceImage = $installEsd
            Write-DeploymentLog "Found install.esd" -Level Info
        }
        else {
            throw "No install.wim or install.esd found in ISO"
        }

        # Get image index from config
        $imageIndex = if ($config.imageSource.imageIndex) { $config.imageSource.imageIndex } else { 1 }

        Write-DeploymentLog "Applying Windows image (index $imageIndex) to W:\" -Level Info
        Write-DeploymentLog "This may take 10-30 minutes depending on image size..." -Level Info

        # Apply image using DISM
        $dismArgs = @(
            "/Apply-Image",
            "/ImageFile:`"$sourceImage`"",
            "/Index:$imageIndex",
            "/ApplyDir:W:\"
        )

        $dismProcess = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru

        if ($dismProcess.ExitCode -ne 0) {
            throw "DISM failed to apply image. Exit code: $($dismProcess.ExitCode)"
        }

        Write-DeploymentLog "Windows image applied successfully" -Level Info

        # Configure bootloader
        Write-DeploymentLog "Configuring UEFI bootloader..." -Level Info
        $bcdbootArgs = "W:\Windows /s S: /f UEFI"
        $bcdbootResult = Start-Process -FilePath "bcdboot.exe" -ArgumentList $bcdbootArgs -Wait -NoNewWindow -PassThru

        if ($bcdbootResult.ExitCode -ne 0) {
            throw "BCDBoot failed. Exit code: $($bcdbootResult.ExitCode)"
        }

        Write-DeploymentLog "Bootloader configured successfully" -Level Info

        # Dismount ISO
        Write-DeploymentLog "Dismounting ISO..." -Level Info
        Dismount-DiskImage -ImagePath $imagePath | Out-Null
        $DeploymentState.MountedImages = $DeploymentState.MountedImages | Where-Object { $_ -ne $imagePath }
        Write-DeploymentLog "ISO dismounted" -Level Info
    }
    elseif ($deploymentMode -eq "FFU") {
        Write-DeploymentLog "FFU deployment mode detected" -Level Warning
        Write-DeploymentLog "FFU deployment is not yet implemented" -Level Error
        throw "FFU deployment mode is not yet implemented. Please use ISO or WIM format."
    }
    elseif ($deploymentMode -eq "WIM") {
        Show-DeploymentStatus -CurrentPhase "Installing Windows (WIM)" -PercentComplete 35

        $imageIndex = if ($config.imageSource.imageIndex) { $config.imageSource.imageIndex } else { 1 }

        Write-DeploymentLog "Applying Windows image (index $imageIndex) to W:\" -Level Info

        $dismArgs = @(
            "/Apply-Image",
            "/ImageFile:`"$imagePath`"",
            "/Index:$imageIndex",
            "/ApplyDir:W:\"
        )

        $dismProcess = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru

        if ($dismProcess.ExitCode -ne 0) {
            throw "DISM failed to apply WIM. Exit code: $($dismProcess.ExitCode)"
        }

        Write-DeploymentLog "Windows image applied successfully" -Level Info

        # Configure bootloader
        Write-DeploymentLog "Configuring UEFI bootloader..." -Level Info
        $bcdbootResult = Start-Process -FilePath "bcdboot.exe" -ArgumentList "W:\Windows /s S: /f UEFI" -Wait -NoNewWindow -PassThru

        if ($bcdbootResult.ExitCode -ne 0) {
            throw "BCDBoot failed. Exit code: $($bcdbootResult.ExitCode)"
        }

        Write-DeploymentLog "Bootloader configured successfully" -Level Info
    }
    #endregion

    #region Customization Phase
    Write-DeploymentLog "===== CUSTOMIZATION PHASE =====" -Level Info

    # Driver Injection
    if ($config.customization.drivers.enabled) {
        Show-DeploymentStatus -CurrentPhase "Injecting Drivers" -PercentComplete 65
        Write-DeploymentLog "Driver injection enabled" -Level Info

        foreach ($driverSource in $config.customization.drivers.sources) {
            Write-DeploymentLog "Processing driver source: $($driverSource.path)" -Level Info

            $driverTempPath = Join-Path $tempDir "Drivers_$(New-Guid)"
            $DeploymentState.TempPaths += $driverTempPath
            New-Item -Path $driverTempPath -ItemType Directory -Force | Out-Null

            # Download or copy driver package
            if ($driverSource.path -like "https://*") {
                $driverZip = Join-Path $driverTempPath "drivers.zip"

                if ($driverSource.authType -eq "SAS") {
                    Get-AzureBlobWithSAS -BlobUrl $driverSource.path -SasToken $config.imageSource.location.sasToken -Destination $driverZip -ShowProgress
                }
                else {
                    Get-AzureBlobAnonymous -BlobUrl $driverSource.path -Destination $driverZip -ShowProgress
                }

                # Extract drivers
                Expand-Archive -Path $driverZip -DestinationPath $driverTempPath -Force
            }
            else {
                Copy-Item -Path $driverSource.path -Destination $driverTempPath -Recurse -Force
            }

            # Inject drivers
            if ($config.customization.drivers.injectionMethod -eq "Offline") {
                Write-DeploymentLog "Injecting drivers offline with DISM..." -Level Info

                $dismArgs = "/Image:W:\ /Add-Driver /Driver:`"$driverTempPath`""
                if ($driverSource.recursive) {
                    $dismArgs += " /Recurse"
                }

                $dismProcess = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru

                if ($dismProcess.ExitCode -eq 0) {
                    Write-DeploymentLog "Drivers injected successfully" -Level Info
                }
                else {
                    Write-DeploymentLog "Driver injection completed with warnings or errors (Exit code: $($dismProcess.ExitCode))" -Level Warning
                }
            }
            else {
                Write-DeploymentLog "Copying drivers to image for Unattend.xml injection..." -Level Info
                $driverDestPath = "W:\Drivers"
                Copy-Item -Path $driverTempPath -Destination $driverDestPath -Recurse -Force
                Write-DeploymentLog "Drivers copied to: $driverDestPath" -Level Info
            }
        }
    }

    # Registry Modifications
    if ($config.customization.registry.enabled) {
        Show-DeploymentStatus -CurrentPhase "Applying Registry Modifications" -PercentComplete 75
        Write-DeploymentLog "Registry modifications enabled" -Level Info

        foreach ($regMod in $config.customization.registry.modifications) {
            Write-DeploymentLog "Applying registry modification: $($regMod.hive)\$($regMod.path)\$($regMod.name)" -Level Info

            # Determine which hive to load
            $hiveName = "DEPLOYER_" + ($regMod.hive -replace "HKLM\\", "")
            $hiveFile = switch -Regex ($regMod.hive) {
                "HKLM\\SOFTWARE" { "W:\Windows\System32\config\SOFTWARE" }
                "HKLM\\SYSTEM" { "W:\Windows\System32\config\SYSTEM" }
                "HKU\\DEFAULT" { "W:\Windows\System32\config\DEFAULT" }
                default { throw "Unsupported registry hive: $($regMod.hive)" }
            }

            # Load hive if not already loaded
            if ($hiveName -notin $DeploymentState.LoadedHives) {
                Write-DeploymentLog "Loading registry hive: $hiveName from $hiveFile" -Level Info
                $regLoadResult = Start-Process -FilePath "reg.exe" -ArgumentList "load `"HKLM\$hiveName`" `"$hiveFile`"" -Wait -NoNewWindow -PassThru

                if ($regLoadResult.ExitCode -ne 0) {
                    Write-DeploymentLog "Failed to load hive (exit code: $($regLoadResult.ExitCode))" -Level Warning
                    continue
                }

                $DeploymentState.LoadedHives += $hiveName
            }

            # Apply registry modification
            $regPath = "HKLM:\$hiveName\" + ($regMod.path -replace "$($regMod.hive)\\", "")

            # Create path if it doesn't exist
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }

            # Set value
            $regType = switch ($regMod.type) {
                "String" { "String" }
                "DWord" { "DWord" }
                "QWord" { "QWord" }
                "Binary" { "Binary" }
                default { "String" }
            }

            Set-ItemProperty -Path $regPath -Name $regMod.name -Value $regMod.value -Type $regType -Force
            Write-DeploymentLog "Registry value set successfully" -Level Info
        }

        # Unload all registry hives
        foreach ($hiveName in $DeploymentState.LoadedHives) {
            Write-DeploymentLog "Unloading registry hive: $hiveName" -Level Info
            Start-Process -FilePath "reg.exe" -ArgumentList "unload `"HKLM\$hiveName`"" -Wait -NoNewWindow | Out-Null
        }

        $DeploymentState.LoadedHives = @()
        Write-DeploymentLog "All registry hives unloaded" -Level Info
    }

    # File Copy Operations
    if ($config.customization.files.enabled) {
        Show-DeploymentStatus -CurrentPhase "Copying Files" -PercentComplete 80
        Write-DeploymentLog "File copy operations enabled" -Level Info

        foreach ($fileOp in $config.customization.files.copyOperations) {
            Write-DeploymentLog "Copying file: $($fileOp.source) -> $($fileOp.destination)" -Level Info

            $destPath = Join-Path "W:\" $fileOp.destination
            $destDir = Split-Path -Path $destPath -Parent

            # Create destination directory
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }

            # Download or copy file
            if ($fileOp.source -like "https://*") {
                if ($fileOp.authType -eq "SAS") {
                    Get-AzureBlobWithSAS -BlobUrl $fileOp.source -SasToken $config.imageSource.location.sasToken -Destination $destPath -ShowProgress
                }
                else {
                    Get-AzureBlobAnonymous -BlobUrl $fileOp.source -Destination $destPath -ShowProgress
                }
            }
            else {
                Copy-Item -Path $fileOp.source -Destination $destPath -Force:$fileOp.overwrite
            }

            Write-DeploymentLog "File copied successfully" -Level Info
        }
    }

    # Windows Autopilot
    if ($config.customization.autopilot.enabled) {
        Show-DeploymentStatus -CurrentPhase "Configuring Autopilot" -PercentComplete 85
        Write-DeploymentLog "Windows Autopilot configuration enabled" -Level Info

        $autopilotDir = "W:\Windows\Provisioning\Autopilot"
        if (-not (Test-Path $autopilotDir)) {
            New-Item -Path $autopilotDir -ItemType Directory -Force | Out-Null
        }

        $autopilotFile = Join-Path $autopilotDir "AutopilotConfigurationFile.json"

        # Download Autopilot config
        if ($config.customization.autopilot.configurationFile -like "https://*") {
            if ($config.customization.autopilot.authType -eq "SAS") {
                Get-AzureBlobWithSAS -BlobUrl $config.customization.autopilot.configurationFile -SasToken $config.imageSource.location.sasToken -Destination $autopilotFile
            }
            else {
                Get-AzureBlobAnonymous -BlobUrl $config.customization.autopilot.configurationFile -Destination $autopilotFile
            }
        }
        else {
            Copy-Item -Path $config.customization.autopilot.configurationFile -Destination $autopilotFile -Force
        }

        Write-DeploymentLog "Autopilot configuration applied: $autopilotFile" -Level Info
    }

    # Unattend.xml
    if ($config.customization.unattend.enabled) {
        Show-DeploymentStatus -CurrentPhase "Applying Unattend.xml" -PercentComplete 90
        Write-DeploymentLog "Unattend.xml configuration enabled" -Level Info

        $unattendDir = "W:\Windows\Panther"
        if (-not (Test-Path $unattendDir)) {
            New-Item -Path $unattendDir -ItemType Directory -Force | Out-Null
        }

        $unattendFile = Join-Path $unattendDir "unattend.xml"

        # Download Unattend.xml
        if ($config.customization.unattend.unattendFile -like "https://*") {
            if ($config.customization.unattend.authType -eq "SAS") {
                Get-AzureBlobWithSAS -BlobUrl $config.customization.unattend.unattendFile -SasToken $config.imageSource.location.sasToken -Destination $unattendFile
            }
            else {
                Get-AzureBlobAnonymous -BlobUrl $config.customization.unattend.unattendFile -Destination $unattendFile
            }
        }
        else {
            Copy-Item -Path $config.customization.unattend.unattendFile -Destination $unattendFile -Force
        }

        Write-DeploymentLog "Unattend.xml applied: $unattendFile" -Level Info
    }
    #endregion

    #region Finalization Phase
    Write-DeploymentLog "===== FINALIZATION PHASE =====" -Level Info
    Show-DeploymentStatus -CurrentPhase "Finalizing Deployment" -PercentComplete 95

    # Copy deployment logs to image
    if ($config.logging.copyLogsToImage) {
        Write-DeploymentLog "Copying deployment logs to image..." -Level Info
        Copy-DeploymentLogsToImage -ImagePath "W:\" -LogPath $logPath
    }

    Write-DeploymentLog "Deployment finalized successfully" -Level Info
    #endregion

    #region Completion
    Write-DeploymentLog "========================================" -Level Info
    Write-DeploymentLog "DEPLOYMENT COMPLETED SUCCESSFULLY" -Level Info
    Write-DeploymentLog "========================================" -Level Info

    Show-DeploymentStatus -CurrentPhase "Complete" -PercentComplete 100

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Deployment Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Deployment: $($config.deploymentInfo.name) v$($config.deploymentInfo.version)" -ForegroundColor Cyan
    Write-Host "Target Disk: Disk $diskNumber" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Partitions Created:" -ForegroundColor Yellow
    Write-Host "  S: - EFI System ($efiSize MB)" -ForegroundColor White
    Write-Host "  W: - Windows ($([math]::Round($windowsSize / 1024, 2)) GB)" -ForegroundColor White
    Write-Host "  R: - Recovery ($recoverySize MB) - at END" -ForegroundColor White
    Write-Host ""
    Write-Host "You may now remove the installation media and reboot." -ForegroundColor Yellow
    Write-Host ""

    exit 0
    #endregion
}
catch {
    Write-DeploymentLog "========================================" -Level Error
    Write-DeploymentLog "DEPLOYMENT FAILED" -Level Error
    Write-DeploymentLog "========================================" -Level Error
    Write-DeploymentLog "Error: $($_.Exception.Message)" -Level Error
    Write-DeploymentLog "Stack trace: $($_.ScriptStackTrace)" -Level Error

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Deployment Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Check the log file for details:" -ForegroundColor Yellow
    Write-Host "  $logPath" -ForegroundColor White
    Write-Host ""

    Show-DeploymentError -ErrorMessage $_.Exception.Message -AdditionalInfo "Check logs at: $logPath"

    exit 1
}
finally {
    # Cleanup resources
    Write-DeploymentLog "Cleaning up deployment resources..." -Level Info
    Invoke-CleanupDeployment -State $DeploymentState
    Write-DeploymentLog "Cleanup complete" -Level Info
}

#endregion Main Script Logic
