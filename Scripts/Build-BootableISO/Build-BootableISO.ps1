#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Bootable ISO builder with embedded functions

.DESCRIPTION
    Self-contained ISO builder for code signing compatibility.
    All function libraries are embedded in this file.

    Functions included:
    - Utility-Functions: Logging, resource management, UI

.NOTES
    This is a consolidated version for code signing.
    Original modular version: Scripts/Build-BootableISO.ps1

.PARAMETER Architecture
    Target architecture: amd64, x86, or arm64 (default: amd64)

.PARAMETER OutputPath
    Path where the ISO file will be created (default: Build/WinPE_Deployer.iso)

.PARAMETER WorkingDirectory
    Temporary build directory (default: Build/WinPE_Build)

.PARAMETER UseWinRE
    Use WinRE as base instead of WinPE (includes wireless support)

.PARAMETER WinREISOPath
    Path to Windows ISO to extract WinRE from (alternative to local WinRE)

.PARAMETER IncludeScripts
    Embed deployment scripts in the ISO

.PARAMETER IncludeConfigs
    Embed example configuration files in the ISO

.PARAMETER EnableWireless
    Add wireless support DLLs (for WinPE 1607+)

.PARAMETER WirelessProfiles
    Path to directory containing exported wireless XML profiles

.PARAMETER CustomPackages
    Array of optional package names to add (e.g., "WinPE-PowerShell", "WinPE-DismCmdlets")

.PARAMETER CustomDrivers
    Path to directory containing drivers to inject

.EXAMPLE
    .\Build-BootableISO.ps1 -UseWinRE -IncludeScripts -IncludeConfigs

.EXAMPLE
    .\Build-BootableISO.ps1 -WinREISOPath "C:\ISOs\Win11.iso" -EnableWireless -IncludeScripts
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("amd64", "x86", "arm64")]
    [string]$Architecture = "amd64",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "Build\WinPE_Deployer.iso",

    [Parameter(Mandatory = $false)]
    [string]$WorkingDirectory = "Build\WinPE_Build",

    [Parameter(Mandatory = $false)]
    [switch]$UseWinRE,

    [Parameter(Mandatory = $false)]
    [string]$WinREISOPath,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeScripts,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeConfigs,

    [Parameter(Mandatory = $false)]
    [switch]$EnableWireless,

    [Parameter(Mandatory = $false)]
    [string]$WirelessProfiles,

    [Parameter(Mandatory = $false)]
    [string[]]$CustomPackages,

    [Parameter(Mandatory = $false)]
    [string]$CustomDrivers,

    [Parameter(Mandatory = $false)]
    [switch]$PAK
)

# Get script root
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
# Script is in Scripts/Build-BootableISO/, need to go up two levels to project root
$ProjectRoot = Split-Path (Split-Path $ScriptRoot -Parent) -Parent

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

    # Clear screen
    Clear-Host

    # Display header
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
    .PARAMETER LogPath
        Path to log file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $script:LogConfig.LogPath
    )

    Clear-Host
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "    Deployment Error Occurred          " -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: " -NoNewline
    Write-Host $ErrorMessage -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Log file: $LogPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  [R] Retry deployment"
    Write-Host "  [L] View log file"
    Write-Host "  [E] Exit to command prompt"
    Write-Host ""

    $choice = Read-Host "Select an option"

    switch ($choice.ToUpper()) {
        'R' { return 'Retry' }
        'L' {
            if (Test-Path $LogPath) {
                Get-Content $LogPath | Out-Host -Paging
            }
            else {
                Write-Host "Log file not found: $LogPath" -ForegroundColor Red
                Start-Sleep -Seconds 3
            }
            return 'ViewLog'
        }
        'E' { return 'Exit' }
        default { return 'Exit' }
    }
}

# Cleanup deployment resources
function Invoke-CleanupDeployment {
    <#
    .SYNOPSIS
        Clean up deployment resources (mounted images, loaded hives, temp files)
    .PARAMETER DeploymentState
        Hashtable tracking deployment state
    .PARAMETER PreserveLogsOnly
        Only preserve log files, remove everything else
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$DeploymentState,

        [Parameter(Mandatory = $false)]
        [switch]$PreserveLogsOnly
    )

    Write-DeploymentLog "Starting deployment cleanup..." -Level Info

    # Dismount any mounted images
    if ($DeploymentState -and $DeploymentState.MountedImages) {
        foreach ($mount in $DeploymentState.MountedImages) {
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
    if ($DeploymentState -and $DeploymentState.LoadedHives) {
        foreach ($hive in $DeploymentState.LoadedHives) {
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
    if ($DeploymentState -and $DeploymentState.TempPaths) {
        foreach ($tempPath in $DeploymentState.TempPaths) {
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

#endregion Embedded Functions

#region Main Script Logic

# Initialize logging
$logPath = Join-Path $ProjectRoot "Build\Logs"
Initialize-DeploymentLogging -LogPath $logPath -LogLevel "Info"

# Function to clean up leftover mounts from previous runs
function Invoke-StartupCleanup {
    param(
        [string]$WorkingPath
    )

    Write-DeploymentLog "Checking for leftover mounts from previous runs..." -Level Info

    # Check for DISM mounted images
    try {
        $mountedImages = @(Get-WindowsImage -Mounted -ErrorAction SilentlyContinue)

        foreach ($image in $mountedImages) {
            $mountPath = $image.MountPath

            # Check if this mount is within our working directory
            if ($mountPath -like "$WorkingPath*") {
                Write-DeploymentLog "Found DISM mount at: $mountPath" -Level Warning
                Write-DeploymentLog "Unmounting DISM image..." -Level Info

                try {
                    Dismount-WindowsImage -Path $mountPath -Discard -ErrorAction Stop
                    Write-DeploymentLog "Successfully unmounted: $mountPath" -Level Info
                }
                catch {
                    Write-DeploymentLog "Failed to unmount $mountPath using Dismount-WindowsImage, trying DISM command..." -Level Warning

                    # Fallback to DISM command
                    dism.exe /Unmount-Image /MountDir:"$mountPath" /Discard
                    $dismExitCode = $LASTEXITCODE

                    if ($dismExitCode -eq 0) {
                        Write-DeploymentLog "Successfully unmounted using DISM: $mountPath" -Level Info
                    }
                    else {
                        Write-DeploymentLog "Warning: Failed to unmount $mountPath (Exit code: $dismExitCode)" -Level Warning
                    }
                }
            }
        }
    }
    catch {
        Write-DeploymentLog "Error checking for mounted images: $($_.Exception.Message)" -Level Warning
    }

    # Check for mounted ISOs (harder to detect specifically, but we can check common mount points)
    try {
        $mountedISOs = Get-DiskImage -ImagePath "*" -ErrorAction SilentlyContinue | Where-Object { $_.Attached -eq $true }

        foreach ($iso in $mountedISOs) {
            # Check if the ISO path suggests it might be related to our script
            $isoPath = $iso.ImagePath
            Write-DeploymentLog "Found mounted ISO: $isoPath" -Level Info
            Write-DeploymentLog "Note: Leaving ISO mounted as it may be in use" -Level Info
            # Don't automatically dismount ISOs as they might be intentionally mounted by user
        }
    }
    catch {
        Write-DeploymentLog "Error checking for mounted ISOs: $($_.Exception.Message)" -Level Warning
    }

    # Small delay to allow file handles to release
    Start-Sleep -Seconds 2
}

try {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Bootable ISO Builder" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check for administrator privileges (DISM requires elevation)
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  ADMINISTRATOR PRIVILEGES REQUIRED" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "This script must be run as Administrator to perform DISM operations." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please:" -ForegroundColor Yellow
        Write-Host "  1. Close this PowerShell window" -ForegroundColor Cyan
        Write-Host "  2. Right-click PowerShell" -ForegroundColor Cyan
        Write-Host "  3. Select 'Run as Administrator'" -ForegroundColor Cyan
        Write-Host "  4. Re-run the script" -ForegroundColor Cyan
        Write-Host ""
        Write-DeploymentLog "ERROR: Script not running as Administrator" -Level Error

        throw "Administrator privileges required. Please run PowerShell as Administrator."
    }

    Write-DeploymentLog "Administrator privileges confirmed" -Level Info
    Write-Host "  Running with administrator privileges" -ForegroundColor Green
    Write-Host ""

    Write-DeploymentLog "ISO Builder started" -Level Info
    Write-DeploymentLog "Architecture: $Architecture" -Level Info

    # Adjust default paths based on base image type if user didn't specify custom values
    $isWinREBuild = ($UseWinRE -or $WinREISOPath)

    if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
        # User didn't specify OutputPath, use intelligent default
        if ($isWinREBuild) {
            $OutputPath = "Build\WinRE_Deployer.iso"
        }
    }

    if (-not $PSBoundParameters.ContainsKey('WorkingDirectory')) {
        # User didn't specify WorkingDirectory, use intelligent default
        if ($isWinREBuild) {
            $WorkingDirectory = "Build\WinRE_Build"
        }
    }

    Write-DeploymentLog "Output: $OutputPath" -Level Info

    #region Early ISO Lock Detection
    Write-DeploymentLog "===== OUTPUT FILE VALIDATION =====" -Level Info

    # Determine full output path early
    $outputFullPath = Join-Path $ProjectRoot $OutputPath
    Write-DeploymentLog "Output file: $outputFullPath" -Level Info

    # Check if output file exists and is locked
    if (Test-Path $outputFullPath) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Existing ISO File Detected" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Output file already exists:" -ForegroundColor White
        Write-Host "  $outputFullPath" -ForegroundColor Cyan
        Write-Host ""

        $fileResolved = $false
        $attemptCount = 0
        $maxAttempts = 5

        while (-not $fileResolved -and $attemptCount -lt $maxAttempts) {
            try {
                # Try to delete the file to verify it's not locked
                Remove-Item -Path $outputFullPath -Force -ErrorAction Stop
                $fileResolved = $true
                Write-Host "  Existing ISO removed successfully" -ForegroundColor Green
                Write-DeploymentLog "Existing ISO removed successfully" -Level Info
            }
            catch {
                $attemptCount++

                # File is locked - prompt user
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  ISO FILE IS LOCKED" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "Cannot delete existing ISO file - it is in use by another program." -ForegroundColor Red
                Write-Host ""
                Write-Host "Common causes:" -ForegroundColor Yellow
                Write-Host "  - ISO mounted in a test VM (VirtualBox, VMware, Hyper-V)" -ForegroundColor Cyan
                Write-Host "  - File Explorer window viewing the file" -ForegroundColor Gray
                Write-Host "  - Windows Explorer preview pane" -ForegroundColor Gray
                Write-Host "  - Antivirus software scanning the file" -ForegroundColor Gray
                Write-Host ""
                Write-Host "Please:" -ForegroundColor Yellow
                Write-Host "  1. Shut down or dismount ISO from test VMs" -ForegroundColor Cyan
                Write-Host "  2. Close File Explorer preview pane" -ForegroundColor Cyan
                Write-Host "  3. Close any programs using the ISO" -ForegroundColor Cyan
                Write-Host ""

                if ($attemptCount -ge $maxAttempts) {
                    Write-Host "Maximum retry attempts ($maxAttempts) reached." -ForegroundColor Red
                    Write-Host ""
                    Write-DeploymentLog "Failed to resolve ISO lock after $maxAttempts attempts" -Level Error
                    throw "Could not delete existing ISO: File is locked. Please close all programs using the file and try again."
                }

                Write-Host "Press any key to retry (attempt $attemptCount/$maxAttempts)..." -ForegroundColor Green
                Write-Host "Or press Ctrl+C to abort the build." -ForegroundColor Gray
                Write-Host ""

                # Wait for user input
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

                Write-DeploymentLog "User retry attempt $attemptCount/$maxAttempts" -Level Info
                Write-Host "Retrying..." -ForegroundColor Yellow
                Write-Host ""
            }
        }
    }
    else {
        Write-DeploymentLog "Output file does not exist - will create new ISO" -Level Info
    }

    Write-Host ""
    #endregion

    #region Prerequisites Validation
    Write-DeploymentLog "===== PREREQUISITES VALIDATION =====" -Level Info
    Write-Host "Validating prerequisites..." -ForegroundColor Yellow

    # Check for Windows ADK
    $adkPath = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit"
    if (-not (Test-Path $adkPath)) {
        throw "Windows ADK not found at: $adkPath"
    }

    Write-DeploymentLog "Windows ADK found" -Level Info

    # Locate copype.cmd
    $copypePath = Join-Path $adkPath "Windows Preinstallation Environment\copype.cmd"
    if (-not (Test-Path $copypePath)) {
        throw "copype.cmd not found. Ensure WinPE add-on is installed."
    }

    Write-DeploymentLog "copype.cmd found" -Level Info

    # Locate DandISetEnv.bat (required for copype.cmd environment)
    $dandISetEnvPath = Join-Path $adkPath "Deployment Tools\DandISetEnv.bat"
    if (-not (Test-Path $dandISetEnvPath)) {
        throw "DandISetEnv.bat not found. Ensure ADK Deployment Tools are installed."
    }

    Write-DeploymentLog "DandISetEnv.bat found" -Level Info

    # Locate MakeWinPEMedia.cmd
    $makeMediaPath = Join-Path $adkPath "Windows Preinstallation Environment\MakeWinPEMedia.cmd"
    if (-not (Test-Path $makeMediaPath)) {
        throw "MakeWinPEMedia.cmd not found. Ensure WinPE add-on is installed."
    }

    Write-DeploymentLog "MakeWinPEMedia.cmd found" -Level Info

    # Check for DISM
    if (-not (Get-Command dism.exe -ErrorAction SilentlyContinue)) {
        throw "DISM not found. Required for image customization."
    }

    Write-DeploymentLog "DISM found" -Level Info

    # Locate WinPE optional components
    $winpeOCsPath = Join-Path $adkPath "Windows Preinstallation Environment\$Architecture\WinPE_OCs"
    if (-not (Test-Path $winpeOCsPath)) {
        throw "WinPE optional components not found at: $winpeOCsPath"
    }
    Write-DeploymentLog "WinPE OCs path: $winpeOCsPath" -Level Info

    # Locate oscdimg.exe and add to PATH
    $deploymentToolsPath = Join-Path $adkPath "Deployment Tools\$Architecture\Oscdimg"
    $oscdimgPath = Join-Path $deploymentToolsPath "oscdimg.exe"

    if (-not (Test-Path $oscdimgPath)) {
        throw "oscdimg.exe not found at: $oscdimgPath. Ensure Deployment Tools are installed."
    }

    Write-DeploymentLog "oscdimg.exe found at: $oscdimgPath" -Level Info

    # Add Deployment Tools to PATH for this session
    $env:PATH = "$deploymentToolsPath;$env:PATH"
    Write-DeploymentLog "Added Deployment Tools to PATH" -Level Info

    Write-Host "  Prerequisites validated successfully" -ForegroundColor Green
    #endregion

    #region Working Directory Setup
    Write-DeploymentLog "===== WORKING DIRECTORY SETUP =====" -Level Info
    Write-Host "Setting up working directory..." -ForegroundColor Yellow

    # Create working directory
    $workingPath = Join-Path $ProjectRoot $WorkingDirectory
    if (Test-Path $workingPath) {
        Write-DeploymentLog "Removing existing working directory..." -Level Info

        # Clean up any leftover mounts first
        Invoke-StartupCleanup -WorkingPath $workingPath

        # Now try to remove the directory
        try {
            Remove-Item -Path $workingPath -Recurse -Force -ErrorAction Stop
            Write-DeploymentLog "Working directory removed successfully" -Level Info
        }
        catch {
            Write-DeploymentLog "Warning: Could not fully remove working directory: $($_.Exception.Message)" -Level Warning
            Write-DeploymentLog "Attempting to continue anyway..." -Level Info

            # Try to remove what we can
            Remove-Item -Path $workingPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Only create working directory if NOT using WinRE extraction
    # copype.cmd will create it for WinRE builds
    if (-not $WinREISOPath -and -not $UseWinRE) {
        New-Item -Path $workingPath -ItemType Directory -Force | Out-Null
        Write-DeploymentLog "Working directory created: $workingPath" -Level Info

        # Create mount directory
        $mountPath = Join-Path $workingPath "mount"
        New-Item -Path $mountPath -ItemType Directory -Force | Out-Null
        Write-DeploymentLog "Mount directory created: $mountPath" -Level Info
    }
    else {
        Write-DeploymentLog "Working directory will be created by copype.cmd" -Level Info
    }
    #endregion

    #region Base Image Creation
    Write-DeploymentLog "===== BASE IMAGE CREATION =====" -Level Info

    if ($WinREISOPath) {
        # Option C: Extract WinRE from Windows ISO
        # Initialize cleanup tracking
        $mountedISOPath = $null
        $tempMountPath = $null

        try {
            Write-Host "Extracting WinRE from Windows ISO..." -ForegroundColor Yellow
            Write-DeploymentLog "Extracting WinRE from ISO: $WinREISOPath" -Level Info

            if (-not (Test-Path $WinREISOPath)) {
                throw "Windows ISO not found: $WinREISOPath"
            }

            # Run copype.cmd to create full directory structure for WinRE
            Write-Host "Creating base WinPE structure..." -ForegroundColor Yellow
            Write-DeploymentLog "Running copype.cmd to create directory structure..." -Level Info

            # CRITICAL: copype.cmd requires DandISetEnv.bat to set environment variables like %WinPERoot%
            # Must run both in the same cmd session using &&
            $copypeArgs = "$Architecture `"$workingPath`""
            $combinedCommand = "`"`"$dandISetEnvPath`" && `"$copypePath`" $copypeArgs`""
            $copypeResult = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $combinedCommand" -Wait -NoNewWindow -PassThru

            if ($copypeResult.ExitCode -ne 0) {
                throw "copype.cmd failed. Exit code: $($copypeResult.ExitCode)"
            }

            Write-DeploymentLog "Base WinPE structure created successfully" -Level Info
            Write-Host "  Base structure created" -ForegroundColor Green

            # Mount ISO
            Write-DeploymentLog "Mounting Windows ISO..." -Level Info
            $mountedISO = Mount-DiskImage -ImagePath $WinREISOPath -PassThru
            $mountedISOPath = $WinREISOPath  # Track for cleanup
            $isoDrive = ($mountedISO | Get-Volume).DriveLetter

            Write-DeploymentLog "ISO mounted at drive $isoDrive`:" -Level Info

            # Mount install.wim
            $installWim = Join-Path "$isoDrive`:" "sources\install.wim"
            $installEsd = Join-Path "$isoDrive`:" "sources\install.esd"

            if (Test-Path $installWim) {
                $sourceImage = $installWim
            }
            elseif (Test-Path $installEsd) {
                $sourceImage = $installEsd
            }
            else {
                throw "No install.wim or install.esd found in ISO"
            }

            # Create temp mount for install.wim
            $tempMount = Join-Path $workingPath "temp_mount"
            $tempMountPath = $tempMount  # Track for cleanup
            New-Item -Path $tempMount -ItemType Directory -Force | Out-Null

            Write-DeploymentLog "Mounting $sourceImage (read-only)..." -Level Info
            Write-Host "  Mounting install.wim (this may take 2-5 minutes)..." -ForegroundColor Cyan

            # Call DISM directly instead of Start-Process (Start-Process -Wait causes hanging)
            dism.exe /Mount-Image /ImageFile:"$sourceImage" /Index:1 /MountDir:"$tempMount" /ReadOnly
            $dismExitCode = $LASTEXITCODE

            if ($dismExitCode -ne 0) {
                throw "Failed to mount install.wim. Exit code: $dismExitCode"
            }

            Write-Host ""
            Write-Host "  DISM Exit Code: $dismExitCode" -ForegroundColor Green
            Write-Host "  Mount completed successfully!" -ForegroundColor Green
            Write-DeploymentLog "DISM mount completed with exit code: $dismExitCode" -Level Info
            Write-Host "  Locating WinRE.wim in mounted image..." -ForegroundColor Cyan

            # Extract WinRE
            $winrePath = Join-Path $tempMount "Windows\System32\Recovery\Winre.wim"
            $bootWimPath = Join-Path $workingPath "media\sources\boot.wim"

            Write-Host "  Checking for WinRE.wim at: $winrePath" -ForegroundColor Cyan

            if (-not (Test-Path $winrePath)) {
                throw "WinRE.wim not found in Windows image"
            }

            Write-Host "  WinRE.wim found! Preparing to copy..." -ForegroundColor Green

            # Get file size for user feedback
            $winreFile = Get-Item $winrePath
            $winreSizeMB = [math]::Round($winreFile.Length / 1MB, 2)

            Write-Host "Copying WinRE.wim to boot.wim..." -ForegroundColor Yellow
            Write-DeploymentLog "Copying WinRE.wim ($winreSizeMB MB) to boot.wim..." -Level Info
            Write-Host "  File size: $winreSizeMB MB" -ForegroundColor Cyan
            Write-Host "  This will take 10-30 minutes with no progress bar - showing updates every 30 seconds" -ForegroundColor Yellow
            Write-Host "  Started at: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
            Write-Host ""

            # Wait for mount to stabilize
            Write-Host "  Waiting 3 seconds for mount to stabilize..." -ForegroundColor Cyan
            Start-Sleep -Seconds 3
            Write-Host "  Starting copy..." -ForegroundColor Cyan

            # Start copy as background job
            $copyJob = Start-Job -ScriptBlock {
                param($Source, $Dest)
                try {
                    Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
                    return @{ Success = $true }
                }
                catch {
                    return @{ Success = $false; Error = $_.Exception.Message }
                }
            } -ArgumentList $winrePath, $bootWimPath

            # Monitor and show progress
            $expectedSize = (Get-Item $winrePath).Length
            $updateCounter = 0

            Write-Host ""
            while ($copyJob.State -eq 'Running') {
                Start-Sleep -Seconds 10
                $updateCounter++

                # Show "still copying" message every 30 seconds (3 x 10 second intervals)
                if ($updateCounter -ge 3) {
                    # Check if destination file exists and show size
                    if (Test-Path $bootWimPath) {
                        $currentSize = (Get-Item $bootWimPath).Length
                        $percentComplete = [math]::Round(($currentSize / $expectedSize) * 100, 1)
                        Write-Host "  Still copying... $percentComplete% complete ($([math]::Round($currentSize / 1MB, 1)) MB / $winreSizeMB MB) - elapsed: $($updateCounter * 10) seconds" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "  Still copying... (initializing, file not yet created) - elapsed: $($updateCounter * 10) seconds" -ForegroundColor Cyan
                    }

                    Write-DeploymentLog "Copy in progress - elapsed: $($updateCounter * 10) seconds" -Level Info
                    $updateCounter = 0
                }
            }

            Write-Host ""

            # Get job result
            $result = Receive-Job -Job $copyJob -Wait
            Remove-Job -Job $copyJob

            # Check result
            if ($result.Success -eq $false) {
                Write-DeploymentLog "ERROR: Copy failed: $($result.Error)" -Level Error
                throw "Failed to copy WinRE.wim: $($result.Error)"
            }

            if (-not (Test-Path $bootWimPath)) {
                throw "Copy job reported success but destination file does not exist"
            }

            Write-DeploymentLog "WinRE.wim copied successfully" -Level Info
            Write-Host "  Copy completed successfully!" -ForegroundColor Green

            # Remove read-only attribute and ensure proper permissions for DISM mount
            Write-Host "  Setting file attributes..." -ForegroundColor Cyan
            try {
                # Remove read-only attribute
                Set-ItemProperty -Path $bootWimPath -Name IsReadOnly -Value $false -ErrorAction Stop

                # Verify file is accessible
                $fileInfo = Get-Item $bootWimPath -ErrorAction Stop
                Write-DeploymentLog "boot.wim file size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -Level Info
                Write-DeploymentLog "boot.wim attributes: $($fileInfo.Attributes)" -Level Verbose
                Write-Host "  File attributes set successfully" -ForegroundColor Green
            }
            catch {
                Write-DeploymentLog "Warning: Could not modify file attributes: $($_.Exception.Message)" -Level Warning
                Write-Host "  Warning: Could not modify file attributes" -ForegroundColor Yellow
            }

            Write-DeploymentLog "WinRE extracted successfully" -Level Info
            $UseWinRE = $true
        }
        catch {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Red
            Write-Host "  ERROR DURING WINRE EXTRACTION" -ForegroundColor Red
            Write-Host "========================================" -ForegroundColor Red
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "  Location: Line $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
            Write-Host "  Command: $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
            Write-Host "" -ForegroundColor Red
            Write-DeploymentLog "ERROR in WinRE extraction: $($_.Exception.Message)" -Level Error
            Write-DeploymentLog "Error location: Line $($_.InvocationInfo.ScriptLineNumber)" -Level Error

            # Re-throw to ensure script exits with error
            throw
        }
        finally {
            # Cleanup: Unmount DISM image and ISO
            Write-Host ""

            # Determine cleanup reason and set appropriate message
            if ($_.Exception) {
                # Error occurred during extraction
                Write-Host "========================================" -ForegroundColor Red
                Write-Host "  CLEANUP: Error Recovery" -ForegroundColor Red
                Write-Host "========================================" -ForegroundColor Red
                Write-DeploymentLog "Cleaning up after error..." -Level Warning
            }
            else {
                # Normal cleanup after successful extraction
                Write-Host "========================================" -ForegroundColor Yellow
                Write-Host "  CLEANUP: WinRE Extraction Complete" -ForegroundColor Yellow
                Write-Host "========================================" -ForegroundColor Yellow
                Write-DeploymentLog "Cleaning up after successful WinRE extraction..." -Level Info
            }

            if ($tempMountPath -and (Test-Path $tempMountPath)) {
                Write-DeploymentLog "Unmounting DISM image..." -Level Info
                Write-Host "  Unmounting DISM image (this may take 1-2 minutes)..." -ForegroundColor Cyan

                # Call DISM directly instead of Start-Process
                dism.exe /Unmount-Image /MountDir:"$tempMountPath" /Discard
                $unmountExitCode = $LASTEXITCODE

                Write-Host "  Unmount completed with exit code: $unmountExitCode" -ForegroundColor Cyan

                if ($unmountExitCode -eq 0) {
                    Write-DeploymentLog "DISM image unmounted successfully" -Level Info
                    Write-Host "  DISM image unmounted successfully!" -ForegroundColor Green
                } else {
                    Write-DeploymentLog "Warning: DISM unmount returned exit code $unmountExitCode" -Level Warning
                    Write-Host "  Warning: Unmount exit code $unmountExitCode" -ForegroundColor Yellow
                }

                # Remove temp mount directory
                if (Test-Path $tempMountPath) {
                    Remove-Item -Path $tempMountPath -Force -Recurse -ErrorAction SilentlyContinue
                }
            }

            if ($mountedISOPath) {
                Write-DeploymentLog "Dismounting ISO..." -Level Info
                Dismount-DiskImage -ImagePath $mountedISOPath -ErrorAction SilentlyContinue | Out-Null
                Write-DeploymentLog "ISO dismounted" -Level Info
                Write-Host "  ISO dismounted successfully" -ForegroundColor Green
            }

            # Cleanup completion message
            Write-Host ""
            if (-not $_.Exception) {
                Write-Host "========================================" -ForegroundColor Green
                Write-Host "  CLEANUP COMPLETED - Continuing Build" -ForegroundColor Green
                Write-Host "========================================" -ForegroundColor Green
                Write-DeploymentLog "WinRE extraction cleanup completed, continuing with build..." -Level Info
            }
            else {
                Write-Host "  Cleanup completed" -ForegroundColor Yellow
            }
        }
    }
    elseif ($UseWinRE) {
        # Option B: Use local WinRE
        Write-Host "Using local WinRE image..." -ForegroundColor Yellow
        Write-DeploymentLog "Using local WinRE from system" -Level Info

        $localWinRE = "C:\Windows\System32\Recovery\Winre.wim"
        if (-not (Test-Path $localWinRE)) {
            Write-DeploymentLog "Local WinRE not found at default location: $localWinRE" -Level Warning
            Write-DeploymentLog "Attempting to query WinRE configuration..." -Level Info

            # Try to get WinRE info from reagentc
            $reagentInfo = reagentc /info 2>&1 | Out-String
            if ($reagentInfo -match "Windows RE location:\s+(.+)") {
                $winreLocation = $matches[1].Trim()
                Write-DeploymentLog "Found WinRE location from reagentc: $winreLocation" -Level Info

                # Try to find winre.wim in the reported location
                if ($winreLocation -match "\\?\?\\([A-Z]):") {
                    $winreDrive = $matches[1]
                    $possiblePath = "${winreDrive}:\Recovery\WindowsRE\Winre.wim"
                    if (Test-Path $possiblePath) {
                        $localWinRE = $possiblePath
                        Write-DeploymentLog "Found WinRE at: $localWinRE" -Level Info
                    }
                }
            }

            # Final check
            if (-not (Test-Path $localWinRE)) {
                throw @"
Local WinRE not found. Tried:
  - C:\Windows\System32\Recovery\Winre.wim
  - reagentc configuration query

Suggestions:
  1. Use -WinREISOPath to extract WinRE from a Windows ISO
  2. Run without -UseWinRE to use standard WinPE
  3. Manually locate Winre.wim and copy to C:\Windows\System32\Recovery\

Example:
  .\Build-BootableISO.ps1 -WinREISOPath "C:\ISOs\Win11.iso"
"@
            }
        }

        # Create media directory structure
        New-Item -Path (Join-Path $workingPath "media\sources") -ItemType Directory -Force | Out-Null

        $bootWimPath = Join-Path $workingPath "media\sources\boot.wim"
        Write-DeploymentLog "Copying WinRE to boot.wim..." -Level Info
        Copy-Item -Path $localWinRE -Destination $bootWimPath -Force

        Write-DeploymentLog "WinRE copied successfully" -Level Info
    }
    else {
        # Option A: Standard WinPE
        Write-Host "Creating standard WinPE base..." -ForegroundColor Yellow
        Write-DeploymentLog "Creating standard WinPE base" -Level Info

        # Run copype.cmd
        Write-DeploymentLog "Running copype.cmd..." -Level Info

        # CRITICAL: copype.cmd requires DandISetEnv.bat to set environment variables like %WinPERoot%
        # Must run both in the same cmd session using &&
        $copypeArgs = "$Architecture `"$workingPath`""
        $combinedCommand = "`"`"$dandISetEnvPath`" && `"$copypePath`" $copypeArgs`""
        $copypeResult = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $combinedCommand" -Wait -NoNewWindow -PassThru

        if ($copypeResult.ExitCode -ne 0) {
            throw "copype.cmd failed. Exit code: $($copypeResult.ExitCode)"
        }

        $bootWimPath = Join-Path $workingPath "media\sources\boot.wim"
        Write-DeploymentLog "WinPE base created successfully" -Level Info
    }

    if (-not (Test-Path $bootWimPath)) {
        throw "boot.wim not found at expected location: $bootWimPath"
    }

    Write-DeploymentLog "Base image ready: $bootWimPath" -Level Info
    #endregion

    # Ensure mount directory exists for customization
    $mountPath = Join-Path $workingPath "mount"
    if (-not (Test-Path $mountPath)) {
        New-Item -Path $mountPath -ItemType Directory -Force | Out-Null
        Write-DeploymentLog "Mount directory created: $mountPath" -Level Info
    } else {
        Write-DeploymentLog "Mount directory already exists: $mountPath" -Level Info
    }

    #region Mount and Customize Boot.wim
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  BOOT IMAGE CUSTOMIZATION" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-DeploymentLog "===== BOOT IMAGE CUSTOMIZATION =====" -Level Info
    Write-Host "Mounting boot.wim for customization..." -ForegroundColor Yellow

    # Mount boot.wim
    Write-DeploymentLog "Mounting boot.wim..." -Level Info
    Write-Host "  Mounting boot.wim (this may take 1-2 minutes)..." -ForegroundColor Cyan

    # Verify file and directory accessibility before mount
    Write-DeploymentLog "Checking file and directory accessibility..." -Level Verbose
    Write-DeploymentLog "boot.wim path: $bootWimPath" -Level Verbose
    Write-DeploymentLog "Mount path: $mountPath" -Level Verbose

    # Verify file exists and is accessible
    if (Test-Path $bootWimPath) {
        $wimFile = Get-Item $bootWimPath
        Write-DeploymentLog "boot.wim exists, size: $([math]::Round($wimFile.Length / 1MB, 2)) MB, attributes: $($wimFile.Attributes)" -Level Verbose
    } else {
        throw "boot.wim not found at: $bootWimPath"
    }

    # Verify mount directory exists and is accessible
    if (Test-Path $mountPath) {
        Write-DeploymentLog "Mount directory exists and is accessible" -Level Verbose
    } else {
        throw "Mount directory not found at: $mountPath"
    }

    dism.exe /Mount-Image /ImageFile:"$bootWimPath" /Index:1 /MountDir:"$mountPath"
    $dismExitCode = $LASTEXITCODE

    # Enhanced error reporting for access denied
    if ($dismExitCode -eq 5) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "  ACCESS DENIED ERROR" -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "DISM failed to mount boot.wim with 'Access Denied'" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Possible causes:" -ForegroundColor Yellow
        Write-Host "  1. Antivirus software blocking DISM" -ForegroundColor Cyan
        Write-Host "  2. File permissions issue" -ForegroundColor Cyan
        Write-Host "  3. File locked by another process" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "  1. Temporarily disable antivirus" -ForegroundColor Cyan
        Write-Host "  2. Check DISM log: C:\WINDOWS\Logs\DISM\dism.log" -ForegroundColor Cyan
        Write-Host "  3. Ensure no other programs are accessing the file" -ForegroundColor Cyan
        Write-Host ""

        Write-DeploymentLog "DISM mount failed with ACCESS DENIED (exit code 5)" -Level Error
        Write-DeploymentLog "boot.wim path: $bootWimPath" -Level Error
        Write-DeploymentLog "Mount path: $mountPath" -Level Error
        Write-DeploymentLog "Check DISM log for details: C:\WINDOWS\Logs\DISM\dism.log" -Level Error
    }

    if ($dismExitCode -ne 0) {
        throw "Failed to mount boot.wim. Exit code: $dismExitCode"
    }

    Write-Host "  boot.wim mounted successfully!" -ForegroundColor Green
    Write-DeploymentLog "boot.wim mounted successfully" -Level Info

    # Remove winpeshl.ini if using WinRE
    if ($UseWinRE) {
        $winpeshlPath = Join-Path $mountPath "Windows\System32\winpeshl.ini"
        if (Test-Path $winpeshlPath) {
            Write-DeploymentLog "Removing winpeshl.ini (prevents recovery environment loading)..." -Level Info
            Remove-Item -Path $winpeshlPath -Force
        }
    }

    # Add wireless support DLLs
    if ($EnableWireless) {
        Write-Host "Adding wireless support..." -ForegroundColor Yellow
        Write-DeploymentLog "Adding wireless support DLLs..." -Level Info

        $systemDllPath = Join-Path $mountPath "Windows\System32"

        # Copy required DLLs for WinPE 1607+
        # Source: https://msendpointmgr.com/2018/03/06/build-a-winpe-with-wireless-support/
        $sourceDllPath = "C:\Windows\System32"

        Write-DeploymentLog "Copying dmcmnutils.dll..." -Level Info
        Copy-Item -Path (Join-Path $sourceDllPath "dmcmnutils.dll") -Destination $systemDllPath -Force

        Write-DeploymentLog "Copying mdmregistration.dll..." -Level Info
        Copy-Item -Path (Join-Path $sourceDllPath "mdmregistration.dll") -Destination $systemDllPath -Force

        Write-DeploymentLog "Wireless support DLLs added" -Level Info
    }

    # Add wireless profiles
    if ($WirelessProfiles -and (Test-Path $WirelessProfiles)) {
        Write-Host "Adding wireless profiles..." -ForegroundColor Yellow
        Write-DeploymentLog "Adding wireless profiles from: $WirelessProfiles" -Level Info

        $profileDestPath = Join-Path $mountPath "Windows"
        Copy-Item -Path "$WirelessProfiles\*" -Destination $profileDestPath -Force -Recurse

        Write-DeploymentLog "Wireless profiles added" -Level Info
    }

    # Add custom packages
    if ($CustomPackages) {
        Write-Host "Adding custom packages..." -ForegroundColor Yellow

        foreach ($package in $CustomPackages) {
            Write-DeploymentLog "Adding package: $package..." -Level Info

            # Build full path to .cab file
            $packagePath = Join-Path $winpeOCsPath "$package.cab"

            if (-not (Test-Path $packagePath)) {
                Write-DeploymentLog "Package not found: $packagePath" -Level Warning
                continue
            }

            dism.exe /Image:"$mountPath" /Add-Package /PackagePath:"$packagePath"
            $dismExitCode = $LASTEXITCODE

            if ($dismExitCode -eq 0) {
                Write-DeploymentLog "Package added successfully: $package" -Level Info
            }
            else {
                Write-DeploymentLog "Failed to add package: $package (Exit code: $dismExitCode)" -Level Warning
            }
        }
    }
    else {
        # Add essential packages (only for WinPE, WinRE has them built-in)
        if (-not $UseWinRE) {
            Write-Host "Adding essential packages..." -ForegroundColor Yellow

            $essentialPackages = @(
                "WinPE-WMI",             # Must be first - base for PowerShell and StorageWMI
                "WinPE-NetFx",           # Independent - can be early
                "WinPE-PowerShell",      # Requires WinPE-WMI
                "WinPE-StorageWMI",      # Requires WinPE-WMI
                "WinPE-DismCmdlets"      # Requires WinPE-PowerShell
            )

            foreach ($package in $essentialPackages) {
                Write-DeploymentLog "Adding essential package: $package..." -Level Info

                # Build full path to .cab file
                $packagePath = Join-Path $winpeOCsPath "$package.cab"

                if (-not (Test-Path $packagePath)) {
                    Write-DeploymentLog "Package not found: $packagePath" -Level Warning
                    continue
                }

                dism.exe /Image:"$mountPath" /Add-Package /PackagePath:"$packagePath"
                $dismExitCode = $LASTEXITCODE

                if ($dismExitCode -eq 0) {
                    Write-DeploymentLog "Package added: $package" -Level Info
                }
                else {
                    Write-DeploymentLog "Package add warning: $package (Exit code: $dismExitCode)" -Level Warning
                }
            }
        }
        else {
            Write-Host "Skipping package installation (WinRE includes these components)" -ForegroundColor Yellow
            Write-DeploymentLog "Skipping essential packages - WinRE includes PowerShell, WMI, and other components by default" -Level Info
        }
    }

    # Add custom drivers
    if ($CustomDrivers -and (Test-Path $CustomDrivers)) {
        Write-Host "Injecting custom drivers..." -ForegroundColor Yellow
        Write-DeploymentLog "Injecting drivers from: $CustomDrivers" -Level Info

        dism.exe /Image:"$mountPath" /Add-Driver /Driver:"$CustomDrivers" /Recurse
        $dismExitCode = $LASTEXITCODE

        if ($dismExitCode -eq 0) {
            Write-DeploymentLog "Drivers injected successfully" -Level Info
        }
        else {
            Write-DeploymentLog "Driver injection completed with warnings (Exit code: $dismExitCode)" -Level Warning
        }
    }

    # Include utility scripts
    if ($IncludeScripts) {
        Write-Host "Including utility scripts..." -ForegroundColor Yellow
        Write-DeploymentLog "Including utility scripts..." -Level Info

        $deployScriptsPath = Join-Path $mountPath "Scripts"
        New-Item -Path $deployScriptsPath -ItemType Directory -Force | Out-Null

        # Note: Build-BootableISO.ps1 is self-contained with embedded functions
        # Deployment scripts (Deploy-Bootstrap.ps1, Deploy-Windows.ps1) are located
        # in separate project directories and not included in the bootable ISO
        # Only utility scripts are included below

        # Copy utility scripts
        $utilsScriptSourcePath = Join-Path $ScriptRoot "Scripts"
        if (Test-Path $utilsScriptSourcePath) {
            $utilsScriptDestPath = Join-Path $deployScriptsPath "Utils"
            New-Item -Path $utilsScriptDestPath -ItemType Directory -Force | Out-Null

            # Copy WiFi connection script
            $wifiScript = Join-Path $utilsScriptSourcePath "Connect-WiFiInteractive-Standalone.ps1"
            if (Test-Path $wifiScript) {
                Copy-Item -Path $wifiScript -Destination (Join-Path $utilsScriptDestPath "Connect-WiFi.ps1") -Force
                Write-DeploymentLog "WiFi connection script included" -Level Info
            }

            # Copy any other utility scripts found in Scripts directory
            $otherScripts = Get-ChildItem -Path $utilsScriptSourcePath -Filter "*.ps1" -File |
                            Where-Object { $_.Name -ne "Connect-WiFiInteractive-Standalone.ps1" }

            foreach ($script in $otherScripts) {
                Copy-Item -Path $script.FullName -Destination $utilsScriptDestPath -Force
                Write-DeploymentLog "Utility script included: $($script.Name)" -Level Info
            }

            if (Test-Path (Join-Path $utilsScriptDestPath "Connect-WiFi.ps1")) {
                Write-Host "  Utility scripts included in X:\Scripts\Utils\" -ForegroundColor Green
            }
        }

        Write-DeploymentLog "Utility scripts included" -Level Info

        # Copy Deploy-Bootstrap.ps1 from project
        $bootstrapSourcePath = Join-Path $ProjectRoot "Scripts\Deploy-Bootstrap\Deploy-Bootstrap.ps1"
        if (Test-Path $bootstrapSourcePath) {
            Copy-Item -Path $bootstrapSourcePath -Destination (Join-Path $deployScriptsPath "Deploy-Bootstrap.ps1") -Force
            Write-DeploymentLog "Deploy-Bootstrap.ps1 included" -Level Info
            Write-Host "  Deploy-Bootstrap.ps1 included in X:\Scripts\" -ForegroundColor Green
        }
        else {
            Write-DeploymentLog "WARNING: Deploy-Bootstrap.ps1 not found at $bootstrapSourcePath" -Level Warning
        }
    }

    # Include configuration files
    if ($IncludeConfigs) {
        Write-Host "Including configuration files..." -ForegroundColor Yellow
        Write-DeploymentLog "Including configuration files..." -Level Info

        $deployConfigPath = Join-Path $mountPath "Deploy\Config"
        New-Item -Path $deployConfigPath -ItemType Directory -Force | Out-Null

        # Copy examples
        $examplesPath = Join-Path $deployConfigPath "Examples"
        Copy-Item -Path (Join-Path $ProjectRoot "Config\Examples") -Destination $examplesPath -Force -Recurse

        # Copy schemas
        $schemasPath = Join-Path $deployConfigPath "Schemas"
        Copy-Item -Path (Join-Path $ProjectRoot "Config\Schemas") -Destination $schemasPath -Force -Recurse

        Write-DeploymentLog "Configuration files included" -Level Info
    }

    # Create startnet.cmd
    Write-Host "Creating startup script..." -ForegroundColor Yellow
    Write-DeploymentLog "Creating startnet.cmd..." -Level Info

    $startnetPath = Join-Path $mountPath "Windows\System32\startnet.cmd"
    $startnetContent = @"
@echo off
echo Windows Deployment Automation
echo ========================================
echo.

wpeinit

REM Wait for network initialization
timeout /t 30

REM Connect to wireless if profiles exist
if exist X:\Windows\*.xml (
    echo Connecting to wireless network...
    for %%f in (X:\Windows\*.xml) do (
        netsh wlan add profile filename="%%f"
    )
    REM Connect to first available network
    for /f "tokens=2 delims=:" %%a in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
        set SSID=%%a
        goto :connect
    )
    :connect
    netsh wlan connect name="%SSID%"
)

echo.
echo Deployment environment ready.
echo.

REM Prompt user to run Deploy-Bootstrap.ps1
if exist X:\Scripts\Deploy-Bootstrap.ps1 (
    echo.
    echo ========================================
    echo   Deploy-Bootstrap.ps1 is available
    echo ========================================
    echo.
    set /p RUN_BOOTSTRAP="Do you want to run Deploy-Bootstrap.ps1? (Y/N): "

    if /i "%RUN_BOOTSTRAP%"=="Y" (
        echo.
        echo Starting Deploy-Bootstrap.ps1...
        echo.
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "X:\Scripts\Deploy-Bootstrap.ps1"
    ) else (
        echo.
        echo Skipped Deploy-Bootstrap.ps1
        echo.
    )
)

REM Show available utility scripts
if exist X:\Scripts\Utils\Connect-WiFi.ps1 (
    echo.
    echo Available utility scripts:
    echo   WiFi: powershell.exe -NoProfile -ExecutionPolicy Bypass -File "X:\Scripts\Utils\Connect-WiFi.ps1"
    echo.
)

cmd
"@

    Set-Content -Path $startnetPath -Value $startnetContent -Force
    Write-DeploymentLog "startnet.cmd created" -Level Info
    #endregion

    #region Unmount and Commit
    Write-DeploymentLog "===== COMMITTING CHANGES =====" -Level Info
    Write-Host "Unmounting and committing changes..." -ForegroundColor Yellow

    Write-DeploymentLog "Unmounting boot.wim..." -Level Info
    $dismArgs = "/Unmount-Image /MountDir:`"$mountPath`" /Commit"
    $dismResult = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru

    if ($dismResult.ExitCode -ne 0) {
        throw "Failed to unmount boot.wim. Exit code: $($dismResult.ExitCode)"
    }

    Write-DeploymentLog "boot.wim unmounted and committed" -Level Info
    #endregion

    #region Create ISO
    Write-DeploymentLog "===== ISO GENERATION =====" -Level Info
    Write-Host "Creating bootable ISO..." -ForegroundColor Yellow

    # Prepare output path (Note: $outputFullPath was already validated/removed in early ISO lock detection)
    $outputDir = Split-Path -Path $outputFullPath -Parent

    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }

    # Copy appropriate boot manager to media directory
    $bootBinsPath = Join-Path $workingPath "bootbins"
    $bootmgrSource = Join-Path $bootBinsPath "bootmgfw_EX.efi"  # Use 2023 signature
    $mediaEfiBootPath = Join-Path $workingPath "media\EFI\BOOT"
    $mediaEfiMsBootPath = Join-Path $workingPath "media\EFI\MICROSOFT\BOOT"

    # Ensure boot directories exist
    if (-not (Test-Path $mediaEfiBootPath)) {
        New-Item -Path $mediaEfiBootPath -ItemType Directory -Force | Out-Null
    }

    # Copy boot manager to boot location(s)
    if (Test-Path $bootmgrSource) {
        # AMD64 uses bootx64.efi
        if ($Architecture -eq "amd64") {
            Copy-Item -Path $bootmgrSource -Destination "$mediaEfiBootPath\bootx64.efi" -Force
        }
        # ARM64 uses bootaa64.efi
        elseif ($Architecture -eq "arm64") {
            Copy-Item -Path $bootmgrSource -Destination "$mediaEfiBootPath\bootaa64.efi" -Force
        }

        # Copy to Microsoft boot path
        Copy-Item -Path $bootmgrSource -Destination "$mediaEfiMsBootPath\bootmgfw.efi" -Force
        Write-DeploymentLog "Boot manager copied (EX signature)" -Level Info
    }
    else {
        Write-DeploymentLog "Warning: bootmgfw_EX.efi not found, trying standard signature..." -Level Warning
        $bootmgrSource = Join-Path $bootBinsPath "bootmgfw.efi"
        if (Test-Path $bootmgrSource) {
            if ($Architecture -eq "amd64") {
                Copy-Item -Path $bootmgrSource -Destination "$mediaEfiBootPath\bootx64.efi" -Force
            }
            elseif ($Architecture -eq "arm64") {
                Copy-Item -Path $bootmgrSource -Destination "$mediaEfiBootPath\bootaa64.efi" -Force
            }
            Copy-Item -Path $bootmgrSource -Destination "$mediaEfiMsBootPath\bootmgfw.efi" -Force
            Write-DeploymentLog "Boot manager copied (standard signature)" -Level Info
        }
        else {
            throw "Boot manager not found in bootbins directory"
        }
    }

    # Select efisys file based on -PAK parameter
    if ($PAK) {
        $efisysFile = "efisys_EX.bin"  # WITH "press any key" prompt
        Write-DeploymentLog "Boot prompt: ENABLED (press any key to boot)" -Level Info
    } else {
        $efisysFile = "efisys_noprompt_EX.bin"  # NO prompt
        Write-DeploymentLog "Boot prompt: DISABLED (automatic boot)" -Level Info
    }

    $efisysPath = Join-Path $bootBinsPath $efisysFile

    if (-not (Test-Path $efisysPath)) {
        # Fallback to standard signature if EX not found
        Write-DeploymentLog "Warning: $efisysFile not found, trying standard signature..." -Level Warning
        if ($PAK) {
            $efisysFile = "efisys.bin"
        } else {
            $efisysFile = "efisys_noprompt.bin"
        }
        $efisysPath = Join-Path $bootBinsPath $efisysFile

        if (-not (Test-Path $efisysPath)) {
            throw "Boot sector file not found: $efisysPath"
        }
    }

    # Build oscdimg boot data argument
    $efisysBootData = "pEF,e,b`"$efisysPath`""

    # Check if BIOS boot is available (for hybrid boot)
    $etfsbootPath = Join-Path $bootBinsPath "etfsboot.com"
    if (Test-Path $etfsbootPath) {
        # Hybrid UEFI + BIOS boot
        $bootData = "2#p0,e,b`"$etfsbootPath`"#$efisysBootData"
        Write-DeploymentLog "Boot mode: Hybrid (UEFI + BIOS)" -Level Info
    } else {
        # UEFI only
        $bootData = "1#$efisysBootData"
        Write-DeploymentLog "Boot mode: UEFI only" -Level Info
    }

    # Run oscdimg to create ISO
    Write-DeploymentLog "Running oscdimg..." -Level Info
    $mediaPath = Join-Path $workingPath "media"

    # Use oscdimg directly instead of MakeWinPEMedia for better control
    $oscdimgArgs = @(
        "-bootdata:$bootData",
        "-u1",
        "-udfver102",
        "`"$mediaPath`"",
        "`"$outputFullPath`""
    )

    Write-DeploymentLog "oscdimg command: oscdimg $($oscdimgArgs -join ' ')" -Level Info

    $oscdimgProcess = Start-Process -FilePath "oscdimg.exe" -ArgumentList $oscdimgArgs -Wait -NoNewWindow -PassThru

    if ($oscdimgProcess.ExitCode -ne 0) {
        throw "oscdimg failed. Exit code: $($oscdimgProcess.ExitCode)"
    }

    if (-not (Test-Path $outputFullPath)) {
        throw "ISO was not created at expected location: $outputFullPath"
    }

    $isoSize = (Get-Item $outputFullPath).Length / 1MB
    Write-DeploymentLog "ISO created successfully: $outputFullPath" -Level Info
    Write-DeploymentLog "ISO size: $([math]::Round($isoSize, 2)) MB" -Level Info
    #endregion

    #region Build Summary
    Write-DeploymentLog "========================================" -Level Info
    Write-DeploymentLog "BUILD COMPLETED SUCCESSFULLY" -Level Info
    Write-DeploymentLog "========================================" -Level Info

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ISO Build Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "ISO File: $outputFullPath" -ForegroundColor Cyan
    Write-Host "ISO Size: $([math]::Round($isoSize, 2)) MB" -ForegroundColor Cyan
    Write-Host "Architecture: $Architecture" -ForegroundColor Cyan
    Write-Host "Base Image: $(if ($UseWinRE) { 'WinRE' } else { 'WinPE' })" -ForegroundColor Cyan

    if ($EnableWireless -or $UseWinRE) {
        Write-Host "Wireless: Enabled" -ForegroundColor Cyan
    }

    if ($IncludeScripts) {
        Write-Host "Scripts: Included" -ForegroundColor Cyan
    }

    if ($IncludeConfigs) {
        Write-Host "Configs: Included" -ForegroundColor Cyan
    }

    if ($PAK) {
        Write-Host "Boot Prompt: ENABLED" -ForegroundColor Cyan
    } else {
        Write-Host "Boot Prompt: DISABLED (default)" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "Burn this ISO to a USB drive or boot from it in a VM." -ForegroundColor Yellow
    Write-Host ""
    #endregion

    # Cleanup working directory
    Write-DeploymentLog "Cleaning up working directory..." -Level Info
    Remove-Item -Path $workingPath -Recurse -Force -ErrorAction SilentlyContinue

    exit 0
}
catch {
    Write-DeploymentLog "========================================" -Level Error
    Write-DeploymentLog "BUILD FAILED" -Level Error
    Write-DeploymentLog "========================================" -Level Error
    Write-DeploymentLog "Error: $($_.Exception.Message)" -Level Error
    Write-DeploymentLog "Stack trace: $($_.ScriptStackTrace)" -Level Error

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ISO Build Failed!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    # Attempt cleanup
    if ($mountPath -and (Test-Path $mountPath)) {
        Write-Host "Attempting to dismount image..." -ForegroundColor Yellow
        dism.exe /Unmount-Image /MountDir:"$mountPath" /Discard | Out-Null
    }

    exit 1
}

#endregion Main Script Logic
