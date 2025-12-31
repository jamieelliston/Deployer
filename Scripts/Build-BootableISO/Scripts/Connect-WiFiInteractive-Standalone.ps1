#Requires -Version 5.1

<#
.SYNOPSIS
    Standalone WiFi connection script for WinPE/WinRE environments
.DESCRIPTION
    Self-contained WiFi network selection and connection tool with automatic
    UI capability detection (Windows Forms GUI or Console TUI).

    This standalone version includes all required functions embedded in the script.
    No external dependencies - just copy this single file to WinPE and run it.

    Features:
    - Automatic UI detection (GUI if .NET available, otherwise TUI)
    - Support for WPA2-Personal and Open networks
    - Hidden network (manual SSID entry) support
    - Connection timeout with progress indication
    - Internet connectivity verification
    - Comprehensive error handling and logging
.PARAMETER ForceTUI
    Force console TUI mode (skip Windows Forms GUI detection)
.PARAMETER TimeoutSeconds
    Connection timeout in seconds (default: 30)
.PARAMETER LogPath
    Custom log file path (default: X:\Deploy\Logs\WiFi-Connection.log)
.EXAMPLE
    .\Connect-WiFiInteractive-Standalone.ps1

    Interactive WiFi selection with automatic UI detection
.EXAMPLE
    .\Connect-WiFiInteractive-Standalone.ps1 -ForceTUI -TimeoutSeconds 60

    Force console mode with 60-second connection timeout
.NOTES
    Author: Deployer Project
    Version: 1.0 Standalone
    Requires: WinRE/WinPE, PowerShell 5.1+, Active WLAN adapter
    Exit Codes:
        0 - Success (connected)
        1 - Error (adapter missing, no networks, connection failed)
        2 - User cancelled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ForceTUI,

    [Parameter(Mandatory = $false)]
    [ValidateRange(10, 300)]
    [int]$TimeoutSeconds = 30,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "X:\Deploy\Logs\WiFi-Connection.log"
)

#region Logging Functions

# Script-level variables for logging configuration
$script:LogConfig = @{
    LogPath = "X:\Deploy\Logs\WiFi-Connection.log"
    LogLevel = "INFO"
    MaxLogSizeMB = 10
    EnableConsole = $true
}

function Initialize-DeploymentLogging {
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "X:\Deploy\Logs\WiFi-Connection.log",

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERRO', 'SUCC')]
        [string]$LogLevel = 'INFO'
    )

    $logDir = Split-Path -Path $LogPath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $header = @"
========================================
WiFi Connection Log - WinRE Deployer
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
PowerShell Version: $($PSVersionTable.PSVersion)
Computer: $env:COMPUTERNAME
========================================

"@

    $header | Out-File -FilePath $LogPath -Encoding UTF8

    $script:LogConfig.LogPath = $LogPath
    $script:LogConfig.LogLevel = $LogLevel

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [SUCC] Logging initialized: $LogPath"
    Write-Host $logEntry -ForegroundColor Green
}

function Write-DeploymentLog {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERRO', 'SUCC')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $script:LogConfig.LogPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    try {
        $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }

    if ($script:LogConfig.EnableConsole) {
        $color = switch ($Level) {
            'INFO' { 'White' }
            'WARN' { 'Yellow' }
            'ERRO' { 'Red' }
            'SUCC' { 'Green' }
        }

        Write-Host $logEntry -ForegroundColor $color
    }
}

function Get-TemporaryPath {
    param(
        [Parameter(Mandatory = $false)]
        [string]$Prefix = "WiFi"
    )

    $tempBase = if (Test-Path "X:\") { "X:\Temp" } else { $env:TEMP }

    if (-not (Test-Path $tempBase)) {
        New-Item -Path $tempBase -ItemType Directory -Force | Out-Null
    }

    $tempName = "{0}_{1}" -f $Prefix, (Get-Date -Format 'yyyyMMdd_HHmmss')
    $tempPath = Join-Path $tempBase $tempName

    New-Item -Path $tempPath -ItemType Directory -Force | Out-Null

    Write-DeploymentLog "Created temporary directory: $tempPath" -Level INFO

    return $tempPath
}

#endregion

#region WiFi Core Functions

function Get-WiFiAdapterStatus {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        Write-DeploymentLog "Checking WiFi adapter status..." -Level INFO

        $wlanService = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue

        if (-not $wlanService) {
            Write-DeploymentLog "WLAN AutoConfig service not found" -Level WARN
            return @{
                Exists = $false
                Enabled = $false
                Name = $null
                InterfaceName = $null
            }
        }

        if ($wlanService.Status -ne 'Running') {
            Write-DeploymentLog "Starting WLAN AutoConfig service..." -Level INFO
            try {
                Start-Service -Name WlanSvc -ErrorAction Stop
                Start-Sleep -Seconds 3
                Write-DeploymentLog "WLAN AutoConfig service started" -Level SUCC
            }
            catch {
                Write-DeploymentLog "Failed to start WLAN service: $_" -Level ERRO
                return @{
                    Exists = $false
                    Enabled = $false
                    Name = $null
                    InterfaceName = $null
                }
            }
        }

        $interfacesOutput = netsh wlan show interfaces 2>&1

        if ($interfacesOutput -match "There is no wireless interface") {
            Write-DeploymentLog "No wireless adapter detected" -Level WARN
            return @{
                Exists = $false
                Enabled = $false
                Name = $null
                InterfaceName = $null
            }
        }

        $interfaceName = $null
        $interfaceState = $null
        $interfaceDescription = $null

        foreach ($line in $interfacesOutput) {
            if ($line -match '^\s*Name\s*:\s*(.+)$') {
                $interfaceName = $matches[1].Trim()
            }
            elseif ($line -match '^\s*Description\s*:\s*(.+)$') {
                $interfaceDescription = $matches[1].Trim()
            }
            elseif ($line -match '^\s*State\s*:\s*(.+)$') {
                $interfaceState = $matches[1].Trim()
            }
        }

        if ($interfaceName) {
            $exists = $true
            $enabled = $interfaceState -notmatch 'disabled'

            Write-DeploymentLog "WiFi adapter found: $interfaceDescription ($interfaceName)" -Level SUCC
            Write-DeploymentLog "Adapter state: $interfaceState" -Level INFO

            return @{
                Exists = $exists
                Enabled = $enabled
                Name = $interfaceDescription
                InterfaceName = $interfaceName
                State = $interfaceState
            }
        }
        else {
            Write-DeploymentLog "Failed to detect wireless adapter information" -Level WARN
            return @{
                Exists = $false
                Enabled = $false
                Name = $null
                InterfaceName = $null
            }
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Failed to check WiFi adapter status: $_" -Level ERRO
        return @{
            Exists = $false
            Enabled = $false
            Name = $null
            InterfaceName = $null
        }
    }
}

function Get-AvailableWiFiNetworks {
    [CmdletBinding()]
    [OutputType([array])]
    param()

    try {
        Write-DeploymentLog "Scanning for available WiFi networks..." -Level INFO

        $scanOutput = netsh wlan show networks mode=bssid 2>&1

        if ($scanOutput -match "There is no wireless interface") {
            Write-DeploymentLog "No wireless interface available for scanning" -Level ERRO
            return @()
        }

        $networks = @()
        $currentNetwork = $null

        foreach ($line in $scanOutput) {
            if ($line -match '^SSID\s+\d+\s*:\s*(.+)$') {
                if ($currentNetwork -and $currentNetwork.SSID) {
                    $networks += $currentNetwork
                }

                $ssid = $matches[1].Trim()
                $currentNetwork = @{
                    SSID = $ssid
                    Signal = 0
                    Authentication = 'Unknown'
                    Encryption = 'Unknown'
                    RadioType = 'Unknown'
                    Channel = 0
                    BSSIDs = @()
                }
            }
            elseif ($line -match '^\s*Network type\s*:\s*(.+)$') {
                if ($currentNetwork) {
                    $currentNetwork.NetworkType = $matches[1].Trim()
                }
            }
            elseif ($line -match '^\s*Authentication\s*:\s*(.+)$') {
                if ($currentNetwork) {
                    $currentNetwork.Authentication = $matches[1].Trim()
                }
            }
            elseif ($line -match '^\s*Encryption\s*:\s*(.+)$') {
                if ($currentNetwork) {
                    $currentNetwork.Encryption = $matches[1].Trim()
                }
            }
            elseif ($line -match '^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]+)$') {
                if ($currentNetwork) {
                    $bssid = $matches[1].Trim()
                    $currentBSSID = @{
                        BSSID = $bssid
                        Signal = 0
                        RadioType = 'Unknown'
                        Channel = 0
                    }
                    $currentNetwork.BSSIDs += $currentBSSID
                }
            }
            elseif ($line -match '^\s*Signal\s*:\s*(\d+)%') {
                $signal = [int]$matches[1]
                if ($currentNetwork) {
                    if ($signal -gt $currentNetwork.Signal) {
                        $currentNetwork.Signal = $signal
                    }
                    if ($currentNetwork.BSSIDs.Count -gt 0) {
                        $currentNetwork.BSSIDs[-1].Signal = $signal
                    }
                }
            }
            elseif ($line -match '^\s*Radio type\s*:\s*(.+)$') {
                $radioType = $matches[1].Trim()
                if ($currentNetwork) {
                    $currentNetwork.RadioType = $radioType
                    if ($currentNetwork.BSSIDs.Count -gt 0) {
                        $currentNetwork.BSSIDs[-1].RadioType = $radioType
                    }
                }
            }
            elseif ($line -match '^\s*Channel\s*:\s*(\d+)') {
                $channel = [int]$matches[1]
                if ($currentNetwork) {
                    $currentNetwork.Channel = $channel
                    if ($currentNetwork.BSSIDs.Count -gt 0) {
                        $currentNetwork.BSSIDs[-1].Channel = $channel
                    }
                }
            }
        }

        if ($currentNetwork -and $currentNetwork.SSID) {
            $networks += $currentNetwork
        }

        $uniqueNetworks = @{}
        foreach ($net in $networks) {
            $ssid = $net.SSID
            if (-not $uniqueNetworks.ContainsKey($ssid)) {
                $uniqueNetworks[$ssid] = $net
            }
            elseif ($net.Signal -gt $uniqueNetworks[$ssid].Signal) {
                $uniqueNetworks[$ssid] = $net
            }
        }

        $sortedNetworks = $uniqueNetworks.Values | Sort-Object -Property Signal -Descending

        Write-DeploymentLog "Found $($sortedNetworks.Count) unique WiFi networks" -Level SUCC

        $topNetworks = $sortedNetworks | Select-Object -First 5
        foreach ($net in $topNetworks) {
            Write-DeploymentLog "  - $($net.SSID) ($($net.Signal)%) [$($net.Authentication)]" -Level INFO
        }

        return $sortedNetworks
    }
    catch {
        Write-DeploymentLog "ERROR: Failed to scan WiFi networks: $_" -Level ERRO
        return @()
    }
}

function New-WiFiProfileXML {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SSID,

        [Parameter(Mandatory = $false)]
        $Password,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Open', 'WPA2-Personal', 'WPA2PSK')]
        [string]$Authentication = 'WPA2-Personal',

        [Parameter(Mandatory = $false)]
        [ValidateSet('none', 'AES', 'TKIP')]
        [string]$Encryption = 'AES',

        [Parameter(Mandatory = $false)]
        [switch]$Hidden,

        [Parameter(Mandatory = $false)]
        [switch]$AutoConnect
    )

    try {
        Write-DeploymentLog "Generating WiFi profile for SSID: $SSID" -Level INFO

        $plainPassword = $null
        if ($Password) {
            if ($Password -is [SecureString]) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            }
            else {
                $plainPassword = $Password
            }
        }

        $escapedSSID = [System.Security.SecurityElement]::Escape($SSID)
        $escapedPassword = if ($plainPassword) { [System.Security.SecurityElement]::Escape($plainPassword) } else { '' }

        $connectionMode = if ($Hidden) { 'manual' } else { 'auto' }
        $connectionType = 'ESS'
        $autoConnectValue = if ($AutoConnect) { 'true' } else { 'false' }

        if ($Authentication -eq 'Open') {
            $profileXML = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$escapedSSID</name>
    <SSIDConfig>
        <SSID>
            <name>$escapedSSID</name>
        </SSID>
        <nonBroadcast>$($Hidden.ToString().ToLower())</nonBroadcast>
    </SSIDConfig>
    <connectionType>$connectionType</connectionType>
    <connectionMode>$connectionMode</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"@
        }
        else {
            $authType = if ($Authentication -eq 'WPA2-Personal') { 'WPA2PSK' } else { $Authentication }

            $profileXML = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$escapedSSID</name>
    <SSIDConfig>
        <SSID>
            <name>$escapedSSID</name>
        </SSID>
        <nonBroadcast>$($Hidden.ToString().ToLower())</nonBroadcast>
    </SSIDConfig>
    <connectionType>$connectionType</connectionType>
    <connectionMode>$connectionMode</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$authType</authentication>
                <encryption>$Encryption</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$escapedPassword</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@
        }

        Write-DeploymentLog "WiFi profile XML generated successfully" -Level SUCC
        return $profileXML
    }
    catch {
        Write-DeploymentLog "ERROR: Failed to generate WiFi profile XML: $_" -Level ERRO
        throw
    }
}

function Connect-WiFiNetwork {
    [CmdletBinding(DefaultParameterSetName = 'NewProfile')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'NewProfile')]
        [string]$SSID,

        [Parameter(Mandatory = $false, ParameterSetName = 'NewProfile')]
        $Password,

        [Parameter(Mandatory = $false, ParameterSetName = 'NewProfile')]
        [ValidateSet('Open', 'WPA2-Personal', 'WPA2PSK')]
        [string]$Authentication,

        [Parameter(Mandatory = $false, ParameterSetName = 'NewProfile')]
        [switch]$Hidden,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30,

        [Parameter(Mandatory = $true, ParameterSetName = 'ExistingProfile')]
        [string]$ProfileName
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'ExistingProfile') {
            $SSID = $ProfileName
            Write-DeploymentLog "Connecting to WiFi network using existing profile: $ProfileName" -Level INFO
        }
        else {
            Write-DeploymentLog "Connecting to WiFi network: $SSID" -Level INFO

            if (-not $Authentication) {
                if ($Password) {
                    $Authentication = 'WPA2-Personal'
                }
                else {
                    $Authentication = 'Open'
                }
            }

            $profileParams = @{
                SSID = $SSID
                Authentication = $Authentication
                AutoConnect = $true
            }

            if ($Password) {
                $profileParams.Password = $Password
            }
            if ($Hidden) {
                $profileParams.Hidden = $true
            }

            $profileXML = New-WiFiProfileXML @profileParams

            $tempPath = Get-TemporaryPath -Prefix "WiFiProfile"
            $profilePath = Join-Path $tempPath "$SSID.xml"
            $profileXML | Out-File -FilePath $profilePath -Encoding UTF8 -Force

            Write-DeploymentLog "Adding WiFi profile to system..." -Level INFO
            $addResult = netsh wlan add profile filename="$profilePath" 2>&1

            if ($LASTEXITCODE -ne 0) {
                if ($addResult -match "already exists") {
                    Write-DeploymentLog "Profile already exists, deleting and re-adding..." -Level WARN
                    netsh wlan delete profile name="$SSID" 2>&1 | Out-Null
                    $addResult = netsh wlan add profile filename="$profilePath" 2>&1

                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to add WiFi profile after deleting existing: $addResult"
                    }
                }
                else {
                    throw "Failed to add WiFi profile: $addResult"
                }
            }

            Write-DeploymentLog "WiFi profile added successfully" -Level SUCC

            Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
        }

        Write-DeploymentLog "Initiating connection to: $SSID" -Level INFO
        $connectResult = netsh wlan connect name="$SSID" 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to initiate connection: $connectResult"
        }

        Write-DeploymentLog "Waiting for connection (timeout: $TimeoutSeconds seconds)..." -Level INFO
        $startTime = Get-Date
        $connected = $false
        $connectionInfo = $null

        while (((Get-Date) - $startTime).TotalSeconds -lt $TimeoutSeconds) {
            $status = Test-WiFiConnection

            if ($status.Connected -and $status.SSID -eq $SSID) {
                $connected = $true
                $connectionInfo = $status
                break
            }

            Start-Sleep -Seconds 2
        }

        if ($connected) {
            Write-DeploymentLog "Successfully connected to: $SSID" -Level SUCC
            Write-DeploymentLog "IP Address: $($connectionInfo.IP)" -Level INFO

            if ($connectionInfo.HasInternet) {
                Write-DeploymentLog "Internet connectivity verified" -Level SUCC
            }
            else {
                Write-DeploymentLog "WARNING: No internet connectivity detected" -Level WARN
            }

            return @{
                Success = $true
                Message = "Connected successfully"
                SSID = $connectionInfo.SSID
                IP = $connectionInfo.IP
                Gateway = $connectionInfo.Gateway
                DNS = $connectionInfo.DNS
                HasInternet = $connectionInfo.HasInternet
            }
        }
        else {
            Write-DeploymentLog "Connection timeout - failed to connect within $TimeoutSeconds seconds" -Level ERRO
            return @{
                Success = $false
                Message = "Connection timeout"
                SSID = $SSID
                IP = $null
                Gateway = $null
                DNS = $null
                HasInternet = $false
            }
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Failed to connect to WiFi network: $_" -Level ERRO
        return @{
            Success = $false
            Message = $_.Exception.Message
            SSID = $SSID
            IP = $null
            Gateway = $null
            DNS = $null
            HasInternet = $false
        }
    }
}

function Test-WiFiConnection {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$TestInternet = $true
    )

    try {
        $interfacesOutput = netsh wlan show interfaces 2>&1

        if ($interfacesOutput -match "There is no wireless interface") {
            return @{
                Connected = $false
                SSID = $null
                IP = $null
                Gateway = $null
                DNS = $null
                HasInternet = $false
            }
        }

        $state = $null
        $ssid = $null
        $signal = 0

        foreach ($line in $interfacesOutput) {
            if ($line -match '^\s*State\s*:\s*(.+)$') {
                $state = $matches[1].Trim()
            }
            elseif ($line -match '^\s*SSID\s*:\s*(.+)$') {
                $ssid = $matches[1].Trim()
            }
            elseif ($line -match '^\s*Signal\s*:\s*(\d+)%') {
                $signal = [int]$matches[1]
            }
        }

        if ($state -ne 'connected') {
            return @{
                Connected = $false
                SSID = $null
                IP = $null
                Gateway = $null
                DNS = $null
                HasInternet = $false
            }
        }

        $ip = $null
        $gateway = $null
        $dns = $null

        try {
            $adapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'wireless|wi-fi|wlan' -and $_.Status -eq 'Up' } | Select-Object -First 1

            if ($adapter) {
                $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($ipConfig) {
                    $ip = $ipConfig.IPAddress
                }

                $route = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
                if ($route) {
                    $gateway = $route.NextHop
                }

                $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($dnsServers -and $dnsServers.ServerAddresses) {
                    $dns = $dnsServers.ServerAddresses -join ', '
                }
            }
        }
        catch {
            Write-DeploymentLog "WARNING: Failed to get IP configuration: $_" -Level WARN
        }

        $hasInternet = $false
        if ($TestInternet -and $ip) {
            try {
                $pingResult = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue
                $hasInternet = $pingResult
            }
            catch {
                $hasInternet = $false
            }
        }

        return @{
            Connected = $true
            SSID = $ssid
            IP = $ip
            Gateway = $gateway
            DNS = $dns
            Signal = $signal
            HasInternet = $hasInternet
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Failed to test WiFi connection: $_" -Level ERRO
        return @{
            Connected = $false
            SSID = $null
            IP = $null
            Gateway = $null
            DNS = $null
            HasInternet = $false
        }
    }
}

#endregion

#region WiFi TUI Functions

function Get-SignalBars {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [int]$SignalPercent,

        [Parameter(Mandatory = $false)]
        [int]$BarCount = 10
    )

    $filledBars = [Math]::Round(($SignalPercent / 100) * $BarCount)
    $emptyBars = $BarCount - $filledBars

    $filled = [char]0x2588
    $empty = [char]0x2591

    return ($filled.ToString() * $filledBars) + ($empty.ToString() * $emptyBars)
}

function Show-WiFiMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Networks,

        [Parameter(Mandatory = $false)]
        [int]$MaxDisplay = 20
    )

    try {
        Clear-Host

        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "║          WiFi Network Selection - WinRE Deployer         ║" -ForegroundColor Cyan
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""

        if ($Networks.Count -eq 0) {
            Write-Host "No WiFi networks found!" -ForegroundColor Red
            Write-Host ""
            Write-Host "Options:" -ForegroundColor Yellow
            Write-Host "  R - Refresh scan" -ForegroundColor Cyan
            Write-Host "  M - Manual SSID entry" -ForegroundColor Cyan
            Write-Host "  Q - Quit" -ForegroundColor Red
            Write-Host ""
        }
        else {
            Write-Host "Available Networks:" -ForegroundColor White
            Write-Host ""

            $displayCount = [Math]::Min($Networks.Count, $MaxDisplay)

            for ($i = 0; $i -lt $displayCount; $i++) {
                $network = $Networks[$i]
                $number = $i + 1

                $signalBars = Get-SignalBars -SignalPercent $network.Signal

                $securityColor = if ($network.Authentication -eq 'Open') { 'Red' } else { 'Green' }

                $ssidDisplay = if ($network.SSID.Length -gt 25) {
                    $network.SSID.Substring(0, 22) + "..."
                } else {
                    $network.SSID.PadRight(25)
                }

                Write-Host "  $number. " -NoNewline -ForegroundColor White
                Write-Host "$signalBars " -NoNewline -ForegroundColor Yellow
                Write-Host "($($network.Signal.ToString().PadLeft(3))%)  " -NoNewline -ForegroundColor Gray
                Write-Host "$ssidDisplay" -NoNewline -ForegroundColor White
                Write-Host " [$($network.Authentication)]" -ForegroundColor $securityColor
            }

            if ($Networks.Count -gt $MaxDisplay) {
                Write-Host ""
                Write-Host "  ... and $($Networks.Count - $MaxDisplay) more networks" -ForegroundColor Gray
            }

            Write-Host ""
        }

        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  R - Refresh scan" -ForegroundColor Cyan
        Write-Host "  M - Manual SSID entry (hidden networks)" -ForegroundColor Cyan
        Write-Host "  S - Skip WiFi configuration" -ForegroundColor Yellow
        Write-Host "  Q - Quit" -ForegroundColor Red
        Write-Host ""

        $validSelection = $false
        $selection = $null

        while (-not $validSelection) {
            Write-Host "Selection: " -NoNewline -ForegroundColor White
            $input = Read-Host

            if ([string]::IsNullOrWhiteSpace($input)) {
                Write-Host "Please enter a valid selection" -ForegroundColor Red
                continue
            }

            $input = $input.Trim().ToUpper()

            if ($input -eq 'R') {
                return "REFRESH"
            }
            elseif ($input -eq 'M') {
                Write-Host ""
                Write-Host "Enter SSID (or press Enter to cancel): " -NoNewline -ForegroundColor Cyan
                $manualSSID = Read-Host

                if ([string]::IsNullOrWhiteSpace($manualSSID)) {
                    return "REFRESH"
                }

                Write-Host "Authentication type:" -ForegroundColor Cyan
                Write-Host "  1 - WPA2-Personal (password required)" -ForegroundColor White
                Write-Host "  2 - Open (no password)" -ForegroundColor White
                Write-Host "Selection: " -NoNewline -ForegroundColor White
                $authChoice = Read-Host

                $authentication = if ($authChoice -eq '2') { 'Open' } else { 'WPA2-Personal' }

                return @{
                    SSID = $manualSSID.Trim()
                    Signal = 0
                    Authentication = $authentication
                    Encryption = if ($authentication -eq 'Open') { 'none' } else { 'AES' }
                    RadioType = 'Unknown'
                    Channel = 0
                    NetworkType = 'Infrastructure'
                    BSSIDs = @()
                    IsManualEntry = $true
                }
            }
            elseif ($input -eq 'S') {
                return "SKIP"
            }
            elseif ($input -eq 'Q') {
                return "QUIT"
            }
            elseif ($input -match '^\d+$') {
                $index = [int]$input - 1

                if ($index -ge 0 -and $index -lt $Networks.Count) {
                    return $Networks[$index]
                }
                else {
                    Write-Host "Invalid selection. Please enter a number between 1 and $($Networks.Count)" -ForegroundColor Red
                }
            }
            else {
                Write-Host "Invalid input. Please enter a number, R, M, S, or Q" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Menu display failed: $_" -Level ERRO
        return "QUIT"
    }
}

function Read-WiFiPassword {
    [CmdletBinding()]
    [OutputType([SecureString])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SSID,

        [Parameter(Mandatory = $false)]
        [switch]$AllowEmpty
    )

    try {
        Write-Host ""
        Write-Host "─────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "Network: " -NoNewline -ForegroundColor Cyan
        Write-Host $SSID -ForegroundColor White
        Write-Host "─────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Enter password (or press Esc to cancel):" -ForegroundColor Cyan
        Write-Host "Password: " -NoNewline -ForegroundColor White

        $securePassword = New-Object System.Security.SecureString
        $passwordChars = @()

        while ($true) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

            if ($key.VirtualKeyCode -eq 13) {
                Write-Host ""

                if ($securePassword.Length -eq 0 -and -not $AllowEmpty) {
                    Write-Host "Password cannot be empty. Please try again." -ForegroundColor Red
                    Write-Host "Password: " -NoNewline -ForegroundColor White
                    $securePassword = New-Object System.Security.SecureString
                    $passwordChars = @()
                    continue
                }

                return $securePassword
            }
            elseif ($key.VirtualKeyCode -eq 27) {
                Write-Host ""
                Write-Host "Password entry cancelled" -ForegroundColor Yellow
                return $null
            }
            elseif ($key.VirtualKeyCode -eq 8) {
                if ($securePassword.Length -gt 0) {
                    $securePassword.RemoveAt($securePassword.Length - 1)
                    $passwordChars = $passwordChars[0..($passwordChars.Length - 2)]
                    Write-Host "`r" -NoNewline
                    Write-Host "Password: " -NoNewline -ForegroundColor White
                    Write-Host ("*" * $securePassword.Length) -NoNewline
                    Write-Host " " -NoNewline
                    Write-Host "`r" -NoNewline
                    Write-Host "Password: " -NoNewline -ForegroundColor White
                    Write-Host ("*" * $securePassword.Length) -NoNewline
                }
            }
            elseif ($key.Character -and -not [char]::IsControl($key.Character)) {
                $securePassword.AppendChar($key.Character)
                $passwordChars += $key.Character
                Write-Host "*" -NoNewline -ForegroundColor White
            }
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Password input failed: $_" -Level ERRO
        return $null
    }
}

function Show-WiFiStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo
    )

    try {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║              WiFi Connection Successful                  ║" -ForegroundColor Green
        Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green

        $ssidLine = "║  Network:        " + $ConnectionInfo.SSID.PadRight(37) + "║"
        Write-Host $ssidLine -ForegroundColor White

        $ipDisplay = if ($ConnectionInfo.IP) { $ConnectionInfo.IP } else { "Not assigned" }
        $ipLine = "║  IP Address:     " + $ipDisplay.PadRight(37) + "║"
        Write-Host $ipLine -ForegroundColor White

        if ($ConnectionInfo.Gateway) {
            $gatewayLine = "║  Gateway:        " + $ConnectionInfo.Gateway.PadRight(37) + "║"
            Write-Host $gatewayLine -ForegroundColor White
        }

        if ($ConnectionInfo.DNS) {
            $dnsDisplay = if ($ConnectionInfo.DNS.Length -gt 37) {
                $ConnectionInfo.DNS.Substring(0, 34) + "..."
            } else {
                $ConnectionInfo.DNS
            }
            $dnsLine = "║  DNS Servers:    " + $dnsDisplay.PadRight(37) + "║"
            Write-Host $dnsLine -ForegroundColor White
        }

        if ($ConnectionInfo.Signal -and $ConnectionInfo.Signal -gt 0) {
            $signalBars = Get-SignalBars -SignalPercent $ConnectionInfo.Signal
            $signalLine = "║  Signal:         $signalBars ($($ConnectionInfo.Signal)%)" + (" " * (37 - 15 - $signalBars.Length - $ConnectionInfo.Signal.ToString().Length - 3)) + "║"
            Write-Host $signalLine -ForegroundColor Yellow
        }

        Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Green
        $internetStatus = if ($ConnectionInfo.HasInternet) {
            "✓ Internet connectivity verified"
        } else {
            "✗ No internet connectivity detected"
        }
        $internetColor = if ($ConnectionInfo.HasInternet) { 'Green' } else { 'Yellow' }
        $internetLine = "║  " + $internetStatus.PadRight(55) + "║"
        Write-Host $internetLine -ForegroundColor $internetColor

        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-DeploymentLog "ERROR: Status display failed: $_" -Level ERRO
    }
}

function Show-WiFiError {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ErrorMessage,

        [Parameter(Mandatory = $false)]
        [string]$SSID,

        [Parameter(Mandatory = $false)]
        [switch]$ShowRetryOptions = $true
    )

    try {
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║              WiFi Connection Failed                      ║" -ForegroundColor Red
        Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Red

        if ($SSID) {
            $ssidLine = "║  Network:        " + $SSID.PadRight(37) + "║"
            Write-Host $ssidLine -ForegroundColor White
            Write-Host "╠══════════════════════════════════════════════════════════╣" -ForegroundColor Red
        }

        $errorLines = $ErrorMessage -split "`n"
        foreach ($line in $errorLines) {
            if ($line.Length -gt 55) {
                $chunks = [regex]::Matches($line, '.{1,55}')
                foreach ($chunk in $chunks) {
                    $errorLine = "║  " + $chunk.Value.PadRight(55) + "║"
                    Write-Host $errorLine -ForegroundColor Yellow
                }
            }
            else {
                $errorLine = "║  " + $line.PadRight(55) + "║"
                Write-Host $errorLine -ForegroundColor Yellow
            }
        }

        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""

        if ($ShowRetryOptions) {
            Write-Host "Options:" -ForegroundColor Yellow
            Write-Host "  R - Retry connection" -ForegroundColor Cyan
            Write-Host "  B - Back to network selection" -ForegroundColor Cyan
            Write-Host "  Q - Quit" -ForegroundColor Red
            Write-Host ""
            Write-Host "Selection: " -NoNewline -ForegroundColor White
            $choice = Read-Host

            switch ($choice.ToUpper()) {
                'R' { return "RETRY" }
                'B' { return "BACK" }
                'Q' { return "QUIT" }
                default { return "BACK" }
            }
        }
        else {
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return "BACK"
        }
    }
    catch {
        Write-DeploymentLog "ERROR: Error display failed: $_" -Level ERRO
        return "QUIT"
    }
}

#endregion

#region WiFi Forms Functions (Optional - GUI Mode)

function Test-WindowsFormsAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop

        Write-DeploymentLog "Windows Forms assemblies loaded successfully" -Level INFO
        return $true
    }
    catch {
        Write-DeploymentLog "Windows Forms not available: $_" -Level WARN
        Write-DeploymentLog "GUI mode requires WinPE-NetFx package in WinRE image" -Level INFO
        return $false
    }
}

#endregion

#region Main Script Execution

# Initialize logging
try {
    Initialize-DeploymentLogging -LogPath $LogPath -LogLevel 'INFO'
}
catch {
    Write-Error "Failed to initialize logging: $_"
    exit 1
}

# Main execution
try {
    Write-DeploymentLog "========================================" -Level INFO
    Write-DeploymentLog "  WiFi Connection - WinRE Deployer" -Level INFO
    Write-DeploymentLog "  STANDALONE VERSION" -Level INFO
    Write-DeploymentLog "========================================" -Level INFO
    Write-DeploymentLog "Script version: 1.0 Standalone" -Level INFO
    Write-DeploymentLog "PowerShell version: $($PSVersionTable.PSVersion)" -Level INFO
    Write-DeploymentLog "Connection timeout: $TimeoutSeconds seconds" -Level INFO
    Write-Host ""

    # Step 1: Validate WiFi adapter status
    Write-DeploymentLog "Validating WiFi adapter status..." -Level INFO
    $adapterStatus = Get-WiFiAdapterStatus

    if (-not $adapterStatus.Exists) {
        Write-DeploymentLog "ERROR: No WiFi adapter detected" -Level ERRO
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║              No WiFi Adapter Detected                    ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "No wireless adapter was found on this system." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Possible solutions:" -ForegroundColor Cyan
        Write-Host "  1. Connect via wired Ethernet instead" -ForegroundColor White
        Write-Host "  2. Add WiFi drivers to WinRE image" -ForegroundColor White
        Write-Host "  3. Ensure wireless adapter is properly connected" -ForegroundColor White
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }

    if (-not $adapterStatus.Enabled) {
        Write-DeploymentLog "WARNING: WiFi adapter is disabled" -Level WARN
        Write-Host "WiFi adapter appears to be disabled. Please enable it and try again." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }

    Write-DeploymentLog "WiFi adapter validated: $($adapterStatus.Name)" -Level SUCC

    # Step 2: Check current connection status
    Write-DeploymentLog "Checking current WiFi connection status..." -Level INFO
    $currentStatus = Test-WiFiConnection

    if ($currentStatus.Connected) {
        Write-DeploymentLog "Already connected to: $($currentStatus.SSID)" -Level INFO
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║            Already Connected to WiFi                     ║" -ForegroundColor Yellow
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Current connection:" -ForegroundColor Cyan
        Write-Host "  Network: " -NoNewline -ForegroundColor White
        Write-Host $currentStatus.SSID -ForegroundColor Cyan
        Write-Host "  IP Address: " -NoNewline -ForegroundColor White
        Write-Host $currentStatus.IP -ForegroundColor Cyan
        if ($currentStatus.HasInternet) {
            Write-Host "  Internet: " -NoNewline -ForegroundColor White
            Write-Host "Connected" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "Do you want to connect to a different network? (Y/N): " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host

        if ($choice -ne 'Y' -and $choice -ne 'y') {
            Write-DeploymentLog "User chose to keep current connection" -Level INFO
            exit 0
        }

        Write-DeploymentLog "User chose to change network" -Level INFO
    }

    # Step 3: Scan for available networks
    Write-DeploymentLog "Scanning for available WiFi networks..." -Level INFO
    Write-Host "Scanning for WiFi networks..." -ForegroundColor Cyan
    Write-Host ""

    $networks = Get-AvailableWiFiNetworks

    if ($networks.Count -eq 0) {
        Write-DeploymentLog "ERROR: No WiFi networks found" -Level ERRO
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║              No WiFi Networks Found                      ║" -ForegroundColor Red
        Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "No wireless networks were detected." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please check:" -ForegroundColor Cyan
        Write-Host "  - WiFi router is powered on" -ForegroundColor White
        Write-Host "  - You are within range of a wireless network" -ForegroundColor White
        Write-Host "  - Wireless network is broadcasting (not hidden)" -ForegroundColor White
        Write-Host ""
        Write-Host "You can use manual SSID entry for hidden networks." -ForegroundColor Gray
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }

    Write-DeploymentLog "Found $($networks.Count) available networks" -Level SUCC

    # Step 4: Interactive selection loop (Console TUI only for standalone)
    Write-DeploymentLog "Using Console TUI mode (standalone version)" -Level INFO

    $exitLoop = $false
    $connectionAttempts = 0
    $maxAttempts = 3

    while (-not $exitLoop) {
        $selection = Show-WiFiMenu -Networks $networks

        if ($selection -eq $null) {
            Write-DeploymentLog "User cancelled network selection" -Level INFO
            exit 2
        }
        elseif ($selection -eq "REFRESH") {
            Write-DeploymentLog "Refreshing network list..." -Level INFO
            Write-Host "Rescanning for networks..." -ForegroundColor Cyan
            $networks = Get-AvailableWiFiNetworks

            if ($networks.Count -eq 0) {
                Write-Host "No networks found after refresh" -ForegroundColor Red
                Write-Host ""
                Write-Host "Press any key to try again..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            continue
        }
        elseif ($selection -eq "SKIP") {
            Write-DeploymentLog "User skipped WiFi configuration" -Level INFO
            Write-Host ""
            Write-Host "WiFi configuration skipped" -ForegroundColor Yellow
            exit 0
        }
        elseif ($selection -eq "QUIT") {
            Write-DeploymentLog "User quit application" -Level INFO
            exit 2
        }
        elseif ($selection -is [hashtable]) {
            $selectedNetwork = $selection
            Write-DeploymentLog "User selected network: $($selectedNetwork.SSID)" -Level INFO

            $password = $null
            $isOpen = $selectedNetwork.Authentication -eq 'Open'

            if (-not $isOpen) {
                $password = Read-WiFiPassword -SSID $selectedNetwork.SSID

                if ($password -eq $null) {
                    Write-DeploymentLog "Password entry cancelled" -Level WARN
                    continue
                }
            }
            else {
                Write-DeploymentLog "Open network selected - no password required" -Level INFO
            }

            Write-DeploymentLog "Attempting connection to: $($selectedNetwork.SSID)" -Level INFO
            $connectionAttempts++

            try {
                $connectParams = @{
                    SSID = $selectedNetwork.SSID
                    TimeoutSeconds = $TimeoutSeconds
                }

                if ($password) {
                    $connectParams.Password = $password
                }

                if ($selectedNetwork.IsManualEntry) {
                    $connectParams.Hidden = $true
                }

                if ($selectedNetwork.Authentication) {
                    $connectParams.Authentication = $selectedNetwork.Authentication
                }

                $result = Connect-WiFiNetwork @connectParams

                if ($result.Success) {
                    Write-DeploymentLog "Successfully connected to: $($selectedNetwork.SSID)" -Level SUCC
                    Write-DeploymentLog "IP Address: $($result.IP)" -Level INFO

                    if ($result.HasInternet) {
                        Write-DeploymentLog "Internet connectivity verified" -Level SUCC
                    }
                    else {
                        Write-DeploymentLog "WARNING: No internet connectivity" -Level WARN
                    }

                    Show-WiFiStatus -ConnectionInfo $result

                    Write-Host "Press any key to exit..." -ForegroundColor Green
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                    exit 0
                }
                else {
                    Write-DeploymentLog "Connection failed: $($result.Message)" -Level ERRO

                    $errorChoice = Show-WiFiError -ErrorMessage $result.Message -SSID $selectedNetwork.SSID

                    if ($errorChoice -eq "RETRY") {
                        if ($connectionAttempts -ge $maxAttempts) {
                            Write-Host ""
                            Write-Host "Maximum connection attempts ($maxAttempts) reached" -ForegroundColor Red
                            Write-Host "Returning to network selection..." -ForegroundColor Yellow
                            Write-Host ""
                            Start-Sleep -Seconds 2
                            $connectionAttempts = 0
                            continue
                        }
                        continue
                    }
                    elseif ($errorChoice -eq "BACK") {
                        $connectionAttempts = 0
                        continue
                    }
                    elseif ($errorChoice -eq "QUIT") {
                        exit 2
                    }
                }
            }
            catch {
                Write-DeploymentLog "ERROR: Connection attempt failed: $_" -Level ERRO

                $errorChoice = Show-WiFiError -ErrorMessage $_.Exception.Message -SSID $selectedNetwork.SSID

                if ($errorChoice -eq "QUIT") {
                    exit 2
                }
                else {
                    $connectionAttempts = 0
                    continue
                }
            }
        }
        else {
            Write-DeploymentLog "ERROR: Invalid selection type: $($selection.GetType().Name)" -Level ERRO
            continue
        }
    }
}
catch {
    Write-DeploymentLog "ERROR: Unhandled exception: $_" -Level ERRO
    Write-DeploymentLog "Stack trace: $($_.ScriptStackTrace)" -Level ERRO

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║              Critical Error Occurred                     ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "An unexpected error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please check the log file for details:" -ForegroundColor Cyan
    Write-Host $LogPath -ForegroundColor White
    Write-Host ""
    Write-Host "Press any key to exit..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
finally {
    Write-DeploymentLog "WiFi connection script completed" -Level INFO
    Write-DeploymentLog "========================================" -Level INFO
}

#endregion
