# Deployment configuration example - Windows 11 Pro from SMB network share
# Windows 11 Pro deployment with image from network share and drivers from SMB
# This configuration file can be signed with Authenticode signatures

return @{
    deploymentInfo = @{
        name = "Windows 11 Pro SMB Deployment"
        version = "1.0.0"
        description = "Windows 11 Pro deployment with image from network share and drivers from SMB"
    }

    imageSource = @{
        type = "ISO"
        location = @{
            uncPath = "\\fileserver\deploymentshare\Images\Win11_23H2_Pro.iso"
            authType = "SMB"
            username = "DOMAIN\deploymentuser"
            password = "SecurePassword123!"
        }
        imageIndex = 6
        edition = "Windows 11 Pro"
    }

    diskConfiguration = @{
        diskNumber = 0
        partitionStyle = "GPT"
        partitions = @{
            efiSize = 100
            msrSize = 16
            recoverySize = 1024
            windowsSize = 0
        }
        cleanDisk = $true
    }

    customization = @{
        drivers = @{
            enabled = $true
            sources = @(
                @{
                    path = "\\fileserver\deploymentshare\Drivers\Dell-Latitude-7490.zip"
                    recursive = $true
                    authType = "SMB"
                }
            )
            injectionMethod = "Offline"
        }

        registry = @{
            enabled = $true
            modifications = @(
                @{
                    hive = "HKLM\SOFTWARE"
                    path = "Microsoft\Windows\CurrentVersion\OEMInformation"
                    name = "Manufacturer"
                    value = "Contoso Corporation"
                    type = "String"
                }
                @{
                    hive = "HKLM\SOFTWARE"
                    path = "Microsoft\Windows\CurrentVersion\OEMInformation"
                    name = "SupportURL"
                    value = "https://support.contoso.com"
                    type = "String"
                }
            )
        }

        files = @{
            enabled = $true
            copyOperations = @(
                @{
                    source = "\\fileserver\deploymentshare\Config\company-wallpaper.jpg"
                    destination = "Windows\Web\Wallpaper\Company\wallpaper.jpg"
                    authType = "SMB"
                    overwrite = $true
                }
            )
        }

        autopilot = @{
            enabled = $false
        }

        unattend = @{
            enabled = $true
            unattendFile = "\\fileserver\deploymentshare\Config\unattend.xml"
            authType = "SMB"
        }
    }

    logging = @{
        logPath = "X:\Deploy\Logs\Deployment"
        logLevel = "Info"
        copyLogsToImage = $true
    }
}
