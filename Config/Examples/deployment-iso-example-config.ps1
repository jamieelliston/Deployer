# Deployment configuration example - Windows 11 Pro from ISO with customizations
# Standard Windows 11 Pro deployment with Autopilot, drivers, and corporate customizations
# This configuration file can be signed with Authenticode signatures

return @{
    deploymentInfo = @{
        name = "Windows 11 Pro Standard Deployment"
        version = "1.0.0"
        description = "Standard Windows 11 Pro deployment with Autopilot, drivers, and corporate customizations"
    }

    imageSource = @{
        type = "ISO"
        location = @{
            blobUrl = "https://mystorageaccount.blob.core.windows.net/images/Win11_23H2_Pro.iso"
            authType = "Anonymous"
        }
        imageIndex = 6
        edition = "Windows 11 Pro"
    }

    # Optional: Image validation using catalog files (Test-FileCatalog)
    imageValidation = @{
        enabled = $true
        # catalogUrl is optional - auto-discovered by replacing .iso/.wim/.ffu with .cat
        # catalogUrl = "https://mystorageaccount.blob.core.windows.net/images/Win11_23H2_Pro.cat"
        requireValidCatalog = $false  # Set to $true to fail deployment if catalog validation fails
        enableSignatureCheck = $true  # Verify catalog file signature
        trustedPublishers = @(
            "CN:Contoso Corporation"          # Certificate subject CN contains match
            # "Thumbprint:A1B2C3D4E5F6..."    # Or exact certificate thumbprint
        )
    }

    diskConfiguration = @{
        diskNumber = 0
        partitionStyle = "GPT"
        partitions = @{
            efiSize = 100
            msrSize = 16
            recoverySize = 1024
            windowsSize = 0  # 0 = use remaining space
        }
        cleanDisk = $true
    }

    customization = @{
        drivers = @{
            enabled = $true
            sources = @(
                @{
                    path = "https://mystorageaccount.blob.core.windows.net/drivers/Dell-Latitude-7490.zip"
                    recursive = $true
                    authType = "Anonymous"
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
                @{
                    hive = "HKLM\SYSTEM"
                    path = "CurrentControlSet\Control\TimeZoneInformation"
                    name = "TimeZoneKeyName"
                    value = "Pacific Standard Time"
                    type = "String"
                }
            )
        }

        files = @{
            enabled = $true
            copyOperations = @(
                @{
                    source = "https://mystorageaccount.blob.core.windows.net/config/company-wallpaper.jpg"
                    destination = "Windows\Web\Wallpaper\Company\wallpaper.jpg"
                    authType = "Anonymous"
                    overwrite = $true
                }
                @{
                    source = "https://mystorageaccount.blob.core.windows.net/config/company-logo.png"
                    destination = "ProgramData\CompanyAssets\logo.png"
                    authType = "Anonymous"
                    overwrite = $true
                }
            )
        }

        autopilot = @{
            enabled = $true
            configurationFile = "https://mystorageaccount.blob.core.windows.net/autopilot/AutopilotConfigurationFile.json"
            authType = "Anonymous"
            osdCloudConfig = @{
                GroupTag = "StandardDesktop"
                Assign = @{
                    User = "user@contoso.com"
                }
            }
        }

        unattend = @{
            enabled = $true
            unattendFile = "https://mystorageaccount.blob.core.windows.net/config/unattend.xml"
            authType = "Anonymous"
        }
    }

    logging = @{
        logPath = "X:\Deploy\Logs\Deployment"
        logLevel = "Info"
        copyLogsToImage = $true
    }
}
