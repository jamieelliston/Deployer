# Deployment configuration example - Windows 11 Pro from FFU (fast deployment)
# Fast FFU-based deployment with minimal customization
# This configuration file can be signed with Authenticode signatures

return @{
    deploymentInfo = @{
        name = "Windows 11 Pro FFU Fast Deployment"
        version = "1.0.0"
        description = "Fast FFU-based deployment with minimal customization"
    }

    imageSource = @{
        type = "FFU"
        location = @{
            blobUrl = "https://mystorageaccount.blob.core.windows.net/images/Win11_Pro_Master.ffu"
            authType = "SAS"
            sasToken = "sp=r&st=2025-01-01T00:00:00Z&se=2025-12-31T23:59:59Z&spr=https&sv=2021-06-08&sr=b&sig=EXAMPLE_SIGNATURE"
        }
    }

    diskConfiguration = @{
        diskNumber = 0
        partitionStyle = "GPT"
        cleanDisk = $true
    }

    customization = @{
        drivers = @{
            enabled = $false
        }
        registry = @{
            enabled = $false
        }
        files = @{
            enabled = $false
        }
        autopilot = @{
            enabled = $true
            configurationFile = "https://mystorageaccount.blob.core.windows.net/autopilot/AutopilotConfigurationFile.json"
            authType = "Anonymous"
        }
        unattend = @{
            enabled = $false
        }
    }

    logging = @{
        logPath = "X:\Deploy\Logs\Deployment"
        logLevel = "Info"
        copyLogsToImage = $true
    }
}
