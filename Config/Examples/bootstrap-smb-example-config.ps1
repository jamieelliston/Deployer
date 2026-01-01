# Bootstrap configuration - Download deployment package from SMB network share
# Validates Deploy-Windows.ps1 signature with multiple trusted publishers
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        uncPath = "\\\\fileserver\\deploymentshare\\Packages\\deployment-package.zip"
        packageHashUrl = "\\\\fileserver\\deploymentshare\\Packages\\deployment-package-hash.ps1"
        authType = "SMB"
        username = "DOMAIN\\deploymentuser"
        password = "SecurePassword123!"
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "CN=Contoso Corporation"
            "CN=IT Department"
        )
        requireValidSignature = $true
    }

    extraction = @{
        targetPath = "X:\Deploy"
        cleanupOnFailure = $true
    }

    logging = @{
        logPath = "X:\Deploy\Logs\Bootstrap"
        logLevel = "Info"
    }

    # Bootstrap self-update configuration (optional)
    bootstrapUpdate = @{
        enabled = $false                    # Set to $true to enable automatic bootstrap updates
        packageUrl = "\\\\fileserver\\deploymentshare\\Packages\\DeployBootstrap.zip"
        authType = "None"                   # SMB uses Windows authentication
        requireValidSignature = $true
        enableVersionCheck = $true
        forceUpdate = $false
    }
}
