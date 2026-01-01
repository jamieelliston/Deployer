# Bootstrap configuration - Azure Blob with anonymous access
# Validates package via thumbprint validation
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeploymentPackage.zip"
        packageHashUrl = "https://mystorageaccount.blob.core.windows.net/deployment/deployment-package-hash.ps1"
        authType = "Anonymous"
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "Thumbprint:A1B2C3D4E5F6789012345678901234567890ABCD"
        )
        requireValidSignature = $true
    }

    extraction = @{
        targetPath = "X:\Deploy"
        cleanupOnFailure = $true
    }

    logging = @{
        logPath = "X:\Deploy\Logs\Bootstrap.log"
        logLevel = "Info"
    }

    # Bootstrap self-update configuration (optional)
    bootstrapUpdate = @{
        enabled = $false                    # Set to $true to enable automatic bootstrap updates
        packageUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeployBootstrap.zip"
        authType = "Anonymous"              # No authentication required
        # versionFileUrl = $null            # Auto-constructed: DeployBootstrap-version.ps1
        # hashFileUrl = $null               # Auto-constructed: DeployBootstrap.ps1
        requireValidSignature = $true       # Require hash validation
        enableVersionCheck = $true          # Check version before downloading
        forceUpdate = $false               # Don't force update if version is same
    }
}
