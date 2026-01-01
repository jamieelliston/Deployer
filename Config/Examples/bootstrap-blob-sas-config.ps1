# Bootstrap configuration with SAS token authentication
# Validates Deploy-Windows.ps1 signature with mixed thumbprint and CN validation
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeploymentPackage.zip"
        packageHashUrl = "https://mystorageaccount.blob.core.windows.net/deployment/deployment-package-hash.ps1?sp=r&st=2024-01-01T00:00:00Z&se=2024-12-31T23:59:59Z&sv=2023-01-03&sr=b&sig=HASH_SAS_SIGNATURE"
        authType = "SAS"
        sasToken = "sp=r&st=2024-01-01T00:00:00Z&se=2024-12-31T23:59:59Z&sv=2023-01-03&sr=b&sig=SAMPLE_SIGNATURE"
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "Thumbprint:A1B2C3D4E5F6789012345678901234567890ABCD"
            "CN:Contoso Code Signing"
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
        authType = "SAS"                    # Use SAS token authentication
        sasToken = "sp=r&st=2024-01-01T00:00:00Z&se=2024-12-31T23:59:59Z&sv=2023-01-03&sr=b&sig=SAMPLE_SIGNATURE"
        requireValidSignature = $true
        enableVersionCheck = $true
        forceUpdate = $false
    }
}
