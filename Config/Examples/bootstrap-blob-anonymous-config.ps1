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
}
