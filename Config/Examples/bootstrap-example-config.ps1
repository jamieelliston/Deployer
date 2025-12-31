# Bootstrap configuration example
# Downloads and validates deployment package from Azure Blob
# Validates package hash and Deploy-Windows.ps1 script signature
#
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
            "CN=Contoso Code Signing, O=Contoso Corporation, C=US"
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
}
