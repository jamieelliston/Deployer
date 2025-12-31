# Bootstrap configuration - Azure Blob with anonymous access
# Validates package via thumbprint validation
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeploymentPackage.zip"
        authType = "Anonymous"
        # NOTE: catalogUrl removed - Deploy-Windows.ps1 signature validated directly
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
        # logPath = "X:\Deploy\Logs\Bootstrap.log"  # Optional: Let script use defaults based on -TestMode
        # In test mode (-TestMode), defaults to C:\DeploymentTest\Deploy\Logs\Bootstrap
        # In WinPE, defaults to X:\Deploy\Logs\Bootstrap
        # If specified with X:\ path, automatically transformed to C:\DeploymentTest\ in test mode
        logLevel = "Info"
    }
}
