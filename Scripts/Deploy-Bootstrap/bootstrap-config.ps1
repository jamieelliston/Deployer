# Bootstrap configuration - Azure Blob with anonymous access
# Validates package via thumbprint validation
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://raw.githubusercontent.com/jamieelliston/Deployer/refs/heads/master/Scripts/Deploy-Bootstrap.zip"
        authType = "Anonymous"
        # NOTE: catalogUrl removed - Deploy-Windows.ps1 signature validated directly
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "CN:Local Code Signing Cert"  # Updated to match actual certificate CN
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
