# Bootstrap configuration - Azure Blob with anonymous access
# Downloads Deploy-Bootstrap.ps1 directly for self-update (no ZIP extraction)
# Validates script signature via thumbprint validation
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://raw.githubusercontent.com/jamieelliston/Deployer/refs/heads/master/Scripts/Deploy-Bootstrap.zip"
        authType = "Anonymous"
    }

    bootstrapUpdate = @{
        enabled = $true
        # Direct .ps1 script URL for self-update (replaces packageUrl)
        scriptUrl = "https://raw.githubusercontent.com/jamieelliston/Deployer/refs/heads/master/Scripts/Deploy-Bootstrap/Deploy-Bootstrap.ps1"
        # Version file URL (optional - auto-derived from scriptUrl if not specified)
        versionFileUrl = "https://raw.githubusercontent.com/jamieelliston/Deployer/refs/heads/master/Config/Examples/DeployBootstrap-version.ps1"
    }

    validation = @{
        enableSignatureCheck = $true
        trustedPublishers = @(
            "CN:Local Code Signing Cert"  # Updated to match actual certificate CN
        )
        requireValidSignature = $true
        # Note: Using script signature validation only - catalog validation removed
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
