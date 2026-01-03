# Bootstrap configuration example
# Downloads and validates deployment package from Azure Blob
#
# Validation chain (catalog-first approach):
# 1. Download .cat file and validate signature (BEFORE downloading .zip)
# 2. If signature invalid or untrusted, deployment fails immediately
# 3. Download .zip package (AFTER catalog validated)
# 4. Validate package against catalog using Test-FileCatalog
# 5. Validate Deploy-Windows.ps1 script signature
#
# This configuration file can be signed with Authenticode signatures

return @{
    packageSource = @{
        blobUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeploymentPackage.zip"
        # Catalog file (.cat) is auto-discovered by replacing .zip with .cat
        # Package validation now uses catalog-only approach (no hash files)
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

    # Bootstrap self-update configuration (optional)
    # Supports: Azure Blob, HTTP/HTTPS, SMB/UNC, Local paths
    bootstrapUpdate = @{
        enabled = $false                    # Set to $true to enable automatic bootstrap updates

        # Package URL - can be any of:
        # - Azure Blob: https://storage.blob.core.windows.net/deploy/DeployBootstrap.zip
        # - HTTP/HTTPS: https://updates.company.com/DeployBootstrap.zip
        # - SMB/UNC: \\server\deployment\DeployBootstrap.zip
        # - Local: C:\Updates\DeployBootstrap.zip
        packageUrl = "https://mystorageaccount.blob.core.windows.net/deployment/DeployBootstrap.zip"

        # Authentication type: "Anonymous", "SAS", or "None" (for SMB/Local)
        authType = "Anonymous"

        # SAS token (only required if authType = "SAS")
        sasToken = $null

        # Optional: Override auto-constructed URLs
        # versionFileUrl = $null            # Auto: replaces .zip with -version.ps1
        # Catalog file (.cat) is auto-discovered by replacing .zip with .cat

        requireValidSignature = $true       # Require catalog validation before update
        enableVersionCheck = $true          # Check version before downloading
        forceUpdate = $false               # Download even if version is same/older
    }
}
