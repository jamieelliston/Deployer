# Bootstrap Version Metadata
# Example version file for bootstrap self-update feature
# This file should be hosted alongside DeployBootstrap.zip
#
# URL pattern: Replace ".zip" with "-version.ps1" in bootstrap package URL
# Example: DeployBootstrap.zip -> DeployBootstrap-version.ps1

return @{
    # Semantic version string (Major.Minor.Patch)
    version = "1.2.0"

    # Release date in ISO format
    releaseDate = "2026-01-03"

    # Minimum PowerShell version required
    minimumPSVersion = "5.1"

    # List of changes in this version
    changes = @(
        "Removed catalog-based validation (now using script signature validation only)"
        "Simplified bootstrap update process by removing catalog download phase"
        "Reduced bootstrap package size and download time"
        "Improved architecture alignment with script signature validation approach"
    )

    # Flag indicating breaking changes
    breaking = $false

    # Optional: Additional metadata
    releaseNotes = "https://github.com/jamieelliston/Deployer/releases/tag/v1.2.0"
}
