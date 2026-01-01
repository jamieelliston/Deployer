# Bootstrap Version Metadata
# Example version file for bootstrap self-update feature
# This file should be hosted alongside DeployBootstrap.zip
#
# URL pattern: Replace ".zip" with "-version.ps1" in bootstrap package URL
# Example: DeployBootstrap.zip -> DeployBootstrap-version.ps1

return @{
    # Semantic version string (Major.Minor.Patch)
    version = "1.1.0"

    # Release date in ISO format
    releaseDate = "2025-01-15"

    # Minimum PowerShell version required
    minimumPSVersion = "5.1"

    # List of changes in this version
    changes = @(
        "Add self-update capability with URL-agnostic download support"
        "Fix path handling in test mode for C:\DeploymentTest"
        "Improve error messages and logging"
        "Add support for HTTP/HTTPS, SMB/UNC, and local file paths"
    )

    # Flag indicating breaking changes
    breaking = $false

    # Optional: Additional metadata
    releaseNotes = "https://github.com/yourorg/deployer/releases/tag/v1.1.0"
}
