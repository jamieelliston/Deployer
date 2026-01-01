# Bootstrap Package Hash File
# Example hash file for bootstrap self-update validation
# This file should be hosted alongside DeployBootstrap.zip
#
# URL pattern: Replace ".zip" with ".ps1" in bootstrap package URL
# Example: DeployBootstrap.zip -> DeployBootstrap.ps1
#
# To generate hash: Get-FileHash -Path "DeployBootstrap.zip" -Algorithm SHA256
# Then update the 'hash' value below with the output

return @{
    # Hash algorithm (SHA256, SHA512, etc.)
    algorithm = "SHA256"

    # Package hash value (40-character hex string for SHA256)
    # Replace this with actual hash from: Get-FileHash -Path "DeployBootstrap.zip" -Algorithm SHA256
    hash = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"

    # Optional: Additional metadata
    generatedDate = "2025-01-15T12:00:00Z"
    packageVersion = "1.1.0"
    notes = "Example hash file - replace with actual hash value"
}
