param(
    [Parameter(Mandatory)]
    [string]$ProjectFolder
)

# Ensure folder exists
if (-not (Test-Path $ProjectFolder)) {
    Write-Error "Folder does not exist $ProjectFolder"
    exit 1
}

# Prepare paths
$CatName = "Project.cat"
$CdfPath = Join-Path $ProjectFolder "Project.cdf"
$CatPath = Join-Path $ProjectFolder $CatName

Write-Host "ProjectFolder $ProjectFolder"
Write-Host "CDF $CdfPath"
Write-Host "CAT $CatPath"

# --- 1. CREATE CDF FILE -----------------------------------------------------

Write-Host "Creating CDF..."

$cdfHeader = @"
[CatalogHeader]
Name=$CatName
PublicVersion=0x00000001
EncodingType=0x00010001

[CatalogFiles]
"@

# Save CDF header (ASCII is required or MakeCat fails)
Set-Content -Path $CdfPath -Value $cdfHeader -Encoding ASCII

# Add all files (flat folder only)
$files = Get-ChildItem -Path $ProjectFolder -File

foreach ($file in $files) {
    Add-Content -Path $CdfPath -Value "<hash> $($file.Name)" -Encoding ASCII
}

Write-Host "CDF created OK"


# --- 2. RUN MAKECAT ---------------------------------------------------------

Write-Host "Generating catalog file..."

# MakeCat must run from the folder where the files exist
Push-Location $ProjectFolder
try {
    & C:\Code\Deployer\makecat.exe $CdfPath
}
finally {
    Pop-Location
}

if (-not (Test-Path $CatPath)) {
    Write-Error "Catalog was not created. Check formatting in $CdfPath"
    exit 1
}

Write-Host "CAT created OK"


# --- 3. SIGN THE CATALOG ----------------------------------------------------

Write-Host "Signing catalog..."

# Get the first available code-signing certificate
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

if (-not $cert) {
    Write-Error "No code signing certificate found in CurrentUser\My"
    exit 1
}

Set-AuthenticodeSignature `
    -FilePath $CatPath `
    -Certificate $cert `
    -TimestampServer "http://timestamp.digicert.com" `
    | Out-Null

Write-Host "CAT signed successfully"
Write-Host "Completed"
