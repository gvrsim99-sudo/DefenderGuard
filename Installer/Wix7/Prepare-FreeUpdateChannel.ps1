param(
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][string]$ManifestUrl,
    [Parameter(Mandatory=$true)][string]$PackageUrl,
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $PackagePath)) {
    throw "Package not found: $PackagePath"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Split-Path -Parent $PackagePath) "FreeUpdateChannel"
}
$manifestUri = $null
if (-not [Uri]::TryCreate($ManifestUrl, [UriKind]::Absolute, [ref]$manifestUri) -or
    $manifestUri.Scheme -ne [Uri]::UriSchemeHttps) {
    throw "ManifestUrl must be HTTPS."
}
$packageUri = $null
if (-not [Uri]::TryCreate($PackageUrl, [UriKind]::Absolute, [ref]$packageUri) -or
    $packageUri.Scheme -ne [Uri]::UriSchemeHttps) {
    throw "PackageUrl must be HTTPS."
}
$versionValue = $null
if (-not [Version]::TryParse($Version, [ref]$versionValue) -or $versionValue -le [Version]"0.0.0") {
    throw "Invalid version: $Version"
}
if (-not $PackagePath.EndsWith(".exe", [StringComparison]::OrdinalIgnoreCase)) {
    throw "PackagePath must point to the EXE bundle."
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$hash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToUpperInvariant()
$size = (Get-Item -LiteralPath $PackagePath).Length
$packageName = Split-Path -Leaf $PackagePath

$manifest = [ordered]@{
    Version = $Version
    Url = $PackageUrl
    Sha256 = $hash
    SizeBytes = $size
    ReleaseNotes = "DefenderGuard $Version"
}
$manifestPath = Join-Path $OutputDirectory "stable-win-x64.json"
$checksumPath = Join-Path $OutputDirectory "SHA256SUMS.txt"
Copy-Item -LiteralPath $PackagePath -Destination (Join-Path $OutputDirectory $packageName) -Force
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
"$hash  $packageName" | Set-Content -LiteralPath $checksumPath -Encoding UTF8
Write-Host "FREE_UPDATE_CHANNEL_READY"
Write-Host "Version=$Version"
Write-Host "Package=$packageName"
Write-Host "SizeBytes=$size"
Write-Host "Sha256=$hash"
Write-Host "ManifestUrl=$ManifestUrl"
Write-Host "PackageUrl=$PackageUrl"
Write-Host "OutputDirectory=$OutputDirectory"