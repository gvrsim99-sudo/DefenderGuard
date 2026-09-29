param(
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][string]$PackageUrl,
    [string]$ReleaseNotes = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $PackagePath)) {
    throw "Package not found: $PackagePath"
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

$size = (Get-Item -LiteralPath $PackagePath).Length
$hash = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToUpperInvariant()

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Split-Path -Parent $PackagePath) "stable-win-x64.json"
}

$manifest = [ordered]@{
    Version = $Version
    Url = $PackageUrl
    Sha256 = $hash
    SizeBytes = $size
    ReleaseNotes = $ReleaseNotes
}

$json = $manifest | ConvertTo-Json -Depth 4
Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8

Write-Host "UPDATE_MANIFEST_PASS"
Write-Host "Version=$Version"
Write-Host "Url=$PackageUrl"
Write-Host "Sha256=$hash"
Write-Host "SizeBytes=$size"
Write-Host "Output=$OutputPath"
