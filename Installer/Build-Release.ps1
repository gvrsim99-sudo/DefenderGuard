param(
    [ValidateSet("QA","FreeRelease","Production","ArtifactSigning")][string]$SigningMode = "QA",
    [string]$Thumbprint = "",
    [string]$TimestampServer = "",
    [string]$MetadataPath = "",
    [string]$DlibPath = "",
    [string]$SignToolPath = "",
    [string]$UpdateManifestUrl = "",
    [string]$UpdatePackageUrl = "",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
    $Thumbprint = if ($SigningMode -eq "FreeRelease") { "07FBFB60553CC6385383FB7B19A8EB6300BB014B" } else { "371C5721A5A1AFE7EDAA953C9263925C1A5082A7" }
}
$script = Join-Path $PSScriptRoot "Wix7\Build-Wix-Release.ps1"
if (-not (Test-Path -LiteralPath $script)) { throw "WiX release pipeline not found: $script" }

$args = @("-SigningMode",$SigningMode,"-Thumbprint",$Thumbprint,"-Version",$Version)
if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) { $args += @("-TimestampServer",$TimestampServer) }
if (-not [string]::IsNullOrWhiteSpace($MetadataPath)) { $args += @("-MetadataPath",$MetadataPath) }
if (-not [string]::IsNullOrWhiteSpace($DlibPath)) { $args += @("-DlibPath",$DlibPath) }
if (-not [string]::IsNullOrWhiteSpace($SignToolPath)) { $args += @("-SignToolPath",$SignToolPath) }
if (-not [string]::IsNullOrWhiteSpace($UpdateManifestUrl)) { $args += @("-UpdateManifestUrl",$UpdateManifestUrl) }
if (-not [string]::IsNullOrWhiteSpace($UpdatePackageUrl)) { $args += @("-UpdatePackageUrl",$UpdatePackageUrl) }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script @args
exit $LASTEXITCODE