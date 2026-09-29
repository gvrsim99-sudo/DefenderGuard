param(
    [string]$Thumbprint = "",
    [string]$TimestampServer = "",
    [ValidateSet("Both","Exe","Setup")][string]$Target = "Both",
    [switch]$Production,
    [switch]$FreeRelease,
    [switch]$ArtifactSigning,
    [string]$MetadataPath = "",
    [string]$DlibPath = "",
    [string]$SignToolPath = "",
    [string]$ExePath = "C:\Users\User\Downloads\DefenderGuard-release-1.0.0\DefenderGuard.exe",
    [string]$SetupPath = "C:\Users\User\Downloads\DefenderGuard-installer\DefenderGuard-Setup-1.0.0.exe"
)

$ErrorActionPreference = "Stop"

function Get-CodeSigningCertificate {
    param([string]$CertThumbprint)
    $normalized = ($CertThumbprint -replace "\s", "").ToUpperInvariant()
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized } |
        Select-Object -First 1
    if (-not $cert) { throw "Code-signing certificate not found: $normalized" }
    if (-not $cert.HasPrivateKey) { throw "Certificate has no private key: $normalized" }
    return $cert
}

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -match "\\x64\\signtool\.exe$") { return $cmd.Source }
    $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $roots = @(
        (Join-Path $programFilesX86 "Windows Kits\10\bin"),
        (Join-Path $programFiles "Windows Kits\10\bin")
    )
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath $root) {
            $found = Get-ChildItem -LiteralPath $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } |
                Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    throw "x64 signtool.exe not found. Install a compatible Windows SDK."
}

function Find-ArtifactDlib {
    $base = "C:\Users\User\Downloads\DefenderGuard-signing-tools\ArtifactSigning"
    if (Test-Path -LiteralPath $base) {
        $found = Get-ChildItem -LiteralPath $base -Recurse -Filter "Azure.CodeSigning.Dlib.dll" -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\bin\\x64\\Azure\.CodeSigning\.Dlib\.dll$" } |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "Azure.CodeSigning.Dlib.dll x64 not found. Install Microsoft.ArtifactSigning.Client."
}

if (($Production -or $ArtifactSigning) -and -not $ArtifactSigning -and -not $FreeRelease -and [string]::IsNullOrWhiteSpace($TimestampServer)) {
    throw "Production signing requires an RFC 3161 TimestampServer."
}
if ($FreeRelease -and $ArtifactSigning) { throw "FreeRelease and ArtifactSigning cannot be combined." }
if ($FreeRelease) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { throw "FreeRelease requires the DefenderGuard Release certificate thumbprint." }
}
if ($ArtifactSigning) {
    $Production = $true
    if ([string]::IsNullOrWhiteSpace($MetadataPath)) { throw "Artifact Signing requires MetadataPath." }
    if ([string]::IsNullOrWhiteSpace($DlibPath)) { $DlibPath = Find-ArtifactDlib }
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) { $SignToolPath = Find-SignTool }
    if (-not (Test-Path -LiteralPath $MetadataPath)) { throw "Metadata file not found: $MetadataPath" }
    if (-not (Test-Path -LiteralPath $DlibPath)) { throw "Dlib not found: $DlibPath" }
    if (-not (Test-Path -LiteralPath $SignToolPath)) { throw "SignTool not found: $SignToolPath" }
}

$files = switch ($Target) {
    "Exe" { @($ExePath) }
    "Setup" { @($SetupPath) }
    default { @($ExePath, $SetupPath) }
}
if ($Production) {
    if (-not $ArtifactSigning -and -not $FreeRelease) {
        $productionCert = Get-CodeSigningCertificate -CertThumbprint $Thumbprint
        if ($productionCert.Subject -match "DefenderGuard Local QA") {
            throw "Production signing refuses the DefenderGuard Local QA certificate. Use a public CA-issued OV code-signing certificate."
        }
    }
    $signtool = if ($ArtifactSigning) { $SignToolPath } else { Find-SignTool }
    foreach ($path in $files) {
        if (-not (Test-Path -LiteralPath $path)) { throw "File not found: $path" }
        if ($ArtifactSigning) {
            & $signtool sign /v /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib $DlibPath /dmdf $MetadataPath $path
            if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $path" }
            & $signtool verify /pa /all /v $path
            if ($LASTEXITCODE -ne 0) { throw "signtool verify failed: $path" }
            Write-Host "ARTIFACT_SIGNED | $path"
        } elseif ($FreeRelease) {
            & $signtool sign /v /sha1 $Thumbprint /fd SHA256 /d "DefenderGuard" $path
            if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $path" }
            $sig = Get-AuthenticodeSignature -LiteralPath $path
            if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $Thumbprint) {
                throw "FreeRelease signer certificate mismatch: $path"
            }
            Write-Host "FREE_RELEASE_SIGNED | $path | status=$($sig.Status) | signer=$($sig.SignerCertificate.Subject)"
        } else {
            & $signtool sign /sha1 $Thumbprint /a /fd SHA256 /tr $TimestampServer /td SHA256 /d "DefenderGuard" /v $path
            if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $path" }
            & $signtool verify /pa /all /v $path
            if ($LASTEXITCODE -ne 0) { throw "signtool verify failed: $path" }
            Write-Host "PRODUCTION_SIGNED | $path"
        }
    }
} elseif ($FreeRelease) {
    $signtool = if ([string]::IsNullOrWhiteSpace($SignToolPath)) { Find-SignTool } else { $SignToolPath }
    foreach ($path in $files) {
        if (-not (Test-Path -LiteralPath $path)) { throw "File not found: $path" }
        & $signtool sign /v /sha1 $Thumbprint /fd SHA256 /d "DefenderGuard" $path
        if ($LASTEXITCODE -ne 0) { throw "signtool sign failed: $path" }
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $Thumbprint) {
            throw "FreeRelease signer certificate mismatch: $path"
        }
        Write-Host "FREE_RELEASE_SIGNED | $path | status=$($sig.Status) | signer=$($sig.SignerCertificate.Subject)"
    }
} else {
    $cert = Get-CodeSigningCertificate -CertThumbprint $Thumbprint
    foreach ($path in $files) {
        if (-not (Test-Path -LiteralPath $path)) { throw "File not found: $path" }
        $params = @{ LiteralPath = $path; Certificate = $cert; HashAlgorithm = "SHA256"; Force = $true }
        if (-not [string]::IsNullOrWhiteSpace($TimestampServer)) { $params.TimestampServer = $TimestampServer }
        $result = Set-AuthenticodeSignature @params
        Write-Host ("QA_SIGNED | {0} | {1} | {2}" -f $path,$result.Status,$cert.Subject)
        if ($result.Status -ne "Valid") { throw "QA signing failed: $path" }
    }
}

Write-Host "SIGN_RELEASE_PASS"