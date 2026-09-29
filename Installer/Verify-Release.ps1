param(
    [string]$ExePath = "C:\Users\User\Downloads\DefenderGuard-release-1.0.0\DefenderGuard.exe",
    [string]$SetupPath = "C:\Users\User\Downloads\DefenderGuard-installer\DefenderGuard-Setup-1.0.0.exe",
    [ValidateSet("Both","Exe","Setup")][string]$Target = "Both",
    [string]$PinnedThumbprint = "",
    [switch]$RequireTimestamp
)

$ErrorActionPreference = "Stop"

function Verify-File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing release file: $Path" }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
    Write-Host "FILE=$Path"
    Write-Host "SHA256=$hash"
    Write-Host "SIGNATURE=$($sig.Status)"
    Write-Host "SIGNER=$($sig.SignerCertificate.Subject)"
    Write-Host "SIGNER_THUMBPRINT=$($sig.SignerCertificate.Thumbprint)"
    Write-Host "TIMESTAMP_SIGNER=$($sig.TimeStamperCertificate.Subject)"
    if (-not [string]::IsNullOrWhiteSpace($PinnedThumbprint)) {
        if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $PinnedThumbprint) {
            throw "Pinned DefenderGuard release signer mismatch: $Path"
        }
        if ($sig.Status -ne "Valid" -and $sig.Status -ne "UnknownError") {
            throw "Pinned release signature is not present or readable: $Path"
        }
    } elseif ($sig.Status -ne "Valid") {
        throw "Invalid Authenticode signature: $Path"
    }
    if ($RequireTimestamp -and -not $sig.TimeStamperCertificate) { throw "Missing Authenticode timestamp: $Path" }
}

switch ($Target) {
    "Exe" { Verify-File -Path $ExePath }
    "Setup" { Verify-File -Path $SetupPath }
    default { Verify-File -Path $ExePath; Verify-File -Path $SetupPath }
}
Write-Host "VERIFY_RELEASE_PASS"