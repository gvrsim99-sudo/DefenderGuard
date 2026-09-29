$ErrorActionPreference = "Stop"
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Thumbprint -eq "371C5721A5A1AFE7EDAA953C9263925C1A5082A7" } | Select-Object -First 1
if (-not $cert) { throw "QA cert missing" }
$files = @(
"C:\Users\User\Downloads\DefenderGuard-installer-wix\DefenderGuard.msi",
"C:\Users\User\Downloads\DefenderGuard-installer-wix\DefenderGuard-Setup-1.0.0.exe"
)
foreach ($f in $files) { $r=Set-AuthenticodeSignature -LiteralPath $f -Certificate $cert -HashAlgorithm SHA256 -Force; Write-Host "$f | $($r.Status)"; if ($r.Status -ne "Valid") { exit 1 } }