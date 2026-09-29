param(
    [string]$Thumbprint = ""
)

$ErrorActionPreference = "Stop"

function Test-CodeSigningEku {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    foreach ($eku in $Certificate.Extensions) {
        if ($eku -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $eku.EnhancedKeyUsages) {
                if ($oid.Value -eq "1.3.6.1.5.5.7.3.3") { return $true }
            }
            return $false
        }
    }
    return $false
}

$certs = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.HasPrivateKey })
if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
    $normalized = ($Thumbprint -replace "\s", "").ToUpperInvariant()
    $certs = @($certs | Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalized })
    if ($certs.Count -eq 0) { throw "No private-key code-signing certificate found for thumbprint $normalized" }
}

$foundProduction = $false
foreach ($cert in $certs) {
    $ekuOk = Test-CodeSigningEku $cert
    $qa = $cert.Subject -match "DefenderGuard Local QA"
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chainOk = $chain.Build($cert)
    $status = @($chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }) -join "; "
    Write-Host ("CERT | Subject={0} | Issuer={1} | Thumbprint={2} | NotAfter={3:o} | PrivateKey={4} | CodeSigningEKU={5} | Chain={6} | QA={7}" -f $cert.Subject,$cert.Issuer,$cert.Thumbprint,$cert.NotAfter,$cert.HasPrivateKey,$ekuOk,$chainOk,$qa)
    if (-not $qa -and $ekuOk -and $chainOk) { $foundProduction = $true }
    if (-not $chainOk -and $status) { Write-Host "CHAIN_STATUS=$status" }
}
if ($certs.Count -eq 0) {
    Write-Host "No private-key code-signing certificate is installed in CurrentUser\\My."
    exit 2
}
if (-not $foundProduction) {
    Write-Host "OV_PREFLIGHT_FAIL: no eligible public production code-signing certificate found."
    exit 3
}
Write-Host "OV_PREFLIGHT_PASS"