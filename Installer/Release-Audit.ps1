param(
    [ValidateSet("PreInstall","PostInstall","PostUninstall")]
    [string]$Mode = "PostInstall",
    [string]$AppDir = "C:\Program Files\DefenderGuard",
    [string]$SetupPath = "C:\Users\User\Downloads\DefenderGuard-installer\DefenderGuard-Setup-1.0.0.exe",
    [string]$ExpectedSignerThumbprint = "",
    [string]$ExpectedVersion = "1.0.0"
)

$ErrorActionPreference = "Stop"
$failures = 0

function Check {
    param([string]$Name, [bool]$Condition, [string]$Detail)
    if ($Condition) {
        Write-Host "PASS | $Name | $Detail"
    } else {
        Write-Host "FAIL | $Name | $Detail"
        $script:failures++
    }
}

$exe = Join-Path $AppDir "DefenderGuard.exe"
$releaseExe = Join-Path (Split-Path -Parent $SetupPath) ("..\DefenderGuard-release-" + $ExpectedVersion + "\DefenderGuard.exe")
$svc = Get-Service -Name "DefenderGuardSelfProtection" -ErrorAction SilentlyContinue
$task = Get-ScheduledTask -TaskName "DefenderGuard_SelfProtection_UI" -ErrorAction SilentlyContinue
$uninstallKey = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } | Where-Object { $_.DisplayName -eq "DefenderGuard" } | Select-Object -First 1

if ($Mode -eq "PreInstall") {
    Check "Setup exists" (Test-Path -LiteralPath $SetupPath) $SetupPath
    if (Test-Path -LiteralPath $SetupPath) {
        $sig = Get-AuthenticodeSignature -LiteralPath $SetupPath
        $setupSignatureOk = $sig.Status -eq "Valid" -or (
            -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -and
            $sig.Status -eq "UnknownError" -and
            $sig.SignerCertificate -and
            $sig.SignerCertificate.Thumbprint -eq $ExpectedSignerThumbprint)
        Check "Setup signature" $setupSignatureOk ("$($sig.Status) / $($sig.SignerCertificate.Subject)")
    }
    Check "Application directory absent" (-not (Test-Path -LiteralPath $AppDir)) $AppDir
    if (Test-Path -LiteralPath $releaseExe) {
        $releaseSig = Get-AuthenticodeSignature -LiteralPath $releaseExe
        $releaseSignatureOk = $releaseSig.Status -eq "Valid" -or (
            -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -and
            $releaseSig.Status -eq "UnknownError" -and
            $releaseSig.SignerCertificate -and
            $releaseSig.SignerCertificate.Thumbprint -eq $ExpectedSignerThumbprint)
        Check "Release EXE signature" $releaseSignatureOk ("$($releaseSig.Status) / $($releaseSig.SignerCertificate.Subject)")
    }
    Check "Self-protection service absent" ($null -eq $svc) "DefenderGuardSelfProtection"
    Check "Self-protection task absent" ($null -eq $task) "DefenderGuard_SelfProtection_UI"
}

if ($Mode -eq "PostInstall") {
    Check "Application directory exists" (Test-Path -LiteralPath $AppDir) $AppDir
    Check "Installed EXE exists" (Test-Path -LiteralPath $exe) $exe
    if (Test-Path -LiteralPath $exe) {
        $info = (Get-Item $exe).VersionInfo
        $sig = Get-AuthenticodeSignature -LiteralPath $exe
        Check "EXE version" ($info.FileVersion -eq ($ExpectedVersion + ".0")) $info.FileVersion
        $installedSignatureOk = $sig.Status -eq "Valid" -or (
            -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -and
            $sig.Status -eq "UnknownError" -and
            $sig.SignerCertificate -and
            $sig.SignerCertificate.Thumbprint -eq $ExpectedSignerThumbprint)
        Check "EXE signature" $installedSignatureOk ("$($sig.Status) / $($sig.SignerCertificate.Subject)")
        Check "EXE product" ($info.ProductName -eq "DefenderGuard") $info.ProductName
        if (Test-Path -LiteralPath $releaseExe) {
            $installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
            $releaseHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $releaseExe).Hash
            Check "Installed EXE matches release payload" ($installedHash -eq $releaseHash) $installedHash
        }
    }
    Check "Self-protection initially disabled" ($null -eq $svc -and $null -eq $task) "service/task absent"
    Check "Uninstall registration exists" ($null -ne $uninstallKey) "DefenderGuard uninstall entry"
}

if ($Mode -eq "PostUninstall") {
    Check "Application directory removed" (-not (Test-Path -LiteralPath $AppDir)) $AppDir
    Check "Self-protection service removed" ($null -eq $svc) "DefenderGuardSelfProtection"
    Check "Self-protection task removed" ($null -eq $task) "DefenderGuard_SelfProtection_UI"
    Check "Self-protection data removed" (-not (Test-Path "C:\ProgramData\DefenderGuardSelfProtection")) "C:\ProgramData\DefenderGuardSelfProtection"
    Check "Uninstall registration removed" ($null -eq $uninstallKey) "DefenderGuard uninstall entry"
}

Write-Host "RELEASE_AUDIT_MODE=$Mode"
Write-Host "RELEASE_AUDIT_FAILURES=$failures"
if ($failures -gt 0) { exit 1 }
Write-Host "RELEASE_AUDIT_PASS"