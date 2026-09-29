param(
    [ValidateSet("QA","FreeRelease","Production","ArtifactSigning")][string]$SigningMode = "QA",
    [string]$Thumbprint = "",
    [string]$TimestampServer = "",
    [string]$MetadataPath = "",
    [string]$DlibPath = "",
    [string]$SignToolPath = "",
    [string]$UpdateManifestUrl = "",
    [string]$UpdatePackageUrl = "",
    [string]$Version = "1.0.1"
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
    $Thumbprint = if ($SigningMode -eq "FreeRelease") { "07FBFB60553CC6385383FB7B19A8EB6300BB014B" } else { "371C5721A5A1AFE7EDAA953C9263925C1A5082A7" }
}
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$publish = Join-Path $root "..\..\DefenderGuard-release-$Version"
$installerDir = Join-Path $root "..\..\DefenderGuard-installer-wix"
$exe = Join-Path $publish "DefenderGuard.exe"
$msi = Join-Path $installerDir "DefenderGuard.msi"
$bundle = Join-Path $installerDir "DefenderGuard-Setup-$Version.exe"
$wixproj = Join-Path $PSScriptRoot "DefenderGuard.wixproj"
$bundleWxs = Join-Path $PSScriptRoot "DefenderGuardBundle.wxs"
$signScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Sign-Release.ps1"
$verifyScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Verify-Release.ps1"
$auditScript = Join-Path (Split-Path -Parent $PSScriptRoot) "Release-Audit.ps1"
$wix = "C:\Program Files\WiX Toolset v7.0\bin\wix.exe"

if ($SigningMode -ne "QA") {
    if ([string]::IsNullOrWhiteSpace($UpdateManifestUrl)) {
        throw "$SigningMode release requires UpdateManifestUrl so the shipped updater has a public channel."
    }
    if ([string]::IsNullOrWhiteSpace($UpdatePackageUrl)) {
        throw "$SigningMode release requires UpdatePackageUrl so the shipped updater can download the bundle."
    }
}
if ($SigningMode -eq "Production") {
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { throw "Production signing requires an OV certificate thumbprint." }
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) { throw "Production signing requires an RFC 3161 TimestampServer." }
    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$timestampUri) -or
        ($timestampUri.Scheme -ne [Uri]::UriSchemeHttp -and $timestampUri.Scheme -ne [Uri]::UriSchemeHttps)) {
        throw "Production TimestampServer must be an HTTP or HTTPS RFC 3161 endpoint."
    }
    $normalizedThumbprint = ($Thumbprint -replace "\s", "").ToUpperInvariant()
    $productionCert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Thumbprint.ToUpperInvariant() -eq $normalizedThumbprint } |
        Select-Object -First 1
    if (-not $productionCert) { throw "Production OV code-signing certificate not found: $normalizedThumbprint" }
    if (-not $productionCert.HasPrivateKey) { throw "Production certificate has no private key: $normalizedThumbprint" }
    if ($productionCert.Subject -match "DefenderGuard Local QA") { throw "Production signing refuses the DefenderGuard Local QA certificate." }
}
foreach ($channelValue in @(@{Name="UpdateManifestUrl";Value=$UpdateManifestUrl},@{Name="UpdatePackageUrl";Value=$UpdatePackageUrl})) {
    if (-not [string]::IsNullOrWhiteSpace($channelValue.Value)) {
        $updateUri = $null
        if (-not [Uri]::TryCreate($channelValue.Value, [UriKind]::Absolute, [ref]$updateUri) -or
            $updateUri.Scheme -ne [Uri]::UriSchemeHttps) {
            throw "$($channelValue.Name) must be an HTTPS URL."
        }
    }
}

$updateBuildArgs = @()
if (-not [string]::IsNullOrWhiteSpace($UpdateManifestUrl)) {
    $updateBuildArgs += "-p:DefenderGuardUpdateManifestUrl=$UpdateManifestUrl"
}

$versionParts = $Version.Split(".")
if ($versionParts.Count -lt 2 -or $versionParts.Count -gt 4) { throw "Version must contain 2-4 numeric components: $Version" }
$assemblyVersion = $Version + $(if ($versionParts.Count -eq 4) { "" } else { ".0" })
$versionBuildArgs = @(
    "-p:Version=$Version",
    "-p:AssemblyVersion=$assemblyVersion",
    "-p:FileVersion=$assemblyVersion",
    "-p:InformationalVersion=$Version"
)

function Invoke-Step {
    param([string]$Name,[scriptblock]$Action)
    Write-Host "== $Name =="
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

$locked = Get-Process -Name "DefenderGuard" -ErrorAction SilentlyContinue |
    Where-Object { try { $_.Path -eq $exe } catch { $false } }
if ($locked) { throw "Release EXE is in use by DefenderGuard. Close the application before building." }New-Item -ItemType Directory -Force -Path $installerDir | Out-Null
Invoke-Step "dotnet build" { dotnet build (Join-Path $root "DemoGuard.csproj") -c Release -warnaserror @versionBuildArgs @updateBuildArgs }
foreach ($test in @("ScanReportStoreTests","QuarantineStoreTests","NetworkTests","DuplicateScanTests","AppUpdateTests")) {
    $testProject = Join-Path $root "tests\\$test\\$test.csproj"
    Invoke-Step "build test $test" { dotnet build $testProject -c Release --no-restore @versionBuildArgs @updateBuildArgs }
    Invoke-Step "test $test" { dotnet run --project $testProject -c Release --no-build @updateBuildArgs }
}
Invoke-Step "dotnet publish" { dotnet publish (Join-Path $root "DemoGuard.csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publish @versionBuildArgs @updateBuildArgs }
if (-not (Test-Path -LiteralPath $exe)) { throw "Published EXE missing: $exe" }

$signBase = @("-ExePath",$exe,"-SetupPath",$msi,"-Thumbprint",$Thumbprint)
if ($SigningMode -eq "FreeRelease") {
    $signBase += "-FreeRelease"
} elseif ($SigningMode -eq "ArtifactSigning") {
    $signBase += @("-ArtifactSigning","-MetadataPath",$MetadataPath,"-DlibPath",$DlibPath,"-SignToolPath",$SignToolPath)
} elseif ($SigningMode -eq "Production") {
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) { throw "Production signing requires TimestampServer." }
    $signBase += @("-Production","-TimestampServer",$TimestampServer)
}
Invoke-Step "sign EXE" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript @($signBase + @("-Target","Exe")) }
$verifyArgs = @("-ExePath",$exe,"-SetupPath",$msi,"-Target","Exe")
if ($SigningMode -eq "FreeRelease") { $verifyArgs += @("-PinnedThumbprint",$Thumbprint) }
elseif ($SigningMode -ne "QA") { $verifyArgs += "-RequireTimestamp" }
Invoke-Step "verify EXE" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verifyScript @verifyArgs }

Invoke-Step "build MSI" { & $wix build -acceptEula wix7 -arch x64 -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext -d PublishDir=$publish -d MsiVersion=$assemblyVersion $root\\Installer\\Wix7\\DefenderGuard.wxs -o $msi }
if (-not (Test-Path -LiteralPath $msi)) { throw "MSI missing: $msi" }

$signMsi = @("-ExePath",$exe,"-SetupPath",$msi,"-Thumbprint",$Thumbprint,"-Target","Setup")
if ($SigningMode -eq "FreeRelease") { $signMsi += "-FreeRelease" }
elseif ($SigningMode -eq "ArtifactSigning") { $signMsi += @("-ArtifactSigning","-MetadataPath",$MetadataPath,"-DlibPath",$DlibPath,"-SignToolPath",$SignToolPath) }
elseif ($SigningMode -eq "Production") { $signMsi += @("-Production","-TimestampServer",$TimestampServer) }
Invoke-Step "sign MSI" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript @signMsi }

Invoke-Step "build bundle" { & $wix build -acceptEula wix7 -arch x64 -ext WixToolset.BootstrapperApplications.wixext -d MsiPath=$msi -d BundleVersion=$assemblyVersion $bundleWxs -o $bundle }
if (-not (Test-Path -LiteralPath $bundle)) { throw "Bundle missing: $bundle" }
if ($SigningMode -eq "FreeRelease" -or $SigningMode -eq "ArtifactSigning" -or $SigningMode -eq "Production") {
    $engine = Join-Path $installerDir "burn-engine.exe"
    $engineSigned = Join-Path $installerDir "burn-engine-signed.exe"
    Invoke-Step "detach Burn engine" { & $wix burn detach $bundle -engine $engine }
    Copy-Item -LiteralPath $engine -Destination $engineSigned -Force
    $engineSign = @("-ExePath",$exe,"-SetupPath",$engineSigned,"-Thumbprint",$Thumbprint,"-Target","Setup")
    if ($SigningMode -eq "FreeRelease") { $engineSign += "-FreeRelease" }
    elseif ($SigningMode -eq "ArtifactSigning") { $engineSign += @("-ArtifactSigning","-MetadataPath",$MetadataPath,"-DlibPath",$DlibPath,"-SignToolPath",$SignToolPath) }
    else { $engineSign += @("-Production","-TimestampServer",$TimestampServer) }
    Invoke-Step "sign Burn engine" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript @engineSign }
    Invoke-Step "reattach Burn engine" { & $wix burn reattach $bundle -engine $engineSigned -o $bundle }
}

$signBundle = @("-ExePath",$exe,"-SetupPath",$bundle,"-Thumbprint",$Thumbprint,"-Target","Setup")
if ($SigningMode -eq "FreeRelease") { $signBundle += "-FreeRelease" }
elseif ($SigningMode -eq "ArtifactSigning") { $signBundle += @("-ArtifactSigning","-MetadataPath",$MetadataPath,"-DlibPath",$DlibPath,"-SignToolPath",$SignToolPath) }
elseif ($SigningMode -eq "Production") { $signBundle += @("-Production","-TimestampServer",$TimestampServer) }
Invoke-Step "sign bundle" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $signScript @signBundle }

$verifyMsi = @("-SetupPath",$msi,"-Target","Setup")
$verifyBundle = @("-SetupPath",$bundle,"-Target","Setup")
if ($SigningMode -eq "FreeRelease") {
    $verifyMsi += @("-PinnedThumbprint",$Thumbprint)
    $verifyBundle += @("-PinnedThumbprint",$Thumbprint)
} elseif ($SigningMode -ne "QA") { $verifyMsi += "-RequireTimestamp"; $verifyBundle += "-RequireTimestamp" }
Invoke-Step "verify MSI" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verifyScript -ExePath $exe @verifyMsi }
Invoke-Step "verify bundle" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $verifyScript -ExePath $exe @verifyBundle }

$manifestPath = Join-Path $installerDir "stable-win-x64.json"
if (-not [string]::IsNullOrWhiteSpace($UpdateManifestUrl)) {
    Invoke-Step "generate update manifest" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "New-UpdateManifest.ps1") -Version $Version -PackagePath $bundle -PackageUrl $UpdatePackageUrl -ReleaseNotes "DefenderGuard $Version" -OutputPath $manifestPath
    }
}

if ($SigningMode -eq "FreeRelease") {
    $appUpdateTestProject = Join-Path $root "tests\\AppUpdateTests\\AppUpdateTests.csproj"
    Invoke-Step "verify updater against final free bundle" {
        $previousRequire = $env:APPUPDATE_REQUIRE_FREE_RELEASE
        $previousBundle = $env:APPUPDATE_FREE_RELEASE_BUNDLE
        try {
            $env:APPUPDATE_REQUIRE_FREE_RELEASE = "1"
            $env:APPUPDATE_FREE_RELEASE_BUNDLE = $bundle
            dotnet run --project $appUpdateTestProject -c Release --no-build
        }
        finally {
            $env:APPUPDATE_REQUIRE_FREE_RELEASE = $previousRequire
            $env:APPUPDATE_FREE_RELEASE_BUNDLE = $previousBundle
        }
    }
}

$auditArgs = @("-Mode","PreInstall","-SetupPath",$bundle,"-ExpectedVersion",$Version)
if ($SigningMode -eq "FreeRelease") { $auditArgs += @("-ExpectedSignerThumbprint",$Thumbprint) }
Invoke-Step "pre-install audit" { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $auditScript @auditArgs }
Write-Host "BUILD_WIX_RELEASE_PASS"
Write-Host "MSI=$msi"
Write-Host "BUNDLE=$bundle"
if (Test-Path -LiteralPath $manifestPath) { Write-Host "UPDATE_MANIFEST=$manifestPath" }