# DefenderGuard production signing

The primary DefenderGuard distribution path is a free self-signed release key controlled by the project. No paid certificate, Azure subscription or Microsoft Artifact Signing account is required.

## Free release key

A dedicated `CN=DefenderGuard Release` certificate is used only for release signing. Its private key stays on the build machine and is never shipped. DefenderGuard embeds the certificate thumbprint and accepts an update signed by exactly that certificate.

Current release certificate thumbprint:

    71DE240C5B95C8EE5B8ED22A179DBD4349F8D4CD

The built-in `CN=DefenderGuard Local QA` certificate is explicitly rejected by the updater.

## Free production build

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build-Release.ps1 -SigningMode FreeRelease -Thumbprint 71DE240C5B95C8EE5B8ED22A179DBD4349F8D4CD -UpdateManifestUrl https://<your-free-update-host>/stable-win-x64.json -UpdatePackageUrl https://<your-free-update-host>/DefenderGuard-Setup-1.0.0.exe

The build signs:
1. DefenderGuard.exe
2. DefenderGuard.msi
3. detached WiX Burn engine
4. final DefenderGuard-Setup-1.0.0.exe bundle

The final bundle is signed after the Burn engine is reattached.

## Windows trust vs. DefenderGuard release trust

This free release key is self-signed. Windows therefore does not treat it as a publicly trusted publisher on a clean machine. That is expected for a zero-cost release and can produce an `UnknownPublisher` or trust warning.

DefenderGuard itself uses a different trust rule for updates: the application contains the SHA-1 thumbprint of the DefenderGuard Release certificate and accepts only packages signed by that exact certificate. The package is also downloaded only over HTTPS and its SHA-256 must match `stable-win-x64.json`.

This design protects the in-app update path without pretending that a self-signed certificate is publicly trusted by Windows.

## Automatic updates

Free releases provide two HTTPS URLs:

- UpdateManifestUrl: public URL of stable-win-x64.json
- UpdatePackageUrl: public URL of the signed DefenderGuard-Setup-X.Y.Z.exe

The release pipeline writes the manifest after the final bundle signature is verified. The manifest contains the version, package URL, package size and SHA-256. DefenderGuard checks HTTPS, version format, size and SHA-256, then verifies the installer with Windows Authenticode/WinVerifyTrust before it can be executed.

Example free release invocation:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build-Release.ps1 -SigningMode FreeRelease -Thumbprint 71DE240C5B95C8EE5B8ED22A179DBD4349F8D4CD -UpdateManifestUrl https://<host>/stable-win-x64.json -UpdatePackageUrl https://<host>/DefenderGuard-Setup-1.0.0.exe

The updater refuses the local DefenderGuard QA certificate and only installs a package that passes HTTPS, manifest SHA-256 and pinned DefenderGuard Release certificate verification.

## Prepared local tooling

- Windows SDK x64 SignTool 10.0.26100.0
- WiX Toolset 7.0.0

Optional public-CA and Microsoft Artifact Signing paths remain available in the scripts, but neither is required for the free release.

## Final gate

Before public distribution:
- verify the release signer thumbprint on EXE, MSI, Burn engine and final bundle
- verify the manifest SHA-256 against the final bundle
- run PreInstall audit
- test install on a disposable clean Windows VM
- enable self-protection and test uninstall
- run PostUninstall audit
- run a real 1.0.0 -> 1.0.1 update test over HTTPS
- publish only the free release bundle, stable-win-x64.json and SHA-256 checksum