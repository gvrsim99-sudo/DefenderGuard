#define AppName "DefenderGuard"
#define AppVersion "1.0.0"
#define AppPublisher "DefenderGuard"
#define AppExeName "DefenderGuard.exe"
#define PublishDir "..\..\..\DefenderGuard-release-1.0.0"
#define OutputDir "..\..\..\DefenderGuard-installer"

[Setup]
AppId={{2de65226-e2b5-4ed5-9548-e15ba1d46cd6}}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\DefenderGuard
DefaultGroupName={#AppName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=DefenderGuard-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
Uninstallable=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
VersionInfoDescription=DefenderGuard Setup
VersionInfoProductName=DefenderGuard
VersionInfoProductVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=Copyright 2026 DefenderGuard

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные ярлыки:"; Flags: unchecked

[Files]
Source: "{#PublishDir}\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Запустить DefenderGuard"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#AppExeName} /F"; Flags: runhidden waituntilterminated; RunOnceId: "StopDefenderGuard"
Filename: "{app}\{#AppExeName}"; Parameters: "--self-protection-diagnostic disable"; Flags: runhidden waituntilterminated; RunOnceId: "DisableSelfProtection"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\DefenderGuardSelfProtection"