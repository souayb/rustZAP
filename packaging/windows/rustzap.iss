; Inno Setup script for RustZAP (Windows x64).
; Version is injected from CI via `iscc /DAppVersion=<version> rustzap.iss`
; (see scripts/packaging/version.sh — Cargo.toml is the source of truth).
; Never hard-code a version here.
#ifndef AppVersion
  #error AppVersion must be defined: iscc /DAppVersion=0.1.0 rustzap.iss
#endif

#define AppName "RustZAP"
#define AppPublisher "RustZAP Contributors"
#define AppURL "https://github.com/souayb/rustZAP"
#define AppExeName "rustzap.exe"

[Setup]
AppId={{6F9E2B7E-6C0B-4C7B-8B6E-9C7E4E6E9A5F}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
; Per-machine install under Program Files; UAC prompt only for this install/
; uninstall, not for every run of the CLI.
DefaultDirName={autopf}\RustZAP
DefaultGroupName=RustZAP
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist
OutputBaseFilename=rustzap-{#AppVersion}-windows-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Detect + offer upgrade over an existing install; never silently downgrade.
AppendDefaultDirName=no
UsePreviousAppDir=yes
LicenseFile=..\..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Opt-in only — never force a PATH mutation on the user.
Name: "addtopath"; Description: "Add RustZAP to PATH (recommended for CLI use)"; Flags: unchecked

[Files]
Source: "..\..\target\x86_64-pc-windows-msvc\release\rustzap.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\RustZAP"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall RustZAP"; Filename: "{uninstallexe}"

[Registry]
; PATH mutation is done via registry + a helper so uninstall can cleanly
; reverse it. Only touches HKLM\...\Environment when the task is selected.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
  Tasks: addtopath; Check: NeedsAddPath('{app}')

[UninstallDelete]
; Uninstall removes the app directory contents we installed; it must NOT
; touch %APPDATA%\RustZAP or any user-generated scan reports/config.
Type: filesandordirs; Name: "{app}"

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
