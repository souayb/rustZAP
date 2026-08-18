# Windows packaging detail

## Choosing a technology

- **WiX Toolset** → `.msi`. Best for enterprise: Group Policy deploy, Windows Installer transactions, patching, per-machine installs.
- **Inno Setup** → `.exe`. Simple, scriptable (`.iss`), great consumer UX. Recommended default for a CLI/desktop app without enterprise needs.
- **NSIS** → `.exe`. Highly scriptable, small; more manual.

## What the installer must do

Install / upgrade / uninstall; Start-menu shortcut (Desktop shortcut only if requested); **Add/Remove Programs** registration; optional PATH update (opt-in checkbox, never forced); optional Windows Service install for background apps.

- Install to a dir the user can choose (default `C:\Program Files\<App>\`), not a user-writable system location.
- Request elevation (admin) **only** when actually needed (per-machine install, service). Per-user installs can avoid UAC.
- Detect existing version; block downgrades unless intended; replace old binaries cleanly; no duplicate installs.

## Registry — write only what's required

Legitimate uses: uninstall information (`HKLM\...\Uninstall\<App>`), file associations, URL protocol handlers, app registration. Don't scatter app state across the registry — app state belongs in `%APPDATA%`/`%LOCALAPPDATA%`.

## Inno Setup skeleton (`.iss`)

```
[Setup]
AppName=RustZAP
AppVersion={#Version}
DefaultDirName={autopf}\RustZAP
DefaultGroupName=RustZAP
OutputBaseFilename=rustzap-{#Version}-windows-x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
[Files]
Source: "target\x86_64-pc-windows-msvc\release\rustzap.exe"; DestDir: "{app}"; Flags: ignoreversion
[Tasks]
Name: "addtopath"; Description: "Add RustZAP to PATH"; Flags: unchecked
[Icons]
Name: "{group}\RustZAP"; Filename: "{app}\rustzap.exe"
```

Build: `iscc /DVersion=%VERSION% rustzap.iss`.

## Authenticode signing (production)

```
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /f cert.pfx /p %PFX_PASSWORD% rustzap-<version>-windows-x64.exe
signtool verify /pa /v rustzap-<version>-windows-x64.exe
```

- Certificate + password come from **CI secrets**, never the repo. Prefer an EV cert or a cloud signing service (Azure Trusted Signing) to build SmartScreen reputation.
- Sign the payload binaries **and** the installer. Timestamp so signatures survive cert expiry.
