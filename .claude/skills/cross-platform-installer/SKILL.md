---
name: cross-platform-installer
description: Design, build, sign, package, and validate production desktop/CLI installers for Linux, Windows, and macOS. Use when asked to create installers, package an app for distribution, produce .deb/.rpm/AppImage/.msi/.exe/.dmg/.pkg artifacts, set up a release pipeline, code-sign or notarize builds, or generate release checksums.
---

# Cross-Platform Installer Engineering

The installer is part of the product, not a final zip step. Treat it as production software: reproducible, versioned, signed where supported, easy to install and uninstall, and CI-buildable.

## Core principle

One application version and one source of truth for metadata; **separate packaging target per OS**. Never assume one installer format works everywhere.

```
Linux → .deb / .rpm / AppImage      Windows → .msi / .exe      macOS → .dmg / .pkg
```

## The mandatory sequence

Follow this order every time. Do **not** create packaging files before Steps 1–2.

1. **Inspect** — read the real build files, don't guess: `Cargo.toml`, `package.json`, `pyproject.toml`, `*.csproj`, `CMakeLists.txt`, build scripts, Dockerfiles, existing CI, existing packaging config. Reuse existing build infrastructure.
2. **Identify** — app type (GUI / CLI / background service), build system, target OSes + architectures, runtime & native deps, entry point, config/data/log dirs, update mechanism, signing requirements.
3. **Design** — write the packaging architecture (formats, layout, matrix) before editing files. Confirm architecture support before claiming it — never claim ARM unless the app *and all native deps* support it.
4. **Implement** — platform-specific packaging kept isolated (see `references/`), one shared canonical version. Prefer the framework's mature native packager (Tauri/Electron/cargo-deb/etc.) over inventing a new system.
5. **Build** — every requested target. Build platform artifacts on their native OS when signing/notarization is required (don't build macOS on Linux and call it done).
6. **Validate** — inspect resulting artifacts: exist, non-empty, correct arch, correct metadata/version. Use `scripts/verify-installer.sh`.
7. **Test** — on a **clean environment**, not just the dev machine: install → launch → upgrade → uninstall. See "Test lifecycle" below.
8. **Secure** — signatures, permissions, secrets, dependencies, checksums (see "Security gate").
9. **CI/CD** — integrate into the release pipeline (`references/ci-cd.md`).
10. **Report** — platforms/arches built, formats, files changed, commands run, tests performed, signing + notarization status, known limitations, artifact list.

## Decision tree: pick formats

- **Linux**: `.deb` (Debian/Ubuntu) + `.rpm` (Fedora/RHEL/openSUSE) + `AppImage` (portable). Add Flatpak/Snap only on a real distribution requirement.
- **Windows**: `.msi` when enterprise/Group Policy/Windows Installer integration matters; `.exe` (Inno Setup / NSIS) for simple consumer installs. WiX for MSI.
- **macOS**: `.dmg` for normal app distribution; `.pkg` for system-level installs. Ship **Universal 2** (arm64 + x86_64) when practical.

App type changes the strategy:
- **CLI** → binary on `PATH`; usually no GUI shortcuts. (rustzap is a Rust CLI — see `references/rust-cli.md`.)
- **GUI** → desktop/start-menu entry, icons, file associations, URL schemes.
- **Background service** → Windows Service / systemd / launchd, service account, graceful shutdown, logging.

## Installation layout — use OS conventions, never hard-code

| | Linux | Windows | macOS |
|---|---|---|---|
| App | `/opt/myapp/` (GUI), `/usr/bin/myapp` (CLI) | `C:\Program Files\MyApp\` | `/Applications/MyApp.app` |
| Config | `/etc/myapp/` | `%APPDATA%\MyApp\` | `~/Library/Application Support/MyApp/` |
| Data | `/var/lib/myapp/` | `%LOCALAPPDATA%\MyApp\` | `~/Library/Application Support/MyApp/` |
| Logs | `/var/log/myapp/` | `%LOCALAPPDATA%\MyApp\logs\` | `~/Library/Logs/MyApp/` |
| Service | `/etc/systemd/system/myapp.service` | Windows Service | `~/Library/LaunchAgents/` |

Let Windows installers choose the install dir (don't assume `C:\Program Files`). Never store mutable data inside a macOS `.app` bundle.

## Versioning & artifact naming

One canonical version (e.g. `1.8.2`) appearing in package metadata, installer metadata, app metadata, release tag, and artifact names. Derive it from the build file (e.g. `Cargo.toml` `version`) — never hand-maintain parallel numbers.

Name artifacts `<app>-<version>-<os>-<arch>.<ext>`:

```
myapp-1.8.2-linux-x86_64.AppImage   myapp-1.8.2-linux-amd64.deb   myapp-1.8.2-linux-x86_64.rpm
myapp-1.8.2-windows-x64.exe         myapp-1.8.2-windows-x64.msi
myapp-1.8.2-macos-universal.dmg     myapp-1.8.2-macos-arm64.dmg   myapp-1.8.2-macos-x86_64.dmg
```

Never `setup.exe`, `final.exe`, `latest.exe`, `build2.exe`.

## Test lifecycle (every platform, clean OS)

```
Install → Launch → verify functionality → Close → Launch again → Upgrade → Launch → Uninstall → verify cleanup
```

- **Upgrade** (`1.0.0→1.1.0`, `1.1.0→1.1.1`): user data & config intact, migrations run, shortcuts still work, services restart, old binaries replaced, no duplicate installs.
- **Uninstall**: binaries/shortcuts/services/registry/package-metadata removed; **user data preserved** unless the user explicitly asked otherwise. Never silently delete valuable user data.

## Security gate (block release on failure)

- No hard-coded secrets, dev credentials, debug endpoints, or dev certificates in repo or artifacts.
- Never commit `.p12 .pfx .pem .key .cer` or signing passwords — use CI secrets (GitHub Actions Secrets / Vault / cloud secret manager / HSM signing service).
- No writable executable dirs, no unnecessary privileges, no command injection via installer parameters.
- Production binaries **signed** where expected; macOS **notarized + stapled** when Gatekeeper distribution is expected.
- Bundle only required runtime deps — no SDKs/compilers/tests/build artifacts/dev deps.
- Publish `SHA256SUMS` for every release artifact (`scripts/gen-checksums.sh`).

## Reproducibility

Same commit + release config → equivalent artifacts. Record in release metadata: git commit, app version, build env, compiler/toolchain version, packaging-tool version, arch, OS.

## Hard rules

MUST: inspect before creating config · reuse existing build infra · follow OS conventions · preserve user data on upgrade · keep platform packaging isolated · make builds reproducible · generate checksums · fail the release if a required artifact can't be validated · clearly report unsupported OS/arch.

MUST NOT: claim an installer works without testing/validation · invent signing certificates · commit signing credentials · delete user data on upgrade · bundle dev dependencies · disable OS security to ease install · publish unsigned artifacts when signing is required · change app functionality just to ease packaging without explaining why.

## Definition of done

Builds succeed → correct artifacts for the right arches → correct version in metadata → installs/launches/upgrades/uninstalls on a clean OS → user data handled correctly → required binaries signed → macOS notarized when required → checksums generated → CI reproduces the build → predictable artifact names → no secrets in repo/artifacts → install/uninstall documented.

## References (load as needed)

- `references/rust-cli.md` — packaging a Rust binary (cargo-deb, cargo-generate-rpm, AppImage, WiX/Inno, dmg). **Start here for this repo (rustzap).**
- `references/linux.md` — `.deb` / `.rpm` / AppImage detail, systemd, maintainer scripts.
- `references/windows.md` — WiX / NSIS / Inno Setup, registry, Authenticode signing.
- `references/macos.md` — `.app` bundle, `codesign`, `notarytool`, stapling, `.dmg`/`.pkg`.
- `references/ci-cd.md` — release matrix, GitHub Actions pipeline, artifact validation.

## Scripts

- `scripts/gen-checksums.sh <dir>` — write `SHA256SUMS` for all artifacts in a directory.
- `scripts/verify-installer.sh <artifact> [--expect-version X]` — sanity-check an artifact (exists, non-empty, name/arch/version sanity, checksum). Never reports "works" — only structural validation.
