# RustZAP packaging

Native installers for Linux, Windows, and macOS, built per the
[`cross-platform-installer`](../.claude/skills/cross-platform-installer/SKILL.md)
skill. RustZAP is a **CLI**, so every target installs a single binary onto
`PATH` — there is no GUI bundle, no background service, no file associations.

**Version is never hand-maintained here.** `Cargo.toml` `[package].version` is
the single source of truth; `scripts/packaging/version.sh` reads it and every
script below calls that. `src/main.rs`'s `--version` and the JSON report's
`meta.version` also derive from `CARGO_PKG_VERSION` at compile time, so all
four (CLI flag, report metadata, package metadata, artifact filename) always
agree.

## Layout

```
packaging/
├── linux/appimage/    AppRun, rustzap.desktop, rustzap.png — used by
│                       scripts/packaging/build-appimage.sh
├── windows/            rustzap.iss — Inno Setup script (needs -DAppVersion)
├── macos/               (build logic lives in scripts/packaging/build-macos.sh;
│                        no static files needed for a CLI-only .dmg)
└── homebrew/           rustzap.rb.tmpl — filled in by
                         scripts/packaging/generate-homebrew-formula.sh

scripts/packaging/
├── version.sh                        canonical version getter
├── build-appimage.sh <target> <dir>  Linux only
├── build-macos.sh [dir]              macOS only — universal2 + codesign + dmg
├── sign-windows.ps1 <file...>        Windows only — Authenticode sign+verify
└── generate-homebrew-formula.sh      run AFTER a release tag is pushed
```

`.deb` and `.rpm` don't need a script — they're `cargo deb` / `cargo generate-rpm`
driven entirely by `[package.metadata.deb]` / `[package.metadata.generate-rpm]`
in `Cargo.toml`.

## What's bundled — and what isn't

These installers package **only the `rustzap` binary** plus `README.md` and
`LICENSE`. `rustzap install` (a separate, existing subcommand — see the main
README's "Install companion tools" section) is how a user opts into the
SDD companion tools (Semgrep, Nmap, etc.) on top of that; those are never
bundled into the OS installer itself, and the multi-stage `Dockerfile` (which
does bundle them, for the all-in-one container image) is a separate
distribution channel this packaging does not touch or replace.

## Build locally

```bash
# Linux (.deb + .rpm + AppImage) — must run on Linux:
cargo install cargo-deb cargo-generate-rpm
cargo build --release --bin rustzap
cargo deb --no-build -o dist/
cargo generate-rpm -o dist/
bash scripts/packaging/build-appimage.sh x86_64-unknown-linux-gnu dist

# Windows (.exe) — must run on Windows, with Inno Setup installed:
cargo build --release --target x86_64-pc-windows-msvc --bin rustzap
iscc /DAppVersion=$(bash scripts/packaging/version.sh) packaging\windows\rustzap.iss
# Optional, for a real Authenticode-signed build (sign the binary before iscc,
# and the installer after) — see "Code signing" below:
#   $env:WINDOWS_PFX_BASE64="<base64 of cert.pfx>"; $env:WINDOWS_PFX_PASSWORD="<password>"
#   pwsh scripts/packaging/sign-windows.ps1 target\x86_64-pc-windows-msvc\release\rustzap.exe
#   pwsh scripts/packaging/sign-windows.ps1 dist\rustzap-<version>-windows-x64.exe

# macOS (.dmg, universal2) — must run on macOS:
bash scripts/packaging/build-macos.sh dist
# Optional, for a real Gatekeeper-compatible signed+notarized build:
#   MACOS_SIGN_IDENTITY="Developer ID Application: NAME (TEAMID)" \
#   MACOS_NOTARY_PROFILE="your-notarytool-keychain-profile" \
#   bash scripts/packaging/build-macos.sh dist
```

Then, for any platform's output directory:

```bash
bash .claude/skills/cross-platform-installer/scripts/gen-checksums.sh dist
bash .claude/skills/cross-platform-installer/scripts/verify-installer.sh dist/<artifact> --expect-version $(bash scripts/packaging/version.sh)
```

`verify-installer.sh` only performs structural checks (exists, non-empty,
name/version/arch sane, checksum matches) — it does **not** prove the
installer installs/launches/uninstalls correctly. Do that on a clean VM/OS
before shipping; see the skill's "Test lifecycle" section.

## CI

`.github/workflows/release.yml` builds all of the above on native runners per
platform (Linux x86_64 + arm64, Windows x86_64, macOS universal2) on every
`vX.Y.Z` tag push, validates every artifact, generates `SHA256SUMS`, and
publishes a GitHub Release. The signing secrets it reads (`WINDOWS_PFX_*`,
`MACOS_*`) are documented under "Code signing" below — all optional; without
them each platform degrades to unsigned/ad-hoc and says so explicitly rather
than pretending to be SmartScreen- or Gatekeeper-compatible.

## Code signing

Signing is what stops Windows SmartScreen and macOS Gatekeeper from telling
users the publisher is unverified. **Every signing step below already exists in
`release.yml`; each is inert until its secret is present, and each says so
loudly rather than pretending to have signed.** Enabling signing therefore means
buying an identity and adding secrets — no code changes.

### Windows (Authenticode)

`scripts/packaging/sign-windows.ps1` signs the payload `rustzap.exe` before Inno
Setup packs it, and the resulting installer afterwards. Both halves need a
signature; signing only the installer leaves the extracted binary flagged.

| Secret / variable | Kind | Purpose |
|---|---|---|
| `WINDOWS_PFX_BASE64` | secret | Base64 of the `.pfx` holding the cert + private key. Absent → signing is skipped and reported. |
| `WINDOWS_PFX_PASSWORD` | secret | Password for that `.pfx`. Set-but-empty while `WINDOWS_PFX_BASE64` is set is a hard error, deliberately. |
| `WINDOWS_TIMESTAMP_URL` | variable (optional) | RFC 3161 timestamp server; defaults to DigiCert's. Timestamping is what lets signatures outlive cert expiry. |

```bash
base64 -w0 cert.pfx      # value for WINDOWS_PFX_BASE64 (macOS: base64 -i cert.pfx)
```

Certificate options, cheapest first:

- **Azure Trusted Signing** (~$10/month) — cloud-based, CI-friendly, no hardware
  token to babysit. Requires a verified identity; organizations need 3 years of
  legal-entity history.
- **OV certificate** (~$200-400/year) — since the 2023 CA/Browser Forum rules the
  private key must live on a hardware token or cloud HSM, which is awkward in CI.
- **EV certificate** (~$400-700/year) — the only option that grants SmartScreen
  reputation immediately.

**A signature alone does not silence SmartScreen.** OV certs and Trusted Signing
start at zero reputation and accrue it as downloads accumulate, so warnings can
persist for weeks after signing works. Only EV skips that ramp. Publishing via
`winget` sidesteps the prompt entirely and costs nothing.

### macOS (Developer ID + notarization)

`scripts/packaging/build-macos.sh` already implements the full
sign -> notarize -> staple flow. It needs an **Apple Developer Program**
membership ($99/year):

| Secret | Purpose |
|---|---|
| `MACOS_CERT_P12_BASE64` | Base64 of the "Developer ID Application" cert `.p12`. |
| `MACOS_CERT_P12_PASSWORD` | Password for that `.p12`. |
| `MACOS_SIGN_IDENTITY` | e.g. `Developer ID Application: NAME (TEAMID)`. Unset → ad-hoc signing, which is **not** Gatekeeper-compatible. |
| `MACOS_NOTARY_PROFILE` | `xcrun notarytool` keychain-profile name. Unset → notarization skipped (reported, not faked). |

For a CLI, a **Homebrew tap** avoids Gatekeeper prompts altogether and is the
highest-value unblocked step — the formula is already generated per release; it
just needs a tap repo to live in.

### When signing is switched on, update the main README

`README.md` -> "Verifying a download, and the OS trust warnings" states in prose
that release artifacts are unsigned and walks users through the SmartScreen and
Gatekeeper bypasses. That claim is static — it does not track the secrets. It is
also **shipped inside the Windows installer** (`packaging/windows/rustzap.iss`
installs `README.md` alongside the binary), so leaving it stale would tell users
holding a signed installer that their download is unsigned. Adding a signing
secret is therefore a two-part change: the secret, and that README block.

### Linux

Nothing to sign: `.deb`, `.rpm`, and AppImage carry no OS-level publisher gate.
The published `SHA256SUMS` is the integrity check. A GPG-signed release is the
optional upgrade if repo-based distribution is ever added.

## Known limitations (as of this writing)

- **No release artifact is currently signed.** The pipeline steps exist and are
  wired up on both Windows and macOS, but the certificates they need are not
  configured as repository secrets, so Windows ships unsigned and macOS ships
  ad-hoc signed (neither is SmartScreen- nor Gatekeeper-clean). See
  "Code signing" above — this is a purchasing/config task, not a code task.
- **Windows arm64 is not built.** Only x86_64. Add a matrix entry + confirm
  Inno Setup's arm64 support if this becomes a requirement.
- **Linux arm64 is cross-target-built and structurally validated locally on
  a different architecture (see commit history / PR description) but has not
  been installation-tested on real arm64 hardware** — do that before treating
  it as fully verified, per the skill's "never claim ARM support you haven't
  tested" rule.
- The Homebrew formula is generated but this project does not maintain a tap;
  publishing it is a manual step for whoever owns a `homebrew-rustzap` (or
  similar) tap repository.

## Full environment setup

Native packages install the RustZap launcher. `rustzap install` builds the full Kali
Docker environment from the source bundled in that executable; Docker Desktop/Engine
must be installed and running. `rustzap isolated` launches it with a workspace mount.
Native companion installation now requires `--native`. Windows Setup offers full setup
by default on the final page, skips it in silent mode, and installs both isolated and
native console shortcuts. Release signing remains governed by the existing pipeline.

The bundled build context is generated by `build.rs`; keep its manifest aligned with
Docker COPY statements and Rust include_str/include_bytes assets. Changes to these paths
must pass an actual container build, not just host compilation.
