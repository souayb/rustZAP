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
publishes a GitHub Release. See that file's comments for the secrets it reads
(`MACOS_SIGN_IDENTITY`, `MACOS_CERT_P12_BASE64`, `MACOS_CERT_P12_PASSWORD`,
`MACOS_NOTARY_PROFILE`) — all optional; without them the macOS build falls
back to ad-hoc signing and says so explicitly rather than pretending to be
Gatekeeper-compatible.

## Known limitations (as of this writing)

- **Windows codesigning is not wired up** — no Authenticode certificate
  secret exists yet. The `.exe` this pipeline produces is unsigned; SmartScreen
  will warn. Add `WINDOWS_PFX` / `WINDOWS_PFX_PASSWORD` secrets and the
  `signtool sign` step noted in `release.yml` to fix this.
- **macOS signing/notarization requires `MACOS_*` secrets that are not yet
  configured** in this repository. Until they are, macOS builds are ad-hoc
  signed only (not Gatekeeper-compatible).
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
