# Packaging a Rust CLI (applies to rustzap)

`rustzap` is a Rust binary (`[[bin]] name = "rustzap"`) built with `cargo`. Version is the single source of truth in `Cargo.toml` (`version = "x.y.z"`). Derive every installer version from it — never hand-edit a second number.

```bash
VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
```

Build a release binary per target:

```bash
cargo build --release                      # host target
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

A CLI installs a binary onto `PATH` and (optionally) shell completions + a man page. No desktop shortcut, no GUI file associations.

## Linux — `.deb` and `.rpm` via cargo plugins

```bash
cargo install cargo-deb cargo-generate-rpm
cargo deb                       # target/debian/rustzap_<version>_<arch>.deb  → /usr/bin/rustzap
cargo build --release && cargo generate-rpm   # target/generate-rpm/*.rpm
```

Add to `Cargo.toml` (metadata only; keep minimal):

```toml
[package.metadata.deb]
maintainer = "RustZAP Contributors"
depends = "$auto"
section = "utils"
priority = "optional"
assets = [
  ["target/release/rustzap", "usr/bin/", "755"],
  ["README.md", "usr/share/doc/rustzap/README.md", "644"],
]

[package.metadata.generate-rpm]
assets = [
  { source = "target/release/rustzap", dest = "/usr/bin/rustzap", mode = "755" },
]
```

Ship completions/man page as extra `assets` if the CLI generates them (`clap` can, via `clap_complete` / `clap_mangen`).

## Linux — AppImage (portable)

Only worth it for GUI apps or when users can't use a package manager. For a pure CLI, a `.tar.gz` of the static-ish binary + `SHA256SUMS` is usually enough. If required, build with `linuxdeploy`:

```
AppDir/
├── AppRun            # execs usr/bin/rustzap
├── usr/bin/rustzap
└── rustzap.desktop   # Terminal=true for a CLI
```

Prefer musl (`x86_64-unknown-linux-musl`) for a portable, dependency-light binary.

## Windows — `.exe` (Inno Setup) or `.msi` (WiX)

Install `rustzap.exe` under `C:\Program Files\RustZAP\` and offer an **optional** "Add to PATH" checkbox (don't force it). Register Add/Remove Programs entry. See `windows.md`. Sign the `.exe`/`.msi` with Authenticode.

## macOS — CLI distribution

A CLI is **not** a `.app`. Options:
- **Tarball + install script** placing `rustzap` in `/usr/local/bin` (simplest).
- **`.pkg`** via `pkgbuild` for a double-click installer that drops the binary in `/usr/local/bin`.
- **Homebrew tap** (best UX for CLI): a formula pointing at the signed release tarball + SHA256.

Sign the binary (`codesign`) and **notarize** the `.pkg`/`.dmg`/zip if distributing outside Homebrew — see `macos.md`. Ship Universal 2:

```bash
lipo -create -output rustzap-universal \
  target/aarch64-apple-darwin/release/rustzap \
  target/x86_64-apple-darwin/release/rustzap
```

## Docker note (already in this repo)

The repo has a `Dockerfile` and `docker-compose.yml`. A container image is a valid *distribution* channel but not an OS installer — keep it, and verify `CMD`/entrypoint invokes `rustzap` correctly after CLI changes. Don't replace native installers with the container.
