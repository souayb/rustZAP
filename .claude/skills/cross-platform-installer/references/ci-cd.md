# CI/CD release pipeline

Trigger on a git tag. Build each platform on its **native runner** (signing/notarization can't be faked cross-OS). Collect artifacts, generate checksums, validate, then publish.

```
git tag → validate version → run tests → build matrix (native runners)
  → package → sign → (macOS: notarize+staple) → gen SHA256SUMS → validate artifacts → publish release
```

## Build matrix

| OS | x86_64 | arm64 | Runner |
|---|---|---|---|
| Linux | ✓ | ✓ | `ubuntu-latest` (+ cross for arm64) |
| Windows | ✓ | ✓ | `windows-latest` |
| macOS | ✓ | ✓ | `macos-latest` (Universal 2 via `lipo`) |

Only claim an arch you actually build and can run/sign.

## GitHub Actions skeleton (`.github/workflows/release.yml`)

```yaml
name: release
on:
  push:
    tags: ["v*"]
jobs:
  version:
    runs-on: ubuntu-latest
    outputs: { version: ${{ steps.v.outputs.version }} }
    steps:
      - uses: actions/checkout@v4
      - id: v
        run: |
          CARGO_VER=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')
          TAG_VER=${GITHUB_REF_NAME#v}
          [ "$CARGO_VER" = "$TAG_VER" ] || { echo "tag $TAG_VER != Cargo.toml $CARGO_VER"; exit 1; }
          echo "version=$CARGO_VER" >> "$GITHUB_OUTPUT"

  build:
    needs: version
    strategy:
      matrix:
        include:
          - { os: ubuntu-latest,  target: x86_64-unknown-linux-gnu }
          - { os: windows-latest, target: x86_64-pc-windows-msvc }
          - { os: macos-latest,   target: aarch64-apple-darwin }
          - { os: macos-latest,   target: x86_64-apple-darwin }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: "${{ matrix.target }}" }
      - run: cargo test --workspace
      - run: cargo build --release --target ${{ matrix.target }}
      # package per-OS here (cargo-deb / iscc / hdiutil) — see platform refs
      # sign here using SECRETS (never inline keys)
      - uses: actions/upload-artifact@v4
        with: { name: ${{ matrix.target }}, path: dist/* }

  publish:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with: { path: dist }
      - run: bash .claude/skills/cross-platform-installer/scripts/gen-checksums.sh dist
      - run: |
          for a in dist/*; do
            [ -f "$a" ] && bash .claude/skills/cross-platform-installer/scripts/verify-installer.sh "$a" --expect-version "${{ needs.version.outputs.version }}"
          done
      - uses: softprops/action-gh-release@v2
        with: { files: "dist/*" }
```

## Secrets (repo/org settings → Actions secrets)

`APPLE_CERT_P12`, `APPLE_CERT_PASSWORD`, `APPLE_NOTARY_PROFILE` (or API key id/issuer/key), `WINDOWS_PFX`, `WINDOWS_PFX_PASSWORD`, `GPG_PRIVATE_KEY`. Decode into a temp keychain/file at job start, use, then discard. Never echo them.

## Reproducibility record

Emit a `build-info.json` per release: git commit, version, runner OS, `rustc --version`, packaging-tool versions, target triple. Attach it to the release.
