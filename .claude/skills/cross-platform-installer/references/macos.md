# macOS packaging detail

## Bundle vs CLI

GUI apps ship as `MyApp.app/Contents/{Info.plist, MacOS/, Resources/, Frameworks/}`. A CLI is a plain binary → distribute via tarball, `.pkg`, or Homebrew (see `rust-cli.md`). Never put mutable data inside the `.app`.

`Info.plist` essentials: `CFBundleIdentifier` (reverse-DNS), `CFBundleVersion` + `CFBundleShortVersionString`, `LSMinimumSystemVersion`, icon, and (if sandboxed) entitlements.

## Architectures

Ship **Universal 2** when practical:

```bash
lipo -create -output MyApp target/aarch64-apple-darwin/release/MyApp \
                            target/x86_64-apple-darwin/release/MyApp
lipo -info MyApp   # verify: arm64 x86_64
```

## Signing → notarizing → stapling (required for Gatekeeper)

```bash
# 1. Sign nested binaries/frameworks first, then the outer bundle, with hardened runtime.
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: NAME (TEAMID)" MyApp.app/Contents/Frameworks/*
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: NAME (TEAMID)" MyApp.app
codesign --verify --deep --strict --verbose=2 MyApp.app

# 2. Package.
hdiutil create -volname MyApp -srcfolder MyApp.app -ov -format UDZO MyApp.dmg
# or: pkgbuild --root ... --identifier ... --version X --install-location /usr/local/bin out.pkg

# 3. Notarize the DMG/PKG/zip and staple the ticket.
xcrun notarytool submit MyApp.dmg --keychain-profile "AC_PROFILE" --wait
xcrun stapler staple MyApp.dmg
spctl -a -vvv -t install MyApp.dmg   # verify Gatekeeper accepts it
```

- Identity, App Store Connect API key / `notarytool` profile → **CI secrets**. Never commit `.p12`/`.cer`/keys.
- Hardened runtime (`--options runtime`) and a secure timestamp (`--timestamp`) are required for notarization.
- `.pkg` for system-level installs uses `pkgbuild` (component) + `productbuild` (distribution/UI). Sign product with a "Developer ID Installer" identity.

## Homebrew (recommended for CLIs like rustzap)

Publish a signed, notarized release tarball + its SHA256; ship a formula in a tap that `brew install`s it. Best UX and no Gatekeeper prompts for terminal tools.
