#!/usr/bin/env bash
# Build a Universal 2 (arm64 + x86_64) rustzap binary, code-sign it, and
# package a .dmg. MUST run on macOS (codesign/hdiutil/notarytool are
# macOS-only, and cross-signing isn't a thing Apple supports).
#
# Usage: build-macos.sh [output-dir]
#
# Env vars (all optional — script degrades gracefully without them):
#   MACOS_SIGN_IDENTITY   "Developer ID Application: NAME (TEAMID)".
#                         Defaults to ad-hoc signing ("-") which satisfies
#                         codesign locally but is NOT Gatekeeper-compatible —
#                         only a real Developer ID identity is. Never invented
#                         here; must come from a real cert loaded into the
#                         signing keychain (CI: from a secret).
#   MACOS_NOTARY_PROFILE  `xcrun notarytool` keychain-profile name. When set,
#                         the built DMG is submitted for notarization and the
#                         ticket is stapled. When unset, notarization is
#                         skipped (reported, not silently pretended).
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: macOS packaging must run on macOS (got $(uname -s))" >&2
  exit 1
fi

OUT_DIR="${1:-dist}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(bash scripts/packaging/version.sh)"
SIGN_IDENTITY="${MACOS_SIGN_IDENTITY:--}"
NOTARY_PROFILE="${MACOS_NOTARY_PROFILE:-}"

echo "==> Building rustzap ${VERSION} for aarch64-apple-darwin and x86_64-apple-darwin"
for target in aarch64-apple-darwin x86_64-apple-darwin; do
  rustup target list --installed | grep -qx "$target" || rustup target add "$target"
  cargo build --release --bin rustzap --target "$target"
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
UNIVERSAL_BIN="$WORK/rustzap"

echo "==> Combining into a Universal 2 binary"
lipo -create -output "$UNIVERSAL_BIN" \
  "target/aarch64-apple-darwin/release/rustzap" \
  "target/x86_64-apple-darwin/release/rustzap"
lipo -info "$UNIVERSAL_BIN"

echo "==> Code-signing (identity: ${SIGN_IDENTITY})"
if [ "$SIGN_IDENTITY" = "-" ]; then
  # Ad-hoc: no hardened runtime, no timestamp — those require a real Apple
  # identity and network access to Apple's timestamp server. Ad-hoc signing
  # only satisfies local codesign checks; it is NOT Gatekeeper-compatible.
  echo "    NOTE: ad-hoc signature only — not Gatekeeper-compatible." >&2
  echo "    Set MACOS_SIGN_IDENTITY to a real Developer ID for release builds." >&2
  codesign --force --sign "$SIGN_IDENTITY" "$UNIVERSAL_BIN"
else
  codesign --force --options runtime --timestamp \
    --sign "$SIGN_IDENTITY" "$UNIVERSAL_BIN"
fi
codesign --verify --verbose=2 "$UNIVERSAL_BIN"

mkdir -p "$OUT_DIR"
DMG_ROOT="$WORK/dmgroot"
mkdir -p "$DMG_ROOT"
install -m 755 "$UNIVERSAL_BIN" "$DMG_ROOT/rustzap"
install -m 644 README.md "$DMG_ROOT/README.md"
install -m 644 LICENSE "$DMG_ROOT/LICENSE"
cat > "$DMG_ROOT/Install.command" <<'INSTALL'
#!/bin/sh
# Double-click installer: copies rustzap onto PATH for the current user.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="/usr/local/bin"
mkdir -p "$DEST"
cp "$HERE/rustzap" "$DEST/rustzap"
chmod 755 "$DEST/rustzap"
echo "Installed rustzap to $DEST/rustzap"
echo "Run 'rustzap --help' from a new terminal to get started."
INSTALL
chmod +x "$DMG_ROOT/Install.command"

DMG_OUT="$OUT_DIR/rustzap-${VERSION}-macos-universal.dmg"
rm -f "$DMG_OUT"
echo "==> Building $DMG_OUT"
hdiutil create -volname "RustZAP ${VERSION}" -srcfolder "$DMG_ROOT" -ov -format UDZO "$DMG_OUT"

if [ "$SIGN_IDENTITY" != "-" ]; then
  echo "==> Signing DMG"
  codesign --force --sign "$SIGN_IDENTITY" "$DMG_OUT"
fi

if [ -n "$NOTARY_PROFILE" ]; then
  echo "==> Submitting for notarization (profile: ${NOTARY_PROFILE})"
  xcrun notarytool submit "$DMG_OUT" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "==> Stapling notarization ticket"
  xcrun stapler staple "$DMG_OUT"
  spctl -a -t open --context context:primary-signature -v "$DMG_OUT" || true
else
  echo "NOTE: MACOS_NOTARY_PROFILE not set — skipping notarization." >&2
  echo "      This DMG will trigger Gatekeeper warnings on other Macs." >&2
fi

echo "Built $DMG_OUT"
