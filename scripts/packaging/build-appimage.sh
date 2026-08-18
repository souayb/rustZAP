#!/usr/bin/env bash
# Build a portable AppImage for rustzap from an already-built release binary.
# MUST run on Linux (AppImage tooling and the ELF binary it wraps are Linux-only).
#
# Usage: build-appimage.sh <target-triple> <output-dir>
#   e.g. build-appimage.sh x86_64-unknown-linux-gnu dist
set -euo pipefail

TARGET="${1:?usage: build-appimage.sh <target-triple> <output-dir>}"
OUT_DIR="${2:-dist}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [ "$(uname -s)" != "Linux" ]; then
  echo "error: AppImage must be built on Linux (got $(uname -s))" >&2
  exit 1
fi

VERSION="$(bash scripts/packaging/version.sh)"
BIN="target/${TARGET}/release/rustzap"
[ -x "$BIN" ] || { echo "error: binary not found: $BIN (build it first)" >&2; exit 1; }

case "$TARGET" in
  x86_64-*)  ARCH=x86_64 ;;
  aarch64-*) ARCH=aarch64 ;;
  *) echo "error: unsupported target for AppImage: $TARGET" >&2; exit 1 ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
APPDIR="$WORK/AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"

install -m 755 "$BIN" "$APPDIR/usr/bin/rustzap"
install -m 644 packaging/linux/appimage/rustzap.desktop "$APPDIR/rustzap.desktop"
install -m 644 packaging/linux/appimage/rustzap.desktop "$APPDIR/usr/share/applications/rustzap.desktop"
install -m 644 packaging/linux/appimage/rustzap.png "$APPDIR/rustzap.png"
install -m 644 packaging/linux/appimage/rustzap.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/rustzap.png"
install -m 755 packaging/linux/appimage/AppRun "$APPDIR/AppRun"
ln -sf rustzap.png "$APPDIR/.DirIcon"

APPIMAGETOOL="$WORK/appimagetool"
if command -v appimagetool >/dev/null 2>&1; then
  APPIMAGETOOL="$(command -v appimagetool)"
else
  echo "==> Fetching appimagetool (not found on PATH)"
  curl -fsSL -o "$APPIMAGETOOL" \
    "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
  chmod +x "$APPIMAGETOOL"
fi

mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/rustzap-${VERSION}-linux-${ARCH}.AppImage"
ARCH="$ARCH" "$APPIMAGETOOL" "$APPDIR" "$OUT"

echo "Built $OUT"
