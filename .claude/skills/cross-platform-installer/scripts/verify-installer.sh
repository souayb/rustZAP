#!/usr/bin/env bash
# Structural validation of a single installer artifact. This does NOT prove the
# installer "works" — it only checks the things CI can verify without a clean VM:
# existence, non-emptiness, recognized extension, arch/version sanity in the
# name, and (if a SHA256SUMS sits beside it) checksum integrity.
# Usage: verify-installer.sh <artifact> [--expect-version X.Y.Z] [--min-bytes N]
set -euo pipefail

ART="${1:-}"
[ -n "$ART" ] || { echo "usage: verify-installer.sh <artifact> [--expect-version X] [--min-bytes N]" >&2; exit 2; }
shift || true

EXPECT_VERSION=""
MIN_BYTES=1024
while [ $# -gt 0 ]; do
  case "$1" in
    --expect-version) EXPECT_VERSION="${2:-}"; shift 2;;
    --min-bytes)      MIN_BYTES="${2:-}"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

fail() { echo "FAIL: $1" >&2; exit 1; }
warn() { echo "WARN: $1" >&2; }
ok()   { echo "  ok: $1"; }

base="$(basename "$ART")"
echo "Verifying $base"

[ -f "$ART" ] || fail "artifact does not exist: $ART"; ok "exists"

# Size (portable stat).
size="$(wc -c < "$ART" | tr -d ' ')"
[ "$size" -ge "$MIN_BYTES" ] || fail "artifact too small (${size}B < ${MIN_BYTES}B) — likely a broken build"
ok "non-empty (${size} bytes)"

# Recognized extension.
case "$base" in
  *.deb|*.rpm|*.AppImage|*.msi|*.exe|*.dmg|*.pkg|*.tar.gz|*.tgz|*.zip) ok "recognized installer extension" ;;
  *) warn "unrecognized installer extension for '$base'" ;;
esac

# Architecture token present in the name (advisory).
case "$base" in
  *x86_64*|*amd64*|*x64*|*arm64*|*aarch64*|*universal*) ok "architecture token present in name" ;;
  *) warn "no architecture token in name — prefer <app>-<version>-<os>-<arch>.<ext>" ;;
esac

# Ambiguous names are a release smell.
case "$base" in
  setup.*|final.*|latest.*|build[0-9]*.*|test.*) warn "ambiguous artifact name '$base' — use a versioned name" ;;
esac

# Version check (if requested).
if [ -n "$EXPECT_VERSION" ]; then
  case "$base" in
    *"$EXPECT_VERSION"*) ok "version $EXPECT_VERSION present in name" ;;
    *) fail "expected version '$EXPECT_VERSION' not found in artifact name '$base'" ;;
  esac
fi

# Checksum, if a SHA256SUMS is next to the artifact.
dir="$(dirname "$ART")"
if [ -f "$dir/SHA256SUMS" ] && grep -q "  $base\$" "$dir/SHA256SUMS"; then
  if command -v sha256sum >/dev/null 2>&1; then HASH() { sha256sum "$1" | awk '{print $1}'; }
  else HASH() { shasum -a 256 "$1" | awk '{print $1}'; }; fi
  want="$(grep "  $base\$" "$dir/SHA256SUMS" | awk '{print $1}')"
  got="$(HASH "$ART")"
  [ "$want" = "$got" ] || fail "checksum mismatch for $base"
  ok "sha256 matches SHA256SUMS"
else
  warn "no SHA256SUMS entry beside artifact (run gen-checksums.sh)"
fi

echo "PASS (structural checks only — run install/launch/upgrade/uninstall on a clean OS before claiming it works)"
