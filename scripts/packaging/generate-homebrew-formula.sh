#!/usr/bin/env bash
# Fill in packaging/homebrew/rustzap.rb.tmpl with the real version + sha256
# of the tagged GitHub release source tarball, so the formula never ships a
# fabricated checksum.
#
# Usage: generate-homebrew-formula.sh [output-file]
#
# Requires the git tag v<version> (from Cargo.toml) to already be pushed —
# run this AFTER creating the release tag, not before. Downloads the tarball
# from GitHub to compute its real sha256; never invents one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(bash scripts/packaging/version.sh)"
TARBALL_URL="https://github.com/souayb/rustZAP/archive/refs/tags/v${VERSION}.tar.gz"
OUT="${1:-packaging/homebrew/rustzap.rb}"

echo "==> Fetching $TARBALL_URL to compute its sha256"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
if ! curl -fsSL -o "$TMP" "$TARBALL_URL"; then
  echo "error: could not download $TARBALL_URL" >&2
  echo "       tag v${VERSION} must exist on GitHub before generating the formula." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  SHA256="$(sha256sum "$TMP" | awk '{print $1}')"
else
  SHA256="$(shasum -a 256 "$TMP" | awk '{print $1}')"
fi

sed -e "s/@@VERSION@@/${VERSION}/g" -e "s/@@SHA256@@/${SHA256}/g" \
  packaging/homebrew/rustzap.rb.tmpl > "$OUT"

echo "Wrote $OUT (version ${VERSION}, sha256 ${SHA256})"
echo "Publish by copying into your homebrew-tap repo's Formula/rustzap.rb"
echo "(this project does not maintain a tap; that's a manual/CI step for the maintainer)."
