#!/usr/bin/env bash
# Generate SHA256SUMS for every regular file in a release directory.
# Usage: gen-checksums.sh <dir>   (defaults to ./dist)
# Portable across macOS (shasum) and Linux (sha256sum). Excludes an existing
# SHA256SUMS so re-runs are idempotent.
set -euo pipefail

DIR="${1:-dist}"
[ -d "$DIR" ] || { echo "error: not a directory: $DIR" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  HASH() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  HASH() { shasum -a 256 "$1"; }
else
  echo "error: need sha256sum or shasum" >&2; exit 1
fi

OUT="$DIR/SHA256SUMS"
# Accumulate in a tempfile OUTSIDE the scanned dir so it can't hash itself.
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
found=0
# List files with basenames only so the sums file is relocatable.
while IFS= read -r f; do
  base="$(basename "$f")"
  # Never checksum the sums file itself (or a stale temp copy).
  case "$base" in SHA256SUMS|SHA256SUMS.*) continue;; esac
  line="$(HASH "$f")"
  # Normalize to "<hash>  <basename>".
  printf '%s  %s\n' "${line%% *}" "$base" >> "$TMP"
  found=$((found+1))
done < <(find "$DIR" -maxdepth 1 -type f | sort)

if [ "$found" -eq 0 ]; then
  echo "error: no artifacts found in $DIR" >&2; exit 1
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "Wrote $OUT ($found artifact(s)):"
cat "$OUT"
