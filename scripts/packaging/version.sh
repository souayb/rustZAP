#!/usr/bin/env bash
# Single source of truth for the release version: reads it straight out of
# Cargo.toml so every packaging script and CI job derives the same number.
# Usage: version.sh   (prints e.g. "0.1.0", nothing else, to stdout)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CARGO_TOML="$ROOT/Cargo.toml"

[ -f "$CARGO_TOML" ] || { echo "error: $CARGO_TOML not found" >&2; exit 1; }

# First `version = "..."` under [package] (the very first occurrence in the
# file, before any [package.metadata.*] table could theoretically add one).
VERSION="$(grep -m1 -E '^version[[:space:]]*=' "$CARGO_TOML" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')"

[ -n "$VERSION" ] || { echo "error: could not parse version from $CARGO_TOML" >&2; exit 1; }

echo "$VERSION"
