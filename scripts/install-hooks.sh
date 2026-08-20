#!/usr/bin/env sh
# Install or remove repo-local Git hooks (Linux, macOS, Git Bash on Windows).
# Does not change global git config.
#
# Usage:
#   ./scripts/install-hooks.sh           # enable .githooks via core.hooksPath
#   ./scripts/install-hooks.sh --uninstall

set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 1
fi

if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != "true" ]; then
  echo "error: $ROOT is not a git working tree" >&2
  exit 1
fi

case "${1:-}" in
  --uninstall|-u)
    git config --unset core.hooksPath 2>/dev/null || true
    echo "Removed local core.hooksPath (Git will use .git/hooks)."
    exit 0
    ;;
  --help|-h)
    sed -n '2,9p' "$0"
    exit 0
    ;;
  "") ;;
  *)
    echo "Unknown flag: $1" >&2
    exit 2
    ;;
esac

chmod +x "$ROOT/scripts/dev-check.sh" "$ROOT/.githooks/pre-commit" "$ROOT/.githooks/pre-push" 2>/dev/null || true

git config core.hooksPath .githooks

if command -v rustup >/dev/null 2>&1; then
  rustup component add rustfmt clippy >/dev/null
fi

echo "Installed Git hooks (local core.hooksPath=.githooks)."
echo "  pre-commit → rustfmt + block generated reports"
echo "  pre-push   → clippy -D warnings + cargo test"
echo "Uninstall: ./scripts/install-hooks.sh --uninstall"
