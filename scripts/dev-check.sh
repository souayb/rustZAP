#!/bin/sh
# Shared contribution checks for Git hooks and CI.
# POSIX sh so it runs on Linux, macOS, and Git for Windows (bash/sh).
#
# Usage:
#   scripts/dev-check.sh pre-commit   # rustfmt + staged-file hygiene
#   scripts/dev-check.sh pre-push     # clippy + tests
#   scripts/dev-check.sh ci           # all of the above on the whole tree
#
# Environment:
#   RUSTZAP_SKIP_HOOKS=1   skip (not for pull requests)
#   CARGO                  override cargo binary

set -eu

MODE="${1:-}"
case "$MODE" in
  pre-commit|pre-push|ci) ;;
  *)
    echo "usage: $0 <pre-commit|pre-push|ci>" >&2
    exit 2
    ;;
esac

if [ "${RUSTZAP_SKIP_HOOKS:-}" = "1" ]; then
  echo "dev-check: skipping ($MODE) because RUSTZAP_SKIP_HOOKS=1"
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$ROOT" ]; then
  ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
fi
cd "$ROOT"

# ── PATH: GUI Git clients (GitHub Desktop, Sourcetree) often lack rustup ──
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
if [ -n "${USERPROFILE:-}" ] && [ -d "$USERPROFILE/.cargo/bin" ]; then
  PATH="$USERPROFILE/.cargo/bin:$PATH"
fi
PATH="$HOME/.cargo/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"
export PATH

CARGO="${CARGO:-cargo}"

need_cargo() {
  if ! command -v "$CARGO" >/dev/null 2>&1; then
    echo "error: cargo not found on PATH." >&2
    echo "Install Rust from https://rustup.rs/ and re-open your terminal." >&2
    echo "Then:  rustup component add rustfmt clippy" >&2
    echo "Windows contributors: install Git for Windows so hooks run under bash." >&2
    exit 1
  fi
}

# Normalize to forward slashes for Windows paths from Git.
norm_path() {
  printf '%s' "$1" | tr '\\' '/'
}

# Generated app output and other files that must not be committed.
is_forbidden() {
  f="$(norm_path "$1")"
  b="${f##*/}"

  case "$f" in
    reports/.gitkeep) return 1 ;;
    reports/*|target/*|dist/*|public_repos/*) return 0 ;;
  esac

  case "$b" in
    report.json|report.csv|report.html) return 0 ;;
    *-report.json|*-report.csv|*-report.html) return 0 ;;
    .rustzap-gitleaks-report.json) return 0 ;;
    .env|.env.*)
      [ "$b" = ".env.example" ] && return 1
      return 0
      ;;
    id_rsa|id_dsa|id_ecdsa|id_ed25519|*.pem|*.p12|*.pfx|credentials.json)
      return 0
      ;;
  esac

  case "$f" in
    tests/fixtures/*) return 1 ;;
    *.sarif) return 0 ;;
  esac

  return 1
}

check_forbidden_list() {
  bad=0
  while IFS= read -r f || [ -n "${f:-}" ]; do
    [ -z "$f" ] && continue
    if is_forbidden "$f"; then
      echo "error: do not commit generated or secret file: $f" >&2
      bad=1
    fi
  done
  if [ "$bad" -ne 0 ]; then
    echo "Write scanner output under reports/ (gitignored) or a path outside the repo." >&2
    exit 1
  fi
}

run_fmt() {
  need_cargo
  echo "→ cargo fmt --all -- --check"
  if ! "$CARGO" fmt --all -- --check; then
    echo "error: rustfmt check failed. Run:  cargo fmt --all" >&2
    echo "If rustfmt is missing:  rustup component add rustfmt" >&2
    exit 1
  fi
}

run_clippy() {
  need_cargo
  echo "→ cargo clippy --workspace --all-targets -- -D warnings"
  if ! "$CARGO" clippy --workspace --all-targets -- -D warnings; then
    echo "error: clippy failed. If clippy is missing:  rustup component add clippy" >&2
    exit 1
  fi
}

run_test() {
  need_cargo
  echo "→ cargo test --workspace"
  "$CARGO" test --workspace
}

pre_commit() {
  echo "== pre-commit =="
  staged="$(git diff --cached --name-only --diff-filter=ACMR || true)"
  if [ -n "$staged" ]; then
    printf '%s\n' "$staged" | check_forbidden_list
    # Trailing whitespace + conflict markers on the index
    git diff --cached --check
  fi
  run_fmt
}

pre_push() {
  echo "== pre-push =="
  run_clippy
  run_test
}

ci() {
  echo "== ci =="
  git ls-files | check_forbidden_list
  run_fmt
  run_clippy
  run_test
}

case "$MODE" in
  pre-commit) pre_commit ;;
  pre-push) pre_push ;;
  ci) ci ;;
esac

echo "dev-check: $MODE ok"
