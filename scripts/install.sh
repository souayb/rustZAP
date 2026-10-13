#!/bin/sh
# RustZAP one-line installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/souayb/rustZAP/main/scripts/install.sh | sh
#
# Downloads the raw, console CLI binary for your OS/arch from the latest GitHub
# release, verifies its SHA-256 against the release's SHA256SUMS, and installs it
# onto your PATH. No root required (installs to ~/.local/bin by default).
#
# Options (pass with `... | sh -s -- <opts>`, or as env vars):
#   --version X.Y.Z       install a specific version   (env: RUSTZAP_VERSION)
#   --bin-dir DIR         install location             (env: RUSTZAP_INSTALL_DIR)
#   --no-verify           skip checksum verification   (env: RUSTZAP_NO_VERIFY=1)
#
# POSIX sh — no bashisms (matches scripts/dev-check.sh).
set -eu

REPO="souayb/rustZAP"
VERSION="${RUSTZAP_VERSION:-}"
BIN_DIR="${RUSTZAP_INSTALL_DIR:-}"
NO_VERIFY="${RUSTZAP_NO_VERIFY:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)   VERSION="${2:-}"; shift 2 ;;
    --version=*) VERSION="${1#*=}"; shift ;;
    --bin-dir)   BIN_DIR="${2:-}"; shift 2 ;;
    --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "install.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done

err()  { echo "install.sh: $*" >&2; exit 1; }
info() { echo "==> $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ── Downloader (curl or wget) ────────────────────────────────────────────────
if have curl; then
  dl()    { curl -fsSL "$1" -o "$2"; }       # url file
  dltty() { curl -fsSL "$1"; }               # url -> stdout
elif have wget; then
  dl()    { wget -qO "$2" "$1"; }
  dltty() { wget -qO - "$1"; }
else
  err "need curl or wget"
fi
have tar || err "need tar"

# ── Detect OS/arch and the matching release asset ────────────────────────────
os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Linux)  os_tag="linux" ;;
  Darwin) os_tag="macos" ;;
  *) err "unsupported OS '$os' — on Windows download rustzap-<version>-windows-x64.zip from the Releases page" ;;
esac
case "$arch" in
  x86_64|amd64)   arch_tag="x86_64" ;;
  arm64|aarch64)  arch_tag="aarch64" ;;
  *) err "unsupported architecture '$arch'" ;;
esac

if [ "$os_tag" = "macos" ]; then
  asset="rustzap-VERSION-macos-universal.tar.gz"   # universal (arm64 + x86_64)
else
  asset="rustzap-VERSION-linux-${arch_tag}.tar.gz"
fi

# ── Resolve version (latest release unless pinned) ───────────────────────────
if [ -z "$VERSION" ]; then
  info "Resolving latest release"
  tag="$(dltty "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep -m1 '"tag_name"' | sed 's/.*"tag_name"[^"]*"\([^"]*\)".*/\1/')"
  [ -n "$tag" ] || err "could not determine the latest release (set --version)"
  VERSION="${tag#v}"
fi
asset="$(echo "$asset" | sed "s/VERSION/${VERSION}/")"

base="https://github.com/${REPO}/releases/download/v${VERSION}"
info "Installing rustzap ${VERSION} (${os_tag}/${arch_tag})"

# ── Download + verify + extract into a private temp dir ──────────────────────
tmp="$(mktemp -d "${TMPDIR:-/tmp}/rustzap-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "Downloading ${asset}"
dl "${base}/${asset}" "${tmp}/${asset}" || err "download failed: ${base}/${asset}"

if [ "$NO_VERIFY" != "1" ]; then
  if have sha256sum; then hash() { sha256sum "$1" | awk '{print $1}'; }
  elif have shasum;   then hash() { shasum -a 256 "$1" | awk '{print $1}'; }
  else err "need sha256sum or shasum to verify (re-run with --no-verify to skip)"; fi
  info "Verifying checksum"
  if dl "${base}/SHA256SUMS" "${tmp}/SHA256SUMS" 2>/dev/null; then
    want="$(grep " ${asset}\$" "${tmp}/SHA256SUMS" | awk '{print $1}')"
    [ -n "$want" ] || err "no SHA256SUMS entry for ${asset}"
    got="$(hash "${tmp}/${asset}")"
    [ "$want" = "$got" ] || err "checksum mismatch for ${asset} (expected ${want}, got ${got})"
    info "Checksum OK"
  else
    err "could not fetch SHA256SUMS (re-run with --no-verify to skip)"
  fi
fi

tar -xzf "${tmp}/${asset}" -C "$tmp"
[ -f "${tmp}/rustzap" ] || err "archive did not contain a 'rustzap' binary"

# ── Choose an install dir and place the binary ───────────────────────────────
if [ -z "$BIN_DIR" ]; then
  if [ "$(id -u)" = "0" ]; then BIN_DIR="/usr/local/bin"; else BIN_DIR="${HOME}/.local/bin"; fi
fi
mkdir -p "$BIN_DIR" || err "cannot create install dir ${BIN_DIR}"
install -m 755 "${tmp}/rustzap" "${BIN_DIR}/rustzap" 2>/dev/null \
  || { cp "${tmp}/rustzap" "${BIN_DIR}/rustzap" && chmod 755 "${BIN_DIR}/rustzap"; } \
  || err "cannot write to ${BIN_DIR} (set --bin-dir to a writable location)"

info "Installed ${BIN_DIR}/rustzap"

# ── PATH hint ────────────────────────────────────────────────────────────────
case ":${PATH}:" in
  *":${BIN_DIR}:"*) : ;;
  *) echo
     echo "Note: ${BIN_DIR} is not on your PATH. Add it, e.g.:"
     echo "  echo 'export PATH=\"${BIN_DIR}:\$PATH\"' >> ~/.profile && . ~/.profile" ;;
esac

echo
"${BIN_DIR}/rustzap" --version 2>/dev/null || true
echo "Done. Run 'rustzap --help' to get started."
