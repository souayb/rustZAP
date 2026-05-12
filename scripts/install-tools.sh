#!/usr/bin/env bash
# install-tools.sh — Install RustZAP companion tools per the SDD.
#
# Detects the host OS and uses the appropriate package manager:
#   macOS         → Homebrew
#   Debian/Ubuntu → apt-get
#   Fedora/RHEL   → dnf
#   Arch/Manjaro  → pacman (+ AUR helper for some pkgs)
#   Alpine        → apk
#
# Usage:
#   install-tools.sh                 # interactive install
#   install-tools.sh --yes           # non-interactive, install everything available
#   install-tools.sh --dry-run       # print plan, install nothing
#   install-tools.sh --tool semgrep  # install just one tool
#   install-tools.sh --list          # list supported tools per OS
#   install-tools.sh --skip-update   # don't refresh package indexes first

set -euo pipefail

YES=0
DRY_RUN=0
SKIP_UPDATE=0
ONLY_TOOL=""
LIST_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --dry-run|-n) DRY_RUN=1 ;;
    --skip-update) SKIP_UPDATE=1 ;;
    --tool) ONLY_TOOL="${2:-}"; shift ;;
    --list|-l) LIST_ONLY=1 ;;
    --help|-h)
      sed -n '2,17p' "$0"; exit 0 ;;
    *)
      echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

# ── Detect OS ────────────────────────────────────────────────────
detect_os() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo "macos"; return
  fi
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian|ubuntu|kali|raspbian|linuxmint) echo "debian"; return ;;
      fedora|rhel|centos|rocky|almalinux)     echo "fedora"; return ;;
      arch|manjaro|endeavouros)               echo "arch";   return ;;
      alpine)                                 echo "alpine"; return ;;
    esac
    for like in ${ID_LIKE:-}; do
      case "$like" in
        debian) echo "debian"; return ;;
        rhel|fedora) echo "fedora"; return ;;
        arch) echo "arch"; return ;;
      esac
    done
  fi
  echo "unknown"
}

OS="$(detect_os)"
echo "▶ Detected OS: $OS"

if [ "$OS" = "unknown" ]; then
  echo "✗ Unsupported OS. Install tools manually — see SOFTWARE_DESIGN_DOCUMENT.md." >&2
  exit 1
fi

# ── Privilege helper (no-op when already root, e.g. inside Docker) ──
if [ "$(id -u)" = "0" ]; then
  SUDO=""
else
  SUDO="sudo"
fi

# ── Tool table: lookup install command per OS ────────────────────
#
# Each row encodes how to install one tool on each supported OS.
# Use "-" if the tool isn't packaged for that OS.

cmd_for() {
  local tool="$1" os="$2"
  case "$tool/$os" in
    # name             os         install command
    semgrep/macos)     echo "brew install semgrep" ;;
    semgrep/debian)    echo "$SUDO apt-get install -y pipx && pipx install semgrep" ;;
    semgrep/fedora)    echo "$SUDO dnf install -y pipx && pipx install semgrep" ;;
    semgrep/arch)      echo "$SUDO pacman -S --noconfirm python-pipx && pipx install semgrep" ;;
    semgrep/alpine)    echo "$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages semgrep" ;;

    trivy/macos)       echo "brew install aquasecurity/trivy/trivy" ;;
    trivy/debian)      echo "curl -sfL https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg && echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\" | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null && $SUDO apt-get update && $SUDO apt-get install -y trivy" ;;
    trivy/fedora)      echo "$SUDO dnf install -y https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit.rpm" ;;
    trivy/arch)        echo "$SUDO pacman -S --noconfirm trivy || echo 'install via AUR: yay -S trivy-bin'" ;;
    trivy/alpine)      echo "$SUDO apk add --no-cache trivy || echo 'use community repo'" ;;

    gitleaks/macos)    echo "brew install gitleaks" ;;
    gitleaks/debian)   echo "GLV=8.18.4 && curl -sSL \"https://github.com/gitleaks/gitleaks/releases/download/v\${GLV}/gitleaks_\${GLV}_linux_x64.tar.gz\" | $SUDO tar -xz -C /usr/local/bin gitleaks" ;;
    gitleaks/fedora)   echo "$SUDO dnf install -y gitleaks || (GLV=8.18.4 && curl -sSL \"https://github.com/gitleaks/gitleaks/releases/download/v\${GLV}/gitleaks_\${GLV}_linux_x64.tar.gz\" | $SUDO tar -xz -C /usr/local/bin gitleaks)" ;;
    gitleaks/arch)     echo "$SUDO pacman -S --noconfirm gitleaks" ;;
    gitleaks/alpine)   echo "$SUDO apk add --no-cache gitleaks" ;;

    checkov/macos)     echo "brew install checkov" ;;
    checkov/debian)    echo "$SUDO apt-get install -y pipx && pipx install checkov" ;;
    checkov/fedora)    echo "$SUDO dnf install -y pipx && pipx install checkov" ;;
    checkov/arch)      echo "$SUDO pacman -S --noconfirm python-pipx && pipx install checkov" ;;
    checkov/alpine)    echo "$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages checkov" ;;

    nmap/macos)        echo "brew install nmap" ;;
    nmap/debian)       echo "$SUDO apt-get install -y nmap" ;;
    nmap/fedora)       echo "$SUDO dnf install -y nmap" ;;
    nmap/arch)         echo "$SUDO pacman -S --noconfirm nmap" ;;
    nmap/alpine)       echo "$SUDO apk add --no-cache nmap" ;;

    nikto/macos)       echo "brew install nikto" ;;
    nikto/debian)      echo "$SUDO apt-get install -y nikto" ;;
    nikto/fedora)      echo "$SUDO dnf install -y nikto" ;;
    nikto/arch)        echo "$SUDO pacman -S --noconfirm nikto || echo 'install via AUR'" ;;
    nikto/alpine)      echo "- (not packaged for Alpine)" ;;

    wapiti/macos)      echo "brew install wapiti" ;;
    wapiti/debian)     echo "$SUDO apt-get install -y pipx && pipx install wapiti3" ;;
    wapiti/fedora)     echo "$SUDO dnf install -y pipx && pipx install wapiti3" ;;
    wapiti/arch)       echo "$SUDO pacman -S --noconfirm python-pipx && pipx install wapiti3" ;;
    wapiti/alpine)     echo "$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages wapiti3" ;;

    tshark/macos)      echo "brew install --cask wireshark" ;;
    tshark/debian)     echo "$SUDO apt-get install -y tshark" ;;
    tshark/fedora)     echo "$SUDO dnf install -y wireshark-cli" ;;
    tshark/arch)       echo "$SUDO pacman -S --noconfirm wireshark-cli" ;;
    tshark/alpine)     echo "$SUDO apk add --no-cache tshark" ;;

    hashcat/macos)     echo "brew install hashcat" ;;
    hashcat/debian)    echo "$SUDO apt-get install -y hashcat" ;;
    hashcat/fedora)    echo "$SUDO dnf install -y hashcat" ;;
    hashcat/arch)      echo "$SUDO pacman -S --noconfirm hashcat" ;;
    hashcat/alpine)    echo "- (not packaged for Alpine)" ;;

    john/macos)        echo "brew install john-jumbo" ;;
    john/debian)       echo "$SUDO apt-get install -y john" ;;
    john/fedora)       echo "$SUDO dnf install -y john" ;;
    john/arch)         echo "$SUDO pacman -S --noconfirm john" ;;
    john/alpine)       echo "$SUDO apk add --no-cache john" ;;

    hydra/macos)       echo "brew install hydra" ;;
    hydra/debian)      echo "$SUDO apt-get install -y hydra" ;;
    hydra/fedora)      echo "$SUDO dnf install -y hydra" ;;
    hydra/arch)        echo "$SUDO pacman -S --noconfirm hydra" ;;
    hydra/alpine)      echo "- (not packaged for Alpine)" ;;

    medusa/macos)      echo "brew install medusa" ;;
    medusa/debian)     echo "$SUDO apt-get install -y medusa" ;;
    medusa/fedora)     echo "$SUDO dnf install -y medusa" ;;
    medusa/arch)       echo "$SUDO pacman -S --noconfirm medusa || echo 'install via AUR'" ;;
    medusa/alpine)     echo "- (not packaged for Alpine)" ;;

    aircrack-ng/macos)  echo "brew install aircrack-ng" ;;
    aircrack-ng/debian) echo "$SUDO apt-get install -y aircrack-ng" ;;
    aircrack-ng/fedora) echo "$SUDO dnf install -y aircrack-ng" ;;
    aircrack-ng/arch)   echo "$SUDO pacman -S --noconfirm aircrack-ng" ;;
    aircrack-ng/alpine) echo "$SUDO apk add --no-cache aircrack-ng" ;;

    *) echo "" ;;
  esac
}

TOOLS=(semgrep trivy gitleaks checkov nmap nikto wapiti tshark hashcat john hydra medusa aircrack-ng)

# ── --list mode ──────────────────────────────────────────────────
if [ "$LIST_ONLY" = "1" ]; then
  printf "%-14s %s\n" "TOOL" "INSTALL COMMAND ($OS)"
  printf "%-14s %s\n" "──────────────" "─────────────────────────────────────────────"
  for tool in "${TOOLS[@]}"; do
    c="$(cmd_for "$tool" "$OS")"
    printf "%-14s %s\n" "$tool" "${c:-not supported}"
  done
  exit 0
fi

# ── Refresh package indexes first (unless skipped) ──────────────
if [ "$SKIP_UPDATE" = "0" ]; then
  case "$OS" in
    debian) $SUDO apt-get update -qq || true ;;
    fedora) $SUDO dnf -q makecache || true ;;
    arch)   $SUDO pacman -Sy --noconfirm || true ;;
    alpine) $SUDO apk update -q || true ;;
    macos)
      if ! command -v brew >/dev/null 2>&1; then
        echo "✗ Homebrew not installed. Install from https://brew.sh first." >&2
        exit 1
      fi
      brew update --quiet || true
      ;;
  esac
fi

# ── Iterate tools ───────────────────────────────────────────────
INSTALLED=0
SKIPPED=0
FAILED=0

for tool in "${TOOLS[@]}"; do
  if [ -n "$ONLY_TOOL" ] && [ "$tool" != "$ONLY_TOOL" ]; then
    continue
  fi

  if command -v "$tool" >/dev/null 2>&1; then
    echo "✓ $tool already installed"
    SKIPPED=$((SKIPPED+1))
    continue
  fi

  cmd="$(cmd_for "$tool" "$OS")"
  if [ -z "$cmd" ] || [[ "$cmd" =~ ^- ]]; then
    echo "· $tool — not packaged on $OS, skipping"
    SKIPPED=$((SKIPPED+1))
    continue
  fi

  echo "▶ $tool"
  echo "  $ $cmd"

  if [ "$DRY_RUN" = "1" ]; then
    SKIPPED=$((SKIPPED+1))
    continue
  fi

  if [ "$YES" = "0" ]; then
    read -r -p "  Install? [Y/n] " ans
    case "$ans" in n|N|no|No) echo "  skipped"; SKIPPED=$((SKIPPED+1)); continue ;; esac
  fi

  if bash -c "$cmd"; then
    # Re-check PATH — some package managers install to non-standard locations.
    if command -v "$tool" >/dev/null 2>&1; then
      echo "  ✓ installed ($(command -v "$tool"))"
    else
      echo "  ✓ install command succeeded (binary not yet on PATH — may need shell reload)"
    fi
    INSTALLED=$((INSTALLED+1))
  else
    echo "  ✗ failed (continuing with remaining tools)"
    FAILED=$((FAILED+1))
  fi
done

echo ""
echo "Done — installed=$INSTALLED skipped=$SKIPPED failed=$FAILED"

# In Docker builds we still want the layer to succeed even if some optional
# tools didn't install (e.g. medusa on a tiny base image). Set
# RUSTZAP_STRICT_INSTALL=1 to fail the build on any failure instead.
if [ "$FAILED" -gt 0 ] && [ "${RUSTZAP_STRICT_INSTALL:-0}" = "1" ]; then
  exit 1
fi
exit 0
