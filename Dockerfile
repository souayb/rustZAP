# syntax=docker/dockerfile:1.6
#
# RustZAP — Unified DevSecOps pentesting console
#
# Multi-stage build:
#   1. builder  — compiles the rustzap binary with cargo
#   2. runtime  — minimal Debian image with the binary + SDD companion tools
#                 (Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti,
#                  tshark, Hashcat, John, Hydra, Medusa, Aircrack-ng) installed
#                 via scripts/install-tools.sh.

# ──────────────────────────────────────────────────────────────────
# Stage 1 — builder
# ──────────────────────────────────────────────────────────────────
# Pin the builder to the same Debian release as the runtime so the resulting
# binary's glibc requirement matches what bookworm-slim provides. Without this
# the default rust:<version> tag tracks trixie (glibc 2.39+) and the binary
# fails at startup with "version `GLIBC_2.39' not found".
FROM rust:1.91-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --bin rustzap \
    && strip target/release/rustzap \
    && test -s target/release/rustzap

# ──────────────────────────────────────────────────────────────────
# Stage 2 — runtime
# ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

ARG TARGETARCH=amd64

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.local/bin:${PATH}" \
    TERM=xterm-256color \
    RUSTZAP_IN_DOCKER=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ── 1. Base system deps ───────────────────────────────────────────
# Pre-install everything the install script will need so its per-tool
# commands have a working environment. Keep this in its own layer for
# better cache reuse on subsequent builds.
#
# Enable the `contrib` component on the Debian repos — nikto (and a few
# other pentesting tools) live there, not in `main`. Without this the
# install script's `apt-get install -y nikto` step silently fails.
RUN sed -i 's|^Components: main$|Components: main contrib non-free non-free-firmware|' \
        /etc/apt/sources.list.d/debian.sources 2>/dev/null || true \
    && (grep -rq "^deb .* main$" /etc/apt/sources.list 2>/dev/null \
        && sed -i 's|^\(deb .* main\)$|\1 contrib non-free|' /etc/apt/sources.list || true) \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        sudo \
        git \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Python-based companion tools ───────────────────────────────
# Bookworm-slim's pipx (1.1.0) plays badly as root, so we install the
# Python tools straight to system Python via pip --break-system-packages.
# The install script will see them already on PATH and skip them.
RUN pip3 install --root-user-action=ignore \
        semgrep \
        checkov \
        wapiti3

# ── 3. All remaining companion tools via the canonical script ────
# nmap / nikto / john / hydra / medusa / aircrack-ng / tshark / hashcat
# come from apt; gitleaks is fetched as a binary; trivy is added via its
# official apt repo — all driven by scripts/install-tools.sh so host and
# container installs stay in lockstep.
COPY scripts/install-tools.sh /usr/local/bin/install-tools.sh
RUN chmod +x /usr/local/bin/install-tools.sh \
    && apt-get update \
    && /usr/local/bin/install-tools.sh --yes --skip-update \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

# Drop the rustzap binary into PATH.
COPY --from=builder /build/target/release/rustzap /usr/local/bin/rustzap

# Workspace mount point for reports / inputs.
WORKDIR /workspace
VOLUME ["/workspace"]

# Open the proxy port + a generic app port for reference.
EXPOSE 8080

ENTRYPOINT ["rustzap"]
CMD ["--help"]
