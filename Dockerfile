# syntax=docker/dockerfile:1
FROM rust:1.91-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs Dockerfile scope.example.yaml LICENSE ./
COPY scripts/install-tools.sh scripts/install-tools.sh
COPY src ./src
RUN cargo build --locked --release --bin rustzap

# Full companion tool environment. Kali's base image contains no pentest suite.
FROM kalilinux/kali-rolling AS runtime
ENV DEBIAN_FRONTEND=noninteractive \
    TERM=xterm-256color \
    RUSTZAP_IN_DOCKER=1 \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg git python3 python3-venv pipx \
    nmap nikto wapiti tshark hashcat john hydra medusa aircrack-ng wifite \
    gitleaks nuclei \
    && pipx install semgrep && pipx install checkov \
    && curl --fail --silent --show-error --location https://aquasecurity.github.io/trivy-repo/deb/public.key -o /tmp/trivy.key \
    && gpg --batch --dearmor -o /usr/share/keyrings/trivy.gpg /tmp/trivy.key \
    && echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main' > /etc/apt/sources.list.d/trivy.list \
    && apt-get update && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/* /tmp/trivy.key
COPY --from=builder /build/target/release/rustzap /usr/local/bin/rustzap
COPY LICENSE /usr/share/doc/rustzap/LICENSE
# A full installation fails if any promised executable is absent.
RUN for tool in semgrep trivy gitleaks checkov nuclei nmap nikto wapiti tshark hashcat john hydra medusa aircrack-ng wifite; do command -v "$tool" || exit 1; done \
    && semgrep --version && trivy --version && checkov --version \
    && useradd --create-home --uid 1000 rustzap \
    && mkdir /workspace && chown rustzap:rustzap /workspace
USER rustzap
WORKDIR /workspace
ENTRYPOINT ["rustzap"]
CMD []
