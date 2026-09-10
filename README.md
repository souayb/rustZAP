# RustZAP 🦀🔐

A fast, fearless web application security scanner written in Rust, inspired by [OWASP ZAP](https://www.zaproxy.org/).

```
██████╗ ██╗   ██╗███████╗████████╗███████╗ █████╗ ██████╗ 
██╔══██╗██║   ██║██╔════╝╚══██╔══╝╚════██║██╔══██╗██╔══██╗
██████╔╝██║   ██║███████╗   ██║       ██╔╝███████║██████╔╝
██╔══██╗██║   ██║╚════██║   ██║      ██╔╝ ██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝███████║   ██║      ██║  ██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝  ╚═╝  ╚═╝╚═╝     
```

> ⚠️ **Legal Warning**: Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Features

| Feature | Description |
|---|---|
| 🕷️ **Spider/Crawler** | Recursive link, form, and JS URL discovery + `robots.txt` / sitemap enrichment |
| 🔍 **Passive Scanner** | Headers, body, security.txt, deep CSP review, JWT heuristics, tech-stack fingerprint |
| 💥 **Active Scanner** | 22 plugins — XSS, full SQLi suite, NoSQL, SSRF, XXE, GraphQL introspection, HTTP methods, redirect chain, opt-in path probe |
| 🔐 **Transport Probe** | Per-host TLS cert summary — expiry, weak signature, hostname mismatch, self-signed |
| 🛰️ **Intel Hook** | Optional Shodan enrichment when `SHODAN_API_KEY` is set (no-op otherwise) |
| 🔀 **Intercepting Proxy** | HTTP(S) proxy for manual browsing + passive analysis |
| 📊 **JSON / CSV / HTML Reports** | Machine-readable findings with OWASP/CWE references |
| 🖥️ **Interactive TUI** | Seven-tab Ratatui console — DAST scans, local repo **analyze**, scope-gated **agent** runs, findings, tools, logs |
| 🧰 **Unified Tool Console** | Detects & runs Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti, Falco, Hashcat, John, Hydra and more from the TUI |
| 🚀 **Stress Tester** | 5-mode load tester with percentile latency, timeline, and JSON report |
| 🤖 **Agentic Tester** | Scope-gated agent (`rustzap agent`) + MCP server (`rustzap mcp`) over one tool registry — LLM or scripted brain, autonomy modes, HTTP capture/replay, privacy tokenization, prompt-injection shield, OWASP LLM Top-10 red-team |
| 📋 **Roadmap** | [FEATURE.md](FEATURE.md) (DAST status + backlog) · [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (analyze/audit/agent/API) |

---

## Documentation

| Document | Contents |
|----------|----------|
| [README.md](README.md) | Install, Docker, CLI usage, architecture overview |
| [FEATURE.md](FEATURE.md) | Passive/active/spider **status table** + backlog; platform phases in IMPLEMENTATION_PLAN |
| [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) | **Detailed implementation spec**: JSON `modules`, `analyze`/`audit`/`serve`/`agent`, parsers, correlation, SARIF, tests |
| [SOFTWARE_DESIGN_DOCUMENT.md](SOFTWARE_DESIGN_DOCUMENT.md) | Unified DevSecOps platform, UFF, correlation engine, APIs |
| [CLAUDE.md](CLAUDE.md) | Contributor / AI assistant guardrails |
| [CONTRIBUTION.md](CONTRIBUTION.md) | PR workflow + dev expectations |

> **Note:** `rustzap analyze` (including `--tools native`), `rustzap audit`, JSON `"modules"` / `"static"`, `"correlations"`, and SARIF export are implemented per **`IMPLEMENTATION_PLAN.md`** Phases 1–2.5. OpenAPI/HAR/Nuclei are Phase 3. The **agentic tester** (`rustzap agent` + `rustzap mcp`) is implemented — see [Agentic Tester](#agentic-tester-agent--mcp) below. Native **Active Directory / NTLM-relay detection** (`rustzap ad`, Tier A) is implemented — see [Active Directory](#active-directory--ntlm-relay-detection-ad) below. The hosted `serve` viewer remains planned.

---

## Installation

### Prebuilt installers (Linux / Windows / macOS)

Every tagged release publishes native installers for all three OSes, built by
[`.github/workflows/release.yml`](.github/workflows/release.yml) — see
[`packaging/README.md`](packaging/README.md) for how they're built and their
current signing status.

| OS | Formats |
|---|---|
| Linux | `.deb` (Debian/Ubuntu), `.rpm` (Fedora/RHEL), `AppImage` (portable) — x86_64 and arm64 |
| Windows | `.exe` installer (Inno Setup) — x86_64 |
| macOS | `.dmg` (universal2: Apple Silicon + Intel) |

Download from the [Releases page](https://github.com/souayb/rustZAP/releases),
verify against the release's `SHA256SUMS`, then install:

```bash
# Linux
sudo apt install ./rustzap-<version>-linux-amd64.deb      # Debian/Ubuntu
sudo dnf install ./rustzap-<version>-linux-x86_64.rpm      # Fedora/RHEL
chmod +x rustzap-<version>-linux-x86_64.AppImage && ./rustzap-<version>-linux-x86_64.AppImage   # portable

# macOS
open rustzap-<version>-macos-universal.dmg   # then run Install.command, or drag `rustzap` onto your PATH
```

```powershell
# Windows — run the downloaded rustzap-<version>-windows-x64.exe
```

A Homebrew formula is also generated per release (`packaging/homebrew/`); see
`packaging/README.md` for its current publishing status.

### Verifying a download, and the OS trust warnings

**Always verify the checksum first.** It is the only integrity check that does
not depend on code signing, and it is the one that matters most for a security
tool:

```bash
# Linux / macOS - run in the directory holding the downloaded artifact
shasum -a 256 -c SHA256SUMS --ignore-missing
```

```powershell
# Windows - compare against the matching line in SHA256SUMS
Get-FileHash .\rustzap-<version>-windows-x64.exe -Algorithm SHA256
```

Release artifacts are **not yet code-signed** (see `packaging/README.md` ->
"Code signing" for status and how to enable it), so Windows and macOS will each
warn that the publisher is unverified. That warning is expected, not a sign of
tampering - but it is also exactly what tampering would look like, which is why
you check the hash above *before* clicking through:

- **Windows (SmartScreen):** "Windows protected your PC" -> **More info** ->
  **Run anyway**.
- **macOS (Gatekeeper):** the `.dmg` and the `Install.command` inside it are
  both quarantined on download. Clear it after verifying the checksum:

  ```bash
  xattr -c rustzap-<version>-macos-universal.dmg
  ```

  (`xattr -c` clears all extended attributes; unlike `xattr -d
  com.apple.quarantine`, it does not error out when the download method left no
  quarantine flag in the first place — `curl`/`wget` downloads don't.)

  Then `open` the DMG and run `Install.command`. If macOS still refuses, right-
  click `Install.command` -> **Open** -> **Open**.
- **Linux:** `.deb`/`.rpm`/AppImage carry no OS-level publisher check, so there
  is no warning to bypass; the checksum is the verification step.

Prefer to avoid the warnings entirely? Build [from source](#from-source) - it is
a single `cargo build --release`.

### From source

```bash
# Requires Rust 1.91+
git clone https://github.com/souayb/rustZAP
cd rustZAP
./scripts/install-hooks.sh    # Linux/macOS/Git Bash; Windows: scripts\install-hooks.cmd
cargo build --release
./target/release/rustzap --help
```

Contribution checks (fmt, clippy, tests) and how to install hooks on Windows are in [CONTRIBUTION.md](CONTRIBUTION.md).

### VS Code extension

A thin CLI wrapper lives in [`vscode-extension/`](vscode-extension/). It runs **`RustZAP: Analyze Workspace`** (native static analysis → **Problems**), **`RustZAP: Scan URL`** (passive DAST by default, with a legal confirmation), and **`RustZAP: Scan Active Directory`** (LDAP/SPN/NTLM relay detection with an authorization prompt; credentials are entered at run time and passed to the CLI via an env var, never stored in settings). Correlated relay attack paths render as an **Attack paths** section in the Findings tree. Reports go to extension storage, not the repo.

```bash
cd vscode-extension && npm ci && npm run compile   # F5 to debug in VS Code
```

Requires the `rustzap` binary on `PATH` or `rustzap.path` in settings. See [vscode-extension/README.md](vscode-extension/README.md).

### Full isolated installation (default)

After installing the RustZap binary, install and start Docker Desktop on Windows/macOS
or Docker Engine on Linux, then run:

```bash
rustzap install --list                    # detect native tools and show resolved paths
rustzap install --dry-run                 # preview the full setup
rustzap install --yes                     # build the full Kali Linux environment
rustzap isolated                         # start the console in that environment
rustzap isolated analyze . --yes --tools native,semgrep,trivy,gitleaks,checkov
```

The full image includes **Semgrep, Trivy, Gitleaks, Checkov, Nuclei, Nmap, Nikto,
Wapiti, tshark, Hashcat, John, Hydra, Medusa, Aircrack-ng, and Wifite**. Missing
executables fail the image build; installation no longer treats a successful
package-manager exit as proof that a tool is available. The installed binary
bundles its source and build recipe, so setup works without a source checkout.
Docker caches unchanged layers when setup is repeated. Allow several GB of disk
space and time for the initial build and scanner database downloads.

Host detection and container detection are separate: finding Semgrep on Windows
does not mean it exists inside Kali. `rustzap isolated install --list` inspects
the container. The Windows installer selects full setup by default in its final
page (Docker Desktop must already be running); silent installations leave setup
to `rustzap install --yes`. Start-menu entries offer isolated and native consoles.

`isolated` mounts **only the selected workspace**, with read/write access for
reports, and drops Linux capabilities. It does not mount the Docker socket or
host credentials. Run from a dedicated test workspace, or select one explicitly:

```bash
rustzap isolated --workspace ./assessment analyze . --yes --tools native
# Forward only the API-key variable your scope file names:
rustzap isolated --env LLM_API_KEY agent --scope scope.yaml --target http://app:3000
```

Paths passed after the subcommand are container paths. A host model endpoint can
be configured as `http://host.docker.internal:11434/v1` if the model server accepts
connections from Docker. Containers share the host kernel; packet capture,
wireless adapters, GPU cracking, and kernel monitoring need additional hardware
or privileges. Use a dedicated Kali VM for those workflows. Falco remains an
optional host/VM runtime monitor and is not part of the container tool set.
No scanning starts during installation.

### Native tools and Windows detection

Native installation is an explicit alternative, including inside your own Kali VM:

```bash
rustzap install --native --yes
rustzap install --native --tool semgrep
./scripts/install-tools.sh --native --tool nmap
```

Native package managers are Homebrew, apt/pipx, dnf/pipx, pacman/pipx, or apk.
Package availability varies by distribution; the full Kali image is the supported
complete tool set. Native Windows package installation is not automated. Existing
Windows tools are detected and can be run directly.

Discovery checks executable files instead of invoking a Unix shell. On Windows
it reads both the running process PATH and current user/machine PATH, honors
PATHEXT, and checks common pip/pipx, Scoop, Chocolatey, WinGet, Nmap, Wireshark,
and Docker locations. Press **Shift+R** in Tools to refresh after installation;
launching a tool resolves it again. An explicit executable override also works:

```powershell
$env:RUSTZAP_TOOL_TRIVY = 'C:\Tools\Trivy\trivy.exe'
rustzap install --list
```

The same resolver is used by the installer, console, static analyzers, and Nuclei.
Overrides use `RUSTZAP_TOOL_<UPPERCASE_NAME>` (hyphens become underscores).

### Docker

A multi-stage `Dockerfile` ships RustZAP with all companion tools pre-installed (no host setup needed):

```bash
# Build the full Kali image (several GB, depending on package versions)
docker build -t rustzap .

# Drop into the TUI (interactive)
docker run --rm -it -v "$PWD/reports:/workspace" rustzap

# One-shot scan from CLI
docker run --rm -v "$PWD/reports:/workspace" rustzap \
    scan --target https://example.com --output /workspace/report.json

# Intercepting proxy on host port 8080
docker run --rm -p 8080:8080 rustzap proxy --listen 0.0.0.0:8080
```

### docker-compose

```bash
# Drop into the TUI
docker compose run --rm rustzap

# One-shot scan with reports written to ./reports/ on the host
docker compose run --rm rustzap scan --target https://example.com -o /workspace/report.json

# Bring up the optional Juice-Shop lab target
docker compose --profile labs up -d juice-shop
docker compose run --rm rustzap scan --target http://juice-shop:3000
```

The compose file mounts `./reports → /workspace` and exposes the intercepting proxy on `:8080`.

### Vulnerable lab target

RustZAP ships its own deliberately-vulnerable app under
[`tests/fixtures/lab/`](tests/fixtures/lab) — a Node/Express target with an
endpoint per active plugin, an insecure passive surface, a crawlable spider
surface, an injectable mock LLM endpoint, and (as source) a SAST corpus with
planted secrets and IaC. Drive it with `scripts/lab.sh`:

```bash
scripts/lab.sh up        # build + start the lab on http://localhost:3001
scripts/lab.sh scan      # full DAST scan → reports/lab-report.json
scripts/lab.sh analyze   # native SAST over the lab source → reports/lab-sast.json
scripts/lab.sh redteam   # agent OWASP-LLM battery against the mock endpoint
scripts/lab.sh down
```

> Only ever scan the lab or hosts you own. The lab embeds **fake** credentials
> for the scanners to find; never reuse them.

The lab is a **manual** convenience. Regression coverage of the scanner lives in
the pure-Rust matrix `tests/vuln_lab_*.rs`, which boots a deterministic loopback
target inside `cargo test` — every active plugin, the passive checks, the spider,
the full pipeline, and the agent/red-team paths — needing **neither Node nor
Docker**, so it runs in CI on all three OSes. The two slow timing detectors
(`sqli-time`/`sqli-stacked`) are covered positively by the Node lab and asserted
negatively (fast) in the matrix.

---

## Usage

### Full Scan (Spider + Passive + Active)

```bash
# Basic scan
rustzap scan --target https://example.com

# Deep scan with all plugins
rustzap scan \
  --target https://example.com \
  --depth 10 \
  --concurrency 20 \
  --output report.json

# Export to CSV or HTML formats
rustzap scan --target https://example.com --output report.csv
rustzap scan --target https://example.com --output report.html

# SARIF 2.1 (e.g. GitHub Code Scanning uploads)
rustzap scan --target https://example.com --output findings.sarif
rustzap scan --target https://example.com -o report.json --sarif-out findings.sarif

# Authenticated scan with cookies, API key, and Basic Auth
rustzap scan \
  --target https://app.example.com \
  --cookies "session=abc123; role=admin" \
  --auth "Bearer eyJhbGciOiJIUzI1NiJ9..." \
  --api-key "X-Api-Key: my-secret-key" \
  --basic-auth "username:password"

# Passive-only (no attack payloads sent)
rustzap scan --target https://example.com --passive-only

# Do-no-harm: block mutating verbs; cap request rate (default 50 RPS)
rustzap scan --target https://example.com --read-only-safe --max-rps 20

# Lab-only attack mode (raises circuit-breaker tolerances; still requires authorization)
rustzap scan --target https://lab.example.com --attack-mode --plugins xss,sqli

# Skip SSL verification (e.g. staging with self-signed cert)
rustzap scan --target https://staging.example.com --insecure

# Verbose output
rustzap scan --target https://example.com -vv

# Expand attack surface from OpenAPI / HAR (lab targets only)
rustzap scan --target https://lab.example.com \
  --openapi-path openapi.json --passive-only -o report.json
rustzap scan --target https://lab.example.com \
  --har-path recording.har --depth 2 -o report.json

# Opt-in Nuclei (requires `nuclei` on PATH — only against authorized targets)
rustzap scan --target https://lab.example.com --nuclei --passive-only -o report.json
# Or parse existing Nuclei JSONL without spawning:
rustzap scan --target https://lab.example.com --nuclei-jsonl nuclei-out.jsonl --passive-only -o report.json
```

> **Warning:** `--nuclei` runs ProjectDiscovery Nuclei templates against the target. Use only on systems you own or have explicit permission to test.

### Analyze a local repository

Only analyze repositories you **own** or have **permission** to scan. Before walking or reading files, `analyze` and `audit` ask for consent. DAST-only `rustzap scan` of URLs does **not** use this prompt (different command). The TUI **Analyze** tab (press `a` or `6`) shows the same consent as a dialog (`[Y]es` / `[N]o`) instead of stdin `Proceed? [y/N]`.

**Interactive** (stdin is a terminal):

```bash
rustzap analyze ~/src/myapp --tools native
rustzap analyze --repo ~/src/myapp --tools native
# interactive: rustzap analyze   then enter path, then y
```

A positional `REPO` overrides `--repo`. If neither is given, RustZAP prompts `Repository path [.] :` (empty means the current directory). It then prints the absolute path and waits:

```
RustZAP will read files under `/abs/path` for static analysis
(inventory, secrets/sinks heuristics, and any selected tools).
Only analyze repositories you own or have permission to scan.
Proceed? [y/N]:
```

Type `y` or `yes` to continue. Empty, `n`, or `no` aborts with `Repo access declined`.

**CI / non-interactive** — stdin is not a TTY, so you **must** pass `--yes` (`-y`). Give a path (positional or `--repo`); with `--yes` and no path, the current directory is used:

```bash
rustzap analyze ~/src/myapp --tools native --yes -o native-report.json
rustzap analyze --repo . --tools native --yes -o native-report.json
```

Semgrep is **optional**. The default `--tools` is `semgrep`; if that binary is not on `PATH`, `analyze` falls back to the built-in native analyzers and prints a warning. To skip the warning (or run without Semgrep on purpose):

```bash
rustzap analyze ~/src/myapp --tools native
```

If you pass `--tools semgrep` explicitly and Semgrep is missing, the command fails with install instructions. Additional tools listed in `--tools` that are missing from `PATH` are skipped; analysis continues with the rest.

Mix tools (Semgrep, Trivy, Gitleaks, Checkov, plus the built-in native pass):

```bash
rustzap analyze --repo . --tools semgrep,trivy,gitleaks,native --yes
```

Checkov is **opt-in** (noisy on large IaC trees; not in analyze/audit defaults). Alias: `iac`.

```bash
rustzap analyze --repo . --tools checkov --yes
rustzap analyze --repo . --tools native,checkov --yes   # feeds risk_breakdown.iac in static{}
```

Other analyze examples (still require `--yes` in CI):

```bash
# Default tool is semgrep only; add --yes in pipelines
rustzap analyze --repo . --tools semgrep,trivy,gitleaks --yes --output analyze-report.json

# Parse existing tool JSON (no subprocess)
rustzap analyze --repo . \
  --semgrep-json tests/fixtures/semgrep_small.json \
  --trivy-json tests/fixtures/trivy_small.json \
  --gitleaks-json tests/fixtures/gitleaks_small.json \
  --checkov-json tests/fixtures/checkov_small.json \
  --yes --output analyze-report.json

# Correlate SAST SQL signals with DAST SQLi + emit SARIF
rustzap analyze --repo . --semgrep-json semgrep.json --correlate --yes \
  --output analyze-report.json --sarif-out analyze.sarif
```

**Audit** also walks the repo (positional `REPO` or `--repo`) for static tools and optionally spiders `--target`. Same consent rules:

```bash
rustzap audit ~/src/myapp --target https://lab.example.com \
  --tools native --yes --passive-only --depth 2 \
  --output audit-report.json --sarif-out audit.sarif
```

Scan and analyze/audit JSON reports include a **`modules`** array (per-plugin roll-up) and optional **`correlations`** when `--correlate` is set. With `--tools native`, reports also include a **`static`** object (`inventory`, `risk_score`, `risk_breakdown`, `detection_checks`, `attack_plan`). That field is omitted when native is not selected. The native walk respects `.gitignore` and `.rustzapignore` (and always skips `node_modules`, `target`, `.git`, `vendor`, `dist`).

**GitHub Code Scanning:** build SARIF with `rustzap … --sarif-out rustzap.sarif` (or `scan --output rustzap.sarif`), upload the artifact with `github/codeql-action/upload-sarif` against your default branch or PR; confirm the run appears under the repository **Security** tab (manual check).

### Active Directory / NTLM-relay detection (`ad`)

> **Authorization required.** `rustzap ad` sends LDAP and NTLM authentication
> traffic to Active Directory hosts. It is **detection only** — it never generates
> a relay-target list or triggers coercion — but it is intrusive. Only scan AD you
> own or have **explicit written permission** to test. Like `analyze`, it prompts
> for authorization (TTY), or requires `--yes` in CI.

Tier A coverage (native Rust): LDAP/LDAPS signing posture, Ghost-SPN detection
(SPNs whose host has no DNS record), NTLMv1 / NTLM-signing negotiate flags, and
LDAP domain-computer enumeration. Findings carry stable `ad/*` plugin ids and feed
the correlation engine, which consolidates per-host weaknesses into a single
**"NTLM relay exposure on <host>"** attack-path finding.

```bash
# Anonymous, Ghost-SPN + LDAP posture, against a lab DC you control:
rustzap ad --domain corp.local --dc-ip 10.0.0.1 --null-auth --checks spn,ldap --yes

# Authenticated + enumerate every domain computer (password read from env, never argv):
export RZ_AD_PASS='...'
rustzap ad --domain corp.local --dc-ip 10.0.0.1 -u svc-account --audit \
           -o ad-report.json --sarif-out ad.sarif --yes

# Only NTLM negotiate-flag checks against explicit targets:
rustzap ad --domain corp.local --dc-ip 10.0.0.1 --null-auth --checks ntlm \
           -t win-srv01.corp.local -t win-srv02.corp.local --yes
```

Pass the bind password via `--password-env` (default `RZ_AD_PASS`), not on the
command line. `--checks` selects `ldap`, `spn`, `ntlm`, or `all` (default).

### Spider Only

```bash
rustzap spider --target https://example.com --depth 5
rustzap spider --target https://example.com --output urls.json
```

### Intercepting Proxy

```bash
# Start proxy on default port 8080
rustzap proxy

# Custom address + passive analysis of traffic
rustzap proxy --listen 0.0.0.0:9090 --passive --dump captured.json
```

Then configure your browser's HTTP proxy to `127.0.0.1:8080` and browse normally.
Press `Ctrl+C` to stop and save captured transactions.

### Interactive Pentesting Console (TUI)

RustZAP ships with a full multi-tab Ratatui-powered console — the operator's "single pane of glass" from the SDD. It lets you configure **URL scans**, **analyze a local repository**, watch live progress, browse findings, and drive the SDD's external tools (Semgrep, Trivy, Gitleaks, Checkov, Nmap, Nikto, Wapiti, Hashcat, John, Hydra, Medusa, Aircrack-ng, Wifite, Falco, tshark) — all without leaving the terminal.

```bash
rustzap            # bare command → drops straight into the TUI
rustzap tui        # explicit subcommand
rustzap ui         # alias
rustzap console    # alias
```

Running `rustzap` with no arguments launches the console immediately — useful as a daily-driver entry point. On launch the TUI auto-loads `report.json`, `rustzap-report.json`, or `analyze-report.json` if one exists. **Scan URL** (tab 2) is unchanged. **Analyze repo** (tab 6, or press `a`) runs the same pipeline as `rustzap analyze --repo PATH --tools native` (TUI tools default is **`native`** so it works without Semgrep; type `semgrep,trivy,gitleaks,checkov` to add CLI tools). Unified **audit** (static + DAST in one command) remains CLI-only.

**Agent** (tab 7) is a front-end for the [agentic tester](#agentic-tester-agent--mcp): point it at a scope file plus a target and/or repo, pick a brain — **Recon** (`scan_target` + `analyze_repo`) or **Red-team** (OWASP LLM Top-10) — and an autonomy mode, then confirm the consent dialog. Runs are scope-gated and non-interactive (findings flow into the Findings tab); the LLM brain stays on the CLI (`rustzap agent --model …`) since a raw-mode terminal can't service its approval prompt.

#### Tabs

| Tab | What you see | What you can do |
|---|---|---|
| **1·Dashboard** | Target URL + repo path, color-coded risk score (0–100), severity bar chart, top-20 findings | At-a-glance posture overview |
| **2·Scan** | Inline config form + 3 live phase gauges (Spider · Passive · Active) + streaming findings | Edit target/plugins/output, toggle passive/insecure, tune depth/concurrency, start/cancel scans |
| **3·Findings** | Findings list + scrolling detail pane (title, CWE, OWASP, evidence, solution) | Browse, severity-filter, deep-dive into each finding |
| **4·Tools** | Inventory of 15 SDD-listed tools with install status, role, default cmdline | Run any installed tool against the current target — output streams to Logs |
| **5·Logs** | Timestamped event stream from scans, analyze, and tool runs | Scroll, jump to bottom, clear |
| **6·Analyze** | Repo path, tools, output, optional SARIF / correlate | Consent dialog, then local static analysis (native by default) |

#### Key bindings

**Global**

| Key | Action |
|---|---|
| `1`–`6` | Jump to tab |
| `Tab` / `Shift+Tab` | Cycle tabs |
| `a` | Jump to **Analyze** tab |
| `x` | Cancel a running **scan** or **analyze** (whichever is in progress) |
| `q` | Quit (aborts running scans/analyze/tools) |

**Scan tab**

| Key | Action |
|---|---|
| `t` | Edit target URL |
| `P` | Edit active-scan plugins (comma-separated) |
| `o` | Edit output file (`.json` / `.csv` / `.html`) |
| `p` | Toggle passive-only mode |
| `i` | Toggle insecure TLS |
| `+` / `-` | Increment / decrement crawl depth |
| `]` / `[` | Increment / decrement concurrency |
| `s` | Start scan |
| `x` | Cancel running scan |
| `Enter` / `Esc` | Commit / cancel field edit |

**Analyze tab** (also `a` or `6` from any tab)

| Key | Action |
|---|---|
| `r` | Edit repo path (default `.`) |
| `t` | Edit tools (default `native`; comma list: `semgrep`, `trivy`, `gitleaks`, `checkov`, `native`) |
| `o` | Edit output file (default `analyze-report.json`) |
| `S` | Edit optional SARIF path (empty = off) |
| `c` | Toggle finding correlation |
| `s` | Start analyze — **consent dialog first** (`Y` proceed / `N` or `Esc` cancel) |
| `x` | Cancel running analyze |
| `Enter` / `Esc` | Commit / cancel field edit |

The consent dialog replaces CLI `--yes`: *RustZAP will read files under `<abs path>`. Only analyze repos you own. [Y]es / [N]o*. After **Y**, the TUI calls the same `run_analyze` library path as the CLI with `assume_yes`.

**Findings tab**

| Key | Action |
|---|---|
| `j` / `k` (or `↓` / `↑`) | Navigate findings |
| `PgUp` / `PgDn` | Scroll detail pane |
| `f` | Cycle severity filter (all → Critical → High → Medium → Low → Info → all) |
| `c` | Clear filter |

**Tools tab**

| Key | Action |
|---|---|
| `j` / `k` | Navigate tool list |
| `r` or `Enter` | Run the highlighted tool (uses configured target if required) |
| `R` | Re-detect tools on PATH |

**Logs tab**

| Key | Action |
|---|---|
| `j` / `k` / `PgUp` / `PgDn` | Scroll |
| `G` | Jump to bottom |
| `c` | Clear log buffer |

#### Quick walkthrough

```bash
rustzap tui            # opens the console
# → press '2' to go to the Scan tab
# → press 't', type https://example.com, Enter
# → press 's' to launch — Spider/Passive/Active gauges fill live
# → press '3' to browse findings, 'f' to filter by severity
# → press '4' to see which SDD tools are installed; 'r' runs the highlighted one
# → press '5' to watch live event logs
# → press 'a' or '6' for Analyze — edit repo with 'r', then 's'
#    confirm [Y] to walk the repo (native tools by default)
# → 'q' to quit
```

### Passive Analysis Only

```bash
rustzap passive --input https://example.com --output passive-report.json
```

### List Plugins

```bash
rustzap plugins
```

---

## Agentic Tester (`agent` + `mcp`)

RustZAP can drive its own scanners, static analysis, and evidence primitives from
an **agentic loop** — an LLM (or deterministic scripted) brain that plans and
calls tools under strict, config-selected guardrails. The same capabilities share **one tool registry**:

- **Agent tab (`7`)** — configure a live LLM and run it from the console.
- **`rustzap agent`** — the native loop. A brain observes findings + the
  attack-plan frontier, calls tools, and RustZAP assembles a `Report`.
- **`rustzap mcp`** — an [MCP](https://modelcontextprotocol.io/) server over
  stdio, so an external brain (Claude Code, Cursor, …) drives the same tools.

> ⚠️ Network-touching tools **refuse to run without a scope file**. Only ever
> point the agent at hosts you own or have explicit written permission to test.

### Configure the LLM in the console

Open `rustzap isolated` (or `rustzap tui`) and press **7** for the Agent tab.
**LLM (live)** is the default brain. Configure it directly:

| Key | Field |
|---|---|
| `e` | Agent's OpenAI-compatible API base URL, typically ending in `/v1` |
| `m` | Agent's provider model ID |
| `k` | Agent's API key — masked while typing or pasting |
| `g` | Goal for the assessment |
| `c`, `t`, `r` | Scope file, target URL, repository path |
| `s` | Start after the existing consent dialog |

These configure **RustZAP's own brain**. When the brain is **Red-team**, the
*application under test* is configured separately — it is a different model
behind a different credential:

| Key | Field |
|---|---|
| `M` | Target model ID (blank: the tool's default) |
| `A` | Name of the env var holding the target's bearer token (the name, never the secret) |
| `P` | Target system-prompt marker — without it the leak probes cannot fire |
| `G` | Generations per variant — cycles 1 → 3 → 5 → 10 (above 1 reports an attack success rate) |
| `X` | Prompt mutators to add (`base64,rot13`, `all`, …; blank for plain prompts only) |

Starting a red-team run whose `A` variable is unset fails immediately with the
reason, rather than producing a run in which every probe is unevaluated.

Press **Enter** to save a field, **Esc** to discard edits, and **Ctrl+U** to
clear the editor. **Shift+K** clears the session key. The key stays in memory
until cleared or the console exits; it is never saved to the scope file or
added to prompts, reports, logs, or command-line arguments. No environment
forwarding is needed when entering the key inside the isolated console.

Blank model/API URL fields inherit the scope configuration (the API URL falls
back to local Ollama). A blank key uses the scope's `api_key_env`, if configured,
or keyless access otherwise. Entered values take precedence over scope defaults.
The model must be specified in the form or scope. Use **b** to cycle to the
existing scripted Recon and Red-team workflows. Autonomy and scope enforcement
are unchanged: actions requiring approval are denied in this non-interactive
runner unless the selected autonomy permits them.

### The scope file (mandatory)

The scope file (YAML or JSON) is the guardrail: it declares what is in bounds,
the autonomy mode, which action classes need human approval, and the resource
budget. Loading is strict — a missing or malformed scope is a hard error, never
a default.

Scaffold a documented starter (a copy of [`scope.example.yaml`](scope.example.yaml))
and edit `allowed_hosts`:

```bash
rustzap agent --init-scope scope.yaml     # writes a commented template (won't overwrite)
```

```yaml
# scope.yaml
allowed_schemes: [http, https]
allowed_hosts:                 # exact, or "*.example.com" suffix wildcard
  - localhost
  - 127.0.0.1
  - "*.juice-shop.local"
forbidden_paths:               # regex; a matching URL path is out of bounds
  - "^/admin/delete"
max_requests_per_min: 120

autonomy: assisted             # assisted | semi | auto
approval_for: [exploit, rce, exfil]   # classes that gate in `semi` mode

budget:
  max_requests: 500            # 0 = unlimited
  max_turns: 40
  max_tokens: 0

privacy: false                 # opt-in tokenization (see below)

model:                         # LLM brain (all fields optional / CLI-overridable)
  base_url: http://localhost:11434/v1   # default: local Ollama
  model: qwen2.5-coder
  api_key_env: LLM_API_KEY     # omit for keyless local servers
  json_mode: false             # force response_format for open-source models
```

**Autonomy modes** decide what runs without a human in the loop:

| Mode | Behavior |
|------|----------|
| `assisted` *(default, safest)* | True recon (analyze/list/GET probe) runs freely; **Exploit-class** tools (`run_plugin`, `scan_target`, `replay_request`, mutating `http_probe`, `ai_redteam`) need approval; explore-first blocks Exploit until recon succeeds |
| `semi` | Runs autonomously; only the classes in `approval_for` (e.g. `exploit`, `rce`, `exfil`) need approval |
| `auto` | Runs the whole loop with no prompts — scope + budget + explore-first (unless auto-approve) are the guardrails |

Approval is a TTY prompt. In CI / headless (`-n` / `--non-interactive`, or no
TTY) gated actions are **auto-denied**, never blocked waiting on input.

### Running the native agent

```bash
# Deterministic scripted brain — no live LLM, ideal for CI and demos
rustzap agent --scope scope.yaml --repo . --script steps.json -n \
  -o agent-report.json

# LLM brain against a local keyless server (Ollama default base URL)
rustzap agent --scope scope.yaml --target http://localhost:3000 \
  --model qwen2.5-coder

# LLM brain against a hosted OpenAI-compatible endpoint
LLM_API_KEY=sk-... rustzap agent --scope scope.yaml \
  --target http://localhost:3000 \
  --base-url https://api.openai.com/v1 --model gpt-4o-mini \
  --api-key-env LLM_API_KEY --json-mode

# Override the scope's autonomy for one run, and turn on privacy tokenization
rustzap agent --scope scope.yaml --target http://localhost:3000 \
  --autonomy semi --privacy

# Safety gates on agent HTTP (same flags as scan)
rustzap agent --scope scope.yaml --target http://localhost:3000 \
  --read-only-safe --max-rps 10 -n

# Export remediation prompts from a JSON report (findings with file locations)
rustzap autofix --report analyze-report.json --out patches/
```

### Safety profiles

Scans can select a named safety envelope. The default profile keeps the normal
web-assessment behavior; `ot-safe` is a low-rate, read-only profile for fragile
SCADA/ICS-adjacent services. Explicit `--attack`, `--read-only-safe`, and
`--max-rps` options remain available for authorized staging and lab tests.

```bash
rustzap scan --target https://staging.example --profile default
rustzap scan --target https://plant-staging.example --profile ot-safe --plugins xss,sqli
```

`ot-safe` is a transport safety envelope, not an OT certification. Obtain asset
owner approval and test on representative staging systems before scanning live
control networks.

CLI flags override the scope file (`--model`, `--base-url`, `--api-key-env`,
`--json-mode`, `--autonomy`, `--privacy`). The brain speaks a portable
one-JSON-action-per-turn protocol, so any OpenAI-compatible gateway works
(OpenAI, OpenRouter/Together/Groq, Anthropic/Gemini compat, or local Ollama /
vLLM / LM Studio / llama.cpp).

A scripted-brain step file is just a list of actions:

```json
[
  { "tool": "analyze_repo", "args": { "path": ".", "tools": "native" } },
  { "tool": "get_attack_plan", "args": { "path": "." } },
  { "finish": "static pass complete" }
]
```

### Tool registry

Every tool wraps existing RustZAP logic (no scanning code is duplicated) and is
available to both the native brain and MCP clients:

| Tool | Class | What it does |
|------|-------|--------------|
| `scan_target` | **exploit** | DAST (spider + passive + active) against an in-scope URL |
| `analyze_repo` | recon | Static analysis (native, or semgrep/trivy/gitleaks/checkov) over a repo |
| `get_attack_plan` | recon | The native attack-plan frontier (endpoints + params + reason) |
| `list_plugins` | recon | List available active scan plugins |
| `run_plugin` | **exploit** | Run one active plugin against one in-scope URL |
| `http_probe` | recon / **exploit** | Bounded HTTP request; GET/HEAD/OPTIONS = recon; mutating methods = exploit |
| `list_captures` | recon | List captured HTTP transactions available to replay |
| `replay_request` | recon | Re-send a captured request with mutations (method/url/body/headers) + diff |
| `spawn_subtask` | recon | Delegate a focused plan of recon calls to a bounded sub-agent; findings merge up |
| `ai_redteam` | **exploit** | OWASP LLM Top-10 battery against an in-scope chat endpoint (gated by approval) |
| `export_autofix` | recon | Write remediation prompt `.md` files for findings with locations |
| `ai_redteam` | **exploit** | OWASP LLM Top-10 battery against an in-scope chat endpoint |
| `vector_probes` | recon | Generate bounded synthetic-canary probes for Pinecone, Qdrant, Weaviate, Milvus, or pgvector (offline only) |

### Capture / replay

Every `http_probe` / `replay_request` (and every `ai_redteam` probe) is captured
as an HTTP transaction in the same JSON shape the [proxy](#intercepting-proxy)
dumps. At the end of a run they are written next to the report — e.g.
`agent-report.json` → `agent-report.captures.json` — so traffic is auditable and
replayable. `replay_request` bases a new request on a `capture_id`, applies
mutations, carries session headers forward, and returns a diff (status change,
body-length delta) versus the original.

### Sub-tasking

`spawn_subtask` lets the brain delegate a focused plan of recon calls to a
bounded sub-agent that shares the parent scope, request budget, capture store,
and trace — its findings merge back into the report. To keep the safety model
intact, sub-tasks are **recon-only and cannot nest**: any intrusive (exploit)
action still has to go through the top-level, approval-gated loop. A step naming
a non-recon or nested tool is rejected without a request being sent.

```json
{ "tool": "spawn_subtask", "args": {
    "goal": "map and scan the /api subtree",
    "steps": [
      { "tool": "get_attack_plan", "args": { "path": "." } },
      { "tool": "scan_target", "args": { "target": "http://localhost:3000/api" } }
    ]
} }
```

### Safety layers

- **Prompt-injection shield** — tool output (HTTP bodies, headers, page content)
  is attacker-controlled, so before it reaches the brain RustZAP neutralizes
  known injection directives (`ignore previous instructions`, scope manipulation,
  "conceal from the user", …) and frames observations as untrusted data. Hits are
  logged to the trace as `injection_shield`. The human report keeps raw evidence.
- **Privacy tokenization** (`--privacy` / `privacy: true`) — real hosts, secrets,
  emails, and IPs are replaced with stable placeholders (`RZ_HOST_1`,
  `RZ_SECRET_1`, …) before any text reaches the LLM, and restored locally before
  the tool executes. The model reasons over structure without ever seeing the
  real target or leaked credentials. Off by default; a no-op when disabled.
- **Append-only trace** (`--trace`, default `agent-trace.jsonl`) — every tool
  call, approval decision, scope rejection, shield hit, and capture is one JSON
  line, with sensitive headers redacted.

### AI red-team (OWASP LLM Top-10)

The `ai_redteam` tool probes an in-scope, OpenAI-compatible chat endpoint (the
*application under test*) for LLM-specific weaknesses. It is classed **exploit**
(intrusive) so it is gated by the approval matrix.

| Probe | OWASP | Detection | Confidence |
|-------|-------|-----------|------------|
| Direct prompt injection · role-override jailbreak | LLM01 | reflected unique canary | tentative |
| Insecure output handling (candidate active-content sink) | LLM05 | reflected canary in `<script>` | tentative |
| System-prompt / instruction disclosure | LLM02 | operator-supplied `system_marker` leaks into the reply | **confirmed** |
| Sensitive configuration disclosure | LLM02 | `system_marker` in a rules/tools dump | tentative |
| Excessive agency (unsafe action compliance) | LLM06 | no refusal to a privileged instruction | tentative |
| Indirect injection via retrieved content | LLM01 | canary echoed from an instruction-shaped document | tentative |
| RAG tenant isolation · metadata-filter bypass · deletion retention | LLM08 | synthetic canary or marker returned | tentative |

Only the marker leak is **confirmed**: you know that text was hidden, so its
appearance is disclosure on its own. Canary probes stay *tentative* by design —
an echoed canary shows the model followed the injected instruction, but nothing
here observes the application's instruction boundary or whether the reply is ever
rendered, so confirming those requires checking the deployed system prompt or the
sink that consumes the output.

Leak probes only fire when you supply `system_marker` (a phrase you know is in
the target's system prompt), so there are no false positives when it is omitted.
Findings land in the report with OWASP + CWE metadata under plugin
`agent/ai-redteam`.

#### Three outcomes, not two

Every probe variant ends as **fail**, **pass**, or **unevaluated**, and the run
reports `failed_count` / `passed_count` / `unevaluated_count`. A reply that was an
HTTP error, a provider `error` body, or anything that is not a chat completion
never reaches a detector, so a rejected key or a rate-limited target reads as
*inconclusive* rather than a clean pass — a run with no verdicts at all carries an
explicit `warning`. Rate limits and 5xx are retried twice before a variant is
given up on, and each result carries the `requests` it actually cost.

#### Repeated generations and attack success rate

An LLM is stochastic, so one generation cannot separate "this target is
vulnerable" from "we got unlucky once". Pass `generations` (1–20, default 1) to
repeat every variant and get an **attack success rate** with a 95 % Wilson
confidence interval:

```jsonc
{ "probe": "llm01-direct-injection", "variant": "plain", "verdict": "fail",
  "generations": 10, "evaluated": 10, "hits": 3,
  "asr": 0.3, "asr_ci_95": [0.108, 0.603], "requests": 10 }
```

Wilson rather than the textbook normal interval because these counts are small
and the proportions sit near 0 or 1, exactly where the normal approximation
returns nonsense such as a negative lower bound. `fail_threshold` (default `0`)
sets the ASR a target may exhibit before the probe is failed — the default fails
on any successful attack.

#### Prompt mutators (opt-in)

A guardrail that blocks *"ignore all previous instructions"* often passes the
Base64 of the same sentence, so `mutators` re-asks every probe in obfuscated form
and multiplies coverage without new prompts:

| Mutator | Technique |
|---|---|
| `base64`, `rot13` | encode the instruction and ask the model to decode and follow it |
| `leetspeak` | character substitution (`a→4`, `e→3`, …) that survives keyword filters |
| `zerowidth` | zero-width spaces inside trigger words, splitting them at tokenization |
| `payload-split` | cut the instruction mid-word into two variables the model concatenates |

Pass a comma-separated list or `all`; an unknown name is an error rather than a
silent omission. Mutators are **off by default** because each one re-sends the
whole battery against an intrusive endpoint. A finding from a mutated prompt is
labelled with the variant that produced it, which is itself the signal: a target
that resists the plain prompt but not its Base64 has a filter, not a boundary.

The canary survives every mutation — encodings carry it inside the payload the
model decodes, in-place mutators copy it through verbatim — otherwise the battery
would report false negatives it could not explain.

#### Target shapes

`shape` selects the wire format of the application under test, so the battery is
not limited to OpenAI-compatible endpoints:

| Shape | Request | Auth |
|---|---|---|
| `openai` *(default)* | `messages` | `Authorization: Bearer …` |
| `anthropic` | `messages` + required `max_tokens` | `x-api-key` + `anthropic-version` |
| `custom` | your `body_template` with a `{{prompt}}` placeholder | `auth_header` / `auth_prefix` |

For `custom`, `text_path` is a JSON pointer to the reply text (`/data/answer`),
so an in-house `POST /chat {"question": …}` service is probed like any other.
The prompt is JSON-escaped into the template, so quotes and newlines in a probe
cannot break the body. `temperature` is omitted unless you pass it, since some
reasoning endpoints reject the field.

#### Running it

A brain can call `ai_redteam` mid-run, or you can invoke the battery directly
with the **`--ai-redteam`** flag — no LLM brain required. In this mode `--target`
is the chat endpoint, `--model` / `--api-key-env` name the *target's* model/key,
and `--ai-redteam-marker` supplies the leak marker. The flag is explicit consent
for the intrusive action, so it runs without a separate approval prompt — but the
target must still be in scope (host allowlist, budget, and rate limit all apply).

```bash
# Single pass over the battery.
rustzap agent --scope scope.yaml \
  --target http://localhost:3000/v1/chat/completions \
  --ai-redteam --model gpt-4o-mini \
  --ai-redteam-marker "You are ShopBot, the internal assistant" \
  -o redteam-report.json

# Measured run: 10 generations per variant, every obfuscation.
rustzap agent --scope scope.yaml \
  --target http://localhost:3000/v1/chat/completions \
  --ai-redteam --model gpt-4o-mini \
  --ai-redteam-generations 10 --ai-redteam-mutators all \
  -o redteam-report.json

# A non-OpenAI application.
rustzap agent --scope scope.yaml \
  --target http://localhost:8080/chat \
  --ai-redteam --ai-redteam-shape custom \
  --ai-redteam-body-template '{"question": "{{prompt}}"}' \
  --ai-redteam-text-path /data/answer \
  -o redteam-report.json
```

> ⚠️ Request volume is `probes x (1 + mutators) x generations`. `--ai-redteam-mutators all
> --ai-redteam-generations 10` is **110x** a default run — size it for a target you own.

### MCP server

Expose the whole registry to an external agent over stdio:

```bash
rustzap mcp --scope scope.yaml         # scope enables the network tools
rustzap mcp                            # no scope → only local analysis tools
```

Wire it into an MCP client (e.g. Claude Code / Cursor) by pointing the client at
the `rustzap mcp` command; the server advertises the tools above via
`tools/list` and executes them under the same scope guardrails.

### Outputs

| File | Contents |
|------|----------|
| `--output` (default `agent-report.json`) | Findings `Report` (JSON; `--sarif-out` also emits SARIF) |
| `--trace` (default `agent-trace.jsonl`) | Append-only audit trail of the run |
| `<output>.captures.json` | Captured HTTP transactions (when any traffic was sent) |

---

## Active Scan Plugins

> **Evidence-based, no self-validation.** Active plugins verify that a payload —
> not the page's normal content — caused the observed behavior before reporting.
> They fetch an untouched **baseline**, inject **unique canaries**, and only
> conclude when a DB error / metadata token / evaluated expression is *new
> relative to the baseline* (or a reflection survives **unencoded**). Every
> finding carries a `confidence` (`tentative` / `firm` / `confirmed`) and a
> `poc_validated` flag in JSON, CSV, and HTML output. See `src/verify.rs`.

The SQLi family covers error, boolean-blind, time-blind, UNION, stacked,
second-order, WAF-obfuscated, OOB, fingerprinting, and NoSQL operator probes.
Database-specific variants include MySQL, PostgreSQL, SQL Server, Oracle, and
SQLite comments, conditional expressions, timing functions, string/hex forms,
`ORDER BY`/`HAVING` discovery, and encoded payloads. Heavy timing, stacked,
OOB, and state-changing probes should be selected explicitly for an authorized
staging or lab target.

| Plugin | Vuln | OWASP | CWE |
|---|---|---|---|
| `xss` | Reflected XSS | A03:2021 | CWE-79 |
| `sqli` | SQL Injection (basic error-based) | A03:2021 | CWE-89 |
| `sqli-error` | Error-based SQLi — extended DB coverage (MySQL/PG/MSSQL/Oracle/SQLite) | A03:2021 | CWE-89 |
| `sqli-boolean` | Boolean-blind SQLi — TRUE/FALSE response diff oracle | A03:2021 | CWE-89 |
| `sqli-time` | Time-based blind SQLi — SLEEP/WAITFOR/pg_sleep timing oracle | A03:2021 | CWE-89 |
| `sqli-union` | UNION-based SQLi — column count probe + canary reflection | A03:2021 | CWE-89 |
| `sqli-stacked` | Stacked queries — semicolon-separated secondary statement | A03:2021 | CWE-89 |
| `sqli-oob` | Out-of-band SQLi — dispatches DNS/HTTP callback payloads. **Inert unless `RUSTZAP_OOB_DOMAIN` names a listener** (interactsh/Collaborator); reported `tentative` until you observe a callback | A03:2021 | CWE-89 |
| `sqli-second-order` | Second-order SQLi — stores a payload, then confirms via a DB error that surfaces on retrieval (baseline-differential) | A03:2021 | CWE-89 |
| `sqli-waf-bypass` | WAF bypass SQLi — comment, encoding, case, whitespace tricks | A03:2021 | CWE-89 |
| `nosql` | NoSQL injection — MongoDB $ne/$gt/$where/$regex operator injection | A03:2021 | CWE-943 |
| `sqli-fingerprint` | DB fingerprinting via SQLi — identify MySQL/PG/MSSQL/Oracle/SQLite | A05:2021 | CWE-200 |
| `path-traversal` | Directory Traversal | A01:2021 | CWE-22 |
| `open-redirect` | Open Redirect | A01:2021 | CWE-601 |
| `ssrf` | SSRF (AWS/GCP metadata) | A10:2021 | CWE-918 |
| `xxe` | XML External Entity | A03:2021 | CWE-611 |
| `cmd-injection` | OS Command Injection | A03:2021 | CWE-78 |
| `ssti` | Template Injection | A03:2021 | CWE-94 |
| `graphql-introspection` | GraphQL schema exposure via introspection query | A05:2021 | CWE-200 |
| `http-methods` | OPTIONS probe — flags dangerous methods (PUT/DELETE/TRACE/PATCH) | A05:2021 | CWE-650 |
| `redirect-chain` | Redirect chain analyzer — HTTPS→HTTP downgrade, cross-origin, loops, excessive hops | A02:2021 | CWE-601 |
| `sensitive-paths` ⚠️ | Well-known / backup file probe (`/.git/HEAD`, `/.env`, `/backup.zip`, …) — **opt-in, default OFF** | A05:2021 | CWE-538 |

⚠️ `sensitive-paths` is intentionally excluded from defaults. Enable it only against targets you are explicitly authorized to scan — it issues 25+ HEAD requests against well-known dotfile and backup paths.

Run specific plugins only:

```bash
# Default plugin set (everything except sensitive-paths)
rustzap scan --target https://example.com

# Narrow to a few plugins
rustzap scan --target https://example.com --plugins xss,sqli,ssrf

# Opt in to sensitive-path probing
rustzap scan --target https://example.com \
  --plugins xss,sqli,ssrf,sensitive-paths
```

---

## Passive Check Coverage

| Check | Plugin id | Severity |
|---|---|---|
| Missing HSTS | `passive/missing-headers` | Medium |
| Missing CSP | `passive/missing-headers` | Medium |
| Missing X-Frame-Options | `passive/missing-headers` | Medium |
| Missing X-Content-Type-Options | `passive/missing-headers` | Low |
| Cookie missing HttpOnly / Secure / SameSite | `passive/cookie-flags` | Medium / Medium / Low |
| Server version / X-Powered-By disclosure | `passive/info-disclosure` | Low |
| Stack trace / verbose error in body | `passive/info-disclosure` | Medium |
| Mixed content (HTTP asset on HTTPS page) | `passive/mixed-content` | Medium |
| API keys / passwords / private keys in body | `passive/sensitive-data` | High / Critical |
| Wildcard CORS / CORS + credentials | `passive/cors` | Medium / High |
| Missing cache-control on sensitive pages | `passive/cache-control` | Low |
| Missing charset in Content-Type | `passive/content-type` | Low |
| `security.txt` missing / no Contact / no Expires / expired | `passive/security-txt` | Info / Low / Low / Medium |
| CSP `unsafe-inline`, `unsafe-eval`, wildcard, `object-src` not `'none'` | `passive/csp-unsafe-directives` | Low → High |
| Tech-stack fingerprint (Server, generator meta, framework markers) | `passive/tech-fingerprint` | Info |
| JWT `alg:none`, missing `exp`, lifetime > 1 year | `passive/jwt-heuristic` | High / Medium / Low |

The `security.txt` probe runs **once per origin** (not once per URL). The CSP check inspects both `Content-Security-Policy` and `Content-Security-Policy-Report-Only` — findings on the Report-Only header are downgraded one severity tier.

---

## Spider Enrichment

In addition to recursive HTML link / form / inline-JS extraction, the spider also reads:

- `/robots.txt` — `Allow:` / `Disallow:` paths enqueue as `UrlSource::Robots`; `Sitemap:` lines trigger sitemap fetches.
- XML sitemaps (`urlset` and `sitemapindex`) — `<loc>` URLs enqueue as `UrlSource::Sitemap`.

All of this is bounded: robots up to 256 KB, sitemaps up to 1 MB each, max 5 sitemap fetches, max 500 enriched URLs per scan. Hosts outside the target's are silently dropped.

---

## Transport & Intel

After the active phase, RustZAP runs a per-host **TLS certificate probe** against every unique HTTPS host discovered by the spider. The probe accepts any cert (so it can inspect expired / mismatched chains), then summarises the leaf via `x509-parser`.

| Check | Plugin id | Severity |
|---|---|---|
| Certificate expired | `transport/tls-expired` | Critical |
| Certificate expires in < 30 days | `transport/tls-expiring-soon` | Medium |
| Weak signature algorithm (SHA-1 / MD5) | `transport/tls-weak-signature` | Medium |
| Self-signed (subject == issuer) | `transport/tls-self-signed` | Low |
| Hostname not covered by SANs (exact + 1-label wildcard) | `transport/tls-hostname-mismatch` | Medium |

**Optional intel enrichment** is gated by environment variables — if none are set, the module is a no-op.

| Env var | Provider | Findings |
|---|---|---|
| `SHODAN_API_KEY` | Shodan REST host lookup | `intel/shodan-vulns` (High), `intel/shodan-ports` (Low) |

```bash
SHODAN_API_KEY=xxx rustzap scan --target https://example.com
```

Shodan's `/shodan/host/{ip}` endpoint requires an IP — hostnames return 404 and are silently dropped. Provide IPs as scan targets when intel is the goal. Only call these services for hosts you are authorized to scan.

---

## Report Format

```json
{
  "meta": {
    "scanner": "RustZAP",
    "version": "0.1.0",
    "target": "https://example.com",
    "scan_date": "2026-03-08T12:00:00Z",
    "duration_secs": 42.1
  },
  "summary": {
    "total_urls": 87,
    "total_findings": 12,
    "critical": 1,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 1,
    "risk_score": 47
  },
  "findings": [
    {
      "id": "a1b2c3d4-...",
      "title": "SQL Injection",
      "severity": "critical",
      "url": "https://example.com/search?q=test",
      "parameter": "q",
      "evidence": "Payload ''' — Error keyword 'You have an error in your SQL syntax' found",
      "description": "...",
      "solution": "Use parameterized queries...",
      "cwe": 89,
      "owasp_category": "A03:2021 – Injection",
      "plugin": "active/sqli",
      "found_at": "2026-03-08T12:01:23Z"
    }
  ]
}
```

---

## Stress Testing

RustZAP includes a full load/stress testing engine with 5 modes, real-time stats, percentile latency, and a detailed JSON report.

### Modes

| Mode | Description |
|---|---|
| `constant` | N concurrent users hammering the endpoint for D seconds |
| `ramp` | Linearly ramp from `start_users` up to peak, then hold |
| `spike` | Baseline users with a sudden burst at a specific time |
| `soak` | Long-duration constant load — finds memory leaks and degradation |
| `requests` | Fire exactly N requests at a fixed concurrency, then stop |

### Examples

```bash
# Constant: 50 users for 60 seconds
rustzap stress --target https://api.example.com/v1/users \
  --mode constant --users 50 --duration 60

# Ramp: 1 → 100 users over 30s, hold 30s
rustzap stress --target https://api.example.com/search \
  --mode ramp --start-users 1 --users 100 --ramp-secs 30 --duration 60

# Spike: 10 base users, spike to 200 at t=10s for 5s
rustzap stress --target https://api.example.com/checkout \
  --mode spike --users 200 --start-users 10 \
  --spike-at 10 --spike-duration 5 --duration 30

# Soak: 20 users for 10 minutes (find leaks)
rustzap stress --target https://api.example.com/health \
  --mode soak --users 20 --duration 600

# Fixed request count: 10,000 requests at concurrency 100
rustzap stress --target https://api.example.com/ping \
  --mode requests --requests 10000 --users 100

# POST with JSON body + auth
rustzap stress --target https://api.example.com/orders \
  --mode constant --users 20 --duration 30 \
  --method POST \
  --body '{"item":"widget","qty":1}' \
  --header "Content-Type: application/json" \
  --auth "Bearer eyJhbGci..." \
  --expect-status 201

# Assert response body
rustzap stress --target https://api.example.com/health \
  --expect-body '"status":"ok"'
```

### Live Output (during test)

```
⠸ reqs=1,842  rps=184.2  avg=54ms  min=12ms  max=890ms  err=0.0%
```

### Results Summary

```
────────────────────────────────────────────────────────────────
  STRESS TEST RESULTS
────────────────────────────────────────────────────────────────

  Summary
  Total Requests:              10,000
  Successful:                  9,997
  Failed:                      3
  Error Rate:                  0.03%
  Throughput:                  842.1 req/s
  Data Rate:                   1,204.3 KB/s
  Duration:                    11.9s

  Latency
  Average:                     54ms
  Min:                         8ms
  Max:                         1,204ms
  p50 (median):                42ms
  p75:                         68ms
  p90:                         112ms
  p95:                         189ms
  p99:                         412ms
  p99.9:                       988ms

  Latency Distribution
      0-10ms      127   1.3%  █
     10-25ms    2,841  28.4%  ████████████████████████████
     25-50ms    3,912  39.1%  ██████████████████████████████
     50-100ms   2,203  22.0%  ██████████████████████
    100-250ms     743   7.4%  ███████
    250-500ms     132   1.3%  █
   500-1000ms      35   0.4%
      1000ms+       7   0.1%

  Verdict
  ✓ PASS — no errors, p99 latency within 500ms
────────────────────────────────────────────────────────────────
```

### Stress Report JSON

```json
{
  "meta": {
    "scanner": "RustZAP",
    "target": "https://api.example.com/v1/users",
    "mode": "constant",
    "method": "GET",
    "start_time": "2026-03-08T12:00:00Z",
    "end_time": "2026-03-08T12:01:00Z",
    "duration_secs": 60.0
  },
  "summary": {
    "total_requests": 50420,
    "successful": 50418,
    "failed": 2,
    "error_rate_pct": 0.004,
    "throughput_rps": 840.3,
    "avg_latency_ms": 58,
    "min_latency_ms": 9,
    "max_latency_ms": 1840,
    "total_bytes_received": 72604320,
    "throughput_kbps": 1181.2
  },
  "percentiles": {
    "p50_ms": 45,
    "p75_ms": 72,
    "p90_ms": 118,
    "p95_ms": 201,
    "p99_ms": 480,
    "p999_ms": 1102
  },
  "histogram": { "buckets": [...] },
  "timeline": [
    { "elapsed_secs": 1, "rps": 812.0, "avg_latency_ms": 61, "errors": 0 },
    ...
  ],
  "errors": [
    { "message": "Request timeout", "count": 2 }
  ]
}
```

---

## Architecture

```
rustzap/
├── src/
│   ├── main.rs              # CLI (clap) — entry point & subcommands
│   ├── types.rs             # Shared data types (Finding, Severity, UrlSource, …)
│   ├── scanner.rs           # Full-scan orchestrator (Spider→Passive→Active→TLS+Intel→Report)
│   ├── spider.rs            # Recursive crawler + robots.txt / sitemap enrichment
│   ├── passive.rs           # Passive checks (headers, body, security.txt, CSP, tech-fp, JWT)
│   ├── active.rs            # Active scanner core + ScanPlugin registrations (core plugins)
│   ├── sqli_advanced.rs     # Advanced SQLi/NoSQL/stacked/etc. ScanPlugins
│   ├── sensitive_paths.rs   # B2 — opt-in well-known path probe
│   ├── tls.rs               # C1 — rustls-based per-host TLS cert summary
│   ├── intel.rs             # C2 — env-gated Shodan / external intel hook
│   ├── proxy.rs             # Intercepting HTTP proxy (hyper)
│   ├── stress.rs            # Load/stress tester (5 modes, percentiles, timeline)
│   ├── report.rs            # JSON / CSV / HTML — modules[], correlations[], static{}
│   ├── analyze/             # analyze/audit: Semgrep/Trivy/Gitleaks/Checkov parsers + native inventory/JS/forms
│   ├── events.rs            # ScanEvent / ScanPhase — telemetry for the TUI
│   ├── tools.rs             # External tool detection + streaming runner (Semgrep, Trivy, …)
│   ├── installer.rs         # OS-aware companion-tool installer (`rustzap install`)
│   └── tui/                 # Multi-tab console (Dashboard / Scan / Findings / Tools / Logs / Analyze / Agent)
├── scripts/
│   └── install-tools.sh     # Full setup wrapper; explicit native package installation
├── Dockerfile               # Multi-stage build with all companion tools pre-installed
├── docker-compose.yml       # Compose service + optional Juice-Shop lab target
└── Cargo.toml
```

---

## Extending with Custom Plugins

Implement the `ScanPlugin` trait:

```rust
use async_trait::async_trait;
use crate::active::ScanPlugin;
use crate::types::{DiscoveredUrl, Finding, Severity};

pub struct MyPlugin;

#[async_trait]
impl ScanPlugin for MyPlugin {
    fn name(&self) -> &str { "my-plugin" }
    fn description(&self) -> &str { "Detects XYZ vulnerability" }

    /// Override to `true` when the plugin targets a path itself (e.g. an
    /// `/admin` endpoint) rather than a query parameter. The default `false`
    /// keeps the plugin behind the URL-must-have-`?param=` gate.
    fn always_run(&self) -> bool { false }

    async fn scan(&self, client: &reqwest::Client, target: &DiscoveredUrl) -> Vec<Finding> {
        // Your detection logic here
        vec![]
    }
}
```

Then register it in `ActiveScanner::new()` and `list_plugins()` inside `active.rs` (both lists must stay in sync — the binary uses one for execution, the other for `rustzap plugins`).

---

## License

MIT — Use responsibly. Never scan systems without authorization.

### Agent reliability and evidence

The LLM planner uses a bounded projection of local state rather than an ever-growing
conversation. Recent observations include stable `obs-N` IDs and truncation markers;
compact older coverage, findings counts, and the attack-plan frontier remain visible.
An LLM completion must cite successful observation IDs. These references establish
provenance, not semantic proof that an arbitrary natural-language goal was met.
Tool-generated findings remain authoritative.

Malformed actions, unknown tools, invalid arguments, and unsupported evidence references
receive one repair attempt, then fail explicitly. HTTP 429 and server errors use bounded
backoff; authentication errors fail immediately. Timeouts and response limits are
configured in `model.limits` in [scope.example.yaml](scope.example.yaml). Temperature is
omitted unless configured. Select `output_token_field: max_completion_tokens` for an
endpoint that requires it; the default `max_tokens` supports older/local endpoints.
The run budget counts reported input and output usage; missing usage falls back to a
conservative byte estimate. Provider billing for interrupted requests may be unknown.

Each run writes a restricted-permission `OUTPUT.tasks-<run-id>.jsonl` journal containing
task intents, outcomes, evidence IDs, and terminal status. Intents are flushed before tool
execution. Completed identical calls are suppressed across the run, including alternating
loops. Token/turn exhaustion, loop stops, and provider errors produce a nonzero exit and
preserve the partial report. Journals redact recognized secrets but may still contain
sensitive target output. They support audit and manual recovery; automatic resume and a
separate Supervisor/Executor scheduler are not implemented.
