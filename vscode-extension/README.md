# RustZAP for VS Code

Run **RustZAP** static analysis and DAST scans from Visual Studio Code. The extension shells out to the [`rustzap`](https://github.com/souayb/rustZAP) CLI — it does not bundle the scanner.

> **Legal:** Only scan systems you own or have explicit written permission to test.

## Requirements

- [RustZAP CLI](https://github.com/souayb/rustZAP#installation) on `PATH`, or built locally (`cargo build --release`), or set **`rustzap.path`** in settings.
- VS Code **1.85+**.

## Commands

| Command | Description |
|---------|-------------|
| **RustZAP: Analyze Workspace** | Static analysis — findings in **Problems**, **sidebar**, and **summary** |
| **RustZAP: Scan URL** | Passive DAST (legal confirmation required) |
| **RustZAP: Show Report Summary** | Markdown summary (inventory, attack plan, modules) |
| **RustZAP: Open Last Report (JSON)** | Open the latest JSON report from extension storage |
| **RustZAP: Show Finding Details** | Full finding write-up in the editor |
| **RustZAP: Clear Findings** | Reset Problems, sidebar, and status bar |

## Sidebar (RustZAP activity bar)

After a run, the tree shows:

1. **Summary** — risk score, severity counts (click for full markdown report)
2. **Inventory** — languages, frameworks, entrypoints, risk breakdown (native analyze)
3. **Attack plan** — suggested DAST targets from static analysis (click to scan when a live URL is available)
4. **Findings** — grouped by severity; each row shows `file:line` when known

**Status bar:** `RustZAP: risk N · M finding(s)` — click to focus the sidebar.

Reports are written under extension storage (not your repo).

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `rustzap.path` | *(empty)* | Path to `rustzap` binary |
| `rustzap.analyze.tools` | `native` | Analyze tools list |
| `rustzap.analyze.onSave` | `false` | Re-analyze on save |
| `rustzap.scan.passiveOnly` | `true` | Passive-only DAST |
| `rustzap.scan.depth` | `1` | Spider depth |
| `rustzap.scan.plugins` | *(empty)* | Active plugins when passive is off |
| `rustzap.scan.insecure` | `false` | Skip TLS verification |
| `rustzap.problems.infoSeverity` | `information` | Show info findings in Problems (`hint` hides most) |

## Development

```bash
cd vscode-extension
npm ci
npm run compile
npm test
```

Press **F5** in VS Code to launch an Extension Development Host.

## License

MIT — same as RustZAP.
