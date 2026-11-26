# rustzap (npm)

Installs the prebuilt [RustZAP](https://github.com/souayb/rustZAP) web security
scanner binary.

```bash
npm install -g rustzap
rustzap --help
# or, without installing:
npx rustzap --help
```

Only scan targets you own or have explicit written permission to test.

## How it works

The `postinstall` script downloads the release asset matching this package's
version and your platform from GitHub Releases (the same raw CLI archives
`scripts/install.sh` / `install.ps1` use), verifies its SHA-256 against the
release's `SHA256SUMS`, and extracts the binary with the system `tar`. Nothing
is executed during install.

Supported: Linux x64/arm64, macOS x64/arm64 (universal binary), Windows x64
(Windows 10+, uses the built-in `tar.exe`).

## Options

- `RUSTZAP_SKIP_DOWNLOAD=1` — skip the download (offline/CI installs). The
  `rustzap` command then reports that the binary is missing.
- Proxies: the installer has no proxy support of its own (`HTTPS_PROXY` is not
  read). On Node versions that support it, `NODE_USE_ENV_PROXY=1` makes Node
  itself honour `HTTPS_PROXY`. Otherwise download the binary manually.
- `npm install --ignore-scripts` also skips the download; run
  `node <package dir>/install.js` afterwards.

Manual download: https://github.com/souayb/rustZAP/releases
