#!/usr/bin/env node
// postinstall: download the prebuilt rustzap binary for this platform from the
// GitHub release matching this package's version, verify its SHA-256 against
// the release's SHA256SUMS, and extract it into ./vendor. Mirrors
// scripts/install.sh / install.ps1 (same assets, same checksum check).
// Zero dependencies; never executes the downloaded binary.
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const REPO = 'souayb/rustZAP';
const RELEASES_URL = `https://github.com/${REPO}/releases`;
const VENDOR_DIR = path.join(__dirname, 'vendor');

// Release asset for a Node platform/arch, or null when no prebuilt binary exists.
function assetName(platform, arch, version) {
  const suffix = {
    'linux-x64': 'linux-x86_64.tar.gz',
    'linux-arm64': 'linux-aarch64.tar.gz',
    'darwin-x64': 'macos-universal.tar.gz',
    'darwin-arm64': 'macos-universal.tar.gz',
    'win32-x64': 'windows-x64.zip',
  }[`${platform}-${arch}`];
  return suffix ? `rustzap-${version}-${suffix}` : null;
}

function binName(platform) {
  return platform === 'win32' ? 'rustzap.exe' : 'rustzap';
}

// Downloads (and redirects) may only go to GitHub over HTTPS.
function isAllowedUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return (
    u.protocol === 'https:' &&
    (u.hostname === 'github.com' || u.hostname.endsWith('.githubusercontent.com'))
  );
}

function shouldSkip(env) {
  return env.RUSTZAP_SKIP_DOWNLOAD === '1' || env.RUSTZAP_SKIP_DOWNLOAD === 'true';
}

// Expected hash for `asset` from SHA256SUMS text ("<hash>  <name>" lines), or null.
function parseSums(text, asset) {
  for (const line of text.split(/\r?\n/)) {
    const m = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/.exec(line);
    if (m && m[2] === asset) return m[1].toLowerCase();
  }
  return null;
}

function verifyChecksum(buf, sumsText, asset) {
  const want = parseSums(sumsText, asset);
  if (!want) throw new Error(`no SHA256SUMS entry for ${asset}`);
  const got = crypto.createHash('sha256').update(buf).digest('hex');
  if (got !== want) {
    throw new Error(`checksum mismatch for ${asset} (expected ${want}, got ${got})`);
  }
}

async function download(url, fetchImpl = fetch) {
  for (let hops = 0; hops <= 5; hops++) {
    if (!isAllowedUrl(url)) throw new Error(`refusing to download from ${url}`);
    const res = await fetchImpl(url, { redirect: 'manual' });
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`redirect without location from ${url}`);
      url = new URL(loc, url).href;
      continue;
    }
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return Buffer.from(await res.arrayBuffer());
  }
  throw new Error(`too many redirects for ${url}`);
}

function tarPath(platform) {
  // Windows 10+ ships bsdtar (reads .zip); Git-for-Windows' GNU tar on PATH does not.
  if (platform === 'win32') {
    return path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
  }
  return 'tar';
}

async function main() {
  if (shouldSkip(process.env)) {
    console.log('rustzap: RUSTZAP_SKIP_DOWNLOAD set, skipping binary download');
    return;
  }
  const { version } = require('./package.json');
  const asset = assetName(process.platform, process.arch, version);
  if (!asset) {
    throw new Error(`no prebuilt binary for ${process.platform}-${process.arch}`);
  }
  const base = `${RELEASES_URL}/download/v${version}`;
  console.log(`rustzap: downloading ${base}/${asset}`);
  const [archive, sums] = await Promise.all([
    download(`${base}/${asset}`),
    download(`${base}/SHA256SUMS`),
  ]);
  verifyChecksum(archive, sums.toString('utf8'), asset);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rustzap-npm-'));
  try {
    const archivePath = path.join(tmp, asset);
    fs.writeFileSync(archivePath, archive);
    const outDir = path.join(tmp, 'out');
    fs.mkdirSync(outDir);
    execFileSync(tarPath(process.platform), ['-xf', archivePath, '-C', outDir], {
      stdio: 'inherit',
    });
    const bin = binName(process.platform);
    const extracted = path.join(outDir, bin);
    if (!fs.existsSync(extracted)) throw new Error(`archive did not contain ${bin}`);
    fs.mkdirSync(VENDOR_DIR, { recursive: true });
    fs.copyFileSync(extracted, path.join(VENDOR_DIR, bin));
    fs.chmodSync(path.join(VENDOR_DIR, bin), 0o755);
    console.log(`rustzap: installed ${version} (checksum OK)`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(`rustzap: install failed: ${err.message}`);
    console.error(`rustzap: download the binary manually from ${RELEASES_URL}`);
    console.error('rustzap: (set RUSTZAP_SKIP_DOWNLOAD=1 to install without the binary)');
    process.exit(1);
  });
}

module.exports = {
  assetName,
  binName,
  isAllowedUrl,
  shouldSkip,
  parseSums,
  verifyChecksum,
  download,
  VENDOR_DIR,
  RELEASES_URL,
};
