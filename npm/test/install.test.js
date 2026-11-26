'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const {
  assetName,
  binName,
  isAllowedUrl,
  shouldSkip,
  parseSums,
  verifyChecksum,
  download,
} = require('../install.js');

test('maps supported platforms to the release assets install.sh/install.ps1 use', () => {
  assert.strictEqual(assetName('linux', 'x64', '1.2.3'), 'rustzap-1.2.3-linux-x86_64.tar.gz');
  assert.strictEqual(assetName('linux', 'arm64', '1.2.3'), 'rustzap-1.2.3-linux-aarch64.tar.gz');
  assert.strictEqual(assetName('darwin', 'x64', '1.2.3'), 'rustzap-1.2.3-macos-universal.tar.gz');
  assert.strictEqual(assetName('darwin', 'arm64', '1.2.3'), 'rustzap-1.2.3-macos-universal.tar.gz');
  assert.strictEqual(assetName('win32', 'x64', '1.2.3'), 'rustzap-1.2.3-windows-x64.zip');
  assert.strictEqual(binName('win32'), 'rustzap.exe');
  assert.strictEqual(binName('linux'), 'rustzap');
});

test('returns null for unsupported platforms', () => {
  assert.strictEqual(assetName('win32', 'arm64', '1.2.3'), null);
  assert.strictEqual(assetName('linux', 'ia32', '1.2.3'), null);
  assert.strictEqual(assetName('freebsd', 'x64', '1.2.3'), null);
  assert.strictEqual(assetName('linux', 'toString', '1.2.3'), null);
});

const archive = Buffer.from('fake archive');
const hash = crypto.createHash('sha256').update(archive).digest('hex');
const asset = 'rustzap-1.2.3-linux-x86_64.tar.gz';
const sums = [
  `${'0'.repeat(64)}  rustzap-1.2.3-linux-aarch64.tar.gz`,
  `${hash.toUpperCase()}  ${asset}`,
  `${'1'.repeat(64)}  ${asset}.extra`,
  '',
].join('\n');

test('parses SHA256SUMS by exact asset name', () => {
  assert.strictEqual(parseSums(sums, asset), hash);
  assert.strictEqual(parseSums(sums.replace(/\n/g, '\r\n'), asset), hash);
  assert.strictEqual(parseSums(sums, 'rustzap-1.2.3-windows-x64.zip'), null);
  assert.strictEqual(parseSums('garbage\n', asset), null);
});

test('accepts a matching checksum', () => {
  assert.doesNotThrow(() => verifyChecksum(archive, sums, asset));
});

test('rejects a checksum mismatch', () => {
  assert.throws(() => verifyChecksum(Buffer.from('tampered'), sums, asset), /checksum mismatch/);
});

test('rejects a missing SHA256SUMS entry', () => {
  assert.throws(
    () => verifyChecksum(archive, sums, 'rustzap-1.2.3-windows-x64.zip'),
    /no SHA256SUMS entry/,
  );
});

test('only allows https GitHub hosts', () => {
  assert.ok(isAllowedUrl('https://github.com/souayb/rustZAP/releases/download/v1/x'));
  assert.ok(isAllowedUrl('https://objects.githubusercontent.com/x'));
  assert.ok(isAllowedUrl('https://release-assets.githubusercontent.com/x'));
  assert.ok(!isAllowedUrl('http://github.com/x'));
  assert.ok(!isAllowedUrl('https://evil.com/x'));
  assert.ok(!isAllowedUrl('https://github.com.evil.com/x'));
  assert.ok(!isAllowedUrl('https://evilgithubusercontent.com/x'));
  assert.ok(!isAllowedUrl('not a url'));
});

function fakeFetch(routes) {
  return async (url) => {
    const r = routes[url];
    if (!r) throw new Error(`unexpected fetch ${url}`);
    return {
      status: r.status,
      ok: r.status >= 200 && r.status < 300,
      headers: { get: (h) => (h === 'location' ? r.location : null) },
      arrayBuffer: async () => Buffer.from(r.body || ''),
    };
  };
}

test('download follows redirects to allowed hosts', async () => {
  const buf = await download(
    'https://github.com/a',
    fakeFetch({
      'https://github.com/a': { status: 302, location: 'https://objects.githubusercontent.com/b' },
      'https://objects.githubusercontent.com/b': { status: 200, body: 'ok' },
    }),
  );
  assert.strictEqual(buf.toString(), 'ok');
});

test('download refuses redirects off the allowlist', async () => {
  await assert.rejects(
    download(
      'https://github.com/a',
      fakeFetch({ 'https://github.com/a': { status: 302, location: 'http://evil.com/b' } }),
    ),
    /refusing to download/,
  );
});

test('download fails on HTTP errors', async () => {
  await assert.rejects(
    download('https://github.com/a', fakeFetch({ 'https://github.com/a': { status: 404 } })),
    /HTTP 404/,
  );
});

test('RUSTZAP_SKIP_DOWNLOAD skips the download', () => {
  assert.ok(shouldSkip({ RUSTZAP_SKIP_DOWNLOAD: '1' }));
  assert.ok(shouldSkip({ RUSTZAP_SKIP_DOWNLOAD: 'true' }));
  assert.ok(!shouldSkip({}));
  assert.ok(!shouldSkip({ RUSTZAP_SKIP_DOWNLOAD: '0' }));
});
