#!/usr/bin/env node
// Shim: run the rustzap binary that install.js placed in ../vendor.
'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { binName, VENDOR_DIR, RELEASES_URL } = require('../install.js');

const bin = path.join(VENDOR_DIR, binName(process.platform));
if (!fs.existsSync(bin)) {
  console.error(`rustzap: binary not found at ${bin}`);
  console.error(`rustzap: run "node ${path.join(__dirname, '..', 'install.js')}" or download it from ${RELEASES_URL}`);
  process.exit(1);
}

function fail(err) {
  console.error(`rustzap: failed to start ${bin}: ${err.message}`);
  process.exit(1);
}

let child;
try {
  child = spawn(bin, process.argv.slice(2), { stdio: 'inherit' });
} catch (err) {
  fail(err); // some Node versions throw EPERM/EACCES synchronously
}

// Terminal Ctrl-C already reaches the child (same process group / console), so
// only keep the shim alive for SIGINT; forward signals sent to the shim alone.
const forwarded = ['SIGTERM', 'SIGHUP'];
process.on('SIGINT', () => {});
for (const sig of forwarded) process.on(sig, () => child.kill(sig));

child.on('error', fail);
child.on('exit', (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
