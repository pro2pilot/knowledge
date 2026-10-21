#!/usr/bin/env node
'use strict';

// Opt-in diagnostic command, never a native verification or release gate.
const fs = require('node:fs');
const path = require('node:path');
const { runDiagnostic } = require('./lib/verification-darwin-diagnostic');
async function main() {
  if (process.argv.length !== 3) throw Object.assign(new Error('usage'), { code: 'darwin_diagnostic_request_file_required' });
  const file = path.resolve(process.argv[2]);
  const st = fs.lstatSync(file);
  if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1 || st.size > 1024 * 1024) {
    throw Object.assign(new Error('request'), { code: 'darwin_diagnostic_request_file_unsafe' });
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let value;
  try {
    const current = fs.fstatSync(fd);
    if (!current.isFile() || current.dev !== st.dev || current.ino !== st.ino || current.size !== st.size) {
      throw Object.assign(new Error('request'), { code: 'darwin_diagnostic_request_file_changed' });
    }
    value = JSON.parse(fs.readFileSync(fd, 'utf8'));
  } finally { fs.closeSync(fd); }
  const result = await runDiagnostic(value);
  const status = result.status === 'diagnostic_completed' ? 0 : 1;
  // A timed-out asynchronous report read/write can still be pending in libuv.
  // This CLI must not wait forever for it after returning an unconfirmed result.
  const timer = setTimeout(() => process.exit(1), 5000); timer.unref();
  process.stdout.write(JSON.stringify(result) + '\n', () => process.exit(status));
}
main().catch(error => {
  const code = /^[a-zA-Z0-9_]{1,128}$/.test(error?.code || '') ? error.code : 'darwin_diagnostic_failed';
  process.stderr.write(JSON.stringify({ status: 'failed', code, production_acceptance: false }) + '\n');
  process.exitCode = 1;
});
