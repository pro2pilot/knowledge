#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { runCommand } = require('./release-gate');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const outputArg = process.argv.find((arg) => arg.startsWith('--output='));
const outputPath = outputArg ? path.resolve(outputArg.slice('--output='.length)) : null;
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-release-gate-buffer-'));
const logDir = path.join(fixture, 'logs');
fs.mkdirSync(logDir, { recursive: true });
const bytesPerStream = 2 * 1024 * 1024;
const results = [];

function assert(condition, message) { if (!condition) throw new Error(message); }
function exercise(id, exitCode, expectedStatus) {
  const code = `process.stdout.write('O'.repeat(${bytesPerStream}));process.stderr.write('E'.repeat(${bytesPerStream}));process.exit(${exitCode});`;
  const observed = runCommand({ id, command: process.execPath, args: ['-e', code], semanticChecks: false }, { logDir });
  const stdoutBytes = fs.statSync(path.join(logDir, `${id}.stdout.txt`)).size;
  const stderrBytes = fs.statSync(path.join(logDir, `${id}.stderr.txt`)).size;
  assert(observed.status === expectedStatus, `${id}: expected ${expectedStatus}, got ${observed.status}`);
  assert(observed.exit_code === exitCode, `${id}: expected exit ${exitCode}, got ${observed.exit_code}`);
  assert(stdoutBytes === bytesPerStream, `${id}: stdout truncated to ${stdoutBytes}`);
  assert(stderrBytes === bytesPerStream, `${id}: stderr truncated to ${stderrBytes}`);
  results.push({ id, status: 'pass', expected_status: expectedStatus, observed_status: observed.status, exit_code: observed.exit_code, stdout_bytes: stdoutBytes, stderr_bytes: stderrBytes, stdout_sha256: observed.stdout_sha256, stderr_sha256: observed.stderr_sha256 });
}

let report;
try {
  exercise('large-success', 0, 'pass');
  exercise('large-failure', 7, 'fail');
  report = { schema_version: 'release-gate-buffer-test.v1', status: 'pass', former_default_buffer_bytes: 1024 * 1024, bytes_per_stream: bytesPerStream, results };
} catch (error) {
  report = { schema_version: 'release-gate-buffer-test.v1', status: 'fail', error: error.stack || error.message, results };
  process.exitCode = 1;
} finally {
  if (outputPath) { fs.mkdirSync(path.dirname(outputPath), { recursive: true }); fs.writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8'); }
  console.log(JSON.stringify(report, null, 2));
  removeTempDirStrict(fixture);
}
