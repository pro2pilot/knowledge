#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const args = { runs: 20, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--runs') args.runs = Number(argv[++index]);
    else if (value.startsWith('--runs=')) args.runs = Number(value.slice('--runs='.length));
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice('--out='.length);
  }
  if (!Number.isInteger(args.runs) || args.runs < 20) throw new Error('--runs must be an integer of at least 20');
  return args;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const results = [];
  const script = path.join(root, 'tools', 'self-test-dedicated-verification.js');
  for (let index = 0; index < args.runs; index += 1) {
    const started = process.hrtime.bigint();
    const result = spawnSync(process.execPath, [script], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, CI: 'true' },
      timeout: 120000,
      maxBuffer: 8 * 1024 * 1024,
      windowsHide: true
    });
    results.push({
      run: index + 1,
      exit_code: result.status,
      duration_ms: Number((Number(process.hrtime.bigint() - started) / 1e6).toFixed(3)),
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      passed: result.status === 0 && !result.error
    });
  }
  const report = {
    schema_version: 'dedicated-verification-stress.v1',
    generated_at: new Date().toISOString(),
    ci: true,
    requested_runs: args.runs,
    completed_runs: results.length,
    failures: results.filter((item) => !item.passed).length,
    duration_distribution_ms: results.map((item) => item.duration_ms),
    results,
    status: results.every((item) => item.passed) ? 'pass' : 'fail'
  };
  const out = path.resolve(args.out || path.join(root, '.self-test-tmp', 'dedicated-verification-stress.json'));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ...report, results: results.map(({ stdout, stderr, ...item }) => item) }, null, 2));
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) {
  try { main(); } catch (error) { console.error(error.stack || error.message); process.exitCode = 2; }
}

module.exports = { main };
