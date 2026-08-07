#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildPackageEntries } = require('./package-release');
const { withTempFixture } = require('./lib/strict-temp-cleanup');

const root = path.resolve(__dirname, '..');

function materializePublicRuntime(target) {
  for (const entry of buildPackageEntries(root).entries) {
    const output = path.join(target, '.knowledge', ...entry.rel.split('/'));
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.copyFileSync(entry.abs, output);
  }
}

function runCase(id, mutate) {
  return withTempFixture({ prefix: `knowledge-install-interface-${id}-` }, (fixture) => {
    materializePublicRuntime(fixture);
    const manifestPath = path.join(fixture, '.knowledge', 'install-manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    mutate(manifest);
    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    const result = spawnSync(process.execPath, ['.knowledge/tools/install-check.js', '--json'], {
      cwd: fixture,
      encoding: 'utf8',
      windowsHide: true,
      timeout: 120000,
      env: { ...process.env, NO_COLOR: '1', TERM: 'dumb' }
    });
    let report = {};
    let parseError = null;
    try { report = JSON.parse(result.stdout || '{}'); } catch (error) { parseError = error.message; }
    const codes = (report.issues || []).map((item) => item.code);
    return {
      id,
      observed_exit: result.status,
      observed_status: report.status || null,
      stdout_bytes: Buffer.byteLength(result.stdout || ''),
      json_complete: parseError === null,
      issue_codes: codes,
      pass: result.status !== 0 &&
        Buffer.byteLength(result.stdout || '') > 8192 &&
        parseError === null &&
        report.status === 'failed' &&
        codes.includes('public_self_test_allowlist_mismatch')
    };
  });
}

function run() {
  const results = [
    runCase('missing-shipped-test-in-allowlist', (manifest) => {
      manifest.release_contract.public_self_test_paths = manifest.release_contract.public_self_test_paths.slice(1);
    }),
    runCase('nonexistent-test-in-allowlist', (manifest) => {
      manifest.release_contract.public_self_test_paths.push('tools/self-test-does-not-exist.js');
    })
  ];
  const report = {
    schema_version: 'install-check-public-interface-self-test.v1',
    generated_at: new Date().toISOString(),
    checks_total: results.length,
    checks_passed: results.filter((item) => item.pass).length,
    results,
    status: results.every((item) => item.pass) ? 'pass' : 'fail'
  };
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) run();
module.exports = { run };
