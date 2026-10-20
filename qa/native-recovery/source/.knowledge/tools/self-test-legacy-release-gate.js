#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const { inspectLegacyGate, migrateLegacyGate } = require('./migrate-legacy-release-gate');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-legacy-gate-'));
const checks = [];
const check = (name, fn) => { fn(); checks.push(name); };
try {
  const gate = path.join(root, 'tools/release-gate.js');
  const old = fs.readFileSync(path.join(__dirname, 'fixtures/legacy-release-gate-3.2.0.txt'), 'utf8');
  check('absent gate is untouched', () => assert.equal(migrateLegacyGate(root, true).status, 'absent'));
  fs.mkdirSync(path.dirname(gate), { recursive: true });
  fs.writeFileSync(gate, old);
  check('default inspection never runs or rewrites the gate', () => {
    assert.equal(migrateLegacyGate(root).status, 'obsolete');
    assert.equal(fs.readFileSync(gate, 'utf8'), old);
  });
  check('known legacy gate is backed up and redirected', () => {
    const result = migrateLegacyGate(root, true);
    assert.equal(result.status, 'redirected');
    assert.equal(fs.readFileSync(path.join(root, result.backup), 'utf8'), old);
    assert.equal(inspectLegacyGate(root).status, 'redirected');
  });
  check('migration is idempotent', () => assert.equal(migrateLegacyGate(root, true).applied, false));
  const invoke = (...args) => spawnSync(process.execPath, [gate, ...args], { cwd: os.tmpdir(), encoding: 'utf8', windowsHide: true });
  check('runtime-only install blocks with an honest missing-maintainer result', () => {
    const result = invoke('--json');
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stderr).reason, 'maintainer_release_gate_unavailable');
  });
  const canonical = path.join(root, '.knowledge/tools/release-gate.js');
  fs.mkdirSync(path.dirname(canonical), { recursive: true });
  fs.writeFileSync(canonical, "console.log(JSON.stringify({argv:process.argv.slice(2),cwd:process.cwd()}));process.exitCode=7;\n");
  check('redirect forwards exact argv, cwd and failure status without executing a real gate', () => {
    const result = invoke('--json', '--label=argument with spaces');
    assert.equal(result.status, 7);
    const body = JSON.parse(result.stdout);
    assert.deepEqual(body.argv, ['--json', '--label=argument with spaces']);
    assert.equal(body.cwd, path.join(root, '.knowledge'));
  });
  check('custom project gate is preserved', () => {
    fs.writeFileSync(gate, old + '\n// local customization\n');
    assert.equal(migrateLegacyGate(root, true).status, 'custom_preserved');
    assert(fs.readFileSync(gate, 'utf8').includes('local customization'));
  });
  check('line endings do not hide legacy detection', () => {
    fs.writeFileSync(gate, old.replace(/\r?\n/g, '\r\n'));
    assert.equal(inspectLegacyGate(root).status, 'obsolete');
  });
  check('updater surfaces obsolete project tooling without rewriting it', () => {
    const result = spawnSync(process.execPath, [path.join(__dirname, 'update-system-files.js'),
      '--from', path.resolve(__dirname, '..'), '--target-knowledge-root', path.join(root, '.knowledge'), '--dry-run', '--json'],
    { cwd: root, encoding: 'utf8', windowsHide: true, maxBuffer: 8 * 1024 * 1024, timeout: 60000 });
    const report = JSON.parse(result.stdout || '{}');
    assert.equal(result.status, 0, result.stderr || JSON.stringify(report.errors));
    assert.equal(report.legacy_release_gate.status, 'obsolete');
    assert(report.warnings.some((item) => item.includes('migrate-legacy-release-gate')));
    assert.equal(inspectLegacyGate(root).status, 'obsolete');
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks }, null, 2));
} finally { fs.rmSync(root, { recursive: true, force: true }); }
