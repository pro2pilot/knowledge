#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { removeTempDirStrict } = require('../lib/strict-temp-cleanup');

function main() {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-rc40-doc-consistency-'));
  try {
    const root = path.join(temporary, 'evidence');
    fs.mkdirSync(path.join(root, 'tests'), { recursive: true });
    const packaging = 'READY_FOR_EXTERNAL_AUDIT';
    const release = 'BLOCKED_PENDING_EXTERNAL_AUDIT_AND_OS_NODE_MATRIX';
    fs.writeFileSync(path.join(root, 'RC40-FINAL-REPORT.md'), `Linux matrix: 15/15 PASS\n${packaging}\n${release}\n`, 'utf8');
    fs.writeFileSync(path.join(root, 'RC40-SUMMARY.md'), `Linux container physical matrix: 15/15 PASS\n${packaging}\n${release}\n`, 'utf8');
    fs.writeFileSync(path.join(root, 'KNOWN-LIMITATIONS.md'), `Linux x64 / Node 22 physical matrix passed 15/15.\n${packaging}\n${release}\n`, 'utf8');
    fs.writeFileSync(path.join(root, 'tests', 'linux-project-lock-matrix.json'), JSON.stringify({ status: 'pass', checks_total: 15, passed: 15, failed: 0 }), 'utf8');
    fs.writeFileSync(path.join(root, 'release-gate-report.json'), JSON.stringify({ status: 'pass', checks_total: 62, passed: 62, failed: 0 }), 'utf8');
    fs.writeFileSync(path.join(root, 'release-gate-report.md'), '# Gate\nStatus: pass\nChecks total: 62\nPassed: 62\nFailed: 0\n', 'utf8');
    fs.writeFileSync(path.join(root, 'RC40-STATUS.json'), JSON.stringify({ packaging_status: packaging, release_status: release, gate: { status: 'pass', checks_total: 62, passed: 62, failed: 0 } }), 'utf8');
    const child = spawnSync(process.execPath, [path.join(__dirname, 'verify-rc40-document-consistency.js'), '--root', root], { encoding: 'utf8', windowsHide: true });
    const report = JSON.parse(child.stdout);
    const pass = child.status === 0 && report.status === 'pass' && report.checks_total === 6 && report.passed === 6;
    process.stdout.write(`${JSON.stringify({ schema_version: 'knowledge-rc40-document-consistency-self-test.v1', status: pass ? 'pass' : 'fail', checks_total: 1, passed: pass ? 1 : 0, failed: pass ? 0 : 1, results: [{ id: 'document_consistency_contract', pass, actual: report }] }, null, 2)}\n`);
    if (!pass) process.exitCode = 1;
  } finally { removeTempDirStrict(temporary); }
}

if (require.main === module) main();
