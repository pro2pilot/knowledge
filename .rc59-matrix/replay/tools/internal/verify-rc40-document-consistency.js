#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = { root: null, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--root') args.root = argv[++index] || null;
    else if (value.startsWith('--root=')) args.root = value.slice(7);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice(6);
  }
  if (!args.root) throw new Error('--root=<final evidence root> is required');
  return args;
}

function check(id, expected, actual, pass) { return { id, expected, actual, pass: Boolean(pass) }; }
function text(file) { return fs.readFileSync(file, 'utf8'); }
function readJson(file) { return JSON.parse(text(file)); }

function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = path.resolve(args.root);
  const files = {
    final: path.join(root, 'RC40-FINAL-REPORT.md'),
    summary: path.join(root, 'RC40-SUMMARY.md'),
    limitations: path.join(root, 'KNOWN-LIMITATIONS.md'),
    linux: path.join(root, 'tests', 'linux-project-lock-matrix.json'),
    gateMd: path.join(root, 'release-gate-report.md'),
    gateJson: path.join(root, 'release-gate-report.json'),
    status: path.join(root, 'RC40-STATUS.json')
  };
  const results = [];
  const allPresent = Object.values(files).every((file) => fs.existsSync(file));
  results.push(check('required_documents_present', { files: Object.keys(files) }, { missing: Object.entries(files).filter(([, file]) => !fs.existsSync(file)).map(([id]) => id) }, allPresent));
  if (!allPresent) return finish(args, root, results);

  const final = text(files.final);
  const summary = text(files.summary);
  const limitations = text(files.limitations);
  const gateMd = text(files.gateMd);
  const linux = readJson(files.linux);
  const gate = readJson(files.gateJson);
  const status = readJson(files.status);
  const linuxPass = linux.status === 'pass' && linux.checks_total === 15 && linux.passed === 15 && linux.failed === 0;
  results.push(check('linux_matrix_15_of_15_pass', { status: 'pass', checks_total: 15, passed: 15, failed: 0 }, { status: linux.status, checks_total: linux.checks_total, passed: linux.passed, failed: linux.failed }, linuxPass));
  const documentsDeclareLinux = /Linux[^\n]*15\/15/i.test(final) && /Linux[^\n]*15\/15/i.test(summary) && /Linux[^\n]*15\/15/i.test(limitations);
  const limitationsDoNotDenyLinux = !/Linux[^\n]*(?:unavailable|absent|missing|required|pending)/i.test(limitations);
  results.push(check('linux_claims_match_matrix', { docs: '15/15 PASS; limitations do not deny availability' }, { documents_declare_linux_15_of_15: documentsDeclareLinux, limitations_deny_linux: !limitationsDoNotDenyLinux }, documentsDeclareLinux && limitationsDoNotDenyLinux));
  const statusesMatch = typeof status.packaging_status === 'string' && typeof status.release_status === 'string'
    && final.includes(status.packaging_status) && final.includes(status.release_status)
    && summary.includes(status.packaging_status) && summary.includes(status.release_status)
    && limitations.includes(status.packaging_status) && limitations.includes(status.release_status);
  results.push(check('packaging_and_release_status_consistent', { packaging_status: status.packaging_status, release_status: status.release_status }, { final: final.includes(status.packaging_status) && final.includes(status.release_status), summary: summary.includes(status.packaging_status) && summary.includes(status.release_status), limitations: limitations.includes(status.packaging_status) && limitations.includes(status.release_status) }, statusesMatch));
  const gateValuesMatch = gate.status === status.gate.status && gate.checks_total === status.gate.checks_total && gate.passed === status.gate.passed && gate.failed === status.gate.failed
    && gateMd.includes(`Status: ${gate.status}`) && gateMd.includes(`Checks total: ${gate.checks_total}`) && gateMd.includes(`Passed: ${gate.passed}`) && gateMd.includes(`Failed: ${gate.failed}`);
  results.push(check('gate_markdown_matches_json', status.gate, { status: gate.status, checks_total: gate.checks_total, passed: gate.passed, failed: gate.failed }, gateValuesMatch));
  const controls = [];
  for (let index = 0; index < gateMd.length; index += 1) { const code = gateMd.charCodeAt(index); if (code < 32 && code !== 9 && code !== 10 && code !== 13) controls.push({ index, code }); }
  const unresolvedInterpolation = /\$\{[^}]+\}|\$\([^)]+\)/.test(gateMd);
  results.push(check('gate_markdown_clean_text', { unexpected_control_characters: 0, unresolved_powershell_interpolation: false }, { unexpected_control_characters: controls, unresolved_powershell_interpolation: unresolvedInterpolation }, controls.length === 0 && !unresolvedInterpolation));
  return finish(args, root, results);
}

function finish(args, root, results) {
  const report = { schema_version: 'knowledge-rc40-document-consistency.v1', evidence_root: root, checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results };
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), output, 'utf8'); }
  process.stdout.write(output);
  if (report.failed) process.exitCode = 1;
  return report;
}

if (require.main === module) main();
module.exports = { main };
