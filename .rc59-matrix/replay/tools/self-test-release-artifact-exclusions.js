#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { buildPackageEntries, createZip } = require('./package-release');
const { readZipEntries, validate } = require('./validate-release-artifact');

const root = path.resolve(__dirname, '..');

function parseArgs(argv) {
  const args = { artifact: null, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--artifact') args.artifact = argv[++index] || null;
    else if (value.startsWith('--artifact=')) args.artifact = value.slice('--artifact='.length);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice('--out='.length);
  }
  return args;
}

function fixtureRoot() {
  const base = path.join(root, '.self-test-tmp');
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, 'release-artifact-exclusions-'));
}

function validEntries(artifact, temporaryRoot) {
  if (artifact) {
    const source = readZipEntries(artifact).entries;
    return source.map((entry, index) => {
      const file = path.join(temporaryRoot, 'base', String(index));
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, entry.body);
      return { name: entry.name, rel: entry.name.replace(/^\.knowledge\//, ''), abs: file };
    });
  }
  return buildPackageEntries(root).entries;
}

function createCaseZip(directory, entries, additions) {
  const dirty = path.join(directory, 'dirty-entry');
  fs.writeFileSync(dirty, 'fixture');
  const fixtureEntries = entries.concat(additions.map((name) => ({ name, rel: name, abs: dirty })));
  const zipPath = path.join(directory, 'knowledge-v3.3.0-step1-rc99.zip');
  createZip(fixtureEntries, zipPath);
  return zipPath;
}

function run(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const temporaryRoot = fixtureRoot();
  const entries = validEntries(args.artifact, temporaryRoot);
  const cases = [
    ['exact-excluded', ['.knowledge/tools/self-test-routing-rc4-r4.js'], 'manifest_excluded_path'],
    ['directory-prefix', ['.knowledge/tools/internal/nested.js'], 'manifest_excluded_path'],
    ['backslash-equivalent', ['.knowledge\\tools\\self-test-routing-rc4-r4.js'], 'zip_path_invalid'],
    ['leading-dot-equivalent', ['./.knowledge/tools/self-test-routing-rc4-r4.js'], 'manifest_excluded_path'],
    ['windows-case-collision', ['.knowledge/TOOLS/DOCTOR.JS'], 'zip_duplicate_entry'],
    ['duplicate-entry', ['.knowledge/tools/doctor.js'], 'zip_duplicate_entry'],
    ['source-only-self-test', ['.knowledge/tools/self-test-routing-rc4-r5.js'], 'public_self_test_unallowlisted'],
    ['source-only-agent-integration', ['.knowledge/agent-integrations/codex/skills/release-preparation-workflow.md'], 'public_agent_integration_unallowlisted'],
    ['maintainer-tool', ['.knowledge/tools/package-release.js'], 'manifest_excluded_path'],
    ['candidate-note', ['.knowledge/.release-notes/v3.3.0-step1-rc4-r11.md'], 'manifest_excluded_path'],
    ['routing-runtime-state', ['.knowledge/routing/current.json'], 'manifest_excluded_path'],
    ['temporary-file', ['.knowledge/maintenance/probe.tmp-proof'], 'manifest_excluded_path']
  ];
  const results = [];
  for (const [id, additions, expectedType] of cases) {
    const caseRoot = path.join(temporaryRoot, id);
    fs.mkdirSync(caseRoot, { recursive: true });
    const result = validate(createCaseZip(caseRoot, entries, additions));
    const reasons = result.violations.map((item) => item.type);
    results.push({ id, expected_type: expectedType, status: result.status, violation_types: reasons, pass: result.status === 'failed' && reasons.includes(expectedType) });
  }
  const controlRoot = path.join(temporaryRoot, 'valid-control');
  fs.mkdirSync(controlRoot, { recursive: true });
  const control = validate(createCaseZip(controlRoot, entries, []));
  results.push({ id: 'valid-control', expected_type: null, status: control.status, violation_types: control.violations.map((item) => item.type), pass: control.status === 'ok' });
  const report = {
    schema_version: 'release-artifact-exclusion-tests.v1',
    generated_at: new Date().toISOString(),
    artifact: args.artifact ? path.resolve(args.artifact) : null,
    cases_total: results.length,
    cases_passed: results.filter((item) => item.pass).length,
    results,
    status: results.every((item) => item.pass) ? 'pass' : 'fail'
  };
  const out = path.resolve(args.out || path.join(temporaryRoot, 'release-artifact-exclusion-tests.json'));
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) run();
module.exports = { run };
