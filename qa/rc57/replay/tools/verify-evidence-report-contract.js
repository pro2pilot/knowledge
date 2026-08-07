#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = { root: null, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--root') args.root = argv[++index] || null;
    else if (argv[index].startsWith('--root=')) args.root = argv[index].slice(7);
    else if (argv[index] === '--out') args.out = argv[++index] || null;
    else if (argv[index].startsWith('--out=')) args.out = argv[index].slice(6);
  }
  if (!args.root) throw new Error('--root=<evidence directory> is required');
  return args;
}

function listJson(root, output = []) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) listJson(target, output);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith('.json')) output.push(target);
  }
  return output;
}

function reportResult(filePath, root, pass, expected, actual) {
  return { id: path.relative(root, filePath).replace(/\\/g, '/'), expected, actual, pass };
}

function validateReport(value) {
  const failures = [];
  if (!Array.isArray(value.results)) failures.push('results_not_array');
  if (!Number.isInteger(value.checks_total) || value.checks_total < 0) failures.push('checks_total_invalid');
  if (Array.isArray(value.results) && value.checks_total !== value.results.length) failures.push('checks_total_mismatch');
  if (Number.isInteger(value.passed) && Number.isInteger(value.failed) && value.passed + value.failed !== value.checks_total) failures.push('passed_failed_mismatch');
  if (Array.isArray(value.results)) {
    const ids = new Set();
    for (const item of value.results) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) { failures.push('result_not_object'); continue; }
      if (typeof item.id !== 'string' || !item.id) failures.push('result_id_missing');
      else if (ids.has(item.id)) failures.push('result_id_duplicate');
      else ids.add(item.id);
      if (!Object.prototype.hasOwnProperty.call(item, 'expected')) failures.push('result_expected_missing');
      if (!Object.prototype.hasOwnProperty.call(item, 'actual') && !Object.prototype.hasOwnProperty.call(item, 'observed')) failures.push('result_actual_missing');
      if (typeof item.pass !== 'boolean' && typeof item.expectation_met !== 'boolean') failures.push('result_outcome_missing');
    }
    const outcomes = value.results.map((item) => item.pass === true || item.expectation_met === true);
    if (value.status === 'pass' && outcomes.some((item) => !item)) failures.push('pass_status_inconsistent');
    if (value.status === 'expected_failure' && (value.expectation_met !== true || outcomes.some((item) => !item))) failures.push('expected_failure_status_inconsistent');
    if (value.status === 'fail' && outcomes.every(Boolean) && value.results.length) failures.push('fail_status_inconsistent');
  }
  return Array.from(new Set(failures));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = path.resolve(args.root);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error('evidence root must be an existing directory');
  const results = [];
  for (const filePath of listJson(root).sort()) {
    let value;
    try { value = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
    catch (error) { results.push(reportResult(filePath, root, false, 'valid_json', error.message)); continue; }
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.prototype.hasOwnProperty.call(value, 'checks_total') || !Object.prototype.hasOwnProperty.call(value, 'results')) continue;
    const violations = validateReport(value);
    results.push(reportResult(filePath, root, violations.length === 0, 'report_contract_valid', { violations }));
  }
  const report = {
    schema_version: 'knowledge-evidence-report-contract.v1',
    generated_at: new Date().toISOString(),
    root,
    checks_total: results.length,
    passed: results.filter((item) => item.pass).length,
    failed: results.filter((item) => !item.pass).length,
    status: results.every((item) => item.pass) ? 'pass' : 'fail',
    results
  };
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
  process.stdout.write(text);
  if (report.failed) process.exitCode = 1;
}

if (require.main === module) main();
module.exports = { validateReport, main };
