#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { validateReport } = require('./verify-evidence-report-contract');

function parseArgs(argv) { const args = { out: null }; for (let index = 0; index < argv.length; index += 1) { if (argv[index] === '--out') args.out = argv[++index] || null; else if (argv[index].startsWith('--out=')) args.out = argv[index].slice(6); } return args; }
function sample(overrides = {}) { return { status: 'pass', checks_total: 1, passed: 1, failed: 0, results: [{ id: 'one', expected: { value: true }, actual: { value: true }, pass: true }], ...overrides }; }
function main() {
  const args = parseArgs(process.argv.slice(2));
  const checks = [
    ['valid_report', [], validateReport(sample())],
    ['checks_total_matches_result_list', ['checks_total_mismatch', 'passed_failed_mismatch'], validateReport(sample({ checks_total: 2 }))],
    ['passed_failed_matches_total', ['passed_failed_mismatch'], validateReport(sample({ passed: 0, failed: 0 }))],
    ['result_ids_unique', ['result_id_duplicate'], validateReport(sample({ checks_total: 2, passed: 2, results: [sample().results[0], sample().results[0]] }))],
    ['result_has_expected_and_actual', ['result_expected_missing', 'result_actual_missing'], validateReport(sample({ results: [{ id: 'one', pass: true }] }))],
    ['expected_failure_is_unambiguous', [], validateReport(sample({ status: 'expected_failure', expectation_met: true, results: [{ id: 'negative', expected: { failure: true }, actual: { failure: true }, expectation_met: true }] }))]
  ];
  const results = checks.map(([id, expected, actual]) => ({ id, expected, actual, pass: JSON.stringify(expected) === JSON.stringify(actual) }));
  const report = { schema_version: 'knowledge-evidence-report-contract-self-test.v1', generated_at: new Date().toISOString(), checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results };
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
  process.stdout.write(text);
  if (report.failed) process.exitCode = 1;
}
if (require.main === module) main();
module.exports = { main };
