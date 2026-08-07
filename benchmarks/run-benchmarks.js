#!/usr/bin/env node
'use strict';

// Maintainer/source-only benchmark entrypoint. It deliberately has no dependency
// on tools/package-release.js and is excluded from installed runtime artifacts.

function gate00Result(report = {}) {
  const canonicalPass = report && report.status === 'pass' && Array.isArray(report.steps);
  return {
    schema_version: 'knowledge-benchmark-gate.v1',
    gate_id: 'GATE-00',
    status: canonicalPass ? 'pass' : 'diagnostic',
    metrics: {
      release_gate_passed: canonicalPass ? 1 : 0,
      release_gate_steps: Array.isArray(report.steps) ? report.steps.length : 0
    },
    source_status: report?.status ?? null
  };
}

function main() {
  if (process.argv.includes('--help')) {
    process.stdout.write('Usage: node benchmarks/run-benchmarks.js --gate-report=<path>\n');
    return;
  }
  const arg = process.argv.find((value) => value.startsWith('--gate-report='));
  if (!arg) {
    process.stdout.write(`${JSON.stringify(gate00Result({ status: 'unavailable', steps: [] }), null, 2)}\n`);
    return;
  }
  const fs = require('fs');
  const path = require('path');
  const file = path.resolve(arg.slice('--gate-report='.length));
  const report = JSON.parse(fs.readFileSync(file, 'utf8'));
  const result = gate00Result(report);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.status !== 'pass') process.exitCode = 2;
}

if (require.main === module) main();
module.exports = { gate00Result };
