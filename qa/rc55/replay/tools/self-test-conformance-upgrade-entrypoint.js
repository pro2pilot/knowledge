#!/usr/bin/env node
'use strict';

const path = require('path');
const { upgradeApplyInvocation } = require('./conformance-install-smoke');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const candidate = path.resolve('candidate', '.knowledge');
  const target = path.resolve('public-3.2.11-fixture');
  const invocation = upgradeApplyInvocation(candidate, target);
  const expectedUpdater = path.join(candidate, 'tools', 'update-system-files.js');
  const expectedTarget = path.join(target, '.knowledge');
  assert(invocation.file === process.execPath, 'upgrade must execute with the active Node runtime');
  assert(invocation.args[0] === expectedUpdater, 'upgrade did not bootstrap the updater from the new candidate');
  assert(invocation.args.includes('--target-knowledge-root'), 'upgrade omitted the explicit target boundary');
  assert(invocation.args[invocation.args.indexOf('--target-knowledge-root') + 1] === expectedTarget, 'upgrade target is not the installed public baseline');
  assert(invocation.args[invocation.args.indexOf('--from') + 1] === candidate, 'upgrade source is not the exact new candidate');
  assert(!invocation.args.includes('.knowledge/tools/update-system-files.js'), 'upgrade fell back to the legacy installed updater');
  const report = {
    schema_version: 'conformance-upgrade-entrypoint-self-test.v1',
    status: 'pass',
    checks_total: 6,
    checks: [
      'active Node runtime retained',
      'new candidate updater selected',
      'explicit target boundary present',
      'public baseline target selected',
      'exact candidate source selected',
      'legacy installed updater fallback absent'
    ]
  };
  console.log(JSON.stringify(report, null, 2));
  return report;
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = main;
