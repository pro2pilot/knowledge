#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { LOCK_POLICY } = require('./lib/lock-policy');

function parseArgs(argv) {
  const args = { inventory: null, out: null };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--inventory') args.inventory = argv[++index] || null;
    else if (argv[index].startsWith('--inventory=')) args.inventory = argv[index].slice(12);
    else if (argv[index] === '--out') args.out = argv[++index] || null;
    else if (argv[index].startsWith('--out=')) args.out = argv[index].slice(6);
  }
  if (!args.inventory) throw new Error('--inventory=<LOCK-CONSUMER-INVENTORY.json> is required');
  return args;
}

function equal(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function result(id, expected, actual, pass) { return { id, expected, actual, pass }; }

function main() {
  const args = parseArgs(process.argv.slice(2));
  const document = JSON.parse(fs.readFileSync(path.resolve(args.inventory), 'utf8'));
  const entries = Array.isArray(document.locks) ? document.locks : [];
  const byName = new Map(entries.map((item) => [item.lock_name, item]));
  const policyNames = Object.keys(LOCK_POLICY.locks).sort();
  const results = [];
  results.push(result('all_production_definition_ids_present', policyNames, Array.from(byName.keys()).sort(), policyNames.every((name) => byName.has(name))));
  results.push(result('no_unknown_definition_ids', policyNames, Array.from(byName.keys()).sort(), Array.from(byName.keys()).every((name) => policyNames.includes(name))));
  for (const name of policyNames) {
    const definition = LOCK_POLICY.locks[name];
    const entry = byName.get(name) || {};
    results.push(result(`root_kinds_${name}`, definition.root_kinds, entry.root_kinds || null, equal(definition.root_kinds, entry.root_kinds || [])));
    results.push(result(`consumers_${name}`, [...(definition.consumers || [])].sort(), entry.consumers || null, equal([...(definition.consumers || [])].sort(), entry.consumers || [])));
    const publicRuntime = definition.root_kinds.some((kind) => LOCK_POLICY.root_kinds[kind]?.public === true);
    results.push(result(`installed_runtime_${name}`, publicRuntime, entry.installed_runtime, entry.installed_runtime === publicRuntime));
  }
  results.push(result('production_agent_integrations_name', true, byName.has('agent-integrations') && !byName.has('integration-install'), byName.has('agent-integrations') && !byName.has('integration-install')));
  results.push(result('production_sync_name', true, byName.has('sync') && !byName.has('sync-tracked'), byName.has('sync') && !byName.has('sync-tracked')));
  for (const name of ['apply-template', 'git-hooks', 'ingest']) results.push(result(`project_${name}_inspected`, true, byName.get(name)?.inspected_by_install_check, byName.get(name)?.inspected_by_install_check === true));
  results.push(result('system_only_not_public', false, byName.get('evidence-publication')?.inspected_by_install_check, byName.get('evidence-publication')?.inspected_by_install_check === false && byName.get('evidence-publication')?.installed_runtime === false));
  const report = { schema_version: 'knowledge-lock-consumer-inventory-verification.v1', generated_at: new Date().toISOString(), checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results };
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
  process.stdout.write(text);
  if (report.failed) process.exitCode = 1;
}

if (require.main === module) main();
module.exports = { main };
