#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const { parseCliArgs, resolveKnowledgeContext } = require('./lib/path-context');
const routing = require('./lib/task-routing');
const { resolveEffectiveTaskRoutingState, formatTaskRoutingEstimate } = require('./lib/task-routing-state');

function input(flags) { return { task: flags.task, taskClass: flags.taskClass, modules: flags.scopeModule, paths: flags.scopePath, excludeModules: flags.excludeModule, excludePaths: flags.excludePath, scopeSource: flags.scopeSource, constraints: flags.constraint }; }
function fail(message) { const error = new Error(message); error.code = 'task_routing_invalid'; throw error; }
function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv); const flags = parsed.flags; const command = parsed.positional[0] || 'status'; const context = resolveKnowledgeContext(flags);
  let result;
  if (flags.help || command === 'help' || command === '--help') {
    result = {
      status: 'ok',
      usage: 'task-routing <create|refresh|baseline|format|reconcile|list|status|inspect|invalidate|prune> [--task=<text>] [--task-id=<sha256>] [--scope-module=<id>] [--scope-path=<path>] [--json]',
      notes: [
        'Explicit module/path scope is a hard boundary; only direct dependencies may be added.',
        'refresh --task-id reuses the persisted immutable scope contract.',
        'invalidate accepts only canonical 64-character SHA-256 task IDs.'
      ]
    };
  }
  else if (command === 'create' || command === 'refresh') {
    if (command === 'refresh' && flags.all) result = routing.refreshAll(context);
    else if (command === 'refresh' && flags.taskId) result = routing.refreshTask(context, String(flags.taskId));
    else { if (!flags.task) fail('--task is required for create; refresh requires --task-id or --all'); result = routing.create(context, input(flags)); }
  } else if (command === 'baseline') {
    if (!flags.taskId) fail('--task-id is required for baseline');
    result = routing.baselineTask(context, String(flags.taskId), { customBaseline: flags.customBaseline });
  } else if (command === 'format') {
    if (!flags.metrics || !flags.state) fail('--metrics and --state JSON files are required for diagnostic formatting');
    const readDiagnostic = (file) => JSON.parse(fs.readFileSync(path.resolve(String(file)), 'utf8').replace(/^\uFEFF/, ''));
    const metrics = readDiagnostic(flags.metrics);
    const state = readDiagnostic(flags.state);
    result = {
      status: 'diagnostic',
      schema_version: 'knowledge-workspace-narrowing-public-format-diagnostic.v1',
      claim_authority: false,
      public_text: formatTaskRoutingEstimate(metrics, state)
    };
  } else if (command === 'reconcile') result = flags.taskId ? routing.inspectTask(context, String(flags.taskId)) : routing.reconcileAll(context);
  else if (command === 'list') { const reconciliation = routing.reconcileAll(context); result = { status: 'ok', tasks: routing.listTasks(context), index_reconciled: true, reconciliation }; }
  else if (command === 'status' || command === 'inspect') {
    const task = (flags.taskId || '').trim();
    if (task) result = resolveEffectiveTaskRoutingState({ context, taskScopeHash: task, verifyLiveInputs: true });
    else {
      const manifests = routing.listTasks(context);
      const manifest = manifests.find((item) => item.scope?.task === flags.task) || null;
      result = manifest ? routing.inspectTask(context, manifest.task_scope_hash) : { status: 'not_found', task: null };
    }
  } else if (command === 'invalidate') {
    const task = flags.taskId; if (!task) fail('--task-id is required'); result = routing.invalidate(context, String(task), flags.reason || 'manual');
  } else if (command === 'prune') result = { status: 'ok', pruned: 0, note: 'Immutable task snapshots are retained; prune is intentionally non-destructive.' };
  else fail(`Unknown task-routing command: ${command}`);
  if (flags.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n'); else if (!flags.quiet) console.log(JSON.stringify(result, null, 2)); return result;
}
if (require.main === module) { try { main(); } catch (error) { const json = process.argv.includes('--json'); if (json) process.stdout.write(JSON.stringify({ status: 'failed', error: { code: error.code || 'task_routing_failed', message: error.message } }) + '\n'); else console.error(error.stack || error.message); process.exitCode = 2; } }
module.exports = main;
