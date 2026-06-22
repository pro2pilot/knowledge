#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, contextEnv } = require('./lib/path-context');
const { ensureDir, readJson, writeJsonAtomic } = require('./lib/json-store');

const SAFE_STEPS = [
  ['sync', ['tools/sync-tracked.js', '--scan']],
  ['wiki_graph', ['tools/build-wiki-graph.js']],
  ['wiki_lint', ['tools/lint-wiki.js']],
  ['external_memory', ['tools/external-memory-status.js', '--json']],
  ['routing', ['tools/build-routing-bundle.js']],
  ['search', ['tools/build-search-index.js']],
  ['inspector', ['tools/build-visual-inspector.js', '--json']],
  ['secret_scan', ['tools/scan-secrets.js', '--json']],
  ['doctor', ['tools/doctor.js', '--json']]
];

function runStep(context, [name, command]) {
  const started = Date.now();
  const script = path.join(context.projectKnowledgeRoot, command[0]);
  const result = spawnSync(process.execPath, [script, ...command.slice(1)], {
    cwd: context.targetRoot,
    env: contextEnv(context),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 240000
  });
  return {
    name,
    command: ['node', ...command].join(' '),
    status: result.status === 0 ? 'passed' : 'failed',
    exit_code: result.status,
    duration_ms: Date.now() - started,
    stdout_tail: String(result.stdout || '').slice(-1600),
    stderr_tail: String(result.stderr || '').slice(-1600)
  };
}

function renderPlainReport(context, steps) {
  const maintenance = path.join(context.stateRoot, 'maintenance');
  const trust = readJson(path.join(maintenance, 'trust_report.json'), {});
  const stale = readJson(path.join(maintenance, 'stale_items.json'), { items: [] });
  const repair = readJson(path.join(maintenance, 'repair_queue.json'), { queue: [] });
  const failed = steps.filter((step) => step.status !== 'passed');
  return `# Restore Trust Report

Status: ${failed.length ? 'failed' : 'passed'}

What I checked:
- Health, routing, search, wiki graph, freshness and generated Inspector artifacts.
- External memory policy remains advisory-only.
- Repair queue and stale item reports were refreshed from local files.

What changed:
- Generated .knowledge reports were rebuilt.
- No source code files were intentionally changed.
- No branches were merged.

Current state:
- Trust status: ${trust.status || 'unknown'}
- Stale items: ${(stale.items || stale.stale_items || []).length}
- Repair items: ${(repair.queue || repair.items || []).length}

Next step:
${failed.length ? '- Review failed command output in maintenance/restore-trust-report.json.' : '- Review the Inspector or run PR Impact before merging source changes.'}
`;
}

function main(argv = process.argv.slice(2)) {
  const parsed = parseCliArgs(argv);
  if (!parsed.flags.safe) throw new Error('Restore Trust requires --safe.');
  const context = resolveKnowledgeContext(parsed.flags);
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  const steps = SAFE_STEPS.map((step) => runStep(context, step));
  const report = {
    schema_version: '3.2.0',
    generated_at: new Date().toISOString(),
    safe: true,
    status: steps.every((step) => step.status === 'passed') ? 'passed' : 'failed',
    source_code_changed: false,
    merged_branches: false,
    raised_trust_without_evidence: false,
    steps
  };
  writeJsonAtomic(path.join(context.stateRoot, 'maintenance', 'restore-trust-report.json'), report);
  fs.writeFileSync(path.join(context.stateRoot, 'maintenance', 'restore-trust-report.md'), renderPlainReport(context, steps), 'utf8');
  if (parsed.flags.json) console.log(JSON.stringify(report, null, 2));
  else console.log(`restore trust ${report.status}`);
  if (report.status !== 'passed') process.exit(2);
  return report;
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.stack || error.message); process.exit(1); }
}

module.exports = { main };
