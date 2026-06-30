#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, writeJsonAtomic } = require('./lib/json-store');
const { resolveKnowledgeContext, contextEnv } = require('./lib/path-context');

const context = resolveKnowledgeContext();
const checks = [
  ['doctor', 'tools/doctor.js'],
  ['routing', 'tools/build-routing-bundle.js'],
  ['search_index', 'tools/build-search-index.js'],
  ['wiki_graph', 'tools/build-wiki-graph.js'],
  ['wiki_lint', 'tools/lint-wiki.js'],
  ['external_memory', 'tools/external-memory-status.js'],
  ['metrics', 'tools/collect-metrics.js'],
  ['pr_summary', 'tools/generate-pr-summary.js'],
  ['flow_graph', 'tools/render-graph-execution.js'],
  ['visual_inspector', 'tools/build-visual-inspector.js'],
  ['templates_list', 'tools/apply-template.js --list']
];

function run(rel) {
  const started = Date.now();
  const parts = rel.split(/\s+/);
  const file = parts.shift();
  const args = parts;
  if (!args.includes('--quiet')) args.push('--quiet');
  const r = spawnSync(process.execPath, [path.join(context.systemRoot, file), ...args], {
    cwd: context.targetRoot,
    encoding: 'utf8',
    env: contextEnv(context),
    windowsHide: true
  });
  return {
    status: r.status === 0 ? 'pass' : 'fail',
    duration_ms: Date.now() - started,
    stderr: (r.stderr || '').slice(0, 1000)
  };
}

function main() {
  const outDir = path.join(context.stateRoot, 'evaluation', 'results');
  ensureDir(outDir);
  const results = checks.map(([name, rel]) => ({ name, ...run(rel) }));
  const score = Math.round(results.filter((r) => r.status === 'pass').length / results.length * 100);
  const report = {
    schema_version: '3.2.4',
    generated_at: new Date().toISOString(),
    mode: context.mode,
    score,
    status: score >= 90 ? 'release_candidate' : score >= 75 ? 'usable_with_warnings' : 'needs_repair',
    results
  };
  writeJsonAtomic(path.join(outDir, 'latest.json'), report);
  console.log(JSON.stringify(report, null, 2));
  return report;
}

if (require.main === module) main();
module.exports = main;

