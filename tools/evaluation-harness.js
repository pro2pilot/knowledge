#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { ensureDir, readJson, writeJsonAtomic } = require('./lib/json-store');
const { resolveKnowledgeContext, contextEnv } = require('./lib/path-context');
const { inspectSemanticJson, parseJsonOutput } = require('./lib/semantic-json');

const context = resolveKnowledgeContext();
const checks = [
  { name: 'doctor', command: 'tools/doctor.js' },
  { name: 'routing', command: 'tools/build-routing-bundle.js' },
  { name: 'search_index', command: 'tools/build-search-index.js' },
  { name: 'wiki_graph', command: 'tools/build-wiki-graph.js' },
  { name: 'wiki_lint', command: 'tools/lint-wiki.js' },
  { name: 'external_memory', command: 'tools/external-memory-status.js' },
  { name: 'metrics', command: 'tools/collect-metrics.js' },
  { name: 'pr_summary', command: 'tools/generate-pr-summary.js' },
  { name: 'flow_graph', command: 'tools/render-graph-execution.js' },
  { name: 'visual_inspector', command: 'tools/build-visual-inspector.js' },
  { name: 'templates_list', command: 'tools/apply-template.js --list' }
];

function run(spec) {
  const started = Date.now();
  const parts = spec.command.split(/\s+/);
  const file = parts.shift();
  const args = parts;
  const r = spawnSync(process.execPath, [path.join(context.systemRoot, file), ...args], {
    cwd: context.targetRoot,
    encoding: 'utf8',
    env: contextEnv(context),
    windowsHide: true
  });
  let parsed = null;
  const semanticErrors = [];
  try { parsed = parseJsonOutput(r.stdout); }
  catch (error) { semanticErrors.push(`invalid JSON stdout: ${error.message}`); }
  if (parsed) semanticErrors.push(...inspectSemanticJson(parsed).errors);
  if (r.status !== 0) semanticErrors.push(`exit code ${r.status}`);
  return {
    name: spec.name,
    status: semanticErrors.length === 0 ? 'pass' : 'fail',
    exit_code: r.status,
    duration_ms: Date.now() - started,
    json_status: parsed?.status || null,
    semantic_errors: semanticErrors,
    stderr: (r.stderr || r.error?.message || '').slice(0, 1000)
  };
}

function percentile(values, ratio) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  return sorted[Math.floor((sorted.length - 1) * ratio)];
}

function main() {
  const outDir = path.join(context.stateRoot, 'evaluation', 'results');
  ensureDir(outDir);
  const results = checks.map(run);
  const failed = results.filter((result) => result.status === 'fail');
  const score = Math.round(results.filter((r) => r.status === 'pass').length / results.length * 100);
  const metrics = readJson(path.join(context.stateRoot, 'metrics', 'baseline.json'), {});
  const quality = readJson(path.join(context.stateRoot, 'maintenance', 'quality_report.json'), {});
  const durations = results.map((result) => result.duration_ms);
  const report = {
    schema_version: '3.2.11',
    generated_at: new Date().toISOString(),
    mode: context.mode,
    score,
    status: failed.length === 0 ? 'release_candidate' : score >= 75 ? 'usable_with_warnings' : 'needs_repair',
    failed_count: failed.length,
    unexpected_semantic_failure_count: failed.length,
    performance: {
      total_duration_ms: durations.reduce((sum, value) => sum + value, 0),
      p50_ms: percentile(durations, 0.5),
      p95_ms: percentile(durations, 0.95)
    },
    context_economy: {
      token_estimator: metrics.token_estimator || null,
      routing_bundle_tokens_approx: metrics.routing?.bundle_tokens_approx ?? null,
      legacy_first_read_tokens_approx: metrics.routing?.legacy_first_read_tokens_approx ?? null,
      estimated_token_delta: metrics.routing?.estimated_token_delta ?? null,
      estimated_percent_delta: metrics.routing?.estimated_percent_delta ?? null,
      estimated_tokens_saved: metrics.routing?.estimated_tokens_saved ?? null,
      estimated_percent_saved: metrics.routing?.estimated_percent_saved ?? null,
      assessment: metrics.routing?.assessment || null
    },
    trust_layer: {
      doctor_status: quality.status || null,
      doctor_score: quality.quality_score ?? null,
      routing_status: results.find((result) => result.name === 'routing')?.status || null,
      search_status: results.find((result) => result.name === 'search_index')?.status || null,
      wiki_status: results.find((result) => result.name === 'wiki_lint')?.status || null
    },
    results
  };
  writeJsonAtomic(path.join(outDir, 'latest.json'), report);
  console.log(JSON.stringify(report, null, 2));
  return report;
}

if (require.main === module) main();
module.exports = main;
