#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { readJson, writeJsonAtomicContained, ensurePhysicalRoot, ensureContainedDir, assertSafeContainedFile, sleepSync } = require('./lib/json-store');
const { resolveKnowledgeContext, contextEnv } = require('./lib/path-context');
const { inspectSemanticJson, parseJsonOutput, MAX_CHILD_JSON_BYTES } = require('./lib/semantic-json');
const { systemVersion } = require('./lib/system-version');
const owned = require('./lib/command-runner');
const { readReportJson } = require('./lib/report-generation');
const { parseCliArgs } = require('./lib/path-context');

let cachedContext;
function getContext() { return cachedContext || (cachedContext = resolveKnowledgeContext()); }
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

function runSynthetic(spec, hooks = {}) {
  const context = getContext();
  const started = process.hrtime.bigint();
  const parts = spec.command.split(/\s+/);
  const file = parts.shift();
  const args = parts;
  const spawnImpl = hooks.spawnSync || spawnSync;
  const wait = hooks.sleepSync || sleepSync;
  let r = null;
  let attempts = 0;
  let emptyExitRetries = 0;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    attempts = attempt;
    r = spawnImpl(process.execPath, [path.join(context.systemRoot, file), ...args], {
      cwd: context.targetRoot,
      encoding: 'utf8',
      env: contextEnv(context),
      maxBuffer: MAX_CHILD_JSON_BYTES,
      windowsHide: true
    });
    const unexplainedEmptyExit = r.status === 1 && r.signal === null && !r.error &&
      String(r.stdout || '') === '' && String(r.stderr || '') === '';
    if (!unexplainedEmptyExit) break;
    emptyExitRetries += 1;
    if (attempt < 3) wait(50 * attempt);
  }
  return resultFor(spec, r, attempts, emptyExitRetries, Math.round(Number(process.hrtime.bigint() - started) / 1e6));
}

function resultFor(spec, r, attempts, emptyExitRetries, duration_ms) {
  const persistentEmptyExit = emptyExitRetries === 3;
  let parsed = null;
  const semanticErrors = [];
  try { parsed = parseJsonOutput(r.stdout); }
  catch (error) { semanticErrors.push(`invalid JSON stdout: ${error.message}`); }
  if (parsed) semanticErrors.push(...inspectSemanticJson(parsed).errors);
  if (r.status !== 0) semanticErrors.push(`exit code ${r.status}`);
  if (r.error) semanticErrors.push(`spawn error ${r.error.code || 'unknown'}`);
  if (r.signal) semanticErrors.push(`child signal ${r.signal}`);
  if (persistentEmptyExit) semanticErrors.push(`child exited 1 without output after ${attempts} attempts`);
  return {
    name: spec.name,
    status: semanticErrors.length === 0 ? 'pass' : 'fail',
    exit_code: r.status,
    duration_ms,
    json_status: parsed?.status || null,
    semantic_errors: semanticErrors,
    failure_code: persistentEmptyExit ? 'child_empty_exit_persistent'
      : r.error ? 'child_spawn_error' : r.signal ? 'child_signal' : null,
    attempts,
    empty_exit_retries: emptyExitRetries,
    stderr: (r.stderr || r.error?.message || '').slice(0, 1000)
  };
}

function run(spec, hooks = {}) {
  if (typeof hooks.spawnSync === 'function') return runSynthetic(spec, hooks);
  return owned.runOwnedOperationSync('evaluation-check', { spec }, hooks);
}
async function runCheckAsync(spec, options = {}) {
  return (await owned.runOwnedOperation('evaluation-check', { spec }, options)).value;
}
async function runCheckWorker(spec, runtime = {}) {
  const context = getContext(), policy = owned.budgets(runtime.budgets);
  const deadline = runtime.workDeadline ?? owned.mono() + policy.workMs;
  const [file, ...args] = spec.command.split(/\s+/);
  const command = { executable: process.execPath, args: [path.join(context.systemRoot, file), ...args],
    cwd: context.targetRoot, env: contextEnv(context), nestedAuthority: ['flow.js', 'evaluation-harness.js'].includes(path.basename(file)) };
  const start = owned.mono(); let r, attempts = 0, emptyExitRetries = 0;
  runtime.onProgress?.('step_admitted', spec.name);
  for (let attempt = 1; attempt <= 3; attempt++) {
    const remaining = Math.floor(deadline - owned.mono());
    if (remaining < 1 || runtime.signal?.aborted) throw owned.deadlineError(runtime.signal);
    attempts = attempt;
    r = runtime.session ? await runtime.session.run(command) : await owned.runOwnedCommand(command, { ...runtime, budgets: { ...policy, workMs: remaining, progressMs: 0 } });
    if (r.cleanup?.status !== 'completed') throw Object.assign(new Error('Command descendants were not confirmed stopped'), { code: 'command_cleanup_unconfirmed', cleanup: r.cleanup });
    if (['command_cancelled', 'command_work_timeout', 'command_progress_timeout'].includes(r.error?.code)) throw Object.assign(new Error(r.error.message), r.error, { cleanup: r.cleanup });
    const unexplained = r.status === 1 && !r.signal && !r.error && r.stdout === '' && r.stderr === '';
    if (!unexplained) break;
    emptyExitRetries++;
    if (attempt < 3) {
      const pause = 50 * attempt;
      if (deadline - owned.mono() <= pause) throw owned.deadlineError(runtime.signal);
      await owned.delay(pause, runtime.signal);
    }
  }
  runtime.onProgress?.('step_completed', spec.name);
  const result = resultFor(spec, r, attempts, emptyExitRetries, Math.round(owned.mono() - start));
  if (r.error?.code?.startsWith('command_')) result.failure_code = r.error.code;
  result.cleanup = r.cleanup;
  return result;
}

function percentile(values, ratio) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  return sorted[Math.floor((sorted.length - 1) * ratio)];
}

function exitCodeForReport(report) {
  const failedCount = Number(report?.failed_count || 0);
  const hasFailedCheck = Array.isArray(report?.results) && report.results.some((result) => result?.status === 'fail');
  return report?.status === 'release_candidate' && failedCount === 0 && !hasFailedCheck ? 0 : 2;
}

async function mainWorker(runtime = {}) {
  const context = getContext();
  const outDir = path.join(context.stateRoot, 'evaluation', 'results');
  const outputRoot = ensurePhysicalRoot(context.stateRoot);
  ensureContainedDir(outputRoot, outDir);
  const outPath = path.join(outDir, 'latest.json');
  // Refuse unsafe publication before invoking checks with their own effects.
  assertSafeContainedFile(outputRoot, outPath, { allowMissing: true });
  const workDeadline = owned.mono() + owned.budgets(runtime.budgets).workMs;
  const session = await owned.createCommandSession(runtime);
  const results = [];
  let failure;
  try {
    for (const spec of checks) results.push(await runCheckWorker(spec, { ...runtime, session, workDeadline }));
  } catch (error) { failure = error; }
  const cleanup = await session.drain();
  const keeperCleanup = await session.finish();
  if (cleanup.status !== 'completed' || keeperCleanup.status !== 'completed') throw Object.assign(new Error('Evaluation command cleanup was not confirmed'), { code: 'command_cleanup_unconfirmed', cleanup });
  if (failure) throw failure;
  const failed = results.filter((result) => result.status === 'fail');
  const score = Math.round(results.filter((r) => r.status === 'pass').length / results.length * 100);
  const metrics = readReportJson(context.stateRoot, 'metrics', 'baseline.json', {});
  const quality = readJson(path.join(context.stateRoot, 'maintenance', 'quality_report.json'), {});
  const durations = results.map((result) => result.duration_ms);
  const report = {
    schema_version: systemVersion(),
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
    results,
    command_cleanup: cleanup,
    command_authority_cleanup: keeperCleanup
  };
  writeJsonAtomicContained(outPath, report, outputRoot);
  return report;
}

function main(options = {}) {
  const report = owned.runOwnedOperationSync('evaluation-main', {}, options);
  console.log(JSON.stringify(report, null, 2));
  return report;
}
async function mainAsync(options = {}) {
  return (await owned.runOwnedOperation('evaluation-main', {}, options)).value;
}
async function cli(runtime = {}) {
  const controller = new AbortController(), cancel = () => controller.abort();
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  try {
    const report = await mainAsync({ ...runtime, signal: controller.signal, budgets: runtime.budgets || owned.cliBudgets(parseCliArgs().flags) });
    console.log(JSON.stringify(report, null, 2)); process.exitCode = exitCodeForReport(report);
  } catch (error) {
    console.log(JSON.stringify({ status: 'failed', failure_code: error.code || 'evaluation_failed',
      error: { code: error.code || 'evaluation_failed', message: error.message }, cleanup: error.cleanup || null }, null, 2));
    process.exitCode = 2;
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
if (require.main === module) cli();
module.exports = main;
module.exports.mainAsync = mainAsync;
module.exports.exitCodeForReport = exitCodeForReport;
module.exports.runCheck = run;
module.exports.runCheckAsync = runCheckAsync;
module.exports.__owned = { main: mainWorker, runCheck: runCheckWorker, cli };
