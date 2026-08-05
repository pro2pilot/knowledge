#!/usr/bin/env node
'use strict';

// Output modes:
//   default    one line per step ("[ ok ] step  Xms")
//   --quiet    final summary only
//   --json     single well-formed JSON object (never ANSI)
//   --no-color disable ANSI escape sequences in all modes
//
// In repo-local mode runtime logs stay under `.knowledge/maintenance/flow-logs`.
// In team mode runtime logs move to `stateRoot/maintenance/flow-logs`.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { isDeepStrictEqual } = require('util');
const { spawnSync, spawn } = require('child_process');
const { parseCliArgs, resolveKnowledgeContext, contextEnv, jsonContext } = require('./lib/path-context');
const { ensureDir, writeJsonAtomic, sleepSync } = require('./lib/json-store');
const { acquireTeamLock, appendTeamEvent, updateWorkspaceFlow } = require('./lib/team-store');
const { inspectSemanticJson } = require('./lib/semantic-json');

const flows = {
  scan: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  doctor: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'scan-secrets.js', 'doctor.js'],
  lint: ['build-wiki-graph.js', 'lint-wiki.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  import: ['install-check.js --json', 'ingest-existing-project.js --merge', 'sync-tracked.js --scan --discover', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'build-visual-inspector.js', 'scan-secrets.js', 'doctor.js'],
  // Task snapshots must be last among routing-input producers. Consumers then
  // observe the finalized route, not an intermediate release state.
  release: ['sync-tracked.js --scan', 'build-wiki-graph.js', 'lint-wiki.js', 'external-memory-status.js', 'build-routing-bundle.js', 'build-search-index.js', 'scan-secrets.js', 'doctor.js', 'task-routing.js refresh --all --quiet', 'build-visual-inspector.js', 'collect-metrics.js', 'generate-pr-summary.js', 'render-graph-execution.js', 'evaluation-harness.js']
};

const STEP_LABELS = {
  'sync-tracked.js': 'sync',
  'build-wiki-graph.js': 'wiki-graph',
  'lint-wiki.js': 'lint',
  'external-memory-status.js': 'ext-memory',
  'check-updates.js': 'updates',
  'build-routing-bundle.js': 'routing',
  'task-routing.js': 'task-routing',
  'build-search-index.js': 'search-idx',
  'build-visual-inspector.js': 'inspector',
  'scan-secrets.js': 'secret-scan',
  'doctor.js': 'doctor',
  'collect-metrics.js': 'metrics',
  'generate-pr-summary.js': 'pr-summary',
  'render-graph-execution.js': 'graphs',
  'evaluation-harness.js': 'harness',
  'install-check.js': 'install-check',
  'ingest-existing-project.js': 'ingest'
};

function parseArgs(argv) {
  const parsed = parseCliArgs(argv);
  const flags = parsed.flags;
  const name = parsed.positional[0] || 'release';
  return {
    name,
    quiet: Boolean(flags.quiet),
    json: Boolean(flags.json),
    noColor: Boolean(flags.noColor),
    exclusive: Boolean(flags.exclusive),
    contextFlags: flags
  };
}

function colorEnabled({ json, noColor }) {
  if (json) return false;
  if (noColor) return false;
  if (process.env.NO_COLOR) return false;
  if (!process.stdout.isTTY) return false;
  return true;
}

function updateChecksEnabled(context) {
  const configPath = path.join(context.projectKnowledgeRoot, 'config.yaml');
  if (!fs.existsSync(configPath)) return false;
  const lines = fs.readFileSync(configPath, 'utf8').split(/\r?\n/);
  let inUpdates = false;
  for (const line of lines) {
    if (/^updates:\s*$/.test(line)) { inUpdates = true; continue; }
    if (inUpdates && /^\S/.test(line) && line.trim()) return false;
    if (inUpdates && /^\s{2}enabled:\s*true\s*$/.test(line)) return true;
  }
  return false;
}

function stepsForFlow(name, context) {
  const base = flows[name] || [];
  if (!updateChecksEnabled(context)) return base;
  const updateStep = 'check-updates.js --auto --json';
  if (base.includes(updateStep)) return base;
  const doctorIndex = base.findIndex((cmd) => cmd.startsWith('doctor.js'));
  if (doctorIndex === -1) return [...base, updateStep];
  return [...base.slice(0, doctorIndex), updateStep, ...base.slice(doctorIndex)];
}

function runOne(cmd, context, hooks = {}) {
  const [file, ...args] = cmd.split(/\s+/);
  const scriptPath = path.join(context.systemRoot, 'tools', file);
  const started = Date.now();
  const spawnImpl = hooks.spawnSync || spawnSync;
  const wait = hooks.sleepSync || sleepSync;
  let res = null;
  let attempts = 0;
  let emptyExitRetries = 0;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    attempts = attempt;
    res = spawnImpl(process.execPath, [scriptPath, ...args], {
      cwd: context.targetRoot,
      env: contextEnv(context),
      windowsHide: true
    });
    const unexplainedEmptyExit = res.status === 1 &&
      res.signal === null && !res.error &&
      String(res.stdout || '') === '' &&
      String(res.stderr || '') === '';
    if (!unexplainedEmptyExit) break;
    emptyExitRetries += 1;
    if (attempt < 3) wait(50 * attempt);
  }
  const duration_ms = Date.now() - started;
  const stdout = (res.stdout || '').toString();
  const persistentEmptyExit = emptyExitRetries === 3;
  const stderr = persistentEmptyExit
    ? `Child exited 1 without stdout, stderr, signal, or spawn error after ${attempts} attempts.`
    : (res.stderr || '').toString();
  let parsed = null;
  if (stdout.trim()) {
    try { parsed = JSON.parse(stdout.trim().replace(/^\uFEFF/, '')); } catch { parsed = null; }
  }
  const semantic = parsed ? inspectSemanticJson(parsed) : { ok: true, errors: [] };
  const success = res.status === 0 && semantic.ok;
  return {
    step: STEP_LABELS[file] || file.replace(/\.js$/, ''),
    command: `${file}${args.length ? ' ' + args.join(' ') : ''}`,
    exit: res.status,
    success,
    status: success ? 'pass' : 'fail',
    json_status: parsed?.status || null,
    semantic_errors: semantic.errors,
    failure_code: persistentEmptyExit ? 'child_empty_exit_persistent' : null,
    attempts,
    empty_exit_retries: emptyExitRetries,
    duration_ms,
    parsed,
    stdout: stdout.trim().slice(0, 4000),
    stderr: stderr.trim().slice(0, 2000)
  };
}

function detailFor(step) {
  const p = step.parsed;
  if (!p) return '';
  if (step.step === 'doctor') return `${p.quality_score ?? '-'} /100 ${p.status ?? ''}`;
  if (step.step === 'lint') return `${p.quality_score ?? '-'} /100 ${p.status ?? ''}`;
  if (step.step === 'wiki-graph') return `${p.nodes ?? '-'} nodes / ${p.edges ?? '-'} edges`;
  if (step.step === 'search-idx') return `${p.documents ?? p.document_count ?? '-'} docs`;
  if (step.step === 'routing') return `${p.modules ?? '-'} modules`;
  if (step.step === 'inspector') return `${(p.output || '').replace(/^.*\//, '')}`;
  if (step.step === 'secret-scan') return `${p.status || 'unknown'} / ${(p.findings || []).length} findings`;
  if (step.step === 'ext-memory') return `${p.providers?.pinecone?.mode ?? p.providers?.[0]?.mode ?? 'disabled'}`;
  if (step.step === 'metrics') return p.routing?.assessment === 'estimated_overhead'
    ? `${p.routing?.estimated_percent_overhead ?? '-'}% estimated overhead`
    : p.routing?.assessment === 'not_comparable'
      ? 'routing scopes not comparable'
      : `${p.routing?.estimated_percent_saved ?? '-'}% estimated reduction`;
  if (step.step === 'updates') return `${p.status || 'unknown'}${p.latest_version ? ' / latest ' + p.latest_version : ''}`;
  return '';
}

function displayPath(filePath, context) {
  const rel = path.relative(context.targetRoot, filePath).replace(/\\/g, '/');
  if (!rel.startsWith('..') && !path.isAbsolute(rel)) return rel;
  return filePath;
}

function readJsonIfExists(filePath, fallback) {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function onboardingFollowUp(context, flowName) {
  if (!['import', 'release'].includes(flowName)) return null;
  const profile = readJsonIfExists(path.join(context.projectKnowledgeRoot, 'settings', 'operator-profile.json'), {});
  const completed = profile.first_run_onboarding_completed === true;
  if (completed) return null;
  const chatMessage = '.knowledge is installed and already working. I opened the local Inspector for First-run setup so you can tune agent behavior, autonomy rules, and chat/report preferences for full capabilities.';
  return {
    required: true,
    reason: Object.prototype.hasOwnProperty.call(profile, 'first_run_onboarding_completed') ? 'not_completed' : 'upgrade_missing_completion_marker',
    command: 'node .knowledge/inspector.js',
    note: 'The system is ready. Complete First-run setup in the live Inspector for full behavior and autonomy controls.',
    chat_message: chatMessage,
    auto_launch: true,
    auto_launch_disable_env: 'KNOWLEDGE_FLOW_NO_OPEN=1'
  };
}

function launchInspectorForOnboarding(context) {
  const entry = path.join(context.projectKnowledgeRoot, 'inspector.js');
  if (!fs.existsSync(entry)) {
    return { attempted: true, status: 'missing_entrypoint', entry };
  }
  if (process.env.KNOWLEDGE_FLOW_NO_OPEN === '1' || process.env.CI === 'true') {
    return { attempted: false, status: 'disabled', reason: process.env.CI === 'true' ? 'ci' : 'KNOWLEDGE_FLOW_NO_OPEN' };
  }
  const child = spawn(process.execPath, [entry, '--open'], {
    cwd: context.targetRoot,
    env: contextEnv(context),
    detached: true,
    stdio: 'ignore',
    windowsHide: true
  });
  child.unref();
  return {
    attempted: true,
    status: 'started',
    command: 'node .knowledge/inspector.js --open'
  };
}

const FLOW_LOG_READ_RETRY_DELAYS_MS = Object.freeze([50, 100, 200, 400, 800]);
const FLOW_LOG_RETRYABLE_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);

function makeFlowLogError(stage, code, message, cause, details = {}) {
  const error = new Error(message);
  error.stage = stage;
  error.code = code;
  error.os_code = details.os_code || cause?.os_code || (
    cause?.code && /^[A-Z][A-Z0-9_]+$/.test(cause.code) ? cause.code : null
  );
  error.attempts = details.attempts || cause?.attempts || null;
  error.flow_log = details.flow_log || null;
  error.temp_cleanup_status = cause?.temp_cleanup_status || null;
  error.temp_cleanup_error_code = cause?.temp_cleanup_error_code || null;
  error.cause = cause || null;
  return error;
}

function readFlowLogText(filePath, hooks = {}) {
  const readFileSync = hooks.readFileSync || fs.readFileSync;
  const wait = hooks.sleepSync || sleepSync;
  const retryDelays = Array.isArray(hooks.readRetryDelaysMs)
    ? hooks.readRetryDelaysMs
    : FLOW_LOG_READ_RETRY_DELAYS_MS;
  let attempts = 0;
  while (true) {
    attempts += 1;
    try {
      return { text: String(readFileSync(filePath, 'utf8')), attempts };
    } catch (error) {
      if (!FLOW_LOG_RETRYABLE_CODES.has(error?.code)) throw error;
      if (attempts > retryDelays.length) {
        throw makeFlowLogError(
          'readback',
          'flow_log_readback_retry_exhausted',
          `Flow log readback failed after ${attempts} attempts: ${error.message}`,
          error,
          { os_code: error.code, attempts }
        );
      }
      wait(Number(retryDelays[attempts - 1]) || 0);
    }
  }
}

function validateFlowLogReadback(expected, actual) {
  const errors = [];
  const serializedExpected = JSON.parse(
    JSON.stringify(expected)
  );
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) {
    errors.push('readback is not a JSON object');
    return errors;
  }
  if (actual.flow !== expected.flow) errors.push('flow mismatch');
  if (!isDeepStrictEqual(actual.context, serializedExpected.context)) errors.push('context mismatch');
  if (actual.started_at !== expected.started_at) errors.push('started_at mismatch');
  if (actual.duration_total_ms !== expected.duration_total_ms) errors.push('duration_total_ms mismatch');
  if (actual.steps_total !== expected.steps_total) errors.push('steps_total mismatch');
  if (!Array.isArray(actual.steps)) errors.push('steps is not an array');
  else {
    if (actual.steps.length !== serializedExpected.steps.length) errors.push('steps length mismatch');
    if (!isDeepStrictEqual(actual.steps, serializedExpected.steps)) errors.push('steps content mismatch');
    const derivedStepsOk = actual.steps.filter((step) => step?.success === true).length;
    const derivedOverall = derivedStepsOk === actual.steps.length ? 'ok' : 'failed';
    if (actual.steps_ok !== derivedStepsOk) errors.push('steps_ok does not match step outcomes');
    if (actual.overall_status !== derivedOverall) errors.push('overall_status does not match step outcomes');
  }
  if (actual.steps_ok !== expected.steps_ok) errors.push('steps_ok mismatch');
  if (actual.overall_status !== expected.overall_status) errors.push('overall_status mismatch');
  return errors;
}

function writeFlowLog(name, started, results, totalMs, context, hooks = {}) {
  const dir = path.join(context.stateRoot, 'maintenance', 'flow-logs');
  ensureDir(dir);
  const ts = started.toISOString().replace(/[:.]/g, '-');
  const nonce = `${process.pid}-${Math.random().toString(16).slice(2, 10)}`;
  const file = path.join(dir, `${name}-${ts}-${nonce}.json`);
  const display = displayPath(file, context);
  const payload = {
    flow: name,
    context: jsonContext(context),
    started_at: started.toISOString(),
    duration_total_ms: totalMs,
    steps_total: results.length,
    steps_ok: results.filter((r) => r.success).length,
    overall_status: results.every((r) => r.success) ? 'ok' : 'failed',
    steps: results
  };
  try {
    const writer = hooks.writeJsonAtomic || writeJsonAtomic;
    writer(file, payload);
  } catch (error) {
    throw makeFlowLogError(
      'write',
      error.code || 'flow_log_write_failed',
      `Flow log write failed: ${error.message}`,
      error,
      { flow_log: display }
    );
  }

  let raw = null;
  try {
    raw = readFlowLogText(file, hooks).text;
  } catch (error) {
    if (error?.stage === 'readback') {
      error.flow_log = display;
      throw error;
    }
    throw makeFlowLogError(
      'readback',
      error.code || 'flow_log_readback_failed',
      `Flow log readback failed: ${error.message}`,
      error,
      { flow_log: display }
    );
  }

  let persisted = null;
  try {
    persisted = JSON.parse(raw);
  } catch (error) {
    throw makeFlowLogError(
      'readback',
      'flow_log_readback_invalid_json',
      `Flow log readback is invalid JSON: ${error.message}`,
      error,
      { flow_log: display }
    );
  }
  const validationErrors = validateFlowLogReadback(payload, persisted);
  if (validationErrors.length) {
    throw makeFlowLogError(
      'validation',
      'flow_log_validation_failed',
      `Flow log readback validation failed: ${validationErrors.join('; ')}`,
      null,
      { flow_log: display }
    );
  }
  const readbackBody = Buffer.from(raw, 'utf8');
  return {
    path: display,
    bytes: readbackBody.length,
    sha256: crypto
      .createHash('sha256')
      .update(readbackBody)
      .digest('hex')
  };
}

function serializeFlowLogError(error) {
  return {
    stage: error?.stage || 'write',
    code: error?.code || 'flow_log_write_failed',
    os_code: error?.os_code || null,
    attempts: Number.isInteger(error?.attempts) ? error.attempts : null,
    message: error?.message || 'Unknown flow log finalization error',
    temp_cleanup_status: error?.temp_cleanup_status || null,
    temp_cleanup_error_code: error?.temp_cleanup_error_code || null
  };
}

function runFlow(options, hooks = {}) {
  const { name, quiet, json, noColor, exclusive, context } = options;
  if (!flows[name]) {
    throw new Error(`Unknown flow: ${name}. Available: ${Object.keys(flows).join(', ')}`);
  }
  ensureDir(path.join(context.stateRoot, 'maintenance'));
  appendTeamEvent(context, 'flow_start', { flow: name, exclusive });
  const useColor = colorEnabled({ json, noColor });
  const ansi = {
    ok: (s) => useColor ? `\x1b[32m${s}\x1b[0m` : s,
    fail: (s) => useColor ? `\x1b[31m${s}\x1b[0m` : s
  };
  const started = new Date();
  const startedMs = Date.now();
  const results = [];
  const commands = hooks.stepsForFlow
    ? hooks.stepsForFlow(name, context)
    : stepsForFlow(name, context);
  const executeStep = hooks.runOne || runOne;
  for (const cmd of commands) {
    const result = executeStep(cmd, context);
    results.push(result);
    appendTeamEvent(context, 'flow_step', { flow: name, step: result.step, exit: result.exit, success: result.success, duration_ms: result.duration_ms });
    if (!quiet && !json) {
      const status = result.success ? ansi.ok('ok') : ansi.fail('fail');
      const detail = detailFor(result);
      const pad = (s, n) => (s + ' '.repeat(n)).slice(0, n);
      console.log(`[ ${status} ] ${pad(result.step, 11)} ${String(result.duration_ms).padStart(5, ' ')} ms${detail ? '  /  ' + detail : ''}`);
    }
  }
  const totalMs = Date.now() - startedMs;
  const ok = results.filter((r) => r.success).length;
  const total = results.length;
  const checksOverall = ok === total ? 'ok' : 'failed';
  let logRel = null;
  let flowLogBytes = null;
  let flowLogSha256 = null;
  let flowLogStatus = 'written';
  let flowLogError = null;
  try {
    const persistFlowLog = hooks.writeFlowLog || writeFlowLog;
    const flowLogBinding = persistFlowLog(
      name,
      started,
      results,
      totalMs,
      context,
      hooks.flowLog || {}
    );
    if (
      !flowLogBinding ||
      typeof flowLogBinding !== 'object' ||
      typeof flowLogBinding.path !== 'string' ||
      !Number.isInteger(flowLogBinding.bytes) ||
      flowLogBinding.bytes <= 0 ||
      !/^[a-f0-9]{64}$/i.test(
        String(flowLogBinding.sha256 || '')
      )
    ) {
      throw makeFlowLogError(
        'validation',
        'flow_log_binding_invalid',
        'Flow log finalizer did not return a valid readback byte binding',
        null,
        {
          flow_log:
            flowLogBinding?.path || null
        }
      );
    }
    logRel = flowLogBinding.path;
    flowLogBytes = flowLogBinding.bytes;
    flowLogSha256 = String(
      flowLogBinding.sha256
    ).toLowerCase();
  } catch (error) {
    logRel = error?.flow_log || null;
    flowLogStatus = 'failed';
    flowLogError = serializeFlowLogError(error);
  }
  const overall = checksOverall === 'ok' && flowLogStatus === 'written' ? 'ok' : 'failed';
  const onboarding = onboardingFollowUp(context, name);
  if (overall === 'ok' && onboarding?.required && !json && !quiet) {
    onboarding.launch = launchInspectorForOnboarding(context);
  }
  const out = {
    flow: name,
    mode: context.mode,
    repo_id: context.repoId,
    workspace_id: context.workspaceId,
    agent_id: context.agentId,
    target_root: context.targetRoot,
    project_knowledge_root: context.projectKnowledgeRoot,
    state_root: context.stateRoot,
    branch: context.branch,
    head_sha: context.headSha,
    started_at: started.toISOString(),
    duration_total_ms: totalMs,
    steps_total: total,
    steps_ok: ok,
    checks_status: checksOverall,
    status: overall,
    overall_status: overall,
    warnings: context.warnings,
    flow_log: logRel,
    flow_log_bytes: flowLogBytes,
    flow_log_sha256: flowLogSha256,
    flow_log_status: flowLogStatus,
    flow_log_error: flowLogError,
    failure_code: flowLogStatus === 'failed' ? 'flow_log_write_failed' : null,
    onboarding_follow_up: onboarding,
    steps: results.map((r) => ({
      step: r.step,
      command: r.command,
      exit: r.exit,
      success: r.success,
      status: r.status,
      json_status: r.json_status,
      semantic_errors: r.semantic_errors,
      duration_ms: r.duration_ms,
      summary: detailFor(r)
    }))
  };
  updateWorkspaceFlow(context, out);
  appendTeamEvent(context, 'flow_end', {
    flow: name,
    overall_status: overall,
    steps_ok: ok,
    steps_total: total,
    flow_log: logRel,
    flow_log_status: flowLogStatus,
    failure_code: out.failure_code
  });
  return out;
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const context = resolveKnowledgeContext(args.contextFlags);
  let release = null;
  try {
    if (context.mode === 'team' && args.exclusive) release = acquireTeamLock(context, 'flow');
    const out = runFlow({ ...args, context });
    if (args.json) console.log(JSON.stringify(out, null, 2));
    else {
      const logSummary = out.flow_log_status === 'written'
        ? out.flow_log
        : `FAILED (${out.flow_log_error?.code || 'flow_log_write_failed'})`;
      console.log(`flow.${args.name}: ${out.steps_ok}/${out.steps_total} ok / ${out.duration_total_ms} ms / log: ${logSummary}`);
      if (out.flow_log_status === 'failed') {
        console.error('Flow checks completed, but the evidence log could not be finalized. Resolve the file lock or permission error and retry the flow.');
      }
      if (out.onboarding_follow_up?.required) {
        if (out.onboarding_follow_up.chat_message) console.log(out.onboarding_follow_up.chat_message);
        if (out.onboarding_follow_up.launch?.status === 'started') console.log('Inspector opened for First-run setup.');
        else console.log(`next: ${out.onboarding_follow_up.command}`);
        console.log(out.onboarding_follow_up.note);
      }
    }
    if (out.overall_status !== 'ok') process.exitCode = 2;
    return out;
  } finally {
    if (release) release();
  }
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    if (process.argv.slice(2).includes('--json')) {
      console.log(JSON.stringify({
        flow: parseArgs(process.argv.slice(2)).name,
        status: 'failed',
        overall_status: 'failed',
        failure_code: 'flow_unexpected_error',
        error: {
          code: error.code || 'flow_unexpected_error',
          message: error.message
        }
      }, null, 2));
    } else {
      console.error(error.stack || error.message);
    }
    process.exitCode = 1;
  }
}

module.exports = {
  runOne,
  parseArgs,
  colorEnabled,
  runFlow,
  __test: {
    writeFlowLog,
    readFlowLogText,
    validateFlowLogReadback,
    serializeFlowLogError,
    makeFlowLogError
  }
};
