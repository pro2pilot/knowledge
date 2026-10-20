'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { contextEnv } = require('./path-context');
const { assertSafeContainedFile, appendNdjsonContained, writeFileAtomicContained, writeJsonAtomicContained } = require('./json-store');
const { withContainedLock } = require('./contained-lock-manager');
const { LOCKS } = require('./lock-policy');
const { getAction, canRunAction, loadEntitlements, RISK_REQUIRES_CONFIRMATION } = require('./action-registry');
const { inspectSemanticJson, MAX_CHILD_JSON_BYTES } = require('./semantic-json');

const RUNS = new Map();

function nowIso() {
  return new Date().toISOString();
}

function runId() {
  return `run_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
}

function redactText(value) {
  return String(value || '')
    .replace(/(api[_-]?key|secret|token|password)(["'\s:=]+)[^"',\s}]+/ig, '$1$2<redacted>')
    .replace(/\b(pcsk|m0sk|sk|pk|eyJ)[A-Za-z0-9_./+=-]{12,}\b/g, '<redacted-secret>')
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/Users\\[^\\\s"',}]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\/\s"',}]+/gi, 'Users/<local-user>');
}

function actionLogDir(context, run) {
  const date = run.queued_at.slice(0, 10);
  return path.join(context.stateRoot, 'maintenance', 'action-runs', date, run.run_id);
}

function actionJournal(context, run) {
  const date = run.queued_at.slice(0, 10);
  return path.join(context.stateRoot, 'maintenance', 'action-runs', `${date}.ndjson`);
}

function assertLogFile(context, file) {
  assertSafeContainedFile(context.stateRoot, file, { allowMissing: true });
}

function assertEvidencePaths(context, run) {
  assertLogFile(context, actionJournal(context, run));
  const dir = actionLogDir(context, run);
  for (const name of ['stdout.txt', 'stderr.txt', 'run.json']) assertLogFile(context, path.join(dir, name));
}

function appendRunLog(context, run) {
  // The contained append uses atomic replacement. Serialize its read/modify/
  // write interval so concurrent Inspector processes cannot drop prior rows.
  // Do not hold this lock while the child or recording backend is running.
  return withContainedLock({ context, rootKind: 'state', rootPath: context.stateRoot,
    lockName: 'inspector-actions', purpose: LOCKS['inspector-actions'].purpose }, () => {
    const file = actionJournal(context, run);
    assertLogFile(context, file);
    appendNdjsonContained(file, run, context.stateRoot);
  });
}

function saveRunFiles(context, run, stdout, stderr) {
  const dir = actionLogDir(context, run);
  assertEvidencePaths(context, run);
  writeFileAtomicContained(path.join(dir, 'stdout.txt'), redactText(stdout), context.stateRoot);
  writeFileAtomicContained(path.join(dir, 'stderr.txt'), redactText(stderr), context.stateRoot);
  writeJsonAtomicContained(path.join(dir, 'run.json'), run, context.stateRoot);
}

function persistRun(context, run, stdout, stderr) {
  const persisted = { ...run };
  delete persisted.result;
  try {
    saveRunFiles(context, persisted, stdout, stderr);
    appendRunLog(context, persisted);
  } catch (error) {
    run.status = 'failed';
    run.errors.push({ reason: 'evidence_write_failed', code: error.code || 'write_failed' });
    throw error;
  }
}

function commandToString(command) {
  return ['node', ...(command || [])].join(' ');
}

function recordingResult(actionId, context, body) {
  const operations = {
    'recording.blockers': (api) => api.listBlockers(context),
    'recording.resolve': (api) => api.resolveBlocker(context, {
      id: body.id,
      scope: body.scope,
      reason: body.reason,
      confirmed: body.confirmed === true
    }),
    'recording.revoke': (api) => api.revokeOverride(context, {
      id: body.id,
      confirmed: body.confirmed === true
    })
  };
  const operation = operations[actionId];
  if (!operation) return null;
  // Keep the dependency lazy: static Inspector builds and unrelated actions do
  // not need the policy module to be installed or initialized.
  const api = context.recordingBlockers || require('./recording-blockers');
  const raw = operation(api);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('recording_backend_invalid_result');
  }
  if (actionId !== 'recording.blockers') {
    const safeReasons = new Set([
      'explicit_confirmation_required', 'invalid_scope', 'safe_reason_required',
      'blocker_not_open', 'blocker_not_overridable', 'override_not_active'
    ]);
    return {
      status: typeof raw.status === 'string' ? raw.status : 'error',
      reason: safeReasons.has(raw.reason) ? raw.reason : undefined,
      error: typeof raw.error === 'string' && safeReasons.has(raw.error) ? raw.error : undefined,
      override_id: /^EX-[a-f0-9]{64}$/.test(String(raw.override_id || '')) ? raw.override_id : undefined,
      scope: raw.scope === 'once' || raw.scope === 'project' ? raw.scope : undefined,
      retry_required: raw.retry_required === true ? true : undefined
    };
  }
  const rows = (value) => Array.isArray(value) ? value.filter((row) => row && typeof row === 'object' && !Array.isArray(row)).map((row) => ({
    id: typeof row.id === 'string' ? row.id : '',
    status: typeof row.status === 'string' ? row.status : '',
    kind: typeof row.kind === 'string' ? row.kind : '',
    preview: typeof row.preview === 'string' ? row.preview : '',
    field: typeof row.field === 'string' ? row.field : '',
    reason: typeof row.reason === 'string' ? row.reason : '',
    chat_notice: typeof row.chat_notice === 'string' ? row.chat_notice : '',
    created_at: typeof row.created_at === 'string' ? row.created_at : (typeof row.confirmed_at === 'string' ? row.confirmed_at : ''),
    scope: row.scope === 'once' || row.scope === 'project' ? row.scope : '',
    allowed_actions: Array.isArray(row.allowed_actions) ? row.allowed_actions.filter((item) => item === 'once' || item === 'project') : []
  })) : [];
  return {
    status: typeof raw.status === 'string' ? raw.status : 'error',
    language: typeof raw.language === 'string' ? raw.language : 'en',
    blockers: rows(raw.blockers),
    overrides: rows(raw.overrides)
  };
}

function runAction(context, id, body = {}) {
  const action = getAction(id);
  const run = {
    schema_version: 'knowledge-inspector-run.v1',
    run_id: runId(),
    action_id: id,
    action_label: action?.label || id,
    status: 'queued',
    queued_at: nowIso(),
    started_at: null,
    finished_at: null,
    duration_ms: 0,
    risk: action?.risk || 'unknown',
    command: action?.command ? commandToString(action.command) : null,
    stdout_path: null,
    stderr_path: null,
    stdout_summary: '',
    stderr_summary: '',
    updated_artifacts: [],
    warnings: [],
    errors: [],
    next_recommended_actions: []
  };
  // Reject unsafe destinations before a local command or recording mutation.
  // The writers check again after the command, since it can change the tree.
  assertEvidencePaths(context, run);
  RUNS.set(run.run_id, run);

  const entitlementState = loadEntitlements(context.projectKnowledgeRoot);
  const gate = canRunAction(action, entitlementState);
  if (!gate.ok) {
    run.status = 'blocked';
    run.finished_at = nowIso();
    run.errors.push(gate);
    run.stdout_summary = `Action blocked: ${gate.reason}.`;
    appendRunLog(context, run);
    return run;
  }

  if (RISK_REQUIRES_CONFIRMATION.has(action.risk) && body?.confirmed !== true) {
    run.status = 'needs_confirmation';
    run.finished_at = nowIso();
    run.errors.push({ reason: 'confirmation_required', risk: action.risk });
    run.stdout_summary = `${action.label} needs explicit confirmation.`;
    appendRunLog(context, run);
    return run;
  }

  if (id === 'recording.blockers' || id === 'recording.resolve' || id === 'recording.revoke') {
    const started = Date.now();
    run.status = 'running';
    run.started_at = nowIso();
    try {
      const result = recordingResult(id, context, body);
      run.result = result;
      run.status = result?.status === 'ok' ? 'passed' : 'failed';
      run.stdout_summary = id === 'recording.blockers'
        ? `Recording policy status: ${result?.status || 'unknown'}; blockers: ${result?.blockers?.length || 0}; overrides: ${result?.overrides?.length || 0}.`
        : `Recording policy action status: ${result?.status || 'unknown'}.`;
      if (run.status === 'failed') run.errors.push({ reason: result?.reason || result?.error || 'recording_action_failed' });
    } catch {
      run.status = 'failed';
      run.errors.push({ reason: 'recording_backend_unavailable' });
      run.stdout_summary = 'Recording policy action could not be completed.';
    }
    run.finished_at = nowIso();
    run.duration_ms = Date.now() - started;
    run.next_recommended_actions = ['recording.blockers'];
    const dir = actionLogDir(context, run);
    run.stdout_path = path.join(dir, 'stdout.txt');
    run.stderr_path = path.join(dir, 'stderr.txt');
    persistRun(context, run, run.stdout_summary, '');
    return run;
  }

  if (!action.command) {
    run.status = 'blocked';
    run.finished_at = nowIso();
    run.errors.push({ reason: 'no_free_command', action_id: id });
    run.stdout_summary = 'This action is a locked preview or has no free command.';
    appendRunLog(context, run);
    return run;
  }

  const scriptPath = path.join(context.systemRoot || context.projectKnowledgeRoot, action.command[0]);
  const args = [scriptPath, ...action.command.slice(1)];
  const started = Date.now();
  run.status = 'running';
  run.started_at = nowIso();

  const result = spawnSync(process.execPath, args, {
    cwd: context.targetRoot,
    env: contextEnv(context),
    encoding: 'utf8',
    windowsHide: true,
    timeout: action.timeout_ms,
    maxBuffer: MAX_CHILD_JSON_BYTES
  });
  const stdout = redactText(result.stdout || '');
  const stderr = redactText(result.stderr || '');
  run.finished_at = nowIso();
  run.duration_ms = Date.now() - started;
  let parsed = null;
  let semantic = { ok: true, errors: [] };
  try {
    parsed = JSON.parse(String(result.stdout || '').trim().replace(/^\uFEFF/, ''));
    semantic = inspectSemanticJson(parsed);
  } catch (error) {
    // Every allowlisted action is a structured-report command. A successful
    // process exit cannot stand in for a complete, valid evidence report.
    // JSON.parse messages may quote a truncated secret which a value-shaped
    // redactor cannot recognize. Keep this diagnostic independent of stdout.
    semantic = { ok: false, errors: ['invalid_action_json'] };
  }
  run.status = result.status === 0 && !result.error && !result.signal && semantic.ok ? 'passed' : 'failed';
  run.exit_code = result.status;
  run.json_status = parsed?.status || null;
  run.semantic_errors = semantic.errors;
  run.stdout_summary = stdout.trim().slice(-1200) || '(no stdout)';
  run.stderr_summary = stderr.trim().slice(-1200);
  if (result.error) run.errors.push({ reason: 'spawn_error', message: result.error.message });
  if (result.signal) run.errors.push({ reason: 'signal', signal: result.signal });
  if (result.status !== 0) run.errors.push({ reason: 'non_zero_exit', exit_code: result.status });
  if (!semantic.ok) run.errors.push({ reason: 'semantic_failure', errors: semantic.errors });
  run.next_recommended_actions = action.id === 'trust.restore.safe'
    ? ['doctor.run', 'inspector.rebuild']
    : ['trust.restore.safe'];

  const dir = actionLogDir(context, run);
  run.stdout_path = path.join(dir, 'stdout.txt');
  run.stderr_path = path.join(dir, 'stderr.txt');
  persistRun(context, run, stdout, stderr);
  return run;
}

function getRun(id) {
  return RUNS.get(String(id || '')) || null;
}

module.exports = { runAction, getRun, redactText };
