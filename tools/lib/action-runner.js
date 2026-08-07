'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { contextEnv } = require('./path-context');
const { ensureDir, appendNdjson, writeJsonAtomic } = require('./json-store');
const { getAction, canRunAction, loadEntitlements, RISK_REQUIRES_CONFIRMATION } = require('./action-registry');

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

function appendRunLog(context, run) {
  const date = run.queued_at.slice(0, 10);
  appendNdjson(path.join(context.stateRoot, 'maintenance', 'action-runs', `${date}.ndjson`), run);
}

function saveRunFiles(context, run, stdout, stderr) {
  const dir = actionLogDir(context, run);
  ensureDir(dir);
  fs.writeFileSync(path.join(dir, 'stdout.txt'), redactText(stdout), 'utf8');
  fs.writeFileSync(path.join(dir, 'stderr.txt'), redactText(stderr), 'utf8');
  writeJsonAtomic(path.join(dir, 'run.json'), run);
}

function commandToString(command) {
  return ['node', ...(command || [])].join(' ');
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

  if (RISK_REQUIRES_CONFIRMATION.has(action.risk) && !body.confirmed) {
    run.status = 'needs_confirmation';
    run.finished_at = nowIso();
    run.errors.push({ reason: 'confirmation_required', risk: action.risk });
    run.stdout_summary = `${action.label} needs explicit confirmation.`;
    appendRunLog(context, run);
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

  const scriptPath = path.join(context.projectKnowledgeRoot, action.command[0]);
  const args = [scriptPath, ...action.command.slice(1)];
  const started = Date.now();
  run.status = 'running';
  run.started_at = nowIso();

  const result = spawnSync(process.execPath, args, {
    cwd: context.targetRoot,
    env: contextEnv(context),
    encoding: 'utf8',
    windowsHide: true,
    timeout: action.timeout_ms
  });
  const stdout = redactText(result.stdout || '');
  const stderr = redactText(result.stderr || '');
  run.finished_at = nowIso();
  run.duration_ms = Date.now() - started;
  run.status = result.status === 0 ? 'passed' : 'failed';
  run.exit_code = result.status;
  run.stdout_summary = stdout.trim().slice(-1200) || '(no stdout)';
  run.stderr_summary = stderr.trim().slice(-1200);
  if (result.error) run.errors.push({ reason: 'spawn_error', message: result.error.message });
  if (result.signal) run.errors.push({ reason: 'signal', signal: result.signal });
  if (result.status !== 0) run.errors.push({ reason: 'non_zero_exit', exit_code: result.status });
  run.next_recommended_actions = action.id === 'trust.restore.safe'
    ? ['doctor.run', 'inspector.rebuild']
    : ['trust.restore.safe'];

  const dir = actionLogDir(context, run);
  run.stdout_path = path.join(dir, 'stdout.txt');
  run.stderr_path = path.join(dir, 'stderr.txt');
  saveRunFiles(context, run, stdout, stderr);
  appendRunLog(context, run);
  return run;
}

function getRun(id) {
  return RUNS.get(String(id || '')) || null;
}

module.exports = { runAction, getRun, redactText };
