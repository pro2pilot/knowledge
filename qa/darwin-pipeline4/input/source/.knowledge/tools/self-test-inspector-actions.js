#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { runAction } = require('./lib/action-runner');

const systemRoot = path.resolve(__dirname, '..');
const systemVersion = JSON.parse(fs.readFileSync(path.join(systemRoot, 'package.json'), 'utf8')).version || '3.3.0';
const required = ['doctor.run', 'flow.release', 'inspector.rebuild', 'trust.restore.safe', 'pr.review.basic', 'pr.impact.basic', 'repair.queue.refresh', 'memory.status', 'team.status', 'agent.sessions.refresh', 'queue.status', 'merge.readiness', 'evaluation.summary', 'recording.blockers', 'recording.resolve', 'recording.revoke'];
const removed = [
  ['report', 'debug_bundle'].join('.'),
  ['report', 'pro_snapshot'].join('.'),
  ['pro', 'pr_impact', 'pro'].join('.')
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function verifyRecordingActionBoundary() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-recording-actions-'));
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  const calls = [];
  const recordingBlockers = {
    listBlockers() {
      calls.push(['list']);
      return {
        status: 'ok', language: 'ru',
        blockers: [
          { id: 'RB-safe', status: 'blocked', kind: 'suspected_secret', preview: 'api_key=<masked>', field: 'notes', reason: 'secret pattern', chat_notice: 'masked notice', created_at: '2026-10-01T00:00:00Z', allowed_actions: ['once', 'project'], private_secret: 'never expose' },
          { id: 'RB-generic', status: 'blocked', kind: 'generic_scope', preview: 'scope denied', reason: 'scope policy', allowed_actions: [], private_secret: 'never expose' }
        ],
        overrides: [{ id: 'EX-safe', status: 'active', scope: 'once', confirmed_at: '2026-10-01T00:00:00Z', reason: 'confirmed', allowed_actions: ['revoke'], private_secret: 'never expose' }]
      };
    },
    resolveBlocker(context, input) {
      calls.push(['resolve', input]);
      return input.reason === 'trigger safe rejection fixture'
        ? { status: 'rejected', reason: 'blocker_not_open', private_detail: 'never expose' }
        : { status: 'ok', secret: 'never expose' };
    },
    revokeOverride(context, input) { calls.push(['revoke', input]); return { status: 'ok', secret: 'never expose' }; }
  };
  const context = { targetRoot: project, projectKnowledgeRoot: project, systemRoot, stateRoot: state, recordingBlockers };
  try {
    const listed = runAction(context, 'recording.blockers');
    assert(listed.status === 'passed' && listed.result.language === 'ru', 'recording blocker listing did not return localized status');
    assert(listed.result.blockers.length === 2 && listed.result.blockers[1].allowed_actions.length === 0, 'generic non-resolvable blocker policy was not preserved');
    assert(listed.result.overrides[0].scope === 'once' && listed.result.overrides[0].created_at === '2026-10-01T00:00:00Z', 'override scope or safe creation time was dropped by the Inspector action boundary');
    assert(listed.result.blockers[0].private_secret === undefined && listed.result.overrides[0].private_secret === undefined, 'unlisted backend fields crossed the action boundary');
    assert(!listed.stdout_summary.includes('never expose'), 'unlisted backend data was written to the action summary');
    const persistedList = fs.readFileSync(path.join(path.dirname(listed.stdout_path), 'run.json'), 'utf8');
    assert(!persistedList.includes('api_key=<masked>') && !persistedList.includes('never expose'), 'blocker previews must remain in the token-protected response, not persistent action history');
    const unconfirmed = runAction(context, 'recording.resolve', { id: 'RB-safe', scope: 'once', reason: 'approved' });
    assert(unconfirmed.status === 'needs_confirmation', 'recording resolve did not require confirmation');
    assert(calls.filter(([kind]) => kind === 'resolve').length === 0, 'unconfirmed resolve reached backend');
    const resolved = runAction(context, 'recording.resolve', { id: 'RB-safe', scope: 'project', reason: 'operator approved', confirmed: true });
    assert(resolved.status === 'passed' && calls.some(([kind, input]) => kind === 'resolve' && input.scope === 'project' && input.confirmed === true), 'confirmed project resolve did not reach backend');
    const rejected = runAction(context, 'recording.resolve', { id: 'RB-safe', scope: 'once', reason: 'trigger safe rejection fixture', confirmed: true });
    assert(rejected.status === 'failed' && rejected.result.reason === 'blocker_not_open' && rejected.errors[0]?.reason === 'blocker_not_open', 'safe backend rejection reason was dropped by the Inspector action boundary');
    assert(!JSON.stringify(rejected).includes('never expose'), 'safe backend rejection leaked an unlisted backend field');
    const revoked = runAction(context, 'recording.revoke', { id: 'EX-safe', confirmed: true });
    assert(revoked.status === 'passed' && calls.some(([kind, input]) => kind === 'revoke' && input.id === 'EX-safe' && input.confirmed === true), 'confirmed revoke did not reach backend');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function request(port, method, requestPath, token = null, body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const headers = {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {}),
      ...extraHeaders
    };
    const req = http.request({ hostname: '127.0.0.1', port, path: requestPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk.toString(); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch {}
        resolve({ status: res.statusCode, json, body: data });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function wait(port, child, diagnostics = () => '') {
  let lastError = null;
  for (let i = 0; i < 60; i += 1) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${child.exitCode}\n${diagnostics()}`);
    try {
      const res = await request(port, 'GET', '/api/session');
      if (res.status === 200 && res.json?.token) return res.json.token;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`server did not become ready${lastError ? `: ${lastError.message}` : ''}\n${diagnostics()}`);
}

async function main() {
  verifyRecordingActionBoundary();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-actions-'));
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  const port = 19000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [
    path.join(systemRoot, 'tools', 'serve-inspector.js'),
    '--port', String(port),
    '--system-root', systemRoot,
    '--project-knowledge-root', systemRoot,
    '--target-root', project,
    '--state-root', state
  ], { cwd: systemRoot, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let serverStdout = '';
  let serverStderr = '';
  child.stdout.on('data', (chunk) => { serverStdout += chunk.toString(); });
  child.stderr.on('data', (chunk) => { serverStderr += chunk.toString(); });
  try {
    const token = await wait(port, child, () => `stdout:\n${serverStdout}\nstderr:\n${serverStderr}`);
    const noToken = await request(port, 'GET', '/api/actions');
    assert(noToken.status === 401, 'actions endpoint must require token');
    const actions = await request(port, 'GET', '/api/actions', token);
    assert(actions.status === 200, 'actions endpoint failed');
    const ids = new Set((actions.json.actions || []).map((action) => action.id));
    const missing = required.filter((id) => !ids.has(id));
    assert(missing.length === 0, `missing actions: ${missing.join(', ')}`);
    const unexpected = removed.filter((id) => ids.has(id));
    assert(unexpected.length === 0, `removed actions are still exposed: ${unexpected.join(', ')}`);
    const run = await request(port, 'POST', '/api/actions/agent.sessions.refresh/run', token, { confirmed: true });
    assert(run.status === 200 && run.json.run.status === 'passed', `agent.sessions.refresh did not pass: ${run.body}`);
    assert(fs.existsSync(run.json.run.stdout_path), 'stdout log was not saved');
    const deletedAction = await request(port, 'POST', `/api/actions/${removed[0]}/run`, token, { confirmed: true });
    assert(deletedAction.status === 423 && deletedAction.json.run.status === 'blocked', 'removed action id must be blocked');
    const unconfirmedRecording = await request(port, 'POST', '/api/actions/recording.resolve/run', token, { id: 'RB-fixture', scope: 'once', reason: 'test' });
    assert(unconfirmedRecording.status === 409 && unconfirmedRecording.json.run.status === 'needs_confirmation', 'recording mutation endpoint must enforce confirmation before dispatch');
    const crossOriginRecording = await request(port, 'POST', '/api/actions/recording.resolve/run', token, { id: 'RB-fixture', scope: 'once', reason: 'test', confirmed: true }, { origin: 'http://foreign.invalid' });
    assert(crossOriginRecording.status === 403 && crossOriginRecording.json?.error === 'cross_origin_request_forbidden', 'recording mutation endpoint must retain Inspector origin checks');
    console.log(JSON.stringify({ schema_version: systemVersion, status: 'pass', checks: ['token auth', 'required action registry', 'removed actions absent', 'action lifecycle passed', 'logs saved', 'recording action confirmation', 'recording response allowlist', 'recording action origin check'] }, null, 2));
  } finally {
    child.kill();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
