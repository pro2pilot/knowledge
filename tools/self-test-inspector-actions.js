#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');
const required = ['doctor.run', 'flow.release', 'inspector.rebuild', 'trust.restore.safe', 'pr.review.basic', 'pr.impact.basic', 'repair.queue.refresh', 'memory.status', 'team.status', 'agent.sessions.refresh', 'queue.status', 'merge.readiness', 'benchmark.summary'];
const removed = [
  ['report', 'debug_bundle'].join('.'),
  ['report', 'pro_snapshot'].join('.'),
  ['pro', 'pr_impact', 'pro'].join('.')
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function request(port, method, requestPath, token = null, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : '';
    const headers = {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {})
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

async function wait(port, child) {
  for (let i = 0; i < 60; i += 1) {
    if (child.exitCode !== null) throw new Error(`server exited early: ${child.exitCode}`);
    try {
      const res = await request(port, 'GET', '/api/session');
      if (res.status === 200 && res.json?.token) return res.json.token;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('server did not become ready');
}

async function main() {
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
  try {
    const token = await wait(port, child);
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
    console.log(JSON.stringify({ schema_version: '3.2.3', status: 'pass', checks: ['token auth', 'required action registry', 'removed actions absent', 'action lifecycle passed', 'logs saved'] }, null, 2));
  } finally {
    child.kill();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
