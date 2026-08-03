#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');

function run(args, cwd) {
  const res = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', windowsHide: true, timeout: 60000 });
  if (res.status !== 0) throw new Error(`${args.join(' ')} failed\n${res.stdout}\n${res.stderr}`);
  return JSON.parse(res.stdout);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-agent-activity-'));
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  const base = ['tools/agent-session.js', '--system-root', systemRoot, '--project-knowledge-root', systemRoot, '--target-root', project, '--state-root', state, '--runtime', 'codex', '--instance', 'codex-local-01', '--operator', 'andrii', '--workspace-id', 'ws-free-core', '--task-id', 'canonical-free-pro', '--json'];
  const start = run([...base.slice(0, 1), 'start', ...base.slice(1)], systemRoot);
  const heartbeat = run([...base.slice(0, 1), 'heartbeat', '--session-id', start.session.session_id, ...base.slice(1)], systemRoot);
  const report = run([...base.slice(0, 1), 'report', ...base.slice(1)], systemRoot);
  const finish = run([...base.slice(0, 1), 'finish', '--session-id', start.session.session_id, ...base.slice(1)], systemRoot);
  assert(start.session.agent_runtime_id === 'codex', 'runtime id missing');
  assert(start.session.agent_instance_id === 'codex-local-01', 'instance id missing');
  assert(start.session.operator_id === 'andrii', 'operator id missing');
  assert(start.session.workspace_id === 'ws-free-core', 'workspace id missing');
  assert(heartbeat.session.last_heartbeat_at, 'heartbeat missing');
  assert(report.recent_sessions.length >= 1, 'report missing sessions');
  assert(finish.session.status === 'done', 'finish did not mark done');
  console.log(JSON.stringify({ schema_version: systemVersion(), status: 'pass', checks: ['start', 'heartbeat', 'report', 'finish', 'identity fields'] }, null, 2));
  fs.rmSync(root, { recursive: true, force: true });
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
