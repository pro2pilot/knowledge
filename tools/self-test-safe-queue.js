#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');

function run(args, cwd) {
  const res = spawnSync(process.execPath, args, { cwd, encoding: 'utf8', windowsHide: true, timeout: 120000 });
  if (res.status !== 0) throw new Error(`${args.join(' ')} failed\n${res.stdout}\n${res.stderr}`);
  return JSON.parse(res.stdout);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-safe-queue-'));
  const project = path.join(root, 'repo');
  const teamRoot = path.join(root, 'team');
  fs.mkdirSync(project, { recursive: true });
  const repoMode = run(['tools/team-status.js'], systemRoot);
  assert(repoMode.safe_queue?.default === true, 'repo-mode Safe Queue default missing');
  assert(repoMode.merge_policy?.auto_merge === false, 'auto merge must be disabled by default');
  run(['tools/team-init.js', '--team-root', teamRoot, '--target-root', project, '--workspace-id', 'ws-init', '--agent-id', 'agent-init'], systemRoot);
  const registered = run(['tools/workspace-register.js', '--team-root', teamRoot, '--target-root', project, '--workspace-id', 'ws-1', '--agent-id', 'agent-1'], systemRoot);
  const status = run(['tools/team-status.js', '--team-root', teamRoot], systemRoot);
  assert(registered.workspace.workspaceId === 'ws-1', 'workspace did not register');
  assert(status.workspaces_total >= 1, 'team status did not see registered workspace');
  console.log(JSON.stringify({ schema_version: '3.2.3', status: 'pass', checks: ['Safe Queue default', 'Manual Only merge default', 'workspace registration visible'] }, null, 2));
  fs.rmSync(root, { recursive: true, force: true });
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
