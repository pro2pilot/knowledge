#!/usr/bin/env node
'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function request(port, method, requestPath, token = null) {
  return new Promise((resolve, reject) => {
    const headers = token ? { authorization: `Bearer ${token}` } : {};
    const req = http.request({ hostname: '127.0.0.1', port, path: requestPath, method, headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk.toString(); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch {}
        resolve({ status: res.statusCode, body, json });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function wait(port, child) {
  for (let i = 0; i < 60; i += 1) {
    if (child.exitCode !== null) throw new Error(`launcher exited early: ${child.exitCode}`);
    try {
      const res = await request(port, 'GET', '/api/session');
      if (res.status === 200 && res.json?.token) return res.json;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('launcher did not become ready');
}

async function main() {
  assert(fs.existsSync(path.join(systemRoot, 'open-inspector.vbs')), 'click launcher missing');
  assert(fs.existsSync(path.join(systemRoot, 'assets', 'knowledge-trust-gate-light-readme.svg')), 'trust gate README SVG asset missing');
  assert(fs.existsSync(path.join(systemRoot, 'tools', 'create-inspector-shortcut.ps1')), 'shortcut creation script missing');
  assert(fs.existsSync(path.join(systemRoot, 'tools', 'open-inspector.ps1')), 'launcher helper script missing');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-launcher-'));
  const project = path.join(root, 'repo');
  const state = path.join(root, 'state');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  const port = 19000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [
    path.join(systemRoot, 'inspector.js'),
    '--port', String(port),
    '--system-root', systemRoot,
    '--project-knowledge-root', systemRoot,
    '--target-root', project,
    '--state-root', state
  ], {
    cwd: systemRoot,
    env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  try {
    const session = await wait(port, child);
    const denied = await request(port, 'GET', '/api/state');
    assert(denied.status === 401, 'api state must require session token');
    const stateRes = await request(port, 'GET', '/api/state', session.token);
    assert(stateRes.status === 200 && stateRes.json?.state?.product?.version === '3.2.4', 'api state did not return product 3.2.4');
    const html = await request(port, 'GET', '/');
    for (const label of ['Home', 'Review', 'Knowledge Trust', 'Agents Activity', 'Reports', 'Settings', 'Pro Preview']) {
      assert(html.body.includes(`>${label}</button>`), `missing nav label ${label}`);
    }
    assert(!html.body.includes('>Command Center</button>'), 'Command Center must not be a top-level tab');
    assert(!html.body.includes('>Metrics</button>'), 'Metrics must not be a top-level tab');
    assert(html.body.includes('data-table-search="modules"'), 'launcher HTML should share tabular Inspector renderer');
    const result = { schema_version: '3.2.4', status: 'pass', checks: ['one-file launcher starts', 'click launcher files exist', 'trust gate asset exists', 'launcher helper exists', 'session token required', 'canonical nav renders', 'shared Inspector renderer renders'] };
    console.log(JSON.stringify(result, null, 2));
  } finally {
    child.kill();
    fs.rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error.stack || error.message); process.exit(1); });
