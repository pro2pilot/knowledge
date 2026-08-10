#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const systemRoot = path.resolve(__dirname, '..');

function run(args) {
  const res = spawnSync(process.execPath, args, { cwd: systemRoot, encoding: 'utf8', windowsHide: true, timeout: 120000 });
  if (res.status !== 0) {
    throw new Error(`${args.join(' ')} failed (status=${res.status}, signal=${res.signal || 'none'}, error=${res.error?.message || 'none'})\n${res.stdout || ''}\n${res.stderr || ''}`);
  }
  return JSON.parse(res.stdout);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const compact = run(['tools/agent-footer.js', '--json']);
  const full = run(['tools/agent-footer.js', '--mode', 'full', '--json']);
  assert(compact.footer.includes('.knowledge: Trust'), 'compact footer missing trust summary');
  assert(compact.footer.includes('Task routing estimate unavailable'), 'compact footer must report unavailable rather than invent a routing estimate');
  assert(!/estimated system tokens|estimated context saved/i.test(compact.footer), 'compact footer must not fabricate heuristic token/context savings');
  assert(full.footer.includes('## .knowledge report'), 'full footer missing heading');
  assert(full.footer.includes('provider-reported model-token usage'), 'full footer missing canonical routing disclaimer');
  assert(full.footer.includes('node .knowledge/inspector.js'), 'full footer missing Open Inspector command');
  console.log(JSON.stringify({ schema_version: systemVersion(), status: 'pass', checks: ['compact footer', 'full footer', 'unavailable rather than fabricated estimate', 'canonical disclaimer', 'open inspector action'] }, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
