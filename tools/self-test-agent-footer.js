#!/usr/bin/env node
'use strict';

const path = require('path');
const { spawnSync } = require('child_process');

const systemRoot = path.resolve(__dirname, '..');

function run(args) {
  const res = spawnSync(process.execPath, args, { cwd: systemRoot, encoding: 'utf8', windowsHide: true, timeout: 60000 });
  if (res.status !== 0) throw new Error(`${args.join(' ')} failed\n${res.stdout}\n${res.stderr}`);
  return JSON.parse(res.stdout);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function main() {
  const compact = run(['tools/agent-footer.js', '--json']);
  const full = run(['tools/agent-footer.js', '--mode', 'full', '--json']);
  assert(compact.footer.includes('.knowledge: Trust'), 'compact footer missing trust summary');
  assert(compact.footer.includes('estimated system tokens'), 'compact footer must label token metrics as estimates');
  assert(compact.footer.includes('estimated context saved'), 'compact footer missing estimated context saved');
  assert(full.footer.includes('## .knowledge report'), 'full footer missing heading');
  assert(full.footer.includes('node .knowledge/inspector.js'), 'full footer missing Open Inspector command');
  console.log(JSON.stringify({ schema_version: '3.2.2', status: 'pass', checks: ['compact footer', 'full footer', 'estimated token labels', 'open inspector action'] }, null, 2));
}

try { main(); } catch (error) { console.error(error.stack || error.message); process.exit(1); }
