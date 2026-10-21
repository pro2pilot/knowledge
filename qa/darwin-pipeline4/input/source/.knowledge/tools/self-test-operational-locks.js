#!/usr/bin/env node
'use strict';
// Source-only offline regression entrypoint. Every fixture belongs to this run.
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');
const source = path.resolve(__dirname, '..');
const tests = path.join(source, 'tests/operational-locks');
const requested = process.argv.find(v => v.startsWith('--group='))?.slice(8) || 'all';
const groups = ['doctor', 'registry', 'flow-contract', 'team-cli', 'manager-authority'];
if (!['all', ...groups].includes(requested)) throw new Error('Unknown group');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-operational-'));
const results = [];
try {
  for (const group of groups.filter(v => requested === 'all' || requested === v)) {
    const args = group === 'doctor'
      ? ['--system-root', source, '--output', path.join(root, 'doctor-out'), '--work', path.join(root, 'doctor-work')]
      : group === 'manager-authority' ? [`--source=${source}`]
      : [source, path.join(root, group), ...(group === 'team-cli' ? [path.join(tests, 'release-obstruction.cjs')] : [])];
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(?:KNOWLEDGE_|NODE_|GIT_)/.test(k)));
    Object.assign(env, { KNOWLEDGE_AGENT_ID: 'operational-locks-test', KNOWLEDGE_FLOW_NO_OPEN: '1', CI: 'true' });
    const argv = [path.join(tests, `${group}.cjs`), ...args];
    const r = spawnSync(process.execPath, argv, { env, cwd: root, encoding: 'utf8', timeout: 240000, windowsHide: true, maxBuffer: 24*1024*1024 });
    let report; try { report = JSON.parse(r.stdout); } catch { report = null; }
    if (group === 'doctor' && fs.existsSync(path.join(root, 'doctor-out/summary.json'))) {
      report = JSON.parse(fs.readFileSync(path.join(root, 'doctor-out/summary.json'), 'utf8'));
    }
    results.push({ group, argv, exit: r.status, signal: r.signal, error: r.error?.code || null, stderr: r.stderr,
      status: r.status === 0 && report?.status === 'pass' ? 'pass' : 'fail', report,
      ...(!report ? { stdout: r.stdout } : {}) });
  }
} finally {
  const absolute = path.resolve(root);
  if (path.dirname(absolute) !== path.resolve(os.tmpdir()) || !path.basename(absolute).startsWith('knowledge-operational-')) throw new Error('Unsafe test cleanup root');
  removeTempDirStrict(absolute, { label: 'operational lock test fixtures' });
}
const failed = results.filter(v => v.status !== 'pass').length;
console.log(JSON.stringify({ status: failed ? 'fail' : 'pass', total: results.length, passed: results.length-failed, cleanup: 'completed', results }, null, 2));
process.exitCode = failed ? 1 : 0;
