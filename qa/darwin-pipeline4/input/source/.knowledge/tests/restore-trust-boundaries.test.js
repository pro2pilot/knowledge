'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const restore = require.resolve('../tools/restore-trust');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-restore-boundary-'));
  const project = path.join(root, 'проект с пробелами');
  const state = path.join(project, '.knowledge');
  const system = path.join(root, 'system');
  const marker = path.join(root, 'child-ran');
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(path.join(system, 'tools'), { recursive: true });
  fs.writeFileSync(path.join(system, 'package.json'), '{"version":"3.4.4"}\n');
  for (const name of ['sync-tracked', 'build-wiki-graph', 'lint-wiki', 'external-memory-status',
    'build-routing-bundle', 'build-search-index', 'build-visual-inspector', 'scan-secrets', 'doctor']) {
    fs.writeFileSync(path.join(system, 'tools', name + '.js'),
      `require('fs').writeFileSync(${JSON.stringify(marker)}, 'ran');\nconsole.log('{"status":"pass"}');\n`);
  }
  const args = ['--safe', '--json', '--target-root', project, '--project-knowledge-root', state,
    '--state-root', state, '--system-root', system];
  function run(driver = null) {
    const result = spawnSync(process.execPath, driver ? [driver] : [restore, ...args], {
      cwd: project, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' }
    });
    assert(!result.error, result.error?.message);
    assert.equal(result.signal, null);
    return result;
  }
  return { root, state, system, marker, args, run, cleanup() { fs.rmSync(root, { recursive: true, force: false }); } };
}

for (const field of ['error', 'signal']) {
  test(`Restore Trust rejects status zero with a transport ${field}`, () => {
    const f = fixture();
    try {
      const value = field === 'error' ? { code: 'EPERM', message: 'deterministic transport fixture' } : 'SIGTERM';
      const driver = path.join(f.root, 'driver.js');
      fs.writeFileSync(driver, `const cp=require('child_process');
cp.spawnSync=()=>({status:0,stdout:'{"status":"pass"}',stderr:'',${field}:${JSON.stringify(value)}});
require(${JSON.stringify(restore)}).main(${JSON.stringify(f.args)});\n`);
      const result = f.run(driver);
      assert.equal(result.status, 2, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.status, 'failed');
      assert(report.steps.every(step => step.process_success === false && step.status === 'failed'));
      assert.equal(report.steps[0][field === 'error' ? 'spawn_error' : 'signal']?.code || report.steps[0].signal,
        field === 'error' ? 'EPERM' : 'SIGTERM');
    } finally { f.cleanup(); }
  });
}

test('Restore Trust keeps text output valid for steps without a JSON contract', () => {
  const f = fixture();
  try {
    for (const name of ['sync-tracked', 'build-wiki-graph', 'lint-wiki', 'build-routing-bundle', 'build-search-index']) {
      fs.writeFileSync(path.join(f.system, 'tools', name + '.js'), "console.log('Local rebuild completed.');\n");
    }
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, 'passed');
  } finally { f.cleanup(); }
});

for (const target of ['directory', 'json-symlink', 'json-hardlink', 'md-symlink', 'md-hardlink']) {
  test(`Restore Trust rejects an unsafe ${target} report destination before any child`, () => {
    const f = fixture();
    try {
      const outside = path.join(f.root, 'outside');
      fs.mkdirSync(outside);
      const sentinel = path.join(outside, 'sentinel');
      fs.writeFileSync(sentinel, 'original\n');
      const maintenance = path.join(f.state, 'maintenance');
      if (target === 'directory') fs.symlinkSync(outside, maintenance, process.platform === 'win32' ? 'junction' : 'dir');
      else {
        fs.mkdirSync(maintenance);
        const file = path.join(maintenance, 'restore-trust-report.' + target.split('-')[0]);
        if (target.endsWith('hardlink')) fs.linkSync(sentinel, file);
        else fs.symlinkSync(sentinel, file);
      }
      const result = f.run();
      assert.equal(result.status, 1, result.stderr);
      assert.equal(fs.existsSync(f.marker), false, 'unsafe report destination was checked after child effects');
      assert.equal(fs.readFileSync(sentinel, 'utf8'), 'original\n');
      assert.deepEqual(fs.readdirSync(outside), ['sentinel']);
    } finally { f.cleanup(); }
  });
}

test('Inspector declares Doctor report and queue refresh as a local write', () => {
  const { getAction } = require('../tools/lib/action-registry');
  assert.equal(getAction('doctor.run').risk, 'local_write');
});
