'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const source = path.resolve(__dirname, '..');

function fixture(kind) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-child-'));
  const state = path.join(root, '.knowledge');
  fs.mkdirSync(path.join(state, 'tools'), { recursive: true });
  fs.cpSync(path.join(source, 'tools/lib'), path.join(state, 'tools/lib'), { recursive: true });
  for (const file of ['tools/update-system-files.js', 'tools/migrate-legacy-release-gate.js', 'package.json']) {
    fs.copyFileSync(path.join(source, file), path.join(state, file));
  }
  fs.writeFileSync(path.join(state, 'tools/install-check.js'), "console.log('{\"status\":\"pass\"}');\n");
  fs.writeFileSync(path.join(state, 'tools/doctor.js'),
    "process.stdout.write(JSON.stringify({status:'pass',payload:'x'.repeat(2*1024*1024)}));\n");
  const args = [];
  if (kind !== 'large') {
    const value = kind === 'error' ? { code: 'EPERM', message: 'deterministic transport fixture' } : 'SIGTERM';
    const preload = path.join(root, 'transport.cjs');
    fs.writeFileSync(preload, `const cp=require('child_process'); const original=cp.spawnSync;
cp.spawnSync=function(file,args,options){
if(require('path').basename(String(args?.[0]||''))==='doctor.js') return {status:0,stdout:'{"status":"pass"}',stderr:'',${kind}:${JSON.stringify(value)}};
return original.call(this,file,args,options);};\n`);
    args.push('--require', preload);
  }
  args.push(path.join(state, 'tools/update-system-files.js'), '--verify-upgrade', '--target', state, '--json');
  const run = spawnSync(process.execPath, args, { cwd: root, encoding: 'utf8', timeout: 15000, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' } });
  try {
    assert(!run.error, run.error?.message);
    assert.equal(run.signal, null);
    const report = JSON.parse(run.stdout);
    const doctor = report.post_checks.find(row => row.label === 'doctor');
    assert(doctor, run.stdout);
    return doctor;
  } finally { fs.rmSync(root, { recursive: true, force: false }); }
}

test('updater post-check accepts a complete valid 2 MiB Doctor report', () => {
  const doctor = fixture('large');
  assert.equal(doctor.success, true, JSON.stringify(doctor.semantic_errors));
  assert.equal(doctor.json_status, 'pass');
});

for (const kind of ['error', 'signal']) {
  test(`updater post-check rejects exit zero with a transport ${kind}`, () => {
    const doctor = fixture(kind);
    assert.equal(doctor.success, false);
    assert.equal(doctor.exit, 0);
    assert.equal(doctor.process_success, false);
    assert(doctor.semantic_errors.length > 0);
    if (kind === 'error') assert.equal(doctor.spawn_error.code, 'EPERM');
    else assert.equal(doctor.signal, 'SIGTERM');
  });
}
