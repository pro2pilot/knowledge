'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { runAction } = require('../tools/lib/action-runner');
const { MAX_CHILD_JSON_BYTES } = require('../tools/lib/semantic-json');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-action-evidence-'));
  const targetRoot = path.join(root, 'проект с пробелами');
  const stateRoot = path.join(targetRoot, '.knowledge');
  const systemRoot = path.join(root, 'system');
  fs.mkdirSync(stateRoot, { recursive: true });
  fs.mkdirSync(path.join(systemRoot, 'tools'), { recursive: true });
  const context = { mode: 'repo', targetRoot, stateRoot, systemRoot,
    projectKnowledgeRoot: stateRoot, agentId: 'action-evidence-test',
    repoId: 'action-evidence-test', warnings: [], git: { changed_files: [] } };
  const marker = path.join(root, 'child-executed');
  const script = path.join(systemRoot, 'tools/doctor.js');
  function doctor(body) { fs.writeFileSync(script, body); }
  doctor(`require('fs').writeFileSync(${JSON.stringify(marker)}, 'executed');\nconsole.log('{"status":"pass"}');\n`);
  return { root, context, marker, doctor, cleanup() { fs.rmSync(root, { recursive: true, force: false }); } };
}

function outsideLog(f, kind) {
  const outside = path.join(f.root, 'outside');
  fs.mkdirSync(outside);
  const sentinel = path.join(outside, 'sentinel');
  fs.writeFileSync(sentinel, 'original\n');
  const logRoot = path.join(f.context.stateRoot, 'maintenance/action-runs');
  fs.mkdirSync(path.dirname(logRoot), { recursive: true });
  if (kind === 'directory-link') {
    fs.symlinkSync(outside, logRoot, process.platform === 'win32' ? 'junction' : 'dir');
  } else {
    fs.mkdirSync(logRoot);
    const journal = path.join(logRoot, `${new Date().toISOString().slice(0, 10)}.ndjson`);
    if (kind === 'file-link') fs.symlinkSync(sentinel, journal);
    else fs.linkSync(sentinel, journal);
  }
  return { outside, sentinel, logRoot };
}

test('Inspector accepts the same complete 2 MiB report as flow and evaluation', () => {
  const f = fixture();
  try {
    f.doctor("process.stdout.write(JSON.stringify({status:'pass',payload:'x'.repeat(2*1024*1024)}));\n");
    const result = runAction(f.context, 'doctor.run');
    assert.equal(result.status, 'passed', JSON.stringify(result.errors));
    assert.equal(JSON.parse(fs.readFileSync(result.stdout_path, 'utf8')).payload.length, 2 * 1024 * 1024);
    assert.equal(JSON.parse(fs.readFileSync(path.join(path.dirname(result.stdout_path), 'run.json'), 'utf8')).status, 'passed');
  } finally { f.cleanup(); }
});

test('Inspector keeps an explicit bounded failure for oversized output', () => {
  const f = fixture();
  try {
    f.doctor(`process.stdout.write(JSON.stringify({status:'pass',payload:'x'.repeat(${MAX_CHILD_JSON_BYTES + 1024 * 1024})}));\n`);
    const result = runAction(f.context, 'doctor.run');
    assert.equal(result.status, 'failed');
    assert(result.errors.some(row => row.reason === 'spawn_error'));
  } finally { f.cleanup(); }
});

test('Inspector never persists a raw child JSON parser excerpt alongside masked output', () => {
  const f = fixture();
  try {
    const syntheticSecret = 'sk_TESTVALUE12345678901234567890';
    f.doctor(`process.stdout.write(${JSON.stringify(syntheticSecret)});\n`);
    const result = runAction(f.context, 'doctor.run');
    assert.equal(result.status, 'failed');
    assert.equal(result.exit_code, 0);
    assert.deepEqual(result.semantic_errors, ['invalid_action_json']);
    const journal = path.join(f.context.stateRoot, 'maintenance/action-runs', `${result.queued_at.slice(0, 10)}.ndjson`);
    for (const text of [JSON.stringify(result), fs.readFileSync(journal, 'utf8'),
      fs.readFileSync(path.join(path.dirname(result.stdout_path), 'run.json'), 'utf8'),
      fs.readFileSync(result.stdout_path, 'utf8')]) {
      assert(!text.includes('sk_TESTVAL'), 'A parser excerpt bypassed stdout masking');
    }
  } finally { f.cleanup(); }
});

for (const kind of ['directory-link', 'file-link', 'hardlink']) {
  test(`unsafe action journal ${kind} is rejected before the command runs`, () => {
    const f = fixture();
    try {
      const out = outsideLog(f, kind);
      assert.throws(() => runAction(f.context, 'doctor.run'), error => error.code === 'contained_path_unsafe');
      assert.equal(fs.existsSync(f.marker), false);
      assert.equal(fs.readFileSync(out.sentinel, 'utf8'), 'original\n');
      assert.deepEqual(fs.readdirSync(out.outside), ['sentinel']);
    } finally { f.cleanup(); }
  });
}

test('a log-directory replacement during the child cannot redirect evidence writes', () => {
  const f = fixture();
  try {
    const outside = path.join(f.root, 'outside');
    const logRoot = path.join(f.context.stateRoot, 'maintenance/action-runs');
    fs.mkdirSync(outside);
    const sentinel = path.join(outside, 'sentinel');
    fs.writeFileSync(sentinel, 'original\n');
    f.doctor(`const fs=require('fs'); fs.mkdirSync(${JSON.stringify(path.dirname(logRoot))},{recursive:true});
fs.rmSync(${JSON.stringify(logRoot)},{recursive:true,force:true});
fs.symlinkSync(${JSON.stringify(outside)},${JSON.stringify(logRoot)},${JSON.stringify(process.platform === 'win32' ? 'junction' : 'dir')});
console.log('{"status":"pass"}');\n`);
    assert.throws(() => runAction(f.context, 'doctor.run'), error => error.code === 'contained_path_unsafe');
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'original\n');
    assert.deepEqual(fs.readdirSync(outside), ['sentinel']);
  } finally { f.cleanup(); }
});

test('safe blocked-action evidence remains complete under concurrent processes', async () => {
  const f = fixture();
  try {
    const worker = path.join(f.root, 'worker.js');
    fs.writeFileSync(worker, `const {runAction}=require(${JSON.stringify(require.resolve('../tools/lib/action-runner'))});
const result=runAction(JSON.parse(process.argv[2]),'unknown.action');
process.stdout.write(JSON.stringify({id:result.run_id,status:result.status}));\n`);
    const results = await Promise.all(Array.from({ length: 8 }, () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [worker, JSON.stringify(f.context)], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
      let stdout = '', stderr = '';
      child.stdout.on('data', chunk => { stdout += chunk; });
      child.stderr.on('data', chunk => { stderr += chunk; });
      child.once('error', reject);
      child.once('close', (code, signal) => {
        try { assert.equal(code, 0, stderr); assert.equal(signal, null); resolve(JSON.parse(stdout)); } catch (error) { reject(error); }
      });
    })));
    const file = path.join(f.context.stateRoot, 'maintenance/action-runs', `${new Date().toISOString().slice(0, 10)}.ndjson`);
    const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(rows.length, results.length);
    assert.deepEqual(new Set(rows.map(row => row.run_id)), new Set(results.map(row => row.id)));
    assert(rows.every(row => row.status === 'blocked'));
    assert.equal(fs.existsSync(f.marker), false);
  } finally { f.cleanup(); }
});

function restoreFixture(f, output, large = false) {
  const names = ['sync-tracked', 'build-wiki-graph', 'lint-wiki', 'external-memory-status',
    'build-routing-bundle', 'build-search-index', 'build-visual-inspector', 'scan-secrets', 'doctor'];
  for (const name of names) fs.writeFileSync(path.join(f.context.systemRoot, 'tools', `${name}.js`), "console.log('{\"status\":\"pass\"}');\n");
  fs.writeFileSync(path.join(f.context.systemRoot, 'package.json'), '{"version":"3.4.4"}\n');
  fs.writeFileSync(path.join(f.context.systemRoot, 'tools/build-visual-inspector.js'), large
    ? "process.stdout.write(JSON.stringify({status:'pass',payload:'x'.repeat(2*1024*1024)}));\n"
    : `process.stdout.write(${JSON.stringify(output)});\n`);
  return spawnSync(process.execPath, [require.resolve('../tools/restore-trust'), '--safe', '--json',
    '--target-root', f.context.targetRoot, '--project-knowledge-root', f.context.stateRoot,
    '--state-root', f.context.stateRoot, '--system-root', f.context.systemRoot], {
    cwd: f.context.targetRoot, encoding: 'utf8', windowsHide: true, maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' }
  });
}

test('Restore Trust accepts a valid large structured Inspector report', () => {
  const f = fixture();
  try {
    const result = restoreFixture(f, '', true);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, 'passed');
  } finally { f.cleanup(); }
});

for (const [label, output] of [['negative', '{"status":"failed","ok":false}'], ['malformed', '{"status":']]) {
  test(`Restore Trust rejects ${label} JSON despite child exit zero`, () => {
    const f = fixture();
    try {
      const result = restoreFixture(f, output);
      assert.equal(result.status, 2, result.stderr);
      const report = JSON.parse(result.stdout);
      assert.equal(report.status, 'failed');
      const step = report.steps.find(row => row.name === 'inspector');
      assert.equal(step.exit_code, 0);
      assert.equal(step.status, 'failed');
      assert.equal(step.semantic_pass, false);
      assert(step.semantic_errors.length > 0);
    } finally { f.cleanup(); }
  });
}
