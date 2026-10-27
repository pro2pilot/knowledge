'use strict';

// Portable guard-contract tests. These deliberately do not claim macOS native
// ownership, ACL protection, RUID containment, or lifecycle execution coverage.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const envelope = path.join(root, 'tools/lib/macos-worker-envelope.js');

function run(source, { before = '', expected = 0 } = {}) {
  const result = spawnSync(process.execPath, ['-e', `${before}\nconst guard = require(${JSON.stringify(envelope)});\n` +
    `guard.install({ protectedRoot: ${JSON.stringify(root)} });\n${source}`],
  { encoding: 'utf8', timeout: 10000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, expected, result.stderr || result.stdout);
  assert.equal(result.signal, null, result.stderr || result.stdout);
  return result;
}

const denied = (expression, code) => `
  try { ${expression}; throw new Error('guard did not reject'); }
  catch (error) { if (error.code !== ${JSON.stringify(code)}) throw error; }
`;

test('macos envelope installs first, is immutable, and imports the fixed Flow/evaluation graph', () => {
  run(`
    const value = guard.install({ protectedRoot: ${JSON.stringify(root)} });
    if (!Object.isFrozen(value) || value.subprocess_policy !== 'deny_all') throw new Error('invalid policy');
    require(${JSON.stringify(path.join(root, 'tools/flow.js'))});
    require(${JSON.stringify(path.join(root, 'tools/evaluation-harness.js'))});
    require('node:fs').statSync(${JSON.stringify(envelope)});
    if (require('node:crypto').createHash('sha256').update('ok').digest('hex').length !== 64) throw new Error('crypto broken');
  `);
});

test('macos envelope rejects late package imports before any operation is admitted', () => {
  const result = run('', { before: `require(${JSON.stringify(path.join(root, 'tools/lib/inert-data.js'))});`, expected: 1 });
  assert.match(result.stderr, /macos_worker_envelope_late_install/);
});

test('macos envelope denies every child_process entrypoint, including direct ChildProcess.spawn', () => {
  for (const alias of ['child_process', 'node:child_process']) {
    for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
      run(denied(`require(${JSON.stringify(alias)})[${JSON.stringify(method)}]('not-an-executable')`, 'macos_worker_spawn_forbidden'));
    }
  }
  run(denied("new (require('node:child_process').ChildProcess)().spawn({ file: 'not-an-executable', args: [] })", 'macos_worker_spawn_forbidden'));
});

test('macos envelope cannot have subprocess guards replaced or bypassed by native process bindings', () => {
  run(`
    const child = require('node:child_process');
    if (Object.getOwnPropertyDescriptor(child, 'spawn').writable || Object.getOwnPropertyDescriptor(child, 'spawn').configurable) throw new Error('mutable guard');
    ${denied("process.binding('spawn_sync')", 'macos_worker_binding_forbidden')}
    ${denied("process._linkedBinding('process_wrap')", 'macos_worker_binding_forbidden')}
    if (process.execve) { ${denied("process.execve('/bin/false', [], {})", 'macos_worker_spawn_forbidden')} }
  `);
});

test('macos envelope denies other code-loading and worker creation surfaces', () => {
  for (const name of ['module', 'vm', 'worker_threads', 'cluster', 'inspector', 'repl', 'node:module', 'node:worker_threads']) {
    run(denied(`require(${JSON.stringify(name)})`, 'macos_worker_module_forbidden'));
  }
  run(`if (process.getBuiltinModule) { ${denied("process.getBuiltinModule('module')", 'macos_worker_module_forbidden')} }`);
});

test('macos envelope refuses repository modules before their source can execute', t => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-macos-envelope-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const marker = path.join(temporary, 'executed');
  const modulePath = path.join(temporary, 'repository.js');
  fs.writeFileSync(modulePath, `require('fs').writeFileSync(${JSON.stringify(marker)}, 'bad');\n`);
  run(denied(`require(${JSON.stringify(modulePath)})`, 'macos_worker_module_forbidden'));
  assert.equal(fs.existsSync(marker), false);
});

test('macos envelope denies arbitrary native loads even when dlopen is invoked directly', () => {
  run(denied("process.dlopen({ exports: {} }, '/tmp/untrusted-addon.node')", 'macos_worker_native_forbidden'));
  run(denied(`process.dlopen({ exports: {} }, ${JSON.stringify(path.join(root, 'tools/lib/native/other.node'))})`, 'macos_worker_native_forbidden'));
});

test('macos envelope rejects a mismatched protected root', () => {
  const result = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(envelope)}).install({ protectedRoot: '/' })`],
    { encoding: 'utf8', timeout: 10000, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' } });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /macos_worker_envelope_root_invalid/);
});
