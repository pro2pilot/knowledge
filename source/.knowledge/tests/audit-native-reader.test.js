'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const { test, before, after } = require('node:test');
const sourceRoot = process.env.KNOWLEDGE_AUDIT_SOURCE || path.join(__dirname, '..');
const sourceFile = path.join(sourceRoot, 'tools/lib/verification-darwin-stub.c');
const compiler = process.env.CC || 'cc';
const capture = process.env.KNOWLEDGE_AUDIT_CAPTURE && path.join(process.env.KNOWLEDGE_AUDIT_CAPTURE, 'stub');
function record(name, value) {
  if (!capture) return;
  fs.mkdirSync(capture, { recursive: true });
  fs.writeFileSync(path.join(capture, name), typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n');
}
const available = process.platform === 'linux' && cp.spawnSync(compiler, ['--version']).status === 0;
const options = { skip: !available ? 'Linux portable extracted-producer test requires a C compiler; not macOS qualification' : false };
let directory, executable;
function section(source, start, end) {
  const i = source.indexOf(start), j = source.indexOf(end, i + start.length);
  assert.ok(i >= 0 && j > i, `unambiguous production section ${start}`);
  return source.slice(i, j);
}
before(() => {
  if (!available) return;
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-reader-'));
  executable = path.join(directory, 'probe');
  const source = fs.readFileSync(sourceFile, 'utf8');
  let functions = section(source, 'static bool canonical(', 'static bool protected_image(');
  functions += section(source, 'static bool protected_image(', 'static bool parent_origin(');
  const template = fs.readFileSync(path.join(__dirname, 'fixtures/audit-native-reader-probe.c'), 'utf8');
  const combined = template.replace('/* EXTRACTED_PRODUCTION_FUNCTIONS */', functions);
  const probe = path.join(directory, 'probe.c'); fs.writeFileSync(probe, combined);
  const compiled = cp.spawnSync(compiler, ['-std=c11', '-O0', '-Wall', '-Wextra', '-Wno-unused-function', probe, '-o', executable], { encoding: 'utf8', timeout: 30000 });
  record('compiled-producer.c', combined);
  record('compile.stdout', compiled.stdout || ''); record('compile.stderr', compiled.stderr || '');
  record('compile.json', { compiler, args: ['-std=c11', '-O0', '-Wall', '-Wextra', '-Wno-unused-function', probe, '-o', executable], status: compiled.status, signal: compiled.signal, error: compiled.error?.code });
  assert.equal(compiled.status, 0, compiled.stderr || String(compiled.error));
});
after(() => { if (directory) fs.rmSync(directory, { recursive: true, force: true }); });
function run(mode, kind = 'file') {
  const file = path.join(directory, mode);
  if (kind === 'empty') fs.writeFileSync(file, '');
  else if (kind === 'oversized') { const fd = fs.openSync(file, 'wx', 0o600); fs.ftruncateSync(fd, 256 * 1024 * 1024 + 1); fs.closeSync(fd); }
  else if (kind === 'symlink') fs.symlinkSync('missing', file);
  else if (kind === 'fifo') { const mk = cp.spawnSync('mkfifo', [file]); assert.equal(mk.status, 0); }
  else fs.writeFileSync(file, Buffer.alloc(4096, 'a'), { mode: 0o600 });
  const child = cp.spawnSync(executable, [mode, file], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
  record(`${mode}.json`, { pid: child.pid, mode, status: child.status, signal: child.signal, error: child.error?.code, stdout: child.stdout, stderr: child.stderr });
  const note = JSON.stringify({ mode, status: child.status, signal: child.signal, error: child.error?.code, stdout: child.stdout, stderr: child.stderr });
  assert.equal(child.error, undefined, `producer must return; spawnSync killed and waited for its single owned C child: ${note}`);
  assert.equal(child.status, 0, note);
  const result = JSON.parse(child.stdout);
  if (['early-eof', 'eintr', 'growth', 'same-length', 'name-swap', 'fifo-swap'].includes(mode)) {
    assert.equal(result.hook_fired, true, `fixture must reach the intended observation boundary: ${note}`);
  }
  return result;
}
test('native image reader accepts stable regular file', options, () => { const r=run('stable');assert.equal(r.accepted,true);assert.equal(r.hashed_bytes,4096); });
test('native image reader accepts stable empty file', options, () => { const r=run('empty','empty');assert.equal(r.accepted,true);assert.equal(r.hashed_bytes,0); });
test('native image reader rejects early EOF despite unchanged size', options, () => { assert.equal(run('early-eof').accepted,false); });
test('native image reader retries a single EINTR without discarding valid data', options, () => { const r=run('eintr');assert.equal(r.accepted,true);assert.equal(r.hashed_bytes,4096); });
test('native image reader rejects growth and bounds bytes during reading', options, () => { const r=run('growth');assert.equal(r.accepted,false);assert.ok(r.read_bytes<=4097,JSON.stringify(r));assert.ok(r.hashed_bytes<=4096); });
test('native image reader rejects same-length in-place rewrite', options, () => { assert.equal(run('same-length').accepted,false); });
test('native image reader rejects named inode replacement during reading', options, () => { assert.equal(run('name-swap').accepted,false); });
test('native image reader rejects regular-to-FIFO swap without blocking open', options, () => { assert.equal(run('fifo-swap').accepted,false); });
test('native image reader rejects pre-existing FIFO', options, () => { assert.equal(run('fifo','fifo').accepted,false); });
test('native image reader rejects pre-existing symlink', options, () => { assert.equal(run('symlink','symlink').accepted,false); });
test('native image reader rejects oversized regular file before reading', options, () => { const r=run('oversized','oversized');assert.equal(r.accepted,false);assert.equal(r.read_bytes,0); });
