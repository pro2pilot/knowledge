'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const source = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const pack = require(path.join(source, 'tools/package-release'));
const validator = require(path.join(source, 'tools/validate-release-artifact'));
const store = require(path.join(source, 'tools/lib/json-store'));
const relative = `tools/lib/native/linux-${process.arch}/verification-linux-namespace`;
const enabled = process.platform === 'linux';
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-modes-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function launched(file) {
  const result = spawnSync(file, ['--identity-link'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}
test('canonical ZIP extracted by unzip launches its Linux helper with original bytes', { skip: !enabled }, t => {
  const root = fixture(t), archive = path.join(root, 'runtime.zip'), target = path.join(root, 'installed');
  pack.createZip([{ abs: path.join(source, relative), rel: relative, name: '.knowledge/' + relative }], archive);
  const extraction = spawnSync('unzip', ['-q', archive, '-d', target], { encoding: 'utf8', timeout: 10000 });
  assert.equal(extraction.error, undefined, extraction.error?.message);
  assert.equal(extraction.status, 0, extraction.stderr);
  const helper = path.join(target, '.knowledge', relative);
  assert.equal(fs.statSync(helper).mode & 0o777, 0o755);
  assert(fs.readFileSync(helper).equals(fs.readFileSync(path.join(source, relative))));
  launched(helper);
});
test('ZIP admission rejects a CRC-valid Linux helper whose execute mode was removed', { skip: !enabled }, t => {
  const root = fixture(t), archive = path.join(root, 'runtime.zip');
  pack.createZip([{ abs: path.join(source, relative), rel: relative, name: '.knowledge/' + relative }], archive);
  const bytes = fs.readFileSync(archive), eocd = bytes.length - 22, central = bytes.readUInt32LE(eocd + 16);
  bytes.writeUInt32LE((0o100644 << 16) >>> 0, central + 38);fs.writeFileSync(archive, bytes);
  const result = validator.readZipEntries(archive);
  assert(result.violations.some(row => row.type === 'native_executable_mode_invalid'));
  assert(!result.violations.some(row => row.type === 'zip_crc_mismatch'));
});
test('atomic replacement applies execute mode before publication and preserves launchability', { skip: !enabled }, t => {
  const root = fixture(t), file = path.join(root, 'helper');let observed = false;
  store.writeFileAtomicContained(file, fs.readFileSync(path.join(source, relative)), root, {
    mode: 0o755, hooks: { renameSync(from, to) {
      assert.equal(fs.statSync(from).mode & 0o777, 0o755);observed = true;fs.renameSync(from, to);
    } }
  });
  assert(observed);launched(file);
  assert.throws(() => store.writeFileAtomicContained(path.join(root, 'privileged'), 'x', root, { mode: 0o4755 }), TypeError);
  assert(!fs.existsSync(path.join(root, 'privileged')));
});
test('public updater repairs same-byte helper permissions and the installed helper starts', { skip: !enabled, timeout: 120000 }, t => {
  const root = fixture(t), project = path.join(root, 'project'), installed = path.join(project, '.knowledge');
  fs.cpSync(source, installed, { recursive: true });
  fs.mkdirSync(path.join(project, 'src'));fs.writeFileSync(path.join(project, 'src/probe.js'), 'module.exports = 1;\n');
  fs.writeFileSync(path.join(project, 'README.md'), '# Native installer fixture\n');
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'native-installer-fixture', version: '1.0.0' }));
  const config = path.join(installed, 'config.yaml');
  fs.writeFileSync(config, fs.readFileSync(config, 'utf8').replace(/(updates:\s*\r?\n\s+enabled:)\s*true/, '$1 false'));
  const helper = path.join(installed, relative);
  const env = { ...process.env, KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1' };
  const imported = spawnSync(process.execPath, [path.join(installed, 'tools/flow.js'), 'import', '--json', '--no-color'], {
    cwd: project, env, encoding: 'utf8', timeout: 60000, maxBuffer: 32 * 1024 * 1024
  });
  assert.equal(imported.error, undefined, imported.error?.message);
  assert.equal(imported.status, 0, imported.stderr || imported.stdout);
  fs.chmodSync(helper, 0o644);
  const result = spawnSync(process.execPath, [path.join(source, 'tools/update-system-files.js'), '--from', source,
    '--target', installed, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], {
    cwd: project, env, encoding: 'utf8', timeout: 100000, maxBuffer: 32 * 1024 * 1024
  });
  assert.equal(result.error, undefined, result.error?.message);assert.equal(result.signal, null);
  const report = JSON.parse(result.stdout);assert.equal(result.status, 0, JSON.stringify(report.errors));
  assert.equal(report.status, 'ok', JSON.stringify(report.errors));
  assert(report.actions.some(row => row.path === relative && row.action === 'update'));
  assert.equal(fs.statSync(helper).mode & 0o777, 0o755);launched(helper);
});
