'use strict';
// Physical ZIP validation, not execution/qualification of the native bytes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const pack = require(path.join(root, 'tools/package-release'));
const validator = require(path.join(root, 'tools/validate-release-artifact'));
const contractAPI = require(path.join(root, 'tools/lib/release-contract'));
const cleanup = require(path.join(root, 'tools/lib/strict-temp-cleanup'));
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
test('native build workspaces and undeclared binaries are excluded by the effective release contract', () => {
  for (const relative of ['tools/lib/native/linux-x64/.build-fixture/BUILD.json',
    'tools/lib/native/win32-arm64/.command-build-fixture/a.obj',
    'tools/lib/native/linux-arm64/old-unpinned-helper', 'tools/lib/native/darwin-x64/stale.node']) {
    assert.equal(pack.shouldExclude(relative).exclude, true, relative);
  }
  for (const relative of ['tools/lib/native/linux-x64/lock-publication.node',
    'tools/lib/native/linux-x64/lock-publication.manifest.json']) assert.equal(pack.shouldExclude(relative).exclude, false);
});
test('physical ZIP validator rejects a native binary whose manifest no longer matches its bytes', t => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-package-'));
  const identity = cleanup.captureTempDirIdentity(tmp);
  t.after(() => cleanup.removeTempDirStrict(tmp, { expectedIdentity: identity }));
  const binaryName = 'tools/lib/native/linux-x64/lock-publication.node';
  const manifestName = 'tools/lib/native/linux-x64/lock-publication.manifest.json';
  const before = Buffer.from('valid fixture bytes'), after = Buffer.from('changed fixture bytes');
  const manifest = { schema_version: 'knowledge-lock-native-binary.v1', platform: 'linux', architecture: 'x64',
    napi_version: 8, binary: 'lock-publication.node',
    source_sha256: sha(fs.readFileSync(path.join(root, 'tools/native/lock-publication.c'))),
    binary_sha256: sha(before), binary_bytes: before.length };
  const entries = pack.buildPackageEntries(root).entries.filter(row => ![binaryName, manifestName].includes(row.rel));
  for (const [rel, bytes] of [[binaryName, after], [manifestName, Buffer.from(JSON.stringify(manifest))]]) {
    const absolute = path.join(tmp, path.basename(rel));fs.writeFileSync(absolute, bytes);
    entries.push({ rel, abs: absolute, name: '.knowledge/' + rel });
  }
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version;
  const archive = path.join(tmp, 'knowledge-v' + version + '.zip');pack.createZip(entries, archive);
  const result = validator.validate(archive);
  assert.ok(result.violations.some(row => row.type === 'native_binary_hash_mismatch' && row.entry === '.knowledge/' + binaryName),
    'A CRC-valid ZIP must still bind native binary bytes to the declared source and native manifest');
});
test('native inventory requires each source, binary and manifest with the exact platform schema', () => {
  const source = Buffer.from('native source fixture\n'), binary = Buffer.from('native binary fixture');
  const expected = { platform: 'linux', architecture: 'arm64', binary: 'tools/lib/native/linux-arm64/lock-publication.node',
    manifest: 'tools/lib/native/linux-arm64/lock-publication.manifest.json', source: 'tools/native/lock-publication.c',
    schema_version: 'knowledge-lock-native-binary.v1', napi_version: 8 };
  const record = { schema_version: expected.schema_version, platform: expected.platform, architecture: expected.architecture,
    binary: 'lock-publication.node', napi_version: 8, source_sha256: sha(source), binary_sha256: sha(binary), binary_bytes: binary.length };
  const entries = () => [[expected.source, source], [expected.binary, binary], [expected.manifest, Buffer.from(JSON.stringify(record))]]
    .map(([name, body]) => ({ name: '.knowledge/' + name, body }));
  const verify = rows => contractAPI.validateNativeArtifacts(rows, { native_runtime_artifacts: [expected] });
  assert.deepEqual(verify(entries()), []);
  for (let n = 0; n < 3; n++) assert.ok(verify(entries().filter((_, i) => i !== n)).some(row => row.type === 'native_artifact_missing'));
  const changed = entries();changed[0].body = Buffer.from('different native source');
  assert.ok(verify(changed).some(row => row.type === 'native_source_hash_mismatch'));
  for (const patch of [{ architecture: 'x64' }, { platform: 'darwin' }, { napi_version: 9 }, { binary: '../other.node' }]) {
    const bad = entries();bad[2].body = Buffer.from(JSON.stringify({ ...record, ...patch }));
    assert.ok(verify(bad).some(row => row.type === 'native_manifest_invalid'));
  }
});
