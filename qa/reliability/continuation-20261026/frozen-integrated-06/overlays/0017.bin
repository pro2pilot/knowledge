'use strict';
// Package/installer admission checks, not native execution qualification.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), crypto = require('node:crypto');
const root = path.resolve(process.env.KNOWLEDGE_AUDIT_SOURCE_ROOT || path.join(__dirname, '..'));
const pack = require(path.join(root, 'tools/package-release'));
const installer = require(path.join(root, 'tools/update-system-files'));
const validator = require(path.join(root, 'tools/validate-release-artifact'));
const contracts = require(path.join(root, 'tools/lib/release-contract'));
const cleanup = require(path.join(root, 'tools/lib/strict-temp-cleanup'));
const files = ['macos-command-runner.js', 'macos-command-scope.js', 'macos-command-worker.js',
  'macos-lock-preflight.js', 'macos-worker-envelope.js', 'macos-workspace-protocol.js',
  'macos-workspace-session.js', 'watch-maintenance-worker.js'].map(name => 'tools/lib/' + name)
  .concat('schemas/verification-execution-observation.schema.json');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'install-manifest.json')));
const contract = contracts.loadReleaseContract(root), entries = pack.buildPackageEntries(root).entries;
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-install-completeness-'));
  const identity = cleanup.captureTempDirIdentity(directory);
  t.after(() => cleanup.removeTempDirStrict(directory, { expectedIdentity: identity }));
  return directory;
}

test('new runtime modules enter the package and installer plan with exact source hashes', t => {
  const target = fixture(t), policy = installer.loadInstallManifest(root);
  const plan = installer.planActions(root, { targetKnowledgeRoot: target, manifest: policy });
  for (const file of files) {
    assert.equal(entries.filter(entry => entry.rel === file).length, 1, file);
    assert.equal(pack.shouldExclude(file).exclude, false, file);
    const item = plan.find(action => action.path === file);
    assert.equal(item?.action, 'create', file);
    assert.equal(item.source_sha256, sha(fs.readFileSync(path.join(root, file))), file);
  }
  // Separate privileged broker/stub provisioning is not silently added to the
  // public ten-pair runtime native inventory.
  const native = manifest.release_contract.native_runtime_artifacts;
  assert.equal(native.length, 10);
  assert.equal(new Set(native.flatMap(row => [row.binary, row.manifest])).size, 20);
  assert(native.every(row => !/verification-darwin-(?:broker|stub)$/.test(row.binary)));
});

test('manifestless and reduced-manifest installer paths retain every new runtime requirement', t => {
  const directory = fixture(t);
  for (const raw of [null, { required_system_files: [] }]) {
    if (raw) fs.writeFileSync(path.join(directory, 'install-manifest.json'), JSON.stringify(raw));
    const policy = installer.loadInstallManifest(directory);
    for (const file of files) {
      assert(installer.DEFAULT_MANIFEST.required_system_files.includes(file), 'Default fallback omitted ' + file);
      assert(policy.required_system_files.includes(file), 'Manifest merge omitted ' + file);
    }
  }
});

for (const file of files) test('package and installer refuse missing required runtime module: ' + path.posix.basename(file), t => {
  const directory = fixture(t), absent = entries.filter(entry => entry.rel !== file);
  const exact = '.knowledge/' + file;
  assert(manifest.required_system_files.includes(file), 'Canonical install manifest omitted ' + file);
  const staged = contracts.validateReleaseInventory(absent, contract);
  assert(staged.violations.some(row => row.type === 'required_system_entry_missing' && row.entry === exact));
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version;
  const archive = path.join(directory, 'knowledge-v' + version + '.zip');
  pack.createZip(absent, archive);
  assert(validator.validate(archive).violations.some(row => row.type === 'required_system_entry_missing' && row.entry === exact),
    'Physical ZIP validation must name the missing runtime module, independently of other native gates');
  // The actual updater completeness gate must also refuse the missing source;
  // no simulated PID, native receipt, or replacement implementation is used.
  const result = installer.verifySystemCompleteness(directory, {
    system_paths: [], required_system_files: [file], system_exclude_paths: [],
    system_remove_paths: [], legacy_compatible_remove_paths: []
  });
  assert.equal(result.status, 'failed');assert.deepEqual(result.source_missing_system_paths, [file]);
});
