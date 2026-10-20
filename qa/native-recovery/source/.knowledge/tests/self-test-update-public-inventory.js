#!/usr/bin/env node
'use strict';

// Offline source-only regression. The canonical packager supplies the public
// inventory; the updater must use the same inventory from source or ZIP.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const source = path.resolve(process.env.KNOWLEDGE_UPDATE_INVENTORY_SOURCE || path.join(__dirname, '..'));
const parent = path.resolve(process.env.KNOWLEDGE_UPDATE_INVENTORY_TMP || os.tmpdir());
const evidence = process.env.KNOWLEDGE_UPDATE_INVENTORY_EVIDENCE ? path.resolve(process.env.KNOWLEDGE_UPDATE_INVENTORY_EVIDENCE) : null;
fs.mkdirSync(parent, { recursive: true });
if (evidence) fs.mkdirSync(evidence, { recursive: true });
const root = fs.mkdtempSync(path.join(parent, 'update-public-inventory-'));
const full = path.join(root, 'full-source/.knowledge');
const publicRoot = path.join(root, 'public-zip/.knowledge');
const project = path.join(root, 'installed-project');
const installed = path.join(project, '.knowledge');
const checks = [], commands = [], overrides = [];
const digest = data => crypto.createHash('sha256').update(data).digest('hex');
const fileHash = file => digest(fs.readFileSync(file));
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function check(name, action) {
  const began = process.hrtime.bigint();
  try { const observation = action(); checks.push({ name, status: 'pass', observation, duration_ms: Number(process.hrtime.bigint() - began) / 1e6 }); }
  catch (error) { checks.push({ name, status: 'fail', error: error.message, stack: error.stack, duration_ms: Number(process.hrtime.bigint() - began) / 1e6 }); }
}
function node(args, cwd = project) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^KNOWLEDGE_/i.test(key) || key === 'NODE_OPTIONS') delete env[key];
  Object.assign(env, { TMPDIR: parent, TEMP: parent, TMP: parent, GIT_CEILING_DIRECTORIES: root,
    KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
    KNOWLEDGE_AGENT_ID: 'update-public-inventory', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1' });
  const start = process.hrtime.bigint(), stamp = new Date().toISOString();
  const child = spawnSync(process.execPath, args, { cwd, env, encoding: 'utf8', timeout: 120000, maxBuffer: 32 * 1024 * 1024 });
  const index = String(commands.length + 1).padStart(3, '0');
  const result = { argv: [process.execPath, ...args], cwd, started_at: stamp, duration_ms: Number(process.hrtime.bigint() - start) / 1e6,
    status: child.status, signal: child.signal, error: child.error ? { code: child.error.code || null, message: child.error.message } : null,
    stdout_sha256: digest(child.stdout || ''), stderr_sha256: digest(child.stderr || '') };
  if (evidence) for (const stream of ['stdout', 'stderr']) { result[`${stream}_path`] = `${index}.${stream}.log`; write(path.join(evidence, result[`${stream}_path`]), child[stream] || ''); }
  commands.push(result);
  let json = null;
  try { json = JSON.parse(child.stdout); } catch { /* Captured below with raw streams. */ }
  return { ...child, json };
}
function success(result) {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.signal, null);
  assert.equal(result.status, 0, result.stderr || JSON.stringify(result.json));
  assert(result.json); return result.json;
}
function update(from, args) { return node([path.join(installed, 'tools/update-system-files.js'), '--from', from, ...args, '--json']); }
function plannedFiles(actions) {
  return [...new Set(actions.filter(row => row.kind !== 'directory' && row.action !== 'remove' && row.reason !== 'project_specific')
    .map(row => row.path))].sort();
}
const preserved = ['wiki/operator-note.md', 'modules/operator-note.json', 'maintenance/verification_receipts/operator-evidence.json',
  'maintenance/knowledge_currency/receipts/operator-evidence.json', 'settings/operator-profile.json'];
const preservationHashes = () => Object.fromEntries(preserved.map(relative => [relative, fileHash(path.join(installed, relative))]));
const start = process.hrtime.bigint();
let canonicalNames = [], zipSha = null, preserveBefore = null;
try {
  fs.cpSync(source, full, { recursive: true });
  const config = path.join(full, 'config.yaml'), before = fileHash(config);
  const configText = fs.readFileSync(config, 'utf8');
  const offlineText = configText.replace(/(updates:\s*\r?\n\s+enabled:)\s*true/, '$1 false');
  assert(/updates:\s*\r?\n\s+enabled:\s*false/.test(offlineText), 'offline updates override missing');
  write(config, offlineText);
  overrides.push({ path: config, before_sha256: before, after_sha256: fileHash(config), setting: 'updates.enabled', value: false });
  const packager = require(path.join(full, 'tools/package-release.js'));
  const validator = require(path.join(full, 'tools/validate-release-artifact.js'));
  const release = require(path.join(full, 'tools/lib/release-contract.js'));
  const contract = release.loadReleaseContract(full);
  const packageEntries = packager.buildPackageEntries(full).entries;
  const zip = path.join(root, `knowledge-v${read(path.join(full, 'package.json')).version}.zip`);
  packager.createZip(packageEntries, zip); zipSha = fileHash(zip);
  const archive = validator.readZipEntries(zip);
  assert.deepEqual(archive.violations, []);
  assert.deepEqual(release.validateReleaseInventory(archive.entries, contract).violations, []);
  canonicalNames = archive.entries.map(entry => entry.name.replace(/^\.knowledge\//, '')).sort();
  for (const entry of archive.entries) {
    const relative = entry.name.replace(/^\.knowledge\//, '');
    assert(entry.name.startsWith('.knowledge/') && relative && !relative.split('/').includes('..'));
    write(path.join(publicRoot, relative), entry.body);
  }
  fs.cpSync(publicRoot, installed, { recursive: true });
  write(path.join(project, 'package.json'), { name: 'update-public-inventory-fixture', version: '1.0.0' });
  write(path.join(project, 'src/app.js'), 'module.exports = 1;\n');
  write(path.join(project, 'README.md'), '# Offline update inventory fixture\n');
  const updater = require(path.join(installed, 'tools/update-system-files.js'));
  const extras = ['tools/lib/release-contract.js', 'tools/self-test-agent-integration-coexistence.js', 'tools/self-test-install-policy.js'];

  check('canonical ZIP inventory excludes source-only updater leak controls', () => {
    for (const relative of extras) { assert(fs.existsSync(path.join(full, relative))); assert(!canonicalNames.includes(relative)); }
    assert(canonicalNames.includes('tools/doctor.js')); return { canonical_files: canonicalNames.length, excluded_controls: extras, zip_sha256: zipSha };
  });
  check('full-source update plan has exactly the canonical public file inventory', () => {
    const manifest = updater.loadInstallManifest(full);
    const actions = updater.planActions(full, { targetKnowledgeRoot: installed, manifest });
    const files = plannedFiles(actions);
    assert.deepEqual(files, canonicalNames); return { files: files.length, actions: actions.length };
  });
  check('physical dry-run --from full source and extracted public ZIP plan the same files', () => {
    const publicReport = success(update(publicRoot, ['--dry-run']));
    const sourceReport = success(update(full, ['--dry-run']));
    assert.deepEqual(plannedFiles(publicReport.actions), canonicalNames);
    assert.deepEqual(plannedFiles(sourceReport.actions), canonicalNames);
    return { public_status: publicReport.status, source_status: sourceReport.status, files: canonicalNames.length };
  });
  check('system completeness gate accepts the same canonical install from source and ZIP', () => {
    const publicReport = updater.verifySystemCompleteness(publicRoot, updater.loadInstallManifest(publicRoot));
    const sourceReport = updater.verifySystemCompleteness(full, updater.loadInstallManifest(full));
    assert.equal(publicReport.status, 'ok', JSON.stringify(publicReport));
    assert.equal(sourceReport.status, 'ok', JSON.stringify(sourceReport));
    assert.equal(sourceReport.checked_system_files, publicReport.checked_system_files); return { public: publicReport, source: sourceReport };
  });
  check('declared source-only paths constrain inventory without a hardcoded filename list', () => {
    const isolated = path.join(root, 'declared-paths/.knowledge'); fs.cpSync(full, isolated, { recursive: true });
    const manifestPath = path.join(isolated, 'install-manifest.json'), raw = read(manifestPath);
    const declared = ['tools/custom-source-test.js', 'docs/custom-source-document.md', 'tools/custom-maintainer.js'];
    for (const [field, relative] of ['source_only_test_paths', 'source_only_document_paths', 'maintainer_tool_paths'].map((field, index) => [field, declared[index]])) {
      raw.release_contract[field] = [...(raw.release_contract[field] || []), relative]; write(path.join(isolated, relative), 'source-only fixture\n');
    }
    write(manifestPath, raw);
    const actions = updater.planActions(isolated, { targetKnowledgeRoot: installed, manifest: updater.loadInstallManifest(isolated) });
    assert(!actions.some(row => declared.includes(row.path))); return { excluded_declared_paths: declared };
  });
  check('malformed release inventory constraints are rejected at manifest admission', () => {
    const isolated = path.join(root, 'bad-contract'); fs.mkdirSync(isolated);
    const base = read(path.join(full, 'install-manifest.json'));
    const invalid = [null, [], 'text', { source_only_test_paths: 'tools/private.js' }, { source_only_test_paths: [null] },
      { source_only_test_paths: ['../outside'] }, { maintainer_tool_paths: ['/outside'] },
      { source_only_document_paths: ['docs//private.md'] }, { maintainer_tool_paths: ['tools/*.js'] },
      { source_only_test_paths: ['tools/Test.js', 'tools/test.js'] }];
    for (const release_contract of invalid) { write(path.join(isolated, 'install-manifest.json'), { ...base, release_contract }); assert.throws(() => updater.loadInstallManifest(isolated)); }
    return { rejected_variants: invalid.length };
  });
  check('release exclusions cannot waive mandatory runtime or declared public files', () => {
    const isolated = path.join(root, 'required-conflict'); fs.mkdirSync(isolated);
    const base = read(path.join(full, 'install-manifest.json'));
    for (const relative of ['tools/doctor.js', 'tools/explicit-public-required.js']) {
      const raw = JSON.parse(JSON.stringify(base));
      raw.release_contract.maintainer_tool_paths.push(relative);
      if (relative.includes('explicit-public')) raw.release_contract.required_public_paths.push(relative);
      write(path.join(isolated, 'install-manifest.json'), raw);
      assert.throws(() => updater.loadInstallManifest(isolated), /required.*exclud|exclud.*required/i);
    }
  });
  check('legacy manifest without release_contract retains mandatory built-in policy', () => {
    const isolated = path.join(root, 'legacy-manifest'); fs.mkdirSync(isolated);
    const raw = read(path.join(full, 'install-manifest.json')); delete raw.release_contract;
    write(path.join(isolated, 'install-manifest.json'), raw);
    const manifest = updater.loadInstallManifest(isolated);
    assert(manifest.required_system_files.includes('tools/doctor.js')); assert(manifest.system_paths.includes('tools'));
  });
  check('a physically missing mandatory Doctor remains a failed source gate', () => {
    const isolated = path.join(root, 'missing-required/.knowledge'); fs.cpSync(publicRoot, isolated, { recursive: true });
    fs.unlinkSync(path.join(isolated, 'tools/doctor.js'));
    const result = update(isolated, ['--dry-run']);
    assert(!result.error && !result.signal); assert.notEqual(result.status, 0); assert(result.json.errors.some(error => /tools\/doctor\.js/.test(error)));
    return { status: result.status, errors: result.json.errors };
  });
  check('physical public install initializes normally before same-gate verification', () => {
    return success(node([path.join(installed, 'tools/flow.js'), 'import', '--json', '--no-color']));
  });
  for (const relative of preserved) write(path.join(installed, relative), relative.endsWith('.md') ? '# Operator note remains\n' : { fixture: 'operator-owned preserved bytes' });
  preserveBefore = preservationHashes();
  check('physical --verify-upgrade accepts both --from forms on the same public runtime', () => {
    const publicReport = success(update(publicRoot, ['--verify-upgrade']));
    const sourceReport = success(update(full, ['--verify-upgrade']));
    assert.equal(publicReport.system_completeness.status, 'ok'); assert.equal(sourceReport.system_completeness.status, 'ok');
    assert.equal(sourceReport.system_completeness.checked_system_files, publicReport.system_completeness.checked_system_files);
    return { public_status: publicReport.status, source_status: sourceReport.status, public_completeness: publicReport.system_completeness, source_completeness: sourceReport.system_completeness };
  });
  check('physical full-source apply does not install source-only artifacts or delete user state', () => {
    const report = success(update(full, ['--apply', '--yes', '--post-upgrade-trust-refresh', 'none']));
    assert.equal(report.system_completeness.status, 'ok');
    for (const relative of extras) assert(!fs.existsSync(path.join(installed, relative)), `source-only artifact was installed: ${relative}`);
    assert.deepEqual(preservationHashes(), preserveBefore);
    assert.equal(report.curated_preservation_proof.changed_files_count, 0);
    assert.equal(report.runtime_preservation_proof.status, 'preserved');
    return { status: report.status, preserved_sha256: preserveBefore, summary: report.summary };
  });
  check('source-only declarations never schedule deletion of existing target-only material', () => {
    const relative = 'tools/lib/release-contract.js';
    write(path.join(installed, relative), 'operator-retained source note\n');
    const before = fileHash(path.join(installed, relative));
    const actions = updater.planActions(full, { targetKnowledgeRoot: installed, manifest: updater.loadInstallManifest(full) });
    assert(!actions.some(action => action.path === relative));
    assert.equal(fileHash(path.join(installed, relative)), before);
    assert.deepEqual(preservationHashes(), preserveBefore); return { preserved_target_only_sha256: before };
  });
} catch (error) { checks.push({ name: 'fixture setup or dependency', status: 'fail', error: error.message, stack: error.stack }); }
const result = { status: checks.every(row => row.status === 'pass') ? 'pass' : 'fail', checks_total: checks.length,
  checks_passed: checks.filter(row => row.status === 'pass').length, duration_ms: Number(process.hrtime.bigint() - start) / 1e6,
  node: process.execPath, node_version: process.version, source_root: source, fixture_root: root, canonical_files: canonicalNames.length,
  canonical_zip_sha256: zipSha, canonical_inventory: canonicalNames, overrides, commands, checks,
  evidence_kind: 'isolated offline public/source inventory regression; fixture data is not verification authority' };
if (evidence) write(path.join(evidence, 'result.json'), result);
console.log(JSON.stringify(result, null, 2));
if (!process.argv.includes('--keep-temp')) fs.rmSync(root, { recursive: true, force: false });
if (result.status !== 'pass') process.exitCode = 1;
