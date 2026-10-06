#!/usr/bin/env node
'use strict';
const assert = require('assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const updater = require('./update-system-files');
const systemRoot = path.resolve(__dirname, '..');
const releaseManifest = JSON.parse(fs.readFileSync(path.join(systemRoot, 'install-manifest.json'), 'utf8'));
const releaseContract = releaseManifest.release_contract;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-update-safety-'));
const checks = [];
let passed = false;
const check = (name, fn) => { fn(); checks.push(name); };
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); };
const digest = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const manifest = { system_paths: ['tools'], project_preserve_paths: [], system_exclude_paths: [], system_remove_paths: [], legacy_compatible_remove_paths: [], repair_default_paths: ['external_memory/registry.json', 'external_memory/retrieval_policy.json'] };
function copyInstallInput(destination) {
  // A clean install must not inherit the maintainer project's tracked files,
  // module cards, evidence or prior gate output. Use the shipped inventory
  // contract in both source-checkout and packaged replay runs.
  // Read shipped policy data directly: the packaging implementation is
  // deliberately maintainer-only and is absent from an installed artifact.
  const exclusions = [...releaseManifest.system_exclude_paths, ...['source_only_test_paths', 'source_only_document_paths', 'maintainer_tool_paths', 'runtime_state_prefixes']
    .flatMap(key => releaseContract[key] || [])];
  const matches = (relative, rule) => rule.endsWith('/')
    ? relative === rule.slice(0, -1) || relative.startsWith(rule)
    : relative === rule;
  fs.cpSync(systemRoot, destination, { recursive: true, filter(file) {
    const relative = path.relative(systemRoot, file).replace(/\\/g, '/');
    if (!relative) return true;
    if (exclusions.some(rule => matches(relative, rule))) return false;
    if (relative.startsWith('.release-notes/')) return releaseContract.public_release_note_paths.includes(relative);
    const allowed = relative === 'agent-integrations' || relative.startsWith('agent-integrations/')
      ? releaseContract.public_agent_integration_paths
      : releaseContract.system_include_paths;
    return allowed.some(rule => {
      const normalized = rule.replace(/\/$/, '');
      return relative === normalized || relative.startsWith(normalized + '/') || normalized.startsWith(relative + '/');
    });
  } });
}
function small(name) { const src = path.join(root, name, 'source/.knowledge'); const dst = path.join(root, name, 'target/.knowledge'); write(path.join(src, 'tools/flow.js'), 'source'); write(path.join(dst, 'tools/flow.js'), 'target'); return { src, dst }; }
function node(script, args, project, nodeOptions = []) {
  const k = path.join(project, '.knowledge');
  const result = spawnSync(process.execPath, [...nodeOptions, script, ...args], { cwd: project, encoding: 'utf8', maxBuffer: 20 * 1024 * 1024, timeout: 120000,
    env: { ...process.env, KNOWLEDGE_SYSTEM_ROOT: k, KNOWLEDGE_TARGET_ROOT: project, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: k, KNOWLEDGE_STATE_ROOT: k,
      KNOWLEDGE_AGENT_RUNTIME: 'codex', KNOWLEDGE_FLOW_NO_OPEN: '1', KNOWLEDGE_INSPECTOR_NO_OPEN: '1', KNOWLEDGE_UPDATE_MOCK_LATEST: '' } });
  assert(!result.error, result.error?.message); assert(result.stdout, result.stderr);
  return { exit: result.status, body: JSON.parse(result.stdout), stderr: result.stderr };
}
function freshProject(name, initialize = false) {
  const project = path.join(root, name); const knowledge = path.join(project, '.knowledge');
  copyInstallInput(knowledge);
  write(path.join(project, 'src/app.js'), 'module.exports = "isolated upgrade fixture";\n');
  write(path.join(project, 'README.md'), '# Isolated upgrade fixture\n');
  const configPath = path.join(knowledge, 'config.yaml');
  write(configPath, fs.readFileSync(configPath, 'utf8').replace(/(updates:\s*\r?\n\s+enabled:)\s*true/, '$1 false'));
  if (initialize) {
    const integration = node(path.join(knowledge, 'tools/install-agent-integrations.js'), ['--runtime', 'codex', '--no-install-check'], project);
    assert.equal(integration.exit, 0, integration.stderr);
    const imported = node(path.join(knowledge, 'tools/flow.js'), ['import', '--json', '--no-color'], project);
    assert.equal(imported.exit, 0, JSON.stringify(imported.body));
  }
  return { project, knowledge };
}
function nonRuntimeSnapshot(knowledge) {
  const files = {};
  function visit(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name); const relative = path.relative(knowledge, file).replace(/\\/g, '/');
      if (/^(?:maintenance|locks|external_memory)(?:\/|$)/.test(relative)) continue;
      if (entry.isDirectory()) visit(file); else if (entry.isFile()) files[relative] = digest(file);
    }
  }
  visit(knowledge); return files;
}
try {
  const metadata = path.join(root, 'metadata'); fs.mkdirSync(metadata);
  for (const value of [null, [], 'text', { system_paths: 'tools' }, { system_paths: ['../outside'] }, { system_paths: ['C:\\outside'] }, { system_paths: ['/outside'] }, { system_paths: ['tools//outside'] }, { system_paths: ['tools/Flow.js', 'tools/flow.js'] }]) {
    check(`malformed or unsafe manifest rejected: ${JSON.stringify(value)}`, () => { write(path.join(metadata, 'install-manifest.json'), JSON.stringify(value)); assert.throws(() => updater.loadInstallManifest(metadata)); });
  }
  check('absent legacy install manifest falls back to built-in policy', () => { fs.unlinkSync(path.join(metadata, 'install-manifest.json')); assert.equal(updater.loadInstallManifest(metadata).used_default, true); });
  check('manifest cannot authorize writes into user wiki data', () => { const { src, dst } = small('protected'); write(path.join(src, 'wiki/operator.md'), 'replacement'); assert.throws(() => updater.planActions(src, { targetKnowledgeRoot: dst, manifest: { ...manifest, system_paths: ['wiki/operator.md'] } }), /system path policy/); });
  check('manifest cannot authorize protected runtime evidence removal', () => { const { src, dst } = small('evidence'); write(path.join(dst, 'maintenance/verification_receipts/receipt.json'), '{}'); assert.throws(() => updater.planActions(src, { targetKnowledgeRoot: dst, manifest: { ...manifest, system_remove_paths: ['maintenance/verification_receipts'] } })); assert(fs.existsSync(path.join(dst, 'maintenance/verification_receipts/receipt.json'))); });
  check('manifest cannot request copying and removing the same shipped artifact', () => { const { src, dst } = small('remove-shipped'); assert.throws(() => updater.planActions(src, { targetKnowledgeRoot: dst, manifest: { ...manifest, system_remove_paths: ['tools/flow.js'] } }), /remove a shipped system artifact/); });
  check('duplicate parent and child entries produce one file write', () => { const { src, dst } = small('deduplicate'); const plan = updater.planActions(src, { targetKnowledgeRoot: dst, manifest: { ...manifest, system_paths: ['tools', 'tools/flow.js'] } }); assert.equal(plan.filter((entry) => entry.path === 'tools/flow.js' && entry.action === 'update').length, 1); });
  check('project defaults are preserved and missing defaults are planned explicitly', () => { const { src, dst } = small('defaults'); for (const file of manifest.repair_default_paths) write(path.join(src, file), '{}'); write(path.join(src, 'external_memory/README.md'), '# Source guidance'); write(path.join(dst, manifest.repair_default_paths[0]), '{"operator":true}'); const plan = updater.planActions(src, { targetKnowledgeRoot: dst, manifest: { ...manifest, system_paths: ['external_memory'] } }); assert(!plan.some((entry) => entry.action === 'update')); assert(plan.some((entry) => entry.path === 'external_memory/README.md' && entry.action === 'create')); const defaults = updater.planRepairDefaults(src, manifest, { targetKnowledgeRoot: dst }); assert.equal(defaults.filter((entry) => entry.action === 'repair_default').length, 1); assert.equal(defaults[0].reason, 'target_exists'); });
  if (process.platform !== 'win32') {
    for (const kind of ['source file', 'source directory', 'target file', 'target parent']) check(`symlink ${kind} blocks update planning`, () => {
      const { src, dst } = small(`symlink-${kind}`); const outside = path.join(root, `outside-${kind}`); write(path.join(outside, 'sentinel'), 'untouched');
      if (kind === 'source file') { fs.unlinkSync(path.join(src, 'tools/flow.js')); fs.symlinkSync(path.join(outside, 'sentinel'), path.join(src, 'tools/flow.js')); }
      if (kind === 'source directory') fs.symlinkSync(outside, path.join(src, 'tools/nested'), 'dir');
      if (kind === 'target file') { fs.unlinkSync(path.join(dst, 'tools/flow.js')); fs.symlinkSync(path.join(outside, 'sentinel'), path.join(dst, 'tools/flow.js')); }
      if (kind === 'target parent') { fs.rmSync(path.join(dst, 'tools'), { recursive: true }); fs.symlinkSync(outside, path.join(dst, 'tools'), 'dir'); }
      assert.throws(() => updater.planActions(src, { targetKnowledgeRoot: dst, manifest })); assert.equal(fs.readFileSync(path.join(outside, 'sentinel'), 'utf8'), 'untouched');
    });
    for (const side of ['src', 'dst']) check(`hardlinked ${side} file is rejected`, () => { const fixture = small(`hardlink-${side}`); const file = path.join(fixture[side], 'tools/flow.js'); const outside = path.join(root, `hardlink-${side}-sentinel`); fs.linkSync(file, outside); assert.throws(() => updater.planActions(fixture.src, { targetKnowledgeRoot: fixture.dst, manifest })); assert.equal(fs.readFileSync(outside, 'utf8'), side === 'src' ? 'source' : 'target'); });
  }
  check('corrupt source manifest produces a failed CLI report before writes or backup', () => {
    const { src, dst } = small('invalid-cli'); write(path.join(src, 'install-manifest.json'), 'null'); const prior = digest(path.join(dst, 'tools/flow.js'));
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', src, '--target', dst, '--apply', '--yes', '--json'], path.dirname(dst));
    assert.equal(result.exit, 2); assert.equal(result.body.status, 'failed'); assert.equal(digest(path.join(dst, 'tools/flow.js')), prior); assert(!fs.existsSync(path.join(dst, 'maintenance')));
  });
  check('conflicting CLI phases cannot accidentally apply', () => { const { src, dst } = small('phases'); const prior = digest(path.join(dst, 'tools/flow.js')); const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', src, '--target', dst, '--apply', '--dry-run', '--yes', '--json'], path.dirname(dst)); assert.equal(result.exit, 2); assert.equal(digest(path.join(dst, 'tools/flow.js')), prior); });
  const fullSrc = path.join(root, 'release source/.knowledge'); const project = path.join(root, 'installed project'); const fullDst = path.join(project, '.knowledge');
  copyInstallInput(fullSrc); copyInstallInput(fullDst);
  write(path.join(project, 'src/app.js'), 'module.exports = function greeting() { return "hello"; };\n'); write(path.join(project, 'README.md'), '# Fixture project\n');
  const config = fs.readFileSync(path.join(fullDst, 'config.yaml'), 'utf8').replace(/(updates:\s*\r?\n\s+enabled:)\s*true/, '$1 false'); write(path.join(fullDst, 'config.yaml'), config);
  check('clean installed import completes locally before upgrade', () => {
    const integration = node(path.join(fullDst, 'tools/install-agent-integrations.js'), ['--runtime', 'codex', '--no-install-check'], project); assert.equal(integration.exit, 0, integration.stderr);
    const imported = node(path.join(fullDst, 'tools/flow.js'), ['import', '--json', '--no-color'], project); assert.equal(imported.exit, 0, JSON.stringify(imported.body));
  });
  const oldPackage = JSON.parse(fs.readFileSync(path.join(fullDst, 'package.json'), 'utf8')); oldPackage.version = '3.4.0'; write(path.join(fullDst, 'package.json'), oldPackage);
  write(path.join(fullDst, 'config.yaml'), config.replace(/^version:[^\r\n]+/m, 'version: 3.4.0') + '\n# Operator setting survives update.\noperator_audit_marker: retained\n');
  const registryFile = path.join(fullDst, 'external_memory/registry.json'); const registry = JSON.parse(fs.readFileSync(registryFile, 'utf8')); registry.purpose += ' Operator override.'; write(registryFile, registry);
  const userNote = path.join(fullDst, 'wiki/operator-note.md'); write(userNote, '# Operator note\nPreserve these bytes.\n');
  const preserved = [registryFile, userNote, path.join(fullDst, 'external_memory/retrieval_policy.json')].map((file) => [file, digest(file)]);
  const configBefore = fs.readFileSync(path.join(fullDst, 'config.yaml'), 'utf8').replace(/^version:[^\r\n]+/m, '');
  check('real upgrade preserves operator config and project data with verified system parity', () => {
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fullDst, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], project);
    assert.equal(result.body.system_completeness?.status, 'ok', JSON.stringify(result.body.errors)); assert.equal(result.body.curated_preservation_proof?.status, 'preserved'); assert.equal(result.body.runtime_preservation_proof?.status, 'preserved');
    for (const [file, hash] of preserved) assert.equal(digest(file), hash);
    assert.equal(fs.readFileSync(path.join(fullDst, 'config.yaml'), 'utf8').replace(/^version:[^\r\n]+/m, ''), configBefore);
    assert.equal(JSON.parse(fs.readFileSync(path.join(fullDst, 'package.json'), 'utf8')).version, require('../package.json').version);
    assert.equal(result.exit, 0, JSON.stringify(result.body.errors));
  });
  check('first upgrade in an isolated project recreates missing external memory without weakening evidence preservation', () => {
    // No preceding apply/backup in this project: exercise missing defaults independently
    // of a reused target. Observed drift in reused targets must still fail closed.
    const fresh = freshProject('missing defaults project', true);
    fs.rmSync(path.join(fresh.knowledge, 'external_memory'), { recursive: true });
    assert(!fs.existsSync(path.join(fresh.knowledge, 'external_memory')));
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fresh.knowledge, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], fresh.project);
    assert.equal(result.exit, 0, JSON.stringify(result.body.errors)); assert.equal(result.body.system_completeness.status, 'ok'); assert.equal(result.body.runtime_preservation_proof.status, 'preserved');
    assert.equal(result.body.curated_preservation_proof.status, 'preserved'); assert(result.body.curated_preservation_proof.added_files.includes('external_memory/registry.json'));
    for (const file of ['README.md', 'pinecone_sources.json', 'registry.json', 'retrieval_policy.json']) assert.equal(digest(path.join(fresh.knowledge, 'external_memory', file)), digest(path.join(fullSrc, 'external_memory', file)));
    assert.equal(result.body.migration_defaults.status, 'applied'); assert.equal(result.body.summary.migration_defaults_created, 2);
    assert.deepEqual(result.body.migration_defaults.created_paths, manifest.repair_default_paths);
  });
  for (let cycle = 2; cycle <= 3; cycle++) check(`reused target upgrade ${cycle} recreates deleted defaults with existing backups and preserves evidence`, () => {
    // Exercise the original reused-target case, including its earlier import,
    // operator overrides, successful apply and retained backups.
    const memory = path.join(fullDst, 'external_memory');
    assert(memory.startsWith(path.resolve(root) + path.sep));
    fs.rmSync(memory, { recursive: true });
    assert(!fs.existsSync(memory));
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fullDst, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], project);
    assert.equal(result.exit, 0, JSON.stringify(result.body));
    assert.equal(result.body.system_completeness.status, 'ok');
    assert.equal(result.body.curated_preservation_proof.status, 'preserved');
    assert.equal(result.body.runtime_preservation_proof.status, 'preserved');
    for (const file of ['README.md', 'pinecone_sources.json', 'registry.json', 'retrieval_policy.json']) assert.equal(digest(path.join(memory, file)), digest(path.join(fullSrc, 'external_memory', file)));
    assert.equal(digest(userNote), preserved.find(item => item[0] === userNote)[1]);
    assert.equal(fs.readFileSync(path.join(fullDst, 'config.yaml'), 'utf8').replace(/^version:[^\r\n]+/m, ''), configBefore);
    assert.deepEqual(result.body.migration_defaults.created_paths, manifest.repair_default_paths);
    assert.equal(result.body.summary.migration_defaults_created, 2);
    assert(fs.readdirSync(path.join(fullDst, 'maintenance/install-backups')).length >= cycle);
  });
  check('target appearance after planning preserves operator bytes, writes no system files, and reports zero completed defaults', () => {
    const fresh = freshProject('target arrival project');
    for (const file of manifest.repair_default_paths) fs.unlinkSync(path.join(fresh.knowledge, file));
    const arrival = 'external_memory/concurrent-operator-setting.json'; const operatorBytes = '{"operator":"arrived after planning"}\n';
    write(path.join(fullSrc, arrival), '{"release_default":true}\n');
    const before = nonRuntimeSnapshot(fresh.knowledge); const preload = path.join(root, 'inject-target-arrival.cjs');
    write(preload, `const fs = require('fs'); const original = fs.mkdirSync; let fired = false; fs.mkdirSync = function(dir, ...args) { if (!fired && String(dir).includes('system-files-')) { fired = true; fs.writeFileSync(${JSON.stringify(path.join(fresh.knowledge, arrival))}, ${JSON.stringify(operatorBytes)}, { flag: 'wx' }); } return original.call(this, dir, ...args); };\n`);
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fresh.knowledge, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], fresh.project, ['--require', preload]);
    assert.equal(result.exit, 2); assert.equal(result.body.precondition_failure?.code, 'update_target_changed');
    assert.equal(result.body.precondition_failure.path, arrival); assert.equal(result.body.precondition_failure.stage, 'prepare');
    assert.equal(result.body.precondition_failure.expected_sha256, null); assert.equal(result.body.precondition_failure.actual_sha256, digest(path.join(fresh.knowledge, arrival)));
    assert.equal(fs.readFileSync(path.join(fresh.knowledge, arrival), 'utf8'), operatorBytes);
    assert.deepEqual(nonRuntimeSnapshot(fresh.knowledge), before);
    assert.equal(result.body.summary.migration_defaults_planned, 2); assert.equal(result.body.summary.migration_defaults_created, 0);
    assert.deepEqual(result.body.migration_defaults.created_paths, []); assert.equal(result.body.migration_defaults.status, 'not_applied');
    assert.equal(result.body.backup_verification.status, 'retained_for_rollback');
    assert(!JSON.stringify(result.body.precondition_failure).includes('arrived after planning'));
    fs.unlinkSync(path.join(fullSrc, arrival));
  });
  check('a failed second default write reports exactly the first completed file', () => {
    const fresh = freshProject('partial defaults project');
    for (const file of manifest.repair_default_paths) fs.unlinkSync(path.join(fresh.knowledge, file));
    const preload = path.join(root, 'inject-second-default-failure.cjs');
    write(preload, `const fs = require('fs'); const path = require('path'); const original = fs.renameSync; fs.renameSync = function(from, to, ...args) { if (path.resolve(String(to)) === ${JSON.stringify(path.join(fresh.knowledge, manifest.repair_default_paths[1]))}) { const error = new Error('injected second default publication failure'); error.code = 'EIO'; throw error; } return original.call(this, from, to, ...args); };\n`);
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fresh.knowledge, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], fresh.project, ['--require', preload]);
    assert.equal(result.exit, 2); assert(result.body.errors.some(error => error.includes('injected second default publication failure')));
    assert.equal(digest(path.join(fresh.knowledge, manifest.repair_default_paths[0])), digest(path.join(fullSrc, manifest.repair_default_paths[0])));
    assert(!fs.existsSync(path.join(fresh.knowledge, manifest.repair_default_paths[1])));
    assert.equal(result.body.migration_defaults.status, 'partially_applied');
    assert.deepEqual(result.body.migration_defaults.created_paths, [manifest.repair_default_paths[0]]);
    assert.equal(result.body.summary.migration_defaults_planned, 2); assert.equal(result.body.summary.migration_defaults_created, 1);
    assert.equal(result.body.backup_verification.status, 'retained_for_rollback');
  });
  check('source mutation after preflight is rejected before any live system write', () => {
    const targetTool = path.join(fullDst, 'tools/doctor.js'); write(targetTool, '// prior target bytes remain on rejected update\n'); const prior = digest(targetTool);
    const sourceTool = path.join(fullSrc, 'tools/doctor.js'); const preload = path.join(root, 'inject-source-change.cjs');
    write(preload, `const fs = require('fs'); const original = fs.mkdirSync; let fired = false; fs.mkdirSync = function(dir, ...args) { if (!fired && String(dir).includes('system-files-')) { fired = true; fs.writeFileSync(${JSON.stringify(sourceTool)}, '// changed source after planning\\n'); } return original.call(this, dir, ...args); };\n`);
    const result = node(path.join(__dirname, 'update-system-files.js'), ['--from', fullSrc, '--target', fullDst, '--apply', '--yes', '--post-upgrade-trust-refresh', 'none', '--json'], project, ['--require', preload]);
    assert.equal(result.exit, 2); assert(result.body.errors.some((error) => error.includes('Source changed after update planning'))); assert.equal(digest(targetTool), prior); assert.equal(result.body.backup_verification.status, 'retained_for_rollback');
  });
  console.log(JSON.stringify({ status: 'pass', checks_total: checks.length, checks, platform: process.platform, network_used: false }, null, 2));
  passed = true;
} finally {
  if (passed) fs.rmSync(root, { recursive: true, force: true });
  else console.error(`Update-safety fixture retained for diagnosis: ${root}`);
}
