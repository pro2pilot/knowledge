'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

// This override replays the unchanged tests against an immutable audit input.
// Every real CLI still runs from a fresh writable copy; source is never edited.
const sourceRoot = path.resolve(process.env.KNOWLEDGE_INGEST_TEST_SOURCE_ROOT || path.join(__dirname, '..'));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n'); };
const nodePin = hash(fs.readFileSync(process.execPath));

function inventory(root) {
  const result = {};
  function walk(dir) {
    for (const name of fs.readdirSync(dir).sort()) {
      const file = path.join(dir, name), st = fs.lstatSync(file), relative = path.relative(root, file).split(path.sep).join('/');
      const row = { dev: st.dev, ino: st.ino, mode: st.mode, type: st.isDirectory() ? 'directory' : st.isFile() ? 'file' : 'other' };
      if (st.isSymbolicLink()) row.link = fs.readlinkSync(file);
      else if (st.isFile()) row.sha256 = hash(fs.readFileSync(file));
      result[relative] = row; if (st.isDirectory()) walk(file);
    }
  }
  walk(root); return result;
}

function fixture(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'ingest-identities-')), identity = fs.lstatSync(base);
  const root = path.join(base, 'project'), state = path.join(root, '.knowledge'), commands = [];
  fs.mkdirSync(root); fs.cpSync(sourceRoot, state, { recursive: true });
  const put = (relative, value) => write(path.join(root, relative), value);
  put('package.json', { name: 'owned-ingest-identity-fixture', version: '1.0.0' });
  put('README.md', '# Owned ingest test\n');
  put('.knowledge/config.yaml', 'updates:\n  enabled: false\nexternal_memory:\n  enabled: false\n');
  put('.knowledge/project_index.json', { status: 'stub', modules: [], task_routing: [] });
  put('.knowledge/modules/module_registry.json', { modules: [] });
  put('.knowledge/freshness.json', { tracked_files: [], artifact_dependencies: {}, artifact_statuses: {} });
  put('.knowledge/maps/file_criticality.json', { files: [], coverage_by_module: {} });
  put('.knowledge/maintenance/repair_queue.json', { queue: [] });
  const guard = path.join(base, 'guard.cjs');
  write(guard, `
'use strict';
const fs = require('node:fs'), path = require('node:path');
const append = fs.appendFileSync, originalWrite = fs.writeFileSync;
function log(file, row) { append(file, JSON.stringify(row) + '\\n'); }
function deny(kind) { log(process.env.INGEST_TEST_EXTERNAL, { kind }); throw Object.assign(new Error('Offline ingest fixture forbids ' + kind), { code: 'ingest_test_external_forbidden' }); }
for (const key of ['spawn','spawnSync','exec','execSync','execFile','execFileSync','fork']) require('node:child_process')[key] = () => deny('child:' + key);
for (const mod of ['http','https']) for (const key of ['request','get']) require('node:' + mod)[key] = () => deny(mod + ':' + key);
for (const key of ['connect','createConnection']) require('node:net')[key] = () => deny('net:' + key);
require('node:tls').connect = () => deny('tls'); globalThis.fetch = () => deny('fetch');
let injected = false, injecting = false;
for (const key of ['mkdirSync','writeFileSync','appendFileSync','renameSync','unlinkSync','rmSync','rmdirSync','openSync']) {
  const original = fs[key];
  fs[key] = function(...args) {
    const flags = args[1], isWrite = key !== 'openSync' || (typeof flags === 'number' ? (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC)) !== 0 : /[wa+]/.test(String(flags)));
    if (!injecting && isWrite && typeof args[0] === 'string' && path.resolve(args[0]).startsWith(process.env.INGEST_TEST_STATE + path.sep)) log(process.env.INGEST_TEST_MUTATIONS, { kind: key, path: path.relative(process.env.INGEST_TEST_STATE, args[0]) });
    const result = original.apply(this, args);
    return result;
  };
}
// Atomic native publication no longer creates the final directory through
// mkdirSync. Inject only after actual successful acquisition, before the
// protected callback starts; every native acquisition/release still executes.
const locks = require(path.join(process.env.INGEST_TEST_STATE, 'tools/lib/contained-lock-manager.js'));
const withContainedLock = locks.withContainedLock;
locks.withContainedLock = function(request, action) {
  return withContainedLock.call(this, request, function(...args) {
    if (!injected && process.env.INGEST_TEST_INJECT_REGISTRY && request.lockName === 'ingest') {
      injected = true; injecting = true;
      try { originalWrite(path.join(process.env.INGEST_TEST_STATE, 'modules/module_registry.json'), fs.readFileSync(process.env.INGEST_TEST_INJECT_REGISTRY)); }
      finally { injecting = false; }
      log(process.env.INGEST_TEST_MUTATIONS, { kind: 'synthetic_registry_replacement_after_lock_acquire' });
    }
    return action(...args);
  });
};
`);
  t.after(() => {
    t.diagnostic(JSON.stringify({ evidence_kind: 'original Node; actual ingest CLI --merge --no-sync; local optional builders; nested children/network forbidden', source: sourceRoot, node_sha256: nodePin, commands }));
    const latest = fs.lstatSync(base);
    assert(latest.isDirectory() && !latest.isSymbolicLink() && latest.dev === identity.dev && latest.ino === identity.ino, 'Test fixture root identity changed');
    fs.rmSync(base, { recursive: true, force: false });
  });
  function run({ fail = false, injectRegistry = null, extraArgs = [] } = {}) {
    const external = path.join(base, `external-${commands.length}.ndjson`), mutations = path.join(base, `mutations-${commands.length}.ndjson`);
    write(external, ''); write(mutations, '');
    const env = { PATH: path.dirname(process.execPath), TMPDIR: base, TMP: base, TEMP: base, NO_COLOR: '1',
      KNOWLEDGE_MODE: 'repo', KNOWLEDGE_SYSTEM_ROOT: state, KNOWLEDGE_TARGET_ROOT: root, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: state,
      KNOWLEDGE_STATE_ROOT: state, KNOWLEDGE_AGENT_ID: 'ingest-identity-self-test', KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', KNOWLEDGE_UPDATE_DISABLE_ON_LAUNCH: '1',
      INGEST_TEST_STATE: state, INGEST_TEST_EXTERNAL: external, INGEST_TEST_MUTATIONS: mutations };
    if (process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
    if (injectRegistry) { env.INGEST_TEST_INJECT_REGISTRY = path.join(base, 'injected-registry.json'); write(env.INGEST_TEST_INJECT_REGISTRY, injectRegistry); }
    const script = path.join(state, 'tools/ingest-existing-project.js'), pin = hash(fs.readFileSync(script));
    const result = spawnSync(process.execPath, ['--require', guard, script, '--merge', '--no-sync', ...extraArgs], { cwd: root, env, encoding: 'utf8', timeout: 30000, maxBuffer: 4 * 1024 * 1024 });
    const parsedLines = file => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    const row = { status: result.status, signal: result.signal || null, error: result.error ? { code: result.error.code, message: result.error.message } : null,
      script_sha256: pin, script_unchanged: hash(fs.readFileSync(script)) === pin, external_attempts: parsedLines(external),
      mutations: parsedLines(mutations), stdout: result.stdout, stderr: result.stderr };
    commands.push(row);
    assert.equal(row.error, null); assert.equal(row.signal, null); assert.equal(row.script_unchanged, true); assert.deepEqual(row.external_attempts, []);
    if (fail) { assert.equal(row.status, 1, row.stdout + row.stderr); assert.match(row.stderr, /ingest_module_identity_invalid/); }
    else assert.equal(row.status, 0, row.stderr);
    return { ...row, result: fail ? null : JSON.parse(row.stdout) };
  }
  return { base, root, state, put, run, modules: () => read(path.join(state, 'modules/module_registry.json')).modules,
    directories: () => read(path.join(state, 'maps/directory_map.json')).directories };
}

function expectOwnership(f, paths) {
  const modules = f.modules();
  assert.equal(new Set(modules.map(row => row.module_id)).size, modules.length);
  assert.equal(new Set(modules.map(row => row.card)).size, modules.length);
  for (const folder of paths) {
    const rows = modules.filter(row => row.path === `${folder}/`); assert.equal(rows.length, 1, folder);
    const row = rows[0], card = read(path.join(f.root, row.card));
    assert.equal(card.module_id, row.module_id); assert.deepEqual(row.key_files, [`${folder}/index.js`]);
    assert.deepEqual(card.boundaries.owns, [row.path]);
  }
  return new Map(modules.map(row => [row.path, row.module_id]));
}

test('three nested normalized collisions retain separate paths, cards and evidence ownership', t => {
  const f = fixture(t), folders = ['src/auth api', 'src/auth-api', 'src/auth_api'];
  for (const folder of folders) f.put(`${folder}/index.js`, `module.exports = ${JSON.stringify(folder)};\n`);
  f.run(); const first = expectOwnership(f, folders), modules = f.modules(); f.run();
  assert.deepEqual(expectOwnership(f, folders), first); assert.deepEqual(f.modules(), modules);
});

test('top-level collisions and reserved root/registry names receive distinct real directory mappings', t => {
  const f = fixture(t), folders = ['frontend-api', 'frontend_api', 'root', 'module_registry'];
  for (const folder of folders) f.put(`${folder}/index.js`, 'module.exports = true;\n');
  assert.equal(f.run().result.root_module, true); const byPath = expectOwnership(f, folders);
  assert.notEqual(byPath.get('root/'), 'root'); assert.notEqual(byPath.get('module_registry/'), 'module_registry');
  for (const folder of folders) {
    const row = f.directories().find(row => row.path === `${folder}/`);
    assert.equal(row.module_id, byPath.get(`${folder}/`)); assert.deepEqual(row.module_ids, [row.module_id]); assert.equal(row.status, 'detected');
  }
});

test('a source directory with a Windows device name receives a portable card name on hosts that can create it', { skip: process.platform === 'win32' ? 'Windows cannot create an ordinary source directory named NUL' : false }, t => {
  const f = fixture(t); f.put('nul/index.js', 'module.exports = true;\n'); f.run();
  const byPath = expectOwnership(f, ['nul']); assert.notEqual(byPath.get('nul/'), 'nul');
});

test('adding a lexically earlier collider preserves existing IDs, curated bytes and confidence', t => {
  const f = fixture(t), old = ['src/auth-api', 'src/auth_api'];
  for (const folder of old) f.put(`${folder}/index.js`, 'module.exports = true;\n');
  f.run(); const prior = expectOwnership(f, old), modules = f.modules(), cards = new Map();
  for (const row of modules.filter(row => prior.has(row.path) && row.path !== '.')) {
    row.confidence = 'high'; row.custom_note = { retain: row.path };
    const card = JSON.stringify({ module_id: row.module_id, verification_status: 'code_verified', key_files: row.key_files, manual: row.path }, null, 4) + '\n';
    f.put(row.card, card); cards.set(row.card, card);
  }
  f.put('.knowledge/modules/module_registry.json', { modules }); f.put('src/auth api/index.js', 'module.exports = "new earlier collider";\n');
  f.run(); const next = f.modules();
  for (const folder of old) { const row = next.find(row => row.path === `${folder}/`); assert.equal(row.module_id, prior.get(row.path)); assert.equal(row.confidence, 'high'); assert.deepEqual(row.custom_note, { retain: row.path }); }
  assert.equal(next.filter(row => row.path === 'src/auth api/').length, 1);
  for (const [card, bytes] of cards) assert.equal(fs.readFileSync(path.join(f.root, card), 'utf8'), bytes);
  f.run(); assert.deepEqual(f.modules(), next);
});

test('manual IDs follow normalized physical paths and retired IDs remain reserved', t => {
  const f = fixture(t); f.put('src/auth-api/index.js', 'module.exports = true;\n'); f.put('src/auth_api/index.js', 'module.exports = false;\n');
  const manual = { module_id: 'MyManualID', path: './src//auth-api/', card: '.knowledge/modules/custom/auth.json', confidence: 'high', purpose: 'Manual purpose', custom: { retained: true } };
  const retired = { module_id: 'auth_api', path: 'retired/', card: '.knowledge/modules/retired.json', confidence: 'low' };
  const root = { module_id: 'project_manifest', path: './', card: '.knowledge/modules/custom/root.json' };
  f.put('.knowledge/modules/module_registry.json', { modules: [manual, retired, root] });
  const card = '{ "module_id": "MyManualID", "verification_status": "code_verified", "manual": true }\n'; f.put(manual.card, card);
  assert.equal(f.run().result.root_module, true); const modules = f.modules(), reused = modules.find(row => row.module_id === manual.module_id);
  assert.equal(reused.path, manual.path); assert.equal(reused.purpose, manual.purpose); assert.equal(reused.confidence, 'high'); assert.deepEqual(reused.custom, manual.custom);
  assert.equal(fs.readFileSync(path.join(f.root, manual.card), 'utf8'), card);
  assert.deepEqual(modules.find(row => row.module_id === retired.module_id), retired);
  assert.notEqual(modules.find(row => row.path === 'src/auth_api/').module_id, 'auth_api');
  assert(!modules.some(row => row.module_id === 'root'));
});

test('a retired undetected module with an absent optional card receives only the default card path', t => {
  const f = fixture(t), retired = { module_id: 'retired_manual', path: 'gone/', confidence: 'high', custom: { preserve: true } };
  f.put('.knowledge/modules/module_registry.json', { modules: [retired] }); f.run();
  assert.deepEqual(f.modules().find(row => row.module_id === retired.module_id), { ...retired, card: '.knowledge/modules/retired_manual.json' });
  const card = read(path.join(f.state, 'modules/retired_manual.json')); assert.equal(card.module_id, retired.module_id); assert.deepEqual(card.boundaries.owns, [retired.path]);
  assert.equal(card.confidence, 'high');
});

test('a genuinely absent registry initializes normally without treating a present malformed file as missing', t => {
  const f = fixture(t); fs.unlinkSync(path.join(f.state, 'modules/module_registry.json')); f.put('frontend/index.js', 'module.exports = true;\n');
  f.run(); expectOwnership(f, ['frontend']);
});

test('custom and orphan card filenames are reserved before a new normalized module ID is allocated', t => {
  const f = fixture(t); for (const folder of ['src/curated', 'src/auth-api', 'src/orphan-name']) f.put(`${folder}/index.js`, 'module.exports = true;\n');
  f.put('.knowledge/modules/module_registry.json', { modules: [{ module_id: 'custom', path: 'src/curated/', card: '.knowledge/modules/auth_api.json' }] });
  const cards = new Map([
    ['.knowledge/modules/auth_api.json', '{"module_id":"custom","verification_status":"code_verified","manual":1}\n'],
    ['.knowledge/modules/ORPHAN_NAME.json', '{"module_id":"another-unregistered-owner","verification_status":"code_verified","manual":2}\n']
  ]);
  for (const [file, bytes] of cards) f.put(file, bytes);
  f.run(); const modules = f.modules();
  assert.notEqual(modules.find(row => row.path === 'src/auth-api/').module_id, 'auth_api');
  assert.notEqual(modules.find(row => row.path === 'src/orphan-name/').module_id, 'orphan_name');
  for (const [file, bytes] of cards) assert.equal(fs.readFileSync(path.join(f.root, file), 'utf8'), bytes);
  assert(!modules.some(row => row.module_id === 'another-unregistered-owner'));
});

test('promoted parent maps list actual children and preserve an explicitly registered parent ID', t => {
  const f = fixture(t); for (const folder of ['src/auth-api', 'src/auth_api', 'tests']) f.put(`${folder}/index.js`, 'module.exports = true;\n');
  f.run(); let modules = f.modules(), row = f.directories().find(row => row.path === 'src/');
  assert.equal(row.module_id, null); assert.equal(row.status, 'promoted_children');
  const children = modules.filter(row => row.path.startsWith('src/')).map(row => row.module_id).sort(); assert.deepEqual(row.module_ids, children);
  const unassigned = f.directories().find(row => row.path === 'tests/'); assert.equal(unassigned.module_id, null); assert.deepEqual(unassigned.module_ids, []); assert.equal(unassigned.status, 'unassigned');
  modules.push({ module_id: 'manual_parent', path: 'src/', card: '.knowledge/modules/manual_parent.json' });
  f.put('.knowledge/modules/module_registry.json', { modules }); f.run(); row = f.directories().find(row => row.path === 'src/');
  assert.equal(row.module_id, 'manual_parent'); assert.equal(row.status, 'detected'); assert.deepEqual(row.module_ids, [...children, 'manual_parent'].sort());
});

test('NFC and NFD source directories retain distinct physical ownership when supported by the host', t => {
  const f = fixture(t), folders = ['src/caf\u00e9', 'src/cafe\u0301'];
  for (const folder of folders) f.put(`${folder}/index.js`, 'module.exports = true;\n');
  if (fs.readdirSync(path.join(f.root, 'src')).length !== 2) { t.skip('Host filesystem aliases NFC/NFD directory names'); return; }
  f.run(); expectOwnership(f, folders);
});

test('an inherited-object-key module ID receives its own coverage record', t => {
  const f = fixture(t); f.put('constructor/index.js', 'module.exports = true;\n'); f.run();
  const modules = f.modules(), row = modules.find(row => row.path === 'constructor/'); assert.equal(row.module_id, 'constructor');
  const coverage = read(path.join(f.state, 'maps/file_criticality.json')).coverage_by_module;
  assert(Object.hasOwn(coverage, 'constructor')); assert.deepEqual(coverage.constructor.referenced_by_module_card, ['constructor/index.js']);
});

const conflicts = [
  ['same ID with different paths', { modules: [{ module_id: 'same', path: 'first/' }, { module_id: 'same', path: 'second/' }] }, 'duplicate_module_id'],
  ['same ID and same path duplicate metadata', { modules: [{ module_id: 'same', path: 'first/' }, { module_id: 'same', path: 'first/', custom: true }] }, 'duplicate_module_id'],
  ['same normalized path with different IDs', { modules: [{ module_id: 'a', path: 'first/' }, { module_id: 'b', path: './first//' }] }, 'duplicate_module_path'],
  ['portable ID alias', { modules: [{ module_id: 'Alias', path: 'first/', card: '.knowledge/modules/a.json' }, { module_id: 'alias', path: 'second/', card: '.knowledge/modules/b.json' }] }, 'portable_module_id_collision'],
  ['portable card alias', { modules: [{ module_id: 'a', path: 'first/', card: '.knowledge/modules/Shared.json' }, { module_id: 'b', path: 'second/', card: '.knowledge/modules/shared.json' }] }, 'module_card_collision'],
  ['portable Unicode card alias', { modules: [{ module_id: 'a', path: 'first/', card: '.knowledge/modules/caf\u00e9.json' }, { module_id: 'b', path: 'second/', card: '.knowledge/modules/cafe\u0301.json' }] }, 'module_card_collision'],
  ['traversal ID', { modules: [{ module_id: '../escape', path: 'first/' }] }, 'module_id_invalid'],
  ['registry pathname used as card', { modules: [{ module_id: 'manual', path: 'first/', card: '.knowledge/modules/module_registry.json' }] }, 'module_card_collision'],
  ['present null registry', null, 'registry_shape_invalid'],
  ['present malformed registry', '{invalid-json\n', 'registry_read_failed']
];
for (const [label, registry, reason] of conflicts) test(`ambiguous registry refuses before any mutation: ${label}`, t => {
  const f = fixture(t); f.put('first/index.js', 'module.exports = true;\n'); f.put('second/index.js', 'module.exports = true;\n');
  // Explicit otherwise-valid card paths isolate identity ambiguity from an
  // unrelated legacy missing-card TypeError in the paired baseline.
  const value = registry && Array.isArray(registry.modules) ? { ...registry, modules: registry.modules.map((row, i) => ({ card: `.knowledge/modules/conflict-${i}.json`, ...row })) } : registry;
  f.put('.knowledge/modules/module_registry.json', value); const before = inventory(f.root), result = f.run({ fail: true, extraArgs: ['--force'] });
  assert.match(result.stderr, new RegExp(reason)); assert.deepEqual(result.mutations, []); assert.deepEqual(inventory(f.root), before);
});

test('registry authority is re-read after lock acquisition before generated content writes', t => {
  const f = fixture(t); f.put('first/index.js', 'module.exports = true;\n'); f.put('second/index.js', 'module.exports = true;\n');
  const injected = { modules: [{ module_id: 'same', path: 'first/', card: '.knowledge/modules/same-a.json' }, { module_id: 'same', path: 'second/', card: '.knowledge/modules/same-b.json' }] };
  const indexBefore = fs.readFileSync(path.join(f.state, 'project_index.json')), result = f.run({ fail: true, injectRegistry: injected });
  assert.match(result.stderr, /duplicate_module_id/); assert.deepEqual(read(path.join(f.state, 'modules/module_registry.json')), injected);
  assert(fs.readFileSync(path.join(f.state, 'project_index.json')).equals(indexBefore));
  assert(result.mutations.some(row => row.kind === 'synthetic_registry_replacement_after_lock_acquire'));
  assert(!result.mutations.some(row => row.path && /^(modules|maps|wiki)[/\\]/.test(row.path)), JSON.stringify(result.mutations));
});
