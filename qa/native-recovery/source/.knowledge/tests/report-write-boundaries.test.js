'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { test } = require('node:test');
const { buildExternalMemoryReport } = require('../tools/lib/memory-providers');
const { ensurePhysicalRoot } = require('../tools/lib/json-store');
const { removeTempDirStrict } = require('../tools/lib/strict-temp-cleanup');
const source = path.resolve(__dirname, '..');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-report-boundary-'));
  const stateRoot = path.join(root, 'state'), outside = path.join(root, 'outside');
  fs.mkdirSync(stateRoot); fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, 'sentinel'), 'keep\n');
  return { root, stateRoot, outside, context: { mode: 'repo', targetRoot: root,
    projectKnowledgeRoot: source, stateRoot, systemRoot: source, git: {}, warnings: [] },
    cleanup() { removeTempDirStrict(root); } };
}
function linkDirectory(from, to) { fs.symlinkSync(from, to, process.platform === 'win32' ? 'junction' : 'dir'); }

for (const component of ['maintenance', 'metrics']) test(`offline report rejects ${component} symlink before either report is written`, () => {
  const f = fixture();
  try {
    linkDirectory(f.outside, path.join(f.stateRoot, component));
    assert.throws(() => buildExternalMemoryReport(f.context, { write: true }), { code: 'contained_path_unsafe' });
    assert.deepEqual(fs.readdirSync(f.outside), ['sentinel']);
    assert.deepEqual(fs.readdirSync(f.stateRoot), [component]);
    assert.equal(fs.readFileSync(path.join(f.outside, 'sentinel'), 'utf8'), 'keep\n');
  } finally { f.cleanup(); }
});

test('report creation remains functional for missing physical state and read-only status creates nothing', () => {
  const f = fixture();
  try {
    f.context.stateRoot = path.join(f.root, 'new', 'nested', 'state');
    const readOnly = buildExternalMemoryReport(f.context, { write: false });
    assert.equal(readOnly.live_checks.network_calls, 'not_run');
    assert.equal(fs.existsSync(path.join(f.root, 'new')), false);
    const written = buildExternalMemoryReport(f.context, { write: true });
    assert.equal(written.source_of_truth_policy.external_memory_source_of_truth, false);
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.context.stateRoot, 'maintenance/external_memory_status.json'))).providers.length, 2);
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.context.stateRoot, 'metrics/external_memory.json'))).provider_count, 2);
  } finally { f.cleanup(); }
});

test('missing root under a symlink ancestor is rejected before making any outside directory', () => {
  const f = fixture();
  try {
    const alias = path.join(f.root, 'alias'); linkDirectory(f.outside, alias);
    assert.throws(() => ensurePhysicalRoot(path.join(alias, 'missing', 'state')), { code: 'contained_path_unsafe' });
    assert.deepEqual(fs.readdirSync(f.outside), ['sentinel']);
  } finally { f.cleanup(); }
});

test('the second report rechecks a parent changed during the first atomic rename', () => {
  const f = fixture(), rename = fs.renameSync;
  let replaced = false;
  try {
    fs.mkdirSync(path.join(f.stateRoot, 'maintenance')); fs.mkdirSync(path.join(f.stateRoot, 'metrics'));
    fs.renameSync = function (from, to, ...args) {
      const result = rename.call(this, from, to, ...args);
      if (String(to) === path.join(f.stateRoot, 'maintenance/external_memory_status.json') && !replaced) {
        replaced = true; fs.rmdirSync(path.join(f.stateRoot, 'metrics')); linkDirectory(f.outside, path.join(f.stateRoot, 'metrics'));
      }
      return result;
    };
    assert.throws(() => buildExternalMemoryReport(f.context, { write: true }), { code: 'contained_path_unsafe' });
    assert(replaced); assert.deepEqual(fs.readdirSync(f.outside), ['sentinel']);
    // This is physical write containment, not a multi-report transaction: the
    // first complete report may already exist when the second write fails.
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.stateRoot, 'maintenance/external_memory_status.json'))).live_checks.network_calls, 'not_run');
  } finally { fs.renameSync = rename; f.cleanup(); }
});

for (const [tool, name] of [['export-debug-bundle', 'debug-bundle.json'], ['export-pro-snapshot', 'pro-inspector-snapshot.json']]) {
  for (const kind of ['parent-link', 'target-link', 'target-hardlink']) test(`${tool} preflights ${kind} before generating provider reports`, () => {
    const f = fixture(), priorGit = process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY, log = console.log;
    process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY = '1'; console.log = () => {};
    try {
      const parent = path.join(f.stateRoot, 'maintenance'), target = path.join(parent, name), sentinel = path.join(f.outside, 'sentinel');
      if (kind === 'parent-link') linkDirectory(f.outside, parent);
      else {
        fs.mkdirSync(parent);
        if (kind === 'target-link') fs.symlinkSync(sentinel, target);
        else fs.linkSync(sentinel, target);
      }
      assert.throws(() => require('../tools/' + tool)(['--system-root', source, '--project-knowledge-root', source,
        '--target-root', f.root, '--state-root', f.stateRoot, '--json']), { code: 'contained_path_unsafe' });
      assert.deepEqual(fs.readdirSync(f.outside), ['sentinel']);
      assert.equal(fs.readFileSync(sentinel, 'utf8'), 'keep\n');
      assert.equal(fs.existsSync(path.join(f.stateRoot, 'metrics')), false);
      assert.equal(fs.existsSync(path.join(parent, 'external_memory_status.json')), false);
    } finally {
      console.log = log;
      if (priorGit === undefined) delete process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY;
      else process.env.KNOWLEDGE_DISABLE_GIT_DISCOVERY = priorGit;
      f.cleanup();
    }
  });
}
