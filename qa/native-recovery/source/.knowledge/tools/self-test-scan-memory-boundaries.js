#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const systemRoot = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-scan-memory-'));
const results = [];
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value));
}
function test(name, callback) {
  const root = path.join(base, String(results.length));
  fs.mkdirSync(root);
  try { callback(root); results.push({ name, status: 'pass' }); }
  catch (error) { results.push({ name, status: 'fail', error: error.message }); }
}
function environment(root, overrides = {}) {
  fs.mkdirSync(path.join(root, '.knowledge'), { recursive: true });
  fs.mkdirSync(path.join(root, 'state'), { recursive: true });
  return { ...process.env, KNOWLEDGE_SYSTEM_ROOT: systemRoot, KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'), KNOWLEDGE_STATE_ROOT: path.join(root, 'state'),
    KNOWLEDGE_MODE: 'repo', KNOWLEDGE_TEAM_ROOT: '', KNOWLEDGE_WORKSPACE_ID: '', KNOWLEDGE_AGENT_ID: 'audit',
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '1', PINECONE_MODE: 'disabled', PINECONE_LOCAL: '',
    PINECONE_LOCAL_HOST: '', PINECONE_HOST: '', PINECONE_INDEX_HOST: '', PINECONE_API_KEY: '', ...overrides };
}
function run(root, script, args = [], options = {}) {
  return spawnSync(process.execPath, [script, ...args], { cwd: root, env: environment(root, options.env),
    encoding: 'utf8', timeout: options.timeout || 15000, maxBuffer: 4 * 1024 * 1024 });
}
function sourceProbe(root, copied = true, env = {}) {
  const runtime = copied ? path.join(root, '.knowledge') : systemRoot;
  if (copied) fs.cpSync(systemRoot, runtime, { recursive: true });
  return { runtime,
    probe: () => run(root, '-e', [`console.log(JSON.stringify(require(${JSON.stringify(path.join(runtime, 'tools/external/pinecone-common'))}).sourceFiles()))`],
      { env: { KNOWLEDGE_SYSTEM_ROOT: runtime, ...env } }) };
}

try {
  test('secret scan detects later credentials after a documented placeholder and masks all output', (root) => {
    const placeholder = 'ghp_' + 'example' + 'A'.repeat(36);
    const first = 'ghp_' + 'Z'.repeat(40);
    const second = 'ghp_' + 'Q'.repeat(40);
    write(path.join(root, '.knowledge', 'tokens.txt'), [placeholder, first, second].join('\n'));
    const result = run(root, path.join(systemRoot, 'tools/scan-secrets.js'), ['--json']);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    const matches = report.findings.filter((row) => row.rule === 'github_pat');
    assert.deepEqual(matches.map((row) => row.line), [2, 3]);
    assert(!result.stdout.includes(first) && !result.stdout.includes(second));
    const stored = fs.readFileSync(path.join(root, 'state/maintenance/secret_scan_report.json'), 'utf8');
    assert(!stored.includes(first) && !stored.includes(second));
  });
  test('strict secret rejection returns nonzero and releases its lock', (root) => {
    write(path.join(root, '.knowledge', 'token.txt'), 'ghp_' + 'Z'.repeat(40));
    const result = run(root, path.join(systemRoot, 'tools/scan-secrets.js'), ['--strict', '--json']);
    assert.equal(result.status, 1, result.stderr);
    assert(!fs.existsSync(path.join(root, 'state/locks/v1/secret-scan.lock')), 'strict exit left an owned lock');
    fs.unlinkSync(path.join(root, '.knowledge', 'token.txt'));
    const clean = run(root, path.join(systemRoot, 'tools/scan-secrets.js'), ['--strict', '--json'], { timeout: 3000 });
    assert.equal(clean.status, 0, clean.stderr || String(clean.error));
    assert.equal(JSON.parse(clean.stdout).status, 'clean');
  });
  test('secret scan rejects a symlink report parent without writing outside state', (root) => {
    environment(root);
    const outside = path.join(root, 'outside');
    fs.mkdirSync(outside);
    fs.symlinkSync(outside, path.join(root, 'state/maintenance'), process.platform === 'win32' ? 'junction' : 'dir');
    const result = run(root, path.join(systemRoot, 'tools/scan-secrets.js'), ['--json']);
    assert.notEqual(result.status, 0);
    assert.deepEqual(fs.readdirSync(outside), []);
    assert(!fs.existsSync(path.join(root, 'state/locks/v1/secret-scan.lock')));
  });
  test('secret include-repo scope scans only selected important and critical project files', (root) => {
    const token = 'ghp_' + 'Z'.repeat(40);
    write(path.join(root, 'selected.txt'), token);
    write(path.join(root, 'unselected.txt'), token);
    write(path.join(root, 'state/maps/file_criticality.json'), { files: [{ path: 'selected.txt', classification: 'important' }] });
    const result = run(root, path.join(systemRoot, 'tools/scan-secrets.js'), ['--include-repo', '--json']);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).findings.map((row) => row.file), ['selected.txt']);
  });

  test('Pinecone source collection follows selected project roots rather than the installed runtime', (root) => {
    const runtime = path.join(root, 'runtime/.knowledge');
    const project = path.join(root, 'project');
    fs.cpSync(systemRoot, runtime, { recursive: true });
    write(path.join(root, 'runtime', 'wrong.txt'), 'runtime marker');
    write(path.join(runtime, 'external_memory/pinecone_sources.json'), { sources: [{ path: 'wrong.txt' }] });
    write(path.join(project, 'right.txt'), 'project marker');
    write(path.join(project, '.knowledge/external_memory/pinecone_sources.json'), { sources: [{ path: 'right.txt' }] });
    const result = run(project, '-e', [`console.log(JSON.stringify(require(${JSON.stringify(path.join(runtime, 'tools/external/pinecone-common'))}).sourceFiles()))`],
      { env: { KNOWLEDGE_SYSTEM_ROOT: runtime } });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), [path.join(project, 'right.txt')]);
  });
  for (const kind of ['traversal', 'symlink', 'hardlink']) {
    test(`Pinecone source collection rejects ${kind} before collecting external content`, (root) => {
      const { probe } = sourceProbe(root);
      const outside = path.join(base, `outside-${kind}.txt`);
      write(outside, 'boundary marker');
      let relative = '../' + path.basename(outside);
      if (kind === 'symlink') { fs.symlinkSync(outside, path.join(root, 'linked.txt')); relative = 'linked.txt'; }
      if (kind === 'hardlink') { fs.linkSync(outside, path.join(root, 'linked.txt')); relative = 'linked.txt'; }
      write(path.join(root, '.knowledge/external_memory/pinecone_sources.json'), { sources: [{ path: relative }] });
      const result = probe();
      assert.notEqual(result.status, 0, 'unsafe source was accepted');
      assert.equal(fs.readFileSync(outside, 'utf8'), 'boundary marker');
    });
  }
  test('overlapping Pinecone sources produce unique deterministic file paths', (root) => {
    const { probe } = sourceProbe(root);
    write(path.join(root, 'notes/one.md'), 'one');
    write(path.join(root, '.knowledge/external_memory/pinecone_sources.json'), { sources: [{ path: 'notes' }, { path: 'notes/one.md' }] });
    const result = probe();
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), [path.join(root, 'notes/one.md')]);
  });
  test('corrupt Pinecone configuration fails closed and is preserved', (root) => {
    const { probe } = sourceProbe(root);
    const file = path.join(root, '.knowledge/external_memory/pinecone_sources.json');
    write(file, '{broken');
    const result = probe();
    assert.notEqual(result.status, 0);
    assert.equal(fs.readFileSync(file, 'utf8'), '{broken');
  });
  test('Pinecone dry-run upsert executes with no credentials and has advisory semantics', (root) => {
    const { runtime } = sourceProbe(root);
    write(path.join(root, 'notes/one.md'), 'A short project note');
    write(path.join(root, '.knowledge/external_memory/pinecone_sources.json'), { sources: [{ path: 'notes/one.md' }] });
    const result = run(root, path.join(runtime, 'tools/external/pinecone-upsert.js'), ['--dry-run'],
      { env: { KNOWLEDGE_SYSTEM_ROOT: runtime } });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.dry_run, true); assert.equal(output.source_of_truth, false); assert.equal(output.vector_count, 1);
  });
  test('invalid chunk bounds fail promptly instead of entering an endless loop', (root) => {
    const moduleFile = path.join(systemRoot, 'tools/external/pinecone-common');
    const result = run(root, '-e', [`require(${JSON.stringify(moduleFile)}).chunk('abcdef',2,2)`], { timeout: 1000 });
    assert(result.status !== 0 && !result.error, 'invalid chunk options hung the process');
    assert(result.stderr.includes('pinecone_chunk_options_invalid'));
  });
  test('large overlap with paragraph boundaries still makes forward progress', (root) => {
    const moduleFile = path.join(systemRoot, 'tools/external/pinecone-common');
    const input = 'abcdef\n\nuvwxyz\n\nlast';
    const result = run(root, '-e', [`console.log(JSON.stringify(require(${JSON.stringify(moduleFile)}).chunk(${JSON.stringify(input)},10,9)))`], { timeout: 1000 });
    assert.equal(result.status, 0, result.stderr || String(result.error));
    const chunks = JSON.parse(result.stdout);
    assert(chunks.length > 0 && chunks.length <= 20);
    assert(chunks.at(-1).endsWith('last'));
  });
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}
const failed = results.filter((row) => row.status === 'fail');
console.log(JSON.stringify({ suite: 'scan-memory-boundaries', status: failed.length ? 'fail' : 'pass',
  total: results.length, passed: results.length - failed.length, failed: failed.length, results }, null, 2));
if (failed.length) process.exitCode = 1;
