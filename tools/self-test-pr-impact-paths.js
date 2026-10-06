#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');
const systemRoot = path.resolve(__dirname, '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-pr-paths-'));
const checks = [];
const env = { ...process.env };
for (const key of Object.keys(env)) if (/^KNOWLEDGE_/i.test(key)) delete env[key];

function git(repo, args) {
  const result = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8', env, timeout: 20000, windowsHide: true });
  assert.strictEqual(result.status, 0, `${args.join(' ')}: ${result.stderr}`);
}
function seed(name, withCommit = true) {
  const repo = path.join(root, name);
  fs.mkdirSync(path.join(repo, '.knowledge'), { recursive: true });
  fs.mkdirSync(path.join(repo, 'src'));
  git(repo, ['init', '-q']);
  git(repo, ['config', 'user.name', 'PR Impact Test']);
  git(repo, ['config', 'user.email', 'pr-impact@example.invalid']);
  for (const file of ['auth café.js', 'delete.js', 'rename.js']) fs.writeFileSync(path.join(repo, 'src', file), 'exports.check = () => true;\n');
  if (withCommit) { git(repo, ['add', '.']); git(repo, ['commit', '-qm', 'fixture']); }
  return repo;
}
function run(repo, flags = [], expected = 0) {
  const result = spawnSync(process.execPath, [path.join(systemRoot, 'tools/pr-impact.js'), '--system-root', systemRoot, '--target-root', repo, '--project-knowledge-root', path.join(repo, '.knowledge'), '--state-root', path.join(repo, '.knowledge'), '--no-write', '--json', ...flags], { cwd: repo, env, encoding: 'utf8', timeout: 30000, windowsHide: true });
  assert.strictEqual(result.status, expected, `${result.stderr}\n${result.stdout}`);
  return JSON.parse(result.stdout);
}
function check(name, body) {
  try { body(); checks.push({ name, status: 'pass' }); }
  catch (error) { checks.push({ name, status: 'fail', error: error.message }); }
}

try {
  check('Unicode filenames and source deletions appear exactly in impact', () => {
    const repo = seed('unicode delete');
    fs.appendFileSync(path.join(repo, 'src/auth café.js'), 'exports.updated = true;\n');
    fs.unlinkSync(path.join(repo, 'src/delete.js'));
    const files = run(repo).changed_files;
    assert(files.some((item) => item.path === 'src/auth café.js'));
    assert(files.some((item) => item.path === 'src/delete.js' && item.status.includes('D')));
    assert(files.every((item) => !item.path.includes('303')));
  });
  check('staged rename includes both old and new module paths', () => {
    const repo = seed('rename');
    git(repo, ['mv', 'src/rename.js', 'src/перенос name.js']);
    const files = run(repo).changed_files;
    assert(files.some((item) => item.path === 'src/rename.js' && item.staged));
    assert(files.some((item) => item.path === 'src/перенос name.js' && item.staged));
  });
  check('untracked and unborn Git Unicode paths use lossless records', () => {
    const repo = seed('unborn', false);
    git(repo, ['add', 'src/auth café.js']);
    let files = run(repo).changed_files;
    assert(files.some((item) => item.path === 'src/auth café.js' && item.staged));
    assert(files.some((item) => item.path === 'src/delete.js' && !item.staged));
    if (process.platform !== 'win32') {
      const unusual = 'src/name\nwith\twhitespace.js';
      fs.writeFileSync(path.join(repo, unusual), 'exports.ok=true;\n');
      files = run(repo).changed_files;
      assert(files.some((item) => item.path === unusual));
    }
  });
  check('explicit base range includes deletions and rejects invalid revisions/options', () => {
    const repo = seed('revision');
    fs.unlinkSync(path.join(repo, 'src/delete.js'));
    assert(run(repo, ['--base', 'HEAD']).changed_files.some((item) => item.path === 'src/delete.js'));
    const invalid = run(repo, ['--base', 'missing-audit-revision'], 1);
    assert.strictEqual(invalid.status, 'failed');
    const output = path.join(repo, 'unsafe-output.txt');
    run(repo, [`--base=--output=${output}`], 1);
    assert(!fs.existsSync(output));
  });
  const failed = checks.filter((item) => item.status !== 'pass').length;
  console.log(JSON.stringify({ schema_version: systemVersion(), status: failed ? 'fail' : 'pass', total: checks.length, passed: checks.length - failed, failed, checks }, null, 2));
  process.exitCode = failed ? 1 : 0;
} finally {
  if (!process.argv.includes('--keep-temp')) fs.rmSync(root, { recursive: true, force: true });
}
