'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const { withTempFixture } = require('../tools/lib/strict-temp-cleanup');
const source = path.resolve(__dirname, '..');
const windows = process.platform === 'win32';
const powershell = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe');
function ps(script, args) {
  const result = spawnSync(powershell, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, ...args],
    { encoding: 'utf8', timeout: 20000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return result;
}
function fixture(callback) {
  return withTempFixture({ prefix: 'windows-inspector-', keepOnFailure: true }, root => {
    const selected = path.join(root, 'Knowledge проект & (test)');
    fs.mkdirSync(selected);
    const marker = path.join(selected, 'argv.json');
    fs.writeFileSync(path.join(selected, 'inspector.js'), 'require("fs").writeFileSync("argv.json",JSON.stringify({argv:process.argv,cwd:process.cwd()}));\n');
    fs.copyFileSync(path.join(source, 'open-inspector.vbs'), path.join(selected, 'open-inspector.vbs'));
    // An unquoted path used to execute this sibling instead of inspector.js.
    fs.writeFileSync(path.join(root, 'Knowledge'), 'require("fs").writeFileSync("wrong-entry","wrong");\n');
    callback({ root, selected, marker });
  });
}
test('Windows launcher passes one complete Unicode/metacharacter script path', { skip: !windows }, () => fixture(f => {
  const result = ps(path.join(source, 'tools/open-inspector.ps1'), ['-KnowledgeRoot', f.selected, '-NoDialog']);
  assert.equal(result.status, 0, result.stderr);
  const deadline = Date.now() + 10000;
  while (!fs.existsSync(f.marker) && Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);
  assert(fs.existsSync(f.marker), result.stdout + result.stderr);
  const actual = JSON.parse(fs.readFileSync(f.marker, 'utf8'));
  assert.deepEqual(actual.argv.slice(1), [path.join(f.selected, 'inspector.js'), '--open']);
  assert.equal(actual.cwd, f.selected);
  assert(!fs.existsSync(path.join(f.selected, 'wrong-entry')));
}));
test('Missing selected runtime refuses without launching a neighbouring project', { skip: !windows }, () => fixture(f => {
  fs.unlinkSync(path.join(f.selected, 'inspector.js'));
  fs.writeFileSync(path.join(f.root, 'inspector.js'), 'require("fs").writeFileSync("wrong-entry","wrong");\n');
  const result = ps(path.join(source, 'tools/open-inspector.ps1'), ['-KnowledgeRoot', f.selected, '-NoDialog']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Missing Inspector entrypoint/);
  assert(!fs.existsSync(f.marker));
  assert(!fs.existsSync(path.join(f.selected, 'wrong-entry')));
  assert(!fs.existsSync(path.join(f.root, 'wrong-entry')));
}));
test('Windows shortcut records the exact selected launcher and working directory', { skip: !windows }, () => fixture(f => {
  const shortcut = path.join(f.root, 'owned-test.lnk');
  const created = ps(path.join(source, 'tools/create-inspector-shortcut.ps1'), ['-KnowledgeRoot', f.selected, '-ShortcutPath', shortcut]);
  assert.equal(created.status, 0, created.stderr);
  const inspect = path.join(f.root, 'read-shortcut.ps1');
  fs.writeFileSync(inspect, 'param([string]$ShortcutPath)\n[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\n$s=(New-Object -ComObject WScript.Shell).CreateShortcut($ShortcutPath)\n@{target=$s.TargetPath;arguments=$s.Arguments;cwd=$s.WorkingDirectory}|ConvertTo-Json -Compress\n');
  const read = ps(inspect, ['-ShortcutPath', shortcut]);
  assert.equal(read.status, 0, read.stderr);
  const actual = JSON.parse(read.stdout);
  assert.equal(actual.arguments, '"' + path.join(f.selected, 'open-inspector.vbs') + '"');
  assert.equal(actual.cwd, f.selected);
  assert.equal(actual.target.toLowerCase(), path.join(process.env.SystemRoot, 'System32/wscript.exe').toLowerCase());
}));
