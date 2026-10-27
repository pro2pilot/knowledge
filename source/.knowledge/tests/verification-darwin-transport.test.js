'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

test('Darwin shared nonblocking transport: physical pipes/sockets, partial frames, backpressure and bounded turns',
  { timeout: 120_000 }, t => {
    if (!['linux', 'darwin'].includes(process.platform)) {
      t.skip('portable POSIX socket harness requires Linux or Darwin; this is not a Windows native acceptance');
      return;
    }
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge transport '));
    try {
      const compiler = process.platform === 'darwin' ? '/usr/bin/clang' : '/usr/bin/cc';
      const binary = path.join(temporary, 'transport-probe');
      const result = childProcess.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
        '-I', path.join(__dirname, '../tools/lib'), path.join(__dirname, 'fixtures/darwin-transport-probe.c'),
        '-o', binary], { encoding: 'utf8', timeout: 60_000, maxBuffer: 1024 * 1024 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      const run = childProcess.spawnSync(binary, [], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
      assert.ifError(run.error);
      assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}\nsignal=${run.signal}`);
      assert.match(run.stdout, /PASS: 25 transport checks/);
      t.diagnostic(run.stdout.trim());
    } finally {
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  });
