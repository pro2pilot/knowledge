'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
test('the admitted native helper executes its verified bytes during a concurrent public package replacement', { skip: process.platform !== 'linux' }, () => {
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'native-update-test-'));
  const library = path.join(fixture, 'tools/lib');
  fs.cpSync(path.join(__dirname, '../tools/lib'), library, { recursive: true });
  if (process.env.KNOWLEDGE_TEST_NATIVE_BACKEND) fs.copyFileSync(process.env.KNOWLEDGE_TEST_NATIVE_BACKEND, path.join(library, 'verification-linux-namespace.js'));
  const native = require(path.join(library, 'verification-linux-namespace.js')); let helper;
  try {
    helper = native.preparePackagedHelper({ snapshot: true });
    const publicBinary = path.join(library, `native/linux-${process.arch}/verification-linux-namespace`);
    const replacement = path.join(path.dirname(publicBinary), 'replacement');
    fs.writeFileSync(replacement, '#!/bin/sh\nprintf \'{"replacement_executed":true}\\n\'\n', { mode: 0o500 });
    fs.renameSync(replacement, publicBinary);
    const observed = spawnSync(helper.executable, ['--identity'], { encoding: 'utf8', timeout: 5000 });
    const body = JSON.parse(observed.stdout);
    console.log(JSON.stringify({ scenario: 'real_exec_after_package_replacement', backend_sha256: sha(path.join(library, 'verification-linux-namespace.js')),
      admitted_binary_sha256: helper.binary_sha256, public_replacement_sha256: sha(publicBinary), snapshot: !!helper.snapshot,
      exit_code: observed.status, signal: observed.signal, error: observed.error?.code || null, output: body }));
    assert.equal(observed.status, 0); assert.equal(observed.error, undefined);
    assert.equal(body.backend, 'linux_pid_namespace', 'exec used bytes replaced after the successful hash check');
    assert.equal(body.identity.pid, process.pid);
    assert.throws(() => native.preparePackagedHelper({ snapshot: true }), { code: 'command_native_binary_invalid' });
  } finally {
    if (helper?.snapshot) assert.equal(native.cleanupPreparedHelper(helper).status, 'completed');
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});
