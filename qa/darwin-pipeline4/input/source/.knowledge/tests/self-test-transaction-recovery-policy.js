'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tx = require('../tools/lib/json-transaction');

const repo = path.resolve(__dirname, '..', '..');
const ownedParent = path.resolve(process.env.KNOWLEDGE_TRANSACTION_TEST_TMP || path.join(repo, '.qa-tmp', 'transaction-agent-tmp'));
const runRoot = path.join(ownedParent, `json-transaction-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`);
const key = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
if (!ownedParent || !path.isAbsolute(ownedParent) || key(path.relative(repo, ownedParent)).startsWith('..')) {
  throw new Error('transaction_test_temp_must_be_an_absolute_repository_child');
}
fs.mkdirSync(ownedParent, { recursive: true });
tx.assertNoReparseParents(repo, ownedParent);
fs.mkdirSync(runRoot);
const checks = [];
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, Buffer.isBuffer(value) || typeof value === 'string' ? value : `${JSON.stringify(value, null, 2)}\n`);
}
function read(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function fixture(name) {
  const root = path.join(runRoot, name), state = path.join(root, '.knowledge');
  fs.mkdirSync(state, { recursive: true });
  const guard = path.join(root, 'src', 'public.txt'), target = path.join(state, 'maintenance', 'permitted.json');
  write(guard, 'project read guard\n');
  return { root, state, guard, target };
}
function pending(f, id, writes, faultAt = 'after_commit_marker', extraRoots = []) {
  const spec = {
    stateRoot: f.state, transactionId: id, writes,
    guards: [{ path: f.guard, expected_sha256: hash(fs.readFileSync(f.guard)), containmentRoot: f.root }],
    metadata: { type: 'portable_transaction_fixture' },
    allowedContainmentRoots: [f.state, f.root, ...extraRoots], faultAt
  };
  assert.throws(() => tx.commitJsonTransaction(spec), error => error.code === 'transaction_fault_injected');
  return { spec, root: path.join(f.state, 'maintenance', 'transactions', id) };
}
function inspectedPolicy(f, p, outputs) {
  const inspected = tx.inspectTransaction(p.root, { allowedGuardRoots: [f.state, f.root], allowedWriteRoots: [f.state] });
  return {
    allowedGuardRoots: [f.state, f.root], allowedWriteRoots: [f.state], exactWritePaths: outputs,
    expectedTransactionId: inspected.manifest.transaction_id,
    expectedIntentSha256: inspected.manifest.intent_sha256,
    expectedManifestSha256: inspected.manifest_sha256
  };
}
function check(name, fn) { fn(); checks.push(name); }

try {
  check('separate project read guards and state write roots allow bound replay and idempotent retry', () => {
    const f = fixture('legitimate');
    const p = pending(f, 'legitimate', [{ path: f.target, value: { ok: true }, containmentRoot: f.state }]);
    const policy = inspectedPolicy(f, p, [f.target]);
    assert.equal(tx.recoverOne(p.root, policy).status, 'committed');
    assert.deepEqual(read(f.target), { ok: true });
    assert.equal(tx.recoverOne(p.root, policy).recovery_action, 'already_terminal');
    assert.equal(tx.commitJsonTransaction({ ...p.spec, faultAt: null, ...policy }).idempotent, true);
  });
  check('pre-intent cleanup remains limited to exact outputs and supports retry', () => {
    const f = fixture('cleanup');
    const p = pending(f, 'cleanup', [{ path: f.target, value: { ok: true }, containmentRoot: f.state }], 'after_prepare_manifest');
    const policy = inspectedPolicy(f, p, [f.target]);
    assert.equal(tx.recoverOne(p.root, policy).status, 'rolled_back');
    assert(!fs.existsSync(f.target));
    assert.equal(tx.commitJsonTransaction({ ...p.spec, faultAt: null, ...policy }).status, 'committed');
  });
  check('project guard roots never grant project write authority on fresh commit or replay', () => {
    const f = fixture('project-write-denied'), forbidden = path.join(f.root, 'src', 'forbidden.txt');
    assert.throws(() => tx.commitJsonTransaction({ stateRoot: f.state, transactionId: 'fresh-denied',
      writes: [{ path: forbidden, body: 'bad\n', containmentRoot: f.root }],
      allowedGuardRoots: [f.state, f.root], allowedWriteRoots: [f.state], exactWritePaths: [forbidden] }));
    assert(!fs.existsSync(forbidden));
    const p = pending(f, 'replay-denied', [{ path: forbidden, body: 'bad\n', containmentRoot: f.root }]);
    assert.throws(() => tx.recoverOne(p.root, { allowedGuardRoots: [f.state, f.root], allowedWriteRoots: [f.state], exactWritePaths: [forbidden] }));
    assert(!fs.existsSync(forbidden));
  });
  check('recovery rejects a replaced inspected journal before replay', () => {
    const f = fixture('replacement'), p = pending(f, 'replacement', [{ path: f.target, body: 'approved\n', containmentRoot: f.state }]);
    const policy = inspectedPolicy(f, p, [f.target]);
    const source = fixture('replacement-source'), forbidden = path.join(f.root, 'src', 'forbidden.txt');
    const replacement = pending(source, 'replacement', [{ path: forbidden, body: 'hostile\n', containmentRoot: f.root }], 'after_commit_marker', [f.root]);
    for (const name of ['manifest.json', 'prepared.json', 'commit.json', 'staged', 'backups']) {
      const from = path.join(replacement.root, name);
      if (fs.existsSync(from)) fs.cpSync(from, path.join(p.root, name), { recursive: true, force: true });
    }
    assert.throws(() => tx.recoverOne(p.root, policy), error => error.code === 'transaction_recovery_binding_changed');
    assert(!fs.existsSync(forbidden)); assert(!fs.existsSync(f.target));
  });
  check('same-intent manifest byte changes are rejected even when markers are rewritten', () => {
    const f = fixture('same-intent'), p = pending(f, 'same-intent', [{ path: f.target, body: 'approved\n', containmentRoot: f.state }]);
    const policy = inspectedPolicy(f, p, [f.target]), manifestFile = path.join(p.root, 'manifest.json');
    const manifest = read(manifestFile); manifest.prepared_at = '2000-01-01T00:00:00.000Z'; write(manifestFile, manifest);
    write(path.join(p.root, 'prepared.json'), manifest);
    const markerFile = path.join(p.root, 'commit.json'), marker = read(markerFile);
    marker.manifest_sha256 = hash(fs.readFileSync(manifestFile)); write(markerFile, marker);
    assert.throws(() => tx.recoverOne(p.root, policy), error => error.code === 'transaction_recovery_binding_changed');
    assert(!fs.existsSync(f.target));
  });
  check('forbidden state outputs are rejected during rollback cleanup', () => {
    const f = fixture('forbidden-cleanup'), ledger = path.join(f.state, 'maintenance', 'repair_queue.json');
    write(ledger, 'protected fixture\n');
    const p = pending(f, 'forbidden-cleanup', [{ path: ledger, body: 'bad\n', containmentRoot: f.state }], 'after_prepare_manifest');
    assert.throws(() => tx.recoverOne(p.root, inspectedPolicy(f, p, [f.target])), error => error.code === 'transaction_write_policy_denied');
    assert.equal(fs.readFileSync(ledger, 'utf8'), 'protected fixture\n');
  });
  check('transaction APIs reject getters and proxies without executing caller code', () => {
    const f = fixture('inert-admission'), target = path.join(f.state, 'maintenance', 'must-not-exist.json');
    let callbacks = 0;
    const hostileOptions = {};
    Object.defineProperty(hostileOptions, 'allowedWriteRoots', { enumerable: true, get() { callbacks++; return [f.state]; } });
    assert.throws(() => tx.recoverOne(path.join(f.state, 'maintenance', 'absent'), hostileOptions));
    const hostileRequest = {};
    Object.defineProperty(hostileRequest, 'stateRoot', { enumerable: true, get() { callbacks++; return f.state; } });
    assert.throws(() => tx.commitJsonTransaction(hostileRequest));
    assert.throws(() => tx.commitJsonTransaction(new Proxy({}, { get() { callbacks++; throw new Error('proxy trap executed'); } })));
    assert.throws(() => tx.treeGuardHash({ toString() { callbacks++; return f.root; } }));
    assert.equal(callbacks, 0);
    assert(!fs.existsSync(target));
  });
  process.stdout.write(`${JSON.stringify({ status: 'pass', checks, fixture_directory: path.relative(repo, runRoot).replace(/\\/g, '/') }, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ status: 'fail', checks, code: error.code || error.message, stack: error.stack, fixture_directory: path.relative(repo, runRoot).replace(/\\/g, '/') }, null, 2)}\n`);
  process.exitCode = 1;
} finally {
  const physicalRepo = fs.realpathSync.native(repo), physicalRun = fs.realpathSync.native(runRoot);
  const relative = path.relative(physicalRepo, physicalRun);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || key(path.join(physicalRepo, relative)) !== key(physicalRun)) {
    throw new Error('transaction_test_cleanup_refused_outside_owned_run');
  }
  tx.assertNoReparseParents(repo, runRoot);
  fs.rmSync(physicalRun, { recursive: true, force: false });
}
