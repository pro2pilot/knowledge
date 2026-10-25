'use strict';

// Real disposable files and targeted read-boundary fault injection. Every
// mutation runs in an owned process; the FIFO probe has an independent parent
// guard and an observed exit. These are not native Windows/macOS qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const SOURCE = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));

function worker() {
  const fs = require('node:fs');
  const path = require('node:path');
  const [source, root, scenario] = process.argv.slice(1);
  const manager = require(path.join(source, 'tools/lib/contained-lock-manager'));
  const { LOCK_POLICY, LOCKS } = require(path.join(source, 'tools/lib/lock-policy'));
  const { canonicalOwnerText } = require(path.join(source, 'tools/lib/lock-owner-schema'));
  const directory = path.join(root, 'holder');
  fs.mkdirSync(directory);
  const file = path.join(directory, 'owner.json');
  const owner = { schema_version: 'knowledge-lock-owner.v2',
    lock_id: '6d3b0be9-739a-4a79-a678-100000000001',
    lock_name: 'team-flow', purpose: LOCKS['team-flow'].purpose,
    pid: process.pid, hostname: 'host-X', agent_id: 'audit-Привет', workspace_id: null,
    process_started_at: '2026-10-25T00:00:00.000Z', acquired_at: '2026-10-25T00:00:00.000Z',
    nonce: 'a'.repeat(64), native_identity: null };
  const canonical = canonicalOwnerText(owner);
  let bytes = Buffer.from(canonical);
  if (scenario === 'invalid_utf8') bytes[bytes.indexOf(Buffer.from('host-X')) + 5] = 0xff;
  fs.writeFileSync(file, bytes);
  if (scenario === 'hardlink') fs.linkSync(file, path.join(root, 'second-link'));
  const originals = Object.fromEntries(['openSync', 'readFileSync', 'readSync'].map(name => [name, fs[name]]));
  let ownedFd = null, injected = false, actualBytesRead = 0, readCalls = 0, failure = null, result = null;
  const beforeRead = () => {
    if (injected || scenario !== 'growth') return;
    injected = true;
    // The file was small at lstat/fstat. A real append happens immediately
    // before the first data read, not a fabricated stat or return buffer.
    fs.appendFileSync(file, Buffer.alloc(2 * 1024 * 1024, 0x20));
  };
  const afterRead = () => {
    if (injected) return;
    if (scenario === 'parent_symlink_swap') {
      injected = true;
      const retired = path.join(root, 'retired-holder');
      fs.renameSync(directory, retired);
      fs.symlinkSync(retired, directory, 'dir');
      return;
    }
    if (scenario !== 'same_size_rewrite') return;
    injected = true;
    fs.writeFileSync(file, canonical.replace('host-X', 'host-Y'));
    // Ensure an observable revision even on filesystems with coarse clocks.
    // The file content, inode and length are changed/preserved physically.
    const stamp = new Date(Date.now() + 60000);
    fs.utimesSync(file, stamp, stamp);
  };
  fs.openSync = function openBoundary(target, flags) {
    if (target === file) {
      if (scenario === 'fifo_swap' || scenario === 'symlink_swap') {
        fs.unlinkSync(file);
        if (scenario === 'fifo_swap') {
          fs.renameSync(path.join(root, 'prepared-fifo'), file);
        } else {
          const outside = path.join(root, 'replacement.json');
          fs.writeFileSync(outside, canonical);
          fs.symlinkSync(outside, file);
        }
        injected = true;
        process.stdout.write(JSON.stringify({ marker: 'pre_open_swap', scenario, pid: process.pid }) + '\n');
      }
      ownedFd = originals.openSync.apply(this, arguments);
      return ownedFd;
    }
    return originals.openSync.apply(this, arguments);
  };
  fs.readFileSync = function readFileBoundary(target) {
    if (target !== ownedFd || ownedFd === null) return originals.readFileSync.apply(this, arguments);
    beforeRead();
    if (scenario === 'early_eof') { injected = true; readCalls += 1; return arguments[1] === 'utf8' ? '' : Buffer.alloc(0); }
    // Obtain the same file bytes before applying readFileSync's requested
    // UTF-8 decoding. This makes the byte diagnostic exact even for the
    // invalid-UTF-8 fixture, whose replacement characters are longer.
    const output = originals.readFileSync.call(this, target);
    // Node may call the patched readSync internally; count exactly once.
    actualBytesRead = Math.max(actualBytesRead, Buffer.byteLength(output));
    afterRead();
    return arguments[1] === 'utf8' ? output.toString('utf8') : output;
  };
  fs.readSync = function readBoundary(fd) {
    if (fd !== ownedFd || ownedFd === null) return originals.readSync.apply(this, arguments);
    readCalls += 1;
    beforeRead();
    if (scenario === 'early_eof') { injected = true; return 0; }
    const count = originals.readSync.apply(this, arguments);
    actualBytesRead += count;
    afterRead();
    return count;
  };
  try {
    result = scenario === 'invalid_utf8' || scenario === 'stable'
      ? manager.__test.readStrictOwner(root, directory, { lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose })
      : manager.__test.boundedPhysicalRead(root, file);
  } catch (error) { failure = { code: error.code || null, reason: error.reason || null, message: error.message }; }
  finally { Object.assign(fs, originals); }
  process.stdout.write(JSON.stringify({ scenario, host: process.platform, pid: process.pid, injected,
    limit_bytes: LOCK_POLICY.owner_max_bytes, actual_bytes_read: actualBytesRead, read_calls: readCalls,
    initial_bytes: bytes.length, failure, accepted: result !== null,
    raw_matches: result?.raw === canonical, accepted_hostname: result?.owner?.hostname || null,
    physical_path_retained: fs.lstatSync(file).isFile() || fs.lstatSync(file).isFIFO() || fs.lstatSync(file).isSymbolicLink() }) + '\n');
}

function runOwned(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    const output = [], errors = [];
    let timedOut = false, launchError = null, cleanupGuard;
    child.stdout.on('data', chunk => output.push(chunk));
    child.stderr.on('data', chunk => errors.push(chunk));
    child.on('error', error => { launchError = error; });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
      cleanupGuard = setTimeout(() => reject(new Error('Owned probe exit remains unconfirmed after SIGKILL')), 15000);
    }, 10000);
    child.on('close', (status, signal) => {
      clearTimeout(timer); clearTimeout(cleanupGuard);
      resolve({ pid: child.pid, status, signal, timedOut, error: launchError,
        stdout: Buffer.concat(output).toString('utf8'), stderr: Buffer.concat(errors).toString('utf8') });
    });
  });
}

async function probe(t, scenario) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-audit-owner-read-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  if (scenario === 'fifo_swap') {
    const preparation = await runOwned('mkfifo', [path.join(root, 'prepared-fifo')]);
    assert.ifError(preparation.error);
    assert.equal(preparation.timedOut, false);
    assert.equal(preparation.status, 0, preparation.stderr);
  }
  const child = await runOwned(process.execPath, ['-e', `(${worker.toString()})()`, SOURCE, root, scenario], {
    windowsHide: true, env: { ...process.env, NODE_OPTIONS: '', NODE_PATH: '' },
  });
  let exitObserved = false;
  if (child.pid) {
    try { process.kill(child.pid, 0); }
    catch (error) { if (error.code === 'ESRCH') exitObserved = true; else throw error; }
  }
  const lines = String(child.stdout || '').trim().split('\n').filter(Boolean);
  const observed = lines.length ? JSON.parse(lines.at(-1)) : null;
  t.diagnostic(JSON.stringify({ scenario, command_source: SOURCE, status: child.status, signal: child.signal,
    error: child.error?.code || null, timed_out: child.timedOut, exit_observed: exitObserved, stdout: observed, stderr: child.stderr }));
  assert.equal(exitObserved, true, 'The owned child must be reaped and its exit observed; a timeout is not cleanup proof');
  assert.ifError(child.error);
  assert.equal(child.timedOut, false, 'The owner read did not complete within its independent fixture guard');
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.signal, null);
  assert.equal(child.stderr, '');
  assert.equal(observed.physical_path_retained, true, 'A read must preserve the uncertain owner evidence');
  return observed;
}

test('stable canonical UTF-8 owner is accepted unchanged', { timeout: 30000 }, async t => {
  const r = await probe(t, 'stable');
  assert.equal(r.failure, null);
  assert.equal(r.accepted, true);
  assert.equal(r.accepted_hostname, 'host-X');
});

test('owner growth after metadata checks cannot exceed the read budget', { timeout: 30000 }, async t => {
  const r = await probe(t, 'growth');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false);
  assert.ok(r.actual_bytes_read <= r.limit_bytes + 1,
    `Reader consumed ${r.actual_bytes_read} bytes for a ${r.limit_bytes}-byte owner limit`);
  assert.ok(r.failure);
});

test('same-size owner rewrite during the read is rejected', { timeout: 30000 }, async t => {
  const r = await probe(t, 'same_size_rewrite');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false, 'Device/inode/length equality cannot prove immutable owner bytes');
  assert.equal(r.failure?.code, 'unsafe_lock_owner');
});

test('invalid UTF-8 is rejected before canonical owner acceptance', { timeout: 30000 }, async t => {
  const r = await probe(t, 'invalid_utf8');
  assert.equal(r.accepted, false, 'Lossy UTF-8 decoding silently changed the authoritative owner bytes');
  assert.equal(r.failure?.code, 'lock_owner_invalid');
  assert.equal(r.failure?.reason, 'invalid_utf8');
});

test('a premature read EOF cannot produce a complete owner snapshot', { timeout: 30000 }, async t => {
  const r = await probe(t, 'early_eof');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false);
  assert.equal(r.failure?.code, 'unsafe_lock_owner');
});

test('owner swapped to FIFO between validation and open does not block', { timeout: 30000,
  skip: process.platform === 'win32' ? 'POSIX FIFO fixture; Windows reparse qualification is separate' : false }, async t => {
  const r = await probe(t, 'fifo_swap');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false);
  assert.equal(r.failure?.code, 'unsafe_lock_owner');
});

test('owner swapped to symlink before open stays rejected', { timeout: 30000,
  skip: process.platform === 'win32' ? 'POSIX symlink race fixture; Windows reparse qualification is separate' : false }, async t => {
  const r = await probe(t, 'symlink_swap');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false);
  assert.equal(r.failure?.code, 'unsafe_lock_owner');
});

test('hardlinked owner stays rejected without removing evidence', { timeout: 30000 }, async t => {
  const r = await probe(t, 'hardlink');
  assert.equal(r.accepted, false);
  assert.equal(r.failure?.code, 'lock_owner_hardlinked');
});

test('parent symlink replacement is rejected even when the owner inode is unchanged', { timeout: 30000,
  skip: process.platform === 'win32' ? 'POSIX rename-open-directory fixture; Windows qualification is separate' : false }, async t => {
  const r = await probe(t, 'parent_symlink_swap');
  assert.equal(r.injected, true);
  assert.equal(r.accepted, false, 'The same owner inode may have become reachable only through a substituted parent');
  assert.equal(r.failure?.code, 'unsafe_lock_owner');
});
