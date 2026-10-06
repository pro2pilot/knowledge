#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const systemRoot = path.resolve(process.env.KNOWLEDGE_AUDIT_SYSTEM_ROOT || path.join(__dirname, '..'));
const locks = require(path.join(systemRoot, 'tools/lib/contained-lock-manager'));
const { LOCK_POLICY, LOCKS } = require(path.join(systemRoot, 'tools/lib/lock-policy'));
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-lock-transitions-'));
const checks = [];

function identity(directory) {
  const stat = fs.lstatSync(directory, { bigint: true });
  assert(stat.isDirectory() && !stat.isSymbolicLink());
  return `${stat.dev}:${stat.ino}`;
}

function hooks(overrides, run) {
  const originals = {};
  for (const [key, override] of Object.entries(overrides)) {
    originals[key] = fs[key];
    fs[key] = function(...args) { return override(originals[key], args); };
  }
  try { return run(); }
  finally { for (const [key, original] of Object.entries(originals)) fs[key] = original; }
}

function fixture(root, evidence) {
  const stateRoot = path.join(root, 'state');
  const request = {
    rootKind: 'state', rootPath: stateRoot, lockName: 'sync', purpose: LOCKS.sync.purpose,
    context: { stateRoot }, timeoutMs: 1500
  };
  const first = locks.acquireContainedLock(request);
  const lockDir = first.path;
  const ownerFile = path.join(lockDir, 'owner.json');
  const ownerText = fs.readFileSync(ownerFile, 'utf8');
  const policy = locks.__test.requestPolicy(request);
  const paths = locks.lockPaths(policy);
  let successor = null;
  let count = 0;
  let transitioning = false;
  return {
    request, first, lockDir, ownerFile, ownerText, policy, paths,
    get transitioning() { return transitioning; },
    get successor() { return successor; },
    rotate({ unlinkRetiredOwner = false, createSuccessor = true } = {}) {
      transitioning = true;
      try {
        const before = identity(lockDir);
        const retired = path.join(stateRoot, `retired-${++count}`);
        // Keep the retired physical directory allocated: this rules out inode
        // reuse and makes the ABA namespace replacement reproducible.
        fs.renameSync(lockDir, retired);
        if (unlinkRetiredOwner) fs.unlinkSync(path.join(retired, 'owner.json'));
        successor = createSuccessor ? locks.acquireContainedLock(request) : null;
        const after = createSuccessor ? identity(lockDir) : null;
        if (createSuccessor) assert.notEqual(before, after);
        evidence.push({ event: 'physical_directory_transition', before, after });
        return retired;
      } finally { transitioning = false; }
    },
    releaseSuccessor() {
      if (!successor) return;
      transitioning = true;
      try { successor.release(); successor = null; }
      finally { transitioning = false; }
    },
    inspectForAcquire() {
      return locks.__test.inspectCurrent(policy, paths, { retryDirectoryTransitions: true });
    }
  };
}

function isPath(value, target) { return typeof value === 'string' && path.resolve(value) === target; }

function check(name, run) {
  const root = path.join(base, String(checks.length));
  fs.mkdirSync(root);
  const evidence = [];
  try {
    run(root, evidence);
    checks.push({ name, status: 'pass', ...(evidence.length ? { evidence } : {}) });
  } catch (error) {
    checks.push({ name, status: 'fail', error: error.stack || error.message, ...(evidence.length ? { evidence } : {}) });
  }
}

// These hooks schedule real filesystem changes at specific observation
// boundaries. All directory/file identities, reads, owner validation, lock
// acquisition and lock release come from the production implementation.
function acquireAcrossTransition(root, evidence, boundary, options = {}) {
  const f = fixture(root, evidence);
  let armed = true;
  let descriptor = null;
  const overrides = {
    mkdirSync(native, args) {
      if (isPath(args[0], f.lockDir) && !f.transitioning && f.successor) f.releaseSuccessor();
      return native(...args);
    },
    openSync(native, args) {
      const isOwner = isPath(args[0], f.ownerFile) && !f.transitioning;
      if (armed && isOwner && boundary === 'before_open') {
        armed = false;
        f.rotate(options);
      }
      const opened = native(...args);
      if (isOwner) descriptor = opened;
      if (armed && isOwner && boundary === 'after_open') {
        armed = false;
        try { f.rotate(options); }
        catch (error) { fs.closeSync(opened); throw error; }
      }
      return opened;
    },
    closeSync(native, args) {
      const result = native(...args);
      if (armed && args[0] === descriptor && !f.transitioning && boundary === 'after_close') {
        armed = false;
        f.rotate(options);
      }
      return result;
    }
  };
  let acquired;
  try { acquired = hooks(overrides, () => locks.acquireContainedLock(f.request)); }
  finally { f.releaseSuccessor(); }
  assert(!armed, 'scheduled physical transition did not occur');
  assert(Number.isInteger(descriptor), 'physical owner descriptor was not opened');
  assert.notEqual(acquired.lock_id, f.first.lock_id);
  assert.equal(acquired.release().status, 'released');
  assert(!fs.existsSync(f.lockDir), 'acquired lock was not cleaned up');
}

function replaceDuringRead(f, mutation, run, boundary = 'read') {
  let descriptor = null;
  let armed = true;
  const result = hooks({
    openSync(native, args) {
      const opened = native(...args);
      if (isPath(args[0], f.ownerFile) && !f.transitioning) descriptor = opened;
      return opened;
    },
    readFileSync(native, args) {
      const raw = native(...args);
      if (armed && boundary === 'read' && typeof args[0] === 'number' && args[0] === descriptor && !f.transitioning) {
        armed = false;
        mutation();
      }
      return raw;
    },
    closeSync(native, args) {
      const result = native(...args);
      if (armed && boundary === 'close' && args[0] === descriptor && !f.transitioning) {
        armed = false;
        mutation();
      }
      return result;
    }
  }, run);
  assert(!armed, 'scheduled owner read boundary did not occur');
  return result;
}

try {
  check('acquisition retries proven directory replacement between owner lstat and open', (root, evidence) => {
    acquireAcrossTransition(root, evidence, 'before_open');
  });

  check('acquisition tolerates directory disappearance between owner lstat and open', (root, evidence) => {
    acquireAcrossTransition(root, evidence, 'before_open', { createSuccessor: false });
  });

  check('acquisition retries retired owner unlink after a proven directory replacement', (root, evidence) => {
    // Windows forbids moving a directory containing an open owner handle.
    // Schedule at close instead: the old owner is buffered, and production
    // must still detect the proven directory replacement before using it.
    acquireAcrossTransition(root, evidence, process.platform === 'win32' ? 'after_close' : 'after_open', { unlinkRetiredOwner: true });
  });

  check('acquisition does not use a valid buffered owner from a replaced directory', (root, evidence) => {
    const f = fixture(root, evidence);
    try {
      const inspected = replaceDuringRead(f, () => f.rotate(), () => f.inspectForAcquire(), process.platform === 'win32' ? 'close' : 'read');
      assert.equal(inspected.status, 'replaced');
    } finally { f.releaseSuccessor(); }
  });

  check('same directory owner replacement before open remains denied', (root, evidence) => {
    const f = fixture(root, evidence);
    const before = identity(f.lockDir);
    let armed = true;
    assert.throws(() => hooks({
      openSync(native, args) {
        if (armed && isPath(args[0], f.ownerFile)) {
          armed = false;
          fs.renameSync(f.ownerFile, path.join(root, 'retired-owner.json'));
          fs.writeFileSync(f.ownerFile, f.ownerText);
        }
        return native(...args);
      }
    }, () => locks.acquireContainedLock(f.request)), error => error.code === 'unsafe_lock_owner');
    assert(!armed);
    assert.equal(identity(f.lockDir), before);
  });

  check('same directory owner replacement after buffered read remains denied', (root, evidence) => {
    const f = fixture(root, evidence);
    const before = identity(f.lockDir);
    assert.throws(() => replaceDuringRead(f, () => {
      fs.renameSync(f.ownerFile, path.join(root, 'retired-owner.json'));
      fs.writeFileSync(f.ownerFile, f.ownerText);
    }, () => f.inspectForAcquire()), error => error.code === 'unsafe_lock_owner');
    assert.equal(identity(f.lockDir), before);
  });

  check('same directory hardlinked owner remains denied', (root, evidence) => {
    const f = fixture(root, evidence);
    const before = identity(f.lockDir);
    fs.linkSync(f.ownerFile, path.join(root, 'owner-hardlink.json'));
    assert.throws(() => locks.acquireContainedLock(f.request), error => error.code === 'lock_owner_hardlinked');
    assert.equal(identity(f.lockDir), before);
    assert.equal(fs.lstatSync(f.ownerFile).nlink, 2);
  });

  check('same directory owner becoming hardlinked before open remains denied', (root, evidence) => {
    const f = fixture(root, evidence);
    const before = identity(f.lockDir);
    let armed = true;
    assert.throws(() => hooks({
      openSync(native, args) {
        if (armed && isPath(args[0], f.ownerFile)) {
          armed = false;
          fs.linkSync(f.ownerFile, path.join(root, 'owner-hardlink.json'));
        }
        return native(...args);
      }
    }, () => locks.acquireContainedLock(f.request)), error => error.code === 'lock_owner_hardlinked');
    assert(!armed);
    assert.equal(identity(f.lockDir), before);
  });

  check('same directory symlink owner remains denied without modifying its target', (root, evidence) => {
    const f = fixture(root, evidence);
    const target = path.join(root, 'outside-owner.json');
    fs.writeFileSync(target, f.ownerText);
    fs.unlinkSync(f.ownerFile);
    fs.symlinkSync(target, f.ownerFile, 'file');
    assert.throws(() => locks.acquireContainedLock(f.request), error => error.code === 'unsafe_lock_owner');
    assert.equal(fs.readFileSync(target, 'utf8'), f.ownerText);
  });

  check('directory replacement with a symlink remains denied', (root, evidence) => {
    const f = fixture(root, evidence);
    const target = path.join(root, 'outside-lock');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, 'owner.json'), f.ownerText);
    let armed = true;
    assert.throws(() => hooks({
      openSync(native, args) {
        if (armed && isPath(args[0], f.ownerFile)) {
          armed = false;
          fs.renameSync(f.lockDir, path.join(root, 'retired-directory'));
          fs.symlinkSync(target, f.lockDir, process.platform === 'win32' ? 'junction' : 'dir');
        }
        return native(...args);
      }
    }, () => locks.acquireContainedLock(f.request)), error => error.code === 'unsafe_lock_path' || error.code === 'unsafe_lock_owner');
    assert(!armed);
    assert.equal(fs.readFileSync(path.join(target, 'owner.json'), 'utf8'), f.ownerText);
  });

  for (const [name, text, reason] of [
    ['malformed JSON', '{broken', 'malformed_json'],
    ['noncanonical JSON', null, 'noncanonical_json']
  ]) {
    check(`stable ${name} owner remains denied`, (root, evidence) => {
      const f = fixture(root, evidence);
      const bytes = text === null ? JSON.stringify(JSON.parse(f.ownerText)) : text;
      fs.writeFileSync(f.ownerFile, bytes);
      assert.throws(() => locks.acquireContainedLock(f.request), error => error.code === 'lock_owner_invalid' && error.reason === reason);
      assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), bytes);
    });
  }

  check('stable ownerless directory beyond initialization grace remains a safety finding', (root, evidence) => {
    const f = fixture(root, evidence);
    fs.unlinkSync(f.ownerFile);
    const past = new Date(Date.now() - LOCK_POLICY.owner_initialization_grace_ms - 10000);
    fs.utimesSync(f.lockDir, past, past);
    const inspected = locks.inspectLockSafety(f.request);
    assert.equal(inspected.status, 'unsafe');
    assert(inspected.findings.some(item => item.code === 'lock_owner_invalid' && item.reason === 'missing'));
    assert.throws(() => locks.acquireContainedLock(f.request), error => error.code === 'lock_owner_invalid' && error.reason === 'missing');
    assert(fs.existsSync(f.lockDir));
  });

  check('young physical ownerless directory retains bounded initialization grace', (root, evidence) => {
    const f = fixture(root, evidence);
    fs.unlinkSync(f.ownerFile);
    const inspected = locks.inspectLockSafety(f.request);
    assert.equal(inspected.status, 'active');
    assert.deepEqual(inspected.findings, []);
    assert.equal(inspected.current.owner, null);
    assert(fs.existsSync(f.lockDir));
  });

  check('release cannot release a successor after directory replacement', (root, evidence) => {
    const f = fixture(root, evidence);
    f.rotate();
    const ownerText = fs.readFileSync(f.ownerFile, 'utf8');
    try {
      assert.throws(() => f.first.release(), error => error.code === 'lock_ownership_changed');
      assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), ownerText);
    } finally { f.releaseSuccessor(); }
    assert(!fs.existsSync(f.lockDir));
  });

  check('repeated proven directory transitions respect acquisition timeout', (root, evidence) => {
    const f = fixture(root, evidence);
    const started = Date.now();
    try {
      assert.throws(() => hooks({
        openSync(native, args) {
          if (isPath(args[0], f.ownerFile) && !f.transitioning) f.rotate();
          return native(...args);
        }
      }, () => locks.acquireContainedLock({ ...f.request, timeoutMs: 50 })), error => error.code === 'lock_timeout');
      assert(evidence.length > 0);
      assert(Date.now() - started < 3000, 'directory transitions bypassed the acquisition deadline');
    } finally { f.releaseSuccessor(); }
  });
  check('release rejects a replaced directory even with identical owner bytes', (root, evidence) => {
    const f = fixture(root, evidence);
    f.rotate();
    fs.writeFileSync(f.ownerFile, f.ownerText);
    assert.throws(() => f.first.release(), error => error.code === 'lock_ownership_changed');
    assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), f.ownerText);
  });
  check('release preserves a cloned-owner directory swapped at the rename boundary', (root, evidence) => {
    const f = fixture(root, evidence);
    let armed = true, quarantine = null, retired = null;
    assert.throws(() => hooks({ renameSync(native, args) {
      if (armed && isPath(args[0], f.lockDir) && !f.transitioning) {
        armed = false;
        retired = f.rotate({ createSuccessor: false });
        fs.mkdirSync(f.lockDir);
        fs.writeFileSync(f.ownerFile, f.ownerText);
        quarantine = args[1];
      }
      return native(...args);
    } }, () => f.first.release()), error => error.code === 'lock_ownership_changed');
    assert(!armed);
    assert.equal(fs.readFileSync(path.join(quarantine, 'owner.json'), 'utf8'), f.ownerText);
    assert.equal(fs.readFileSync(path.join(retired, 'owner.json'), 'utf8'), f.ownerText);
    assert.notEqual(identity(quarantine), identity(retired));
  });
  if (process.platform === 'win32') {
    for (const failure of ['renamed_handle', 'EBADF']) {
      check(`Windows directory resolution ${failure} requires proven namespace disappearance`, (root, evidence) => {
        const f = fixture(root, evidence);
        const native = fs.realpathSync.native;
        let armed = true;
        try {
          fs.realpathSync.native = function(value, ...args) {
            if (armed && isPath(value, f.lockDir) && !f.transitioning) {
              armed = false;
              const retired = f.rotate({ createSuccessor: false });
              if (failure === 'EBADF') { const error = new Error('deleted directory handle'); error.code = 'EBADF'; throw error; }
              return retired;
            }
            return native.call(fs.realpathSync, value, ...args);
          };
          assert.equal(f.inspectForAcquire().status, 'missing');
          assert(!armed);
        } finally { fs.realpathSync.native = native; }
      });
      check(`Windows directory resolution ${failure} on the same directory remains denied`, (root, evidence) => {
        const f = fixture(root, evidence);
        const native = fs.realpathSync.native;
        let armed = true;
        try {
          fs.realpathSync.native = function(value, ...args) {
            if (armed && isPath(value, f.lockDir)) {
              armed = false;
              if (failure === 'EBADF') { const error = new Error('persistent handle denial'); error.code = 'EBADF'; throw error; }
              return path.join(root, 'outside-directory');
            }
            return native.call(fs.realpathSync, value, ...args);
          };
          assert.throws(() => f.inspectForAcquire(), error => error.code === 'unsafe_lock_path');
          assert(!armed);
          assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), f.ownerText);
        } finally { fs.realpathSync.native = native; f.first.release(); }
      });
    }
    check('Windows release waits for an actual contender owner handle to close', (root, evidence) => {
      const f = fixture(root, evidence);
      const marker = path.join(root, 'reader-ready');
      const child = require('child_process').spawn(process.execPath, ['-e', 'const fs=require("fs");const fd=fs.openSync(process.argv[1],"r");fs.writeFileSync(process.argv[2],"ready");setTimeout(()=>fs.closeSync(fd),500);', f.ownerFile, marker], { stdio: 'ignore', windowsHide: true });
      let failures = 0;
      try {
        const deadline = Date.now() + 3000;
        while (!fs.existsSync(marker) && Date.now() < deadline) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
        assert(fs.existsSync(marker), 'physical reader did not start');
        const result = hooks({ renameSync(native, args) {
          try { return native(...args); }
          catch (error) { if (isPath(args[0], f.lockDir) && ['EPERM', 'EACCES', 'EBUSY'].includes(error.code)) failures++; throw error; }
        } }, () => f.first.release());
        assert.equal(result.status, 'released');
        assert(failures > 0, 'no native Windows sharing failure observed');
        evidence.push({ event: 'native_sharing_failures_retried', count: failures });
        assert(!fs.existsSync(f.lockDir));
      } finally { child.kill(); }
    });
    check('Windows release sharing retries fail closed when the successor changes', (root, evidence) => {
      const f = fixture(root, evidence);
      let armed = true;
      try {
        assert.throws(() => hooks({ renameSync(native, args) {
          if (armed && isPath(args[0], f.lockDir) && !f.transitioning) {
            armed = false; f.rotate(); const error = new Error('scheduled sharing denial'); error.code = 'EPERM'; throw error;
          }
          return native(...args);
        } }, () => f.first.release()), error => error.code === 'lock_ownership_changed');
        assert(!armed);
        assert.equal(JSON.parse(fs.readFileSync(f.ownerFile, 'utf8')).lock_id, f.successor.lock_id);
      } finally { f.releaseSuccessor(); }
    });
    check('Windows persistent release denial respects the deadline and preserves owner', (root, evidence) => {
      const f = fixture(root, evidence);
      const started = Date.now();
      assert.throws(() => hooks({ renameSync(native, args) {
        if (isPath(args[0], f.lockDir)) { const error = new Error('persistent sharing denial'); error.code = 'EACCES'; throw error; }
        return native(...args);
      } }, () => f.first.release()), error => error.code === 'unsafe_lock_path' && error.os_code === 'EACCES');
      assert(Date.now() - started >= 1000 && Date.now() - started < 3500);
      assert.equal(fs.readFileSync(f.ownerFile, 'utf8'), f.ownerText);
      assert.equal(f.first.release().status, 'released');
    });
  }
} finally {
  fs.rmSync(base, { recursive: true, force: true });
}

const failed = checks.filter(item => item.status === 'fail').length;
process.stdout.write(`${JSON.stringify({ status: failed ? 'failed' : 'passed', total: checks.length, passed: checks.length - failed, failed, checks }, null, 2)}\n`);
process.exitCode = failed ? 1 : 0;
