#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {
  writeJsonAtomic,
  writeFileAtomic,
  __test: { removeDirRecursive }
} = require('./lib/json-store');
const { withContainedLock } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { systemVersion } = require('./lib/system-version');

function assert(condition, message, details = {}) {
  if (condition) return;
  const error = new Error(message);
  error.details = details;
  throw error;
}

function ioError(code) {
  const error = new Error(`injected ${code}`);
  error.code = code;
  return error;
}

function tempArtifacts(filePath) {
  const dir = path.dirname(filePath);
  const prefix = `${path.basename(filePath)}.tmp-`;
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((name) => name.startsWith(prefix));
}

function retryHooks(code, failures, observed) {
  return {
    random: () => 0,
    sleepSync: (ms) => observed.sleeps.push(ms),
    renameSync: (from, to) => {
      observed.attempts += 1;
      if (observed.attempts <= failures) throw ioError(code);
      fs.renameSync(from, to);
    }
  };
}

function terminalHooks(code, observed) {
  return {
    random: () => 0,
    sleepSync: (ms) => observed.sleeps.push(ms),
    renameSync: () => {
      observed.attempts += 1;
      throw ioError(code);
    }
  };
}

function main() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'k-json-win-'));
  const checks = [];
  try {
    for (const code of ['EPERM', 'EACCES', 'EBUSY']) {
      const recovered = path.join(root, `${code.toLowerCase()}-recovered.json`);
      const recoveryObserved = { attempts: 0, sleeps: [] };
      writeJsonAtomic(recovered, { code, recovered: true }, {
        hooks: retryHooks(code, 2, recoveryObserved)
      });
      assert(recoveryObserved.attempts === 3, `${code} recovery attempt count is wrong`, recoveryObserved);
      assert(
        JSON.stringify(recoveryObserved.sleeps) === JSON.stringify([50, 100]),
        `${code} recovery backoff is wrong`,
        recoveryObserved
      );
      assert(JSON.parse(fs.readFileSync(recovered, 'utf8')).recovered === true, `${code} recovery target is invalid`);
      assert(tempArtifacts(recovered).length === 0, `${code} recovery left a temp file`, { files: tempArtifacts(recovered) });
      checks.push(`${code} recovers after two transient rename failures`);

      const existing = path.join(root, `${code.toLowerCase()}-terminal-existing.json`);
      const sentinel = `sentinel-${code}\n`;
      fs.writeFileSync(existing, sentinel, 'utf8');
      const terminalObserved = { attempts: 0, sleeps: [] };
      let terminalError = null;
      try {
        writeJsonAtomic(existing, { must_not_replace: true }, {
          hooks: terminalHooks(code, terminalObserved)
        });
      } catch (error) {
        terminalError = error;
      }
      assert(terminalError, `${code} terminal failure did not throw`);
      assert(terminalError.code === 'atomic_write_retry_exhausted', `${code} terminal code is unstable`, terminalError);
      assert(terminalError.os_code === code, `${code} terminal os_code is missing`, terminalError);
      assert(terminalError.attempts === 6, `${code} terminal attempts are wrong`, terminalError);
      assert(terminalError.operation === 'rename', `${code} terminal operation is wrong`, terminalError);
      assert(terminalError.temp_cleanup_status === 'removed', `${code} terminal temp cleanup was not reported`, terminalError);
      assert(terminalObserved.attempts === 6, `${code} terminal hook attempt count is wrong`, terminalObserved);
      assert(
        JSON.stringify(terminalObserved.sleeps) === JSON.stringify([50, 100, 200, 400, 800]),
        `${code} terminal backoff is wrong`,
        terminalObserved
      );
      assert(fs.readFileSync(existing, 'utf8') === sentinel, `${code} terminal failure changed the destination`);
      assert(tempArtifacts(existing).length === 0, `${code} terminal failure left a temp file`, { files: tempArtifacts(existing) });
      checks.push(`${code} exhaustion preserves an existing destination and cleans temp`);

      const absent = path.join(root, `${code.toLowerCase()}-terminal-absent.json`);
      const absentObserved = { attempts: 0, sleeps: [] };
      try {
        writeJsonAtomic(absent, { must_not_exist: true }, {
          hooks: terminalHooks(code, absentObserved)
        });
      } catch {}
      assert(!fs.existsSync(absent), `${code} terminal failure created an absent destination`);
      assert(tempArtifacts(absent).length === 0, `${code} absent-target failure left a temp file`, { files: tempArtifacts(absent) });
      checks.push(`${code} exhaustion leaves an absent destination absent`);
    }

    const nonTransient = path.join(root, 'enospc.json');
    fs.writeFileSync(nonTransient, 'sentinel-enospc\n', 'utf8');
    const enospcObserved = { attempts: 0, sleeps: [] };
    let enospcError = null;
    try {
      writeJsonAtomic(nonTransient, { must_not_replace: true }, {
        hooks: terminalHooks('ENOSPC', enospcObserved)
      });
    } catch (error) {
      enospcError = error;
    }
    assert(enospcError?.code === 'ENOSPC', 'ENOSPC must be rethrown without retry wrapping', enospcError);
    assert(enospcObserved.attempts === 1, 'ENOSPC must not be retried', enospcObserved);
    assert(enospcObserved.sleeps.length === 0, 'ENOSPC unexpectedly slept', enospcObserved);
    assert(fs.readFileSync(nonTransient, 'utf8') === 'sentinel-enospc\n', 'ENOSPC changed the destination');
    assert(tempArtifacts(nonTransient).length === 0, 'ENOSPC left a temp file', { files: tempArtifacts(nonTransient) });
    checks.push('non-transient ENOSPC fails immediately and preserves destination');

    const sharedWriter = path.join(root, 'shared-writer.txt');
    const sharedObserved = { attempts: 0, sleeps: [] };
    writeFileAtomic(sharedWriter, 'shared path\n', {
      hooks: retryHooks('EBUSY', 1, sharedObserved)
    });
    assert(sharedObserved.attempts === 2, 'writeFileAtomic did not use the shared retry path', sharedObserved);
    assert(fs.readFileSync(sharedWriter, 'utf8') === 'shared path\n', 'writeFileAtomic recovery content is wrong');
    assert(tempArtifacts(sharedWriter).length === 0, 'writeFileAtomic recovery left a temp file');
    checks.push('writeFileAtomic shares the bounded retry implementation');

    const lockRoot = path.join(root, 'contained-lock-root');
    fs.mkdirSync(lockRoot);
    let entered = false;
    withContainedLock({
      context: { stateRoot: lockRoot },
      rootKind: 'state',
      rootPath: lockRoot,
      lockName: 'doctor',
      purpose: LOCKS.doctor.purpose,
      timeoutMs: 500,
      staleMs: 120000,
      retryMs: 1
    }, () => { entered = true; });
    assert(entered, 'contained lock callback did not run');
    assert(!fs.existsSync(path.join(lockRoot, 'locks', 'v1', 'doctor.lock')), 'contained lock was not released');
    checks.push('contained directory lock uses the shared strict cleanup path');

    const transientLock = path.join(root, 'transient-lock');
    fs.mkdirSync(transientLock);
    fs.writeFileSync(path.join(transientLock, 'owner.json'), '{}\n');
    let transientAttempts = 0;
    removeDirRecursive(transientLock, {
      attempts: 4,
      initialDelayMs: 1,
      maxDelayMs: 2,
      maxElapsedMs: 1000,
      sleep: () => {},
      remove: (target) => {
        transientAttempts += 1;
        if (transientAttempts <= 2) throw ioError('EBUSY');
        fs.rmSync(target, { recursive: true, force: true });
      }
    });
    assert(transientAttempts === 3, 'lock cleanup did not retry transient EBUSY', { transientAttempts });
    assert(!fs.existsSync(transientLock), 'transient lock directory was not removed');
    checks.push('lock cleanup retries transient EBUSY and verifies removal');

    const persistentLock = path.join(root, 'persistent-lock');
    fs.mkdirSync(persistentLock);
    let persistentError = null;
    try {
      removeDirRecursive(persistentLock, {
        attempts: 3,
        initialDelayMs: 1,
        maxDelayMs: 2,
        maxElapsedMs: 1000,
        sleep: () => {},
        remove: () => { throw ioError('EPERM'); }
      });
    } catch (error) {
      persistentError = error;
    }
    assert(persistentError?.code === 'TEMP_FIXTURE_CLEANUP_FAILED', 'persistent lock cleanup did not fail clearly', persistentError);
    assert(persistentError?.reason === 'persistent_resource_lock', 'persistent lock diagnostic reason is missing', persistentError);
    fs.rmSync(persistentLock, { recursive: true, force: true });
    checks.push('persistent lock cleanup fails with a resource-lock diagnostic');

    return {
      schema_version: systemVersion(),
      status: 'pass',
      checks_total: checks.length,
      checks
    };
  } finally {
    removeDirRecursive(root);
  }
}

if (require.main === module) {
  try {
    console.log(JSON.stringify(main(), null, 2));
  } catch (error) {
    console.error(error.stack || error.message);
    if (error.details) console.error(JSON.stringify(error.details, null, 2));
    process.exitCode = 1;
  }
}

module.exports = main;
