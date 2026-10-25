'use strict';

// Linux kernel-owned descendant containment. A PID namespace is not a network
// or filesystem sandbox. macOS must never be routed through this backend.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const PROTOCOL = 'knowledge-linux-namespace-helper.v1';
const SCHEMA = 'knowledge-linux-pid-namespace.v1';
const SOURCE = path.join(__dirname, 'verification-linux-namespace.c');
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const clock = () => process.hrtime.bigint();
const elapsed = start => Number(clock() - start) / 1e6;
const failure = (code, detail) => Object.assign(new Error(detail || code), { code });
let prepared;
const admittedHelpers = new WeakSet();

// Ordinary Flow uses the packaged executable. Runtime compilation remains an
// explicit legacy verification setup path; it is never a Flow fallback.
function preparePackagedHelper(options = {}) {
  if (process.platform !== 'linux') throw failure('command_containment_unavailable');
  const { readStableFile, decodeUtf8 } = require('./stable-file');
  const root = path.resolve(__dirname, '..', '..');
  const directory = path.join(__dirname, 'native', `linux-${process.arch}`);
  const executable = path.join(directory, 'verification-linux-namespace');
  const record = JSON.parse(decodeUtf8(readStableFile(root, path.join(directory, 'verification-linux-namespace.manifest.json'), { maxBytes: 16384 })));
  const source = readStableFile(root, SOURCE, { maxBytes: 1024 * 1024 });
  const binary = readStableFile(root, executable, { maxBytes: 8 * 1024 * 1024 });
  if (record.schema_version !== 'knowledge-command-native-binary.v1' || record.platform !== 'linux' ||
      record.architecture !== process.arch || record.binary !== 'verification-linux-namespace' ||
      record.source_sha256 !== hash(source) || record.binary_sha256 !== hash(binary) || record.binary_bytes !== binary.length ||
      !(fs.lstatSync(executable).mode & 0o111)) throw failure('command_native_binary_invalid');
  const result = options.snapshot === true ? snapshotPackagedHelper(record, binary, options) : { ...record, executable };
  admittedHelpers.add(result);
  return result;
}

function snapshotPackagedHelper(record, binary, options) {
  // A concurrent package update may replace the public executable after its
  // hash was checked. The admitted invocation executes this private snapshot.
  // This copying work runs only in the isolated preparer/query worker.
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'knowledge-command-native-'));
  fs.chmodSync(directory, 0o700);
  const directoryStat = fs.lstatSync(directory, { bigint: true });
  const executable = path.join(directory, 'verification-linux-namespace');
  let descriptor, result;
  try {
    descriptor = fs.openSync(executable, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
      fs.constants.O_NOFOLLOW, 0o500);
    const fileStat = fs.fstatSync(descriptor, { bigint: true });
    result = { ...record, executable, snapshot: { schema_version: 'knowledge-command-native-snapshot.v1', directory,
      directory_dev: String(directoryStat.dev), directory_ino: String(directoryStat.ino),
      file_dev: String(fileStat.dev), file_ino: String(fileStat.ino), uid: String(fileStat.uid) } };
    options.onSnapshot?.(result);
    fs.writeFileSync(descriptor, binary); fs.fsyncSync(descriptor); fs.closeSync(descriptor); descriptor = undefined;
    const checked = require('./stable-file').readStableFile(directory, executable, { maxBytes: 8 * 1024 * 1024 });
    const final = fs.lstatSync(executable, { bigint: true }), currentDirectory = fs.lstatSync(directory, { bigint: true });
    if (hash(checked) !== record.binary_sha256 || checked.length !== record.binary_bytes ||
        final.dev !== fileStat.dev || final.ino !== fileStat.ino || final.nlink !== 1n || (final.mode & 0o777n) !== 0o500n ||
        currentDirectory.dev !== directoryStat.dev || currentDirectory.ino !== directoryStat.ino ||
        (currentDirectory.mode & 0o777n) !== 0o700n) throw failure('command_native_snapshot_changed');
    return result;
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (result) error.artifact_cleanup = cleanupPreparedHelper(result, { allowIncomplete: true });
    else {
      try { fs.rmdirSync(directory); } catch { /* Unknown entries are never recursively removed. */ }
    }
    throw error;
  }
}

function validSnapshot(value) {
  return value?.schema_version === 'knowledge-command-native-snapshot.v1' && path.isAbsolute(value.directory || '') &&
    path.resolve(value.directory) === value.directory && /^knowledge-command-native-[A-Za-z0-9]+$/.test(path.basename(value.directory)) &&
    ['directory_dev', 'directory_ino', 'file_dev', 'file_ino', 'uid'].every(key => /^(0|[1-9][0-9]*)$/.test(value[key] || '')) &&
    value.directory_ino !== '0' && value.file_ino !== '0';
}

function cleanupPreparedHelper(record, { allowIncomplete = false } = {}) {
  if (!record?.snapshot) return { status: 'not_owned' };
  try {
    const value = record.snapshot, executable = path.join(value.directory, 'verification-linux-namespace');
    if (!validSnapshot(value) || record.executable !== executable) throw failure('command_native_snapshot_invalid');
    const directory = fs.lstatSync(value.directory, { bigint: true });
    if (!directory.isDirectory() || directory.isSymbolicLink() || String(directory.dev) !== value.directory_dev ||
        String(directory.ino) !== value.directory_ino || String(directory.uid) !== value.uid || (directory.mode & 0o777n) !== 0o700n) throw failure('command_native_snapshot_changed');
    const entries = fs.readdirSync(value.directory);
    if (entries.length !== 1 || entries[0] !== 'verification-linux-namespace') throw failure('command_native_snapshot_changed');
    const file = fs.lstatSync(executable, { bigint: true });
    if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1n || String(file.dev) !== value.file_dev ||
        String(file.ino) !== value.file_ino || String(file.uid) !== value.uid || (file.mode & 0o777n) !== 0o500n) throw failure('command_native_snapshot_changed');
    if (!allowIncomplete) {
      const bytes = require('./stable-file').readStableFile(value.directory, executable, { maxBytes: 8 * 1024 * 1024 });
      if (bytes.length !== record.binary_bytes || hash(bytes) !== record.binary_sha256) throw failure('command_native_snapshot_changed');
    }
    fs.unlinkSync(executable);
    const after = fs.lstatSync(value.directory, { bigint: true });
    if (String(after.dev) !== value.directory_dev || String(after.ino) !== value.directory_ino || after.isSymbolicLink()) throw failure('command_native_snapshot_changed');
    fs.rmdirSync(value.directory);
    return { status: 'completed', method: 'private_native_snapshot', directory: value.directory };
  } catch (error) { return { status: 'unconfirmed', method: 'private_native_snapshot', code: error.code || 'command_native_snapshot_cleanup_failed', directory: record.snapshot?.directory }; }
}

// Only the isolated, fixed preparer may supply this result to the responsive
// controller. The controller does no project-file reads after admission.
function admitPreparedHelper(record) {
  const expected = path.join(__dirname, 'native', `linux-${process.arch}`, 'verification-linux-namespace');
  if (!record || record.schema_version !== 'knowledge-command-native-binary.v1' || record.platform !== 'linux' ||
      record.architecture !== process.arch || record.binary !== 'verification-linux-namespace' ||
      (record.snapshot ? !validSnapshot(record.snapshot) || record.executable !== path.join(record.snapshot.directory, record.binary) : record.executable !== expected) ||
      !/^[a-f0-9]{64}$/.test(record.source_sha256 || '') || !/^[a-f0-9]{64}$/.test(record.binary_sha256 || '') ||
      !Number.isSafeInteger(record.binary_bytes) || record.binary_bytes < 1 || record.binary_bytes > 8 * 1024 * 1024) throw failure('command_native_binary_invalid');
  const value = Object.freeze({ ...record, ...(record.snapshot ? { snapshot: Object.freeze({ ...record.snapshot }) } : {}) });
  admittedHelpers.add(value);
  return value;
}

function nativeEnv(extra) {
  const env = { ...(extra === undefined ? process.env : extra) };
  // The native helper must not load user-injected code before it creates the
  // namespace. These variables are not part of a verification command API.
  for (const key of Object.keys(env)) if (key.startsWith('LD_')) delete env[key];
  return env;
}
function checkedFile(file) {
  const s = fs.lstatSync(file);
  if (!s.isFile() || s.isSymbolicLink()) throw failure('verification_native_helper_invalid');
  return s;
}
function prepareHelper() {
  if (process.platform !== 'linux') throw failure('verification_containment_unavailable', 'Linux PID namespaces require Linux');
  checkedFile(SOURCE);
  const source = fs.readFileSync(SOURCE), sourceHash = hash(source);
  if (prepared && prepared.source_sha256 === sourceHash) {
    checkedFile(prepared.executable);
    if (hash(fs.readFileSync(prepared.executable)) === prepared.binary_sha256) return prepared;
    throw failure('verification_native_helper_changed');
  }
  const uid = process.getuid();
  const userNamespace = fs.statSync('/proc/self/ns/user', { bigint: true });
  const root = path.join(os.tmpdir(), `knowledge-linux-native-${uid}-${userNamespace.dev}-${userNamespace.ino}`);
  try { fs.mkdirSync(root, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  const owner = fs.lstatSync(root);
  if (!owner.isDirectory() || owner.isSymbolicLink() || owner.uid !== uid || (owner.mode & 0o077)) throw failure('verification_native_cache_unsafe');
  const target = path.join(root, `${process.arch}-${sourceHash}`);
  const binary = path.join(target, 'keeper');
  const manifestFile = path.join(target, 'build.json');
  if (!fs.existsSync(target)) {
    const compiler = ['/usr/bin/cc', '/usr/bin/gcc'].find(p => { try { return fs.statSync(p).isFile(); } catch { return false; } });
    if (!compiler) throw failure('verification_native_compiler_unavailable', 'A system C compiler is required to build the bundled Linux helper');
    const staging = fs.mkdtempSync(path.join(root, '.build-'));
    try {
      // Compile a snapshot whose hash is the cache key, not a concurrently
      // mutable source path. No network downloads or privileged setup occur.
      const copy = path.join(staging, 'helper.c'); fs.writeFileSync(copy, source, { mode: 0o400 });
      const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', copy, '-o', path.join(staging, 'keeper')];
      const unshare = '/usr/bin/unshare';
      if (!fs.statSync(unshare).isFile()) throw failure('verification_native_bootstrap_unavailable');
      const compilerEnv = { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', TMPDIR: staging };
      const driver = path.join(staging, 'compile-driver.js');
      // GCC has children of its own. A fixed driver is namespace PID1; exiting
      // it at completion/timeout causes kernel cleanup of every compiler child,
      // and unshare waits for that final namespace-init exit. No shell is used.
      fs.writeFileSync(driver, `'use strict';const {spawn}=require('child_process');const p=spawn(${JSON.stringify(compiler)},${JSON.stringify(args)},{env:${JSON.stringify(compilerEnv)},stdio:['ignore','pipe','pipe']});let bytes=0;for(const [stream,out] of [[p.stdout,process.stdout],[p.stderr,process.stderr]])stream.on('data',c=>{bytes+=c.length;if(bytes>1048576)process.exit(125);out.write(c)});p.on('error',()=>process.exit(126));p.on('close',c=>process.exit(Number.isInteger(c)?c:127));setTimeout(()=>process.exit(124),60000);`, { mode: 0o400 });
      const result = spawnSync(unshare, ['--user', '--map-current-user', '--pid', '--fork', '--kill-child=KILL', '--', process.execPath, driver],
        { encoding: 'utf8', timeout: 75000, maxBuffer: 1024 * 1024, env: compilerEnv, windowsHide: true });
      if (result.error || result.status !== 0) throw failure('verification_native_helper_build_failed', String(result.stderr || result.error?.message || '').slice(0, 4000));
      fs.chmodSync(path.join(staging, 'keeper'), 0o500);
      const record = { schema_version: 'knowledge-native-build.v1', architecture: process.arch, platform: process.platform,
        source_sha256: sourceHash, binary_sha256: hash(fs.readFileSync(path.join(staging, 'keeper'))), compiler,
        compiler_sha256: hash(fs.readFileSync(fs.realpathSync(compiler))), flags: args.slice(0, -3),
        bootstrap: 'unshare_pid_namespace', bootstrap_sha256: hash(fs.readFileSync(unshare)) };
      fs.writeFileSync(path.join(staging, 'build.json'), JSON.stringify(record) + '\n', { mode: 0o400 });
      fs.unlinkSync(copy); fs.unlinkSync(driver);
      try { fs.renameSync(staging, target); } catch (e) { if (!['EEXIST', 'ENOTEMPTY'].includes(e.code)) throw e; }
    } finally { fs.rmSync(staging, { recursive: true, force: true }); }
  }
  const dir = fs.lstatSync(target);
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== uid || (dir.mode & 0o077)) throw failure('verification_native_cache_unsafe');
  checkedFile(binary); checkedFile(manifestFile);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (manifest.source_sha256 !== sourceHash || manifest.architecture !== process.arch || manifest.platform !== 'linux' || manifest.binary_sha256 !== hash(fs.readFileSync(binary))) throw failure('verification_native_helper_changed');
  prepared = { ...manifest, executable: binary };
  return prepared;
}
function parseLines(value) {
  return String(value || '').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}
function containmentCapability() {
  if (process.platform !== 'linux') return { platform: process.platform, backend: null, status: 'unavailable', reason: 'linux_pid_namespace_requires_linux' };
  try {
    const helper = prepareHelper();
    const result = spawnSync(helper.executable, ['--probe'], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536, env: nativeEnv() });
    const rows = parseLines(result.stdout);
    if (result.error || result.status !== 0 || !rows.some(x => x.status === 'ready') || !rows.some(x => x.status === 'closed' && x.active_processes === 0 && x.init_reaped === true)) {
      return { platform: 'linux', backend: 'linux_pid_namespace', status: 'unavailable', reason: rows.find(x => x.code)?.code || result.error?.code || 'namespace_probe_failed' };
    }
    return { platform: 'linux', backend: 'linux_pid_namespace', status: 'requires_runtime_setup', reason: 'namespace_init_pidfd_exit_required', helper_source_sha256: helper.source_sha256, helper_binary_sha256: helper.binary_sha256 };
  } catch (e) { return { platform: 'linux', backend: 'linux_pid_namespace', status: 'unavailable', reason: e.code || 'namespace_probe_failed' }; }
}
function validIdentity(value) {
  // A controller may itself be namespace PID1. This metadata validation is
  // separate from native stop/observe, which still refuses target PID1.
  return value && Number.isSafeInteger(value.pid) && value.pid >= 1 && Number.isSafeInteger(value.proc_pid) && value.proc_pid >= 1 &&
    /^\d+$/.test(value.start_ticks || '') && Number.isFinite(Date.parse(value.os_creation_time)) && Number.isSafeInteger(value.namespace_pid) && value.namespace_pid > 0 &&
    /^\d+$/.test(value.pid_namespace?.dev || '') && /^\d+$/.test(value.pid_namespace?.ino || '');
}
function validDescriptor(value) {
  return value && value.schema_version === SCHEMA && value.backend === 'linux_pid_namespace' && /^[a-f0-9-]{36}$/.test(value.boot_id || '') &&
    /^\d+$/.test(value.procfs_dev || '') && /^\d+$/.test(value.observer_pid_namespace?.dev || '') && /^\d+$/.test(value.observer_pid_namespace?.ino || '') &&
    ['controller', 'keeper', 'init', 'worker'].every(role => validIdentity(value[role])) && value.init.namespace_pid === 1 &&
    value.worker.namespace_pid === 2 && ['worker_none', 'authority_setfcap'].includes(value.capability_profile) && value.no_new_privileges === true &&
    ['controller', 'keeper'].every(role => value[role].pid_namespace.ino === value.observer_pid_namespace.ino && value[role].pid_namespace.dev === value.observer_pid_namespace.dev) &&
    value.worker.pid_namespace.ino === value.init.pid_namespace.ino && value.worker.pid_namespace.dev === value.init.pid_namespace.dev &&
    value.init.pid_namespace.ino !== value.observer_pid_namespace.ino && /^[a-f0-9]{64}$/.test(value.helper?.source_sha256 || '') && /^[a-f0-9]{64}$/.test(value.helper?.binary_sha256 || '');
}

function spawnLinuxContainedWorker(executable, args, options = {}, settings = {}) {
  if (!path.isAbsolute(executable) || !Array.isArray(args) || args.some(a => typeof a !== 'string' || a.includes('\0'))) throw failure('verification_worker_invalid');
  const helper = settings.preparedHelper === undefined ? prepareHelper() : settings.preparedHelper;
  if (settings.preparedHelper !== undefined && !admittedHelpers.has(helper)) throw failure('command_native_binary_unadmitted');
  const lifetimeMs = Math.ceil(settings.lifetimeMs ?? 180000);
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0 || lifetimeMs > 2147483647) throw failure('verification_clock_invalid');
  const stdio = options.stdio || ['ignore', 'ignore', 'ignore', 'ipc'];
  if (!Array.isArray(stdio) || stdio.length !== 4 || stdio[3] !== 'ipc') throw failure('verification_worker_invalid', 'Contained Node workers require an IPC channel at fd 3');
  const worker = spawn(helper.executable, ['--run', String(lifetimeMs), settings.trustedAuthority === true ? 'authority' : 'worker', '--', executable, ...args], {
    ...options, detached: false, stdio: [...stdio, 'pipe'], env: nativeEnv(options.env), windowsHide: true
  });
  let readyResolve, readyReject, startedResolve, startedReject;
  let descriptor, identities, buffer = '', closeMessage, exited = false, exitCode, exitSignal, stopping = false, permitted = false, finishedClose;
  let controlEnded = false, controlFailed = false, protocolFailure = null;
  const listeners = new Set();
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const started = new Promise((resolve, reject) => { startedResolve = resolve; startedReject = reject; });
  ready.catch(() => {}); started.catch(() => {});
  const reject = code => { protocolFailure ||= code; const error = failure(code); readyReject(error); startedReject(error); if (!stopping && typeof settings.onFailure === 'function') settings.onFailure(error); };
  worker.once('error', error => { reject(error.code || 'verification_namespace_spawn_failed'); for (const fn of listeners) fn(); });
  worker.once('exit', (code, signal) => { exited = true; exitCode = code; exitSignal = signal; if (!stopping) reject('verification_namespace_keeper_exited'); for (const fn of listeners) fn(); });
  worker.stdio[4].on('error', () => { controlFailed = true; reject('verification_namespace_transport_failed'); for (const fn of listeners) fn(); });
  worker.stdio[4].once('end', () => {
    controlEnded = true;
    if (buffer.length) reject('verification_namespace_protocol_truncated');
    for (const fn of listeners) fn();
  });
  worker.stdio[4].once('close', () => {
    if (!controlEnded) { controlFailed = true; reject('verification_namespace_transport_truncated'); }
    for (const fn of listeners) fn();
  });
  worker.stdio[4].setEncoding('utf8');
  worker.stdio[4].on('data', chunk => {
    buffer += chunk;
    if (Buffer.byteLength(buffer) > 65536) { reject('verification_namespace_protocol_invalid'); worker.kill('SIGKILL'); return; }
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index); buffer = buffer.slice(index + 1); let message;
      try { message = JSON.parse(line); } catch { reject('verification_namespace_protocol_invalid'); continue; }
      if (!message || typeof message !== 'object' || Array.isArray(message) || message.protocol !== PROTOCOL || closeMessage) { reject('verification_namespace_protocol_invalid'); continue; }
      if (message.status === 'ready' && !descriptor && !stopping) {
        identities = message.identities;
        descriptor = { schema_version: SCHEMA, backend: 'linux_pid_namespace', boot_id: message.boot_id,
          observer_pid_namespace: message.observer_pid_namespace, procfs_dev: message.procfs_dev, procfs_mode: message.procfs_mode,
          capability_profile: message.capability_profile, no_new_privileges: message.no_new_privileges,
          ...identities, helper: { source_sha256: helper.source_sha256, binary_sha256: helper.binary_sha256, architecture: helper.architecture } };
        if (!validDescriptor(descriptor) || identities.controller.pid !== process.pid || identities.keeper.pid !== worker.pid ||
            message.capability_profile !== (settings.trustedAuthority === true ? 'authority_setfcap' : 'worker_none')) { descriptor = undefined; reject('verification_namespace_identity_invalid'); continue; }
        descriptor = JSON.parse(JSON.stringify(descriptor)); readyResolve(JSON.parse(JSON.stringify(descriptor)));
      } else if (message.status === 'started' && permitted) { if (!stopping) startedResolve(); }
      else if (message.status === 'closed') { closeMessage = message; for (const fn of listeners) fn(); }
      else if (message.status === 'worker_exit') { if (!stopping) reject('verification_worker_exited'); }
      else if (message.status === 'unconfirmed') { reject(message.code || 'verification_namespace_failed'); }
      else reject('verification_namespace_protocol_invalid');
    }
  });
  const job = {
    ready, started, keeper_pid: worker.pid, keeper_executable: helper.executable, keeper_executable_sha256: helper.binary_sha256,
    get identities() { return identities ? JSON.parse(JSON.stringify(identities)) : {}; },
    get descriptor() { return descriptor ? JSON.parse(JSON.stringify(descriptor)) : undefined; },
    permit() {
      if (!descriptor || stopping || permitted) throw failure('verification_namespace_permit_invalid');
      permitted = true; worker.stdio[4].write('permit\n');
    },
    close(allowanceMs = 30000) {
      if (finishedClose) return finishedClose;
      stopping = true;
      const allowance = Math.max(0, Math.min(2147483647, Math.floor(Number(allowanceMs) || 0)));
      const start = clock();
      finishedClose = new Promise(resolve => {
        let done = false, timer;
        const finish = value => { if (done) return; done = true; clearTimeout(timer); listeners.delete(check); readyReject(failure('verification_namespace_stopped')); startedReject(failure('verification_namespace_stopped')); resolve(value); };
        const check = () => {
          // ChildProcess exit can precede its last control-pipe data. Wait for
          // the bounded channel's terminal state before judging the receipt.
          if (!exited || !controlEnded && !controlFailed) return;
          if (descriptor && controlEnded && !controlFailed && !protocolFailure && buffer.length === 0 && closeMessage?.active_processes === 0 && closeMessage.init_exit_observed === true && closeMessage.init_reaped === true && exitCode === 0 && !exitSignal && elapsed(start) <= allowance) {
            finish({ status: 'completed', method: 'linux_pid_namespace', active_processes: 0, init_exit_observed: true, init_reaped: true, namespace_drained: true,
              keeper_exited: true, worker_exited: true, descriptor_sha256: hash(JSON.stringify(descriptor)), helper_binary_sha256: helper.binary_sha256 });
          } else finish({ status: 'unconfirmed', method: 'linux_pid_namespace', code: 'namespace_close_unconfirmed', keeper_exited: true });
        };
        listeners.add(check);
        timer = setTimeout(() => {
          if (!exited) worker.kill('SIGKILL');
          if (worker.connected) worker.disconnect();
          worker.stdio[4].destroy(); worker.unref();
          finish({ status: 'unconfirmed', method: 'linux_pid_namespace', code: 'namespace_cleanup_timeout', keeper_exited: exited });
        }, Math.max(1, allowance));
        if (!exited) { try { worker.stdio[4].write(`close ${Math.max(1, allowance - Math.min(250, Math.floor(allowance / 5)))}\n`); } catch {} }
        check();
      });
      return finishedClose;
    }
  };
  return { worker, job };
}

function runIdentityOperation(mode, context, identity, timeoutMs, suppliedHelper) {
  const helper = suppliedHelper || prepareHelper();
  if (!validIdentity(identity) || !/^[a-f0-9-]{36}$/.test(context?.boot_id || '') || !/^\d+$/.test(context.procfs_dev || '') ||
      !/^\d+$/.test(context.observer_pid_namespace?.dev || '') || !/^\d+$/.test(context.observer_pid_namespace?.ino || '')) return { status: 'unconfirmed', code: 'native_identity_invalid' };
  const allowance = Math.max(1, Math.min(2147483000, Math.floor(Number(timeoutMs) || 1)));
  const args = [mode, context.boot_id, context.observer_pid_namespace.dev, context.observer_pid_namespace.ino, context.procfs_dev,
    String(identity.pid), String(identity.proc_pid), identity.start_ticks, identity.pid_namespace.dev, identity.pid_namespace.ino, String(identity.namespace_pid), String(allowance)];
  const result = spawnSync(helper.executable, args, { encoding: 'utf8', timeout: allowance + 1000, maxBuffer: 65536, env: nativeEnv() });
  try {
    const rows = parseLines(result.stdout); const record = rows.length === 1 ? rows[0] : null;
    if (result.error || result.status !== 0 || !record || !['active', 'exited'].includes(record.status)) return { status: 'unconfirmed', code: record?.code || result.error?.code || 'native_observation_failed' };
    return record;
  } catch { return { status: 'unconfirmed', code: 'native_observation_invalid' }; }
}
function currentProcessIdentity() {
  const helper = prepareHelper();
  const result = spawnSync(helper.executable, ['--identity'], { encoding: 'utf8', timeout: 15000, maxBuffer: 65536, env: nativeEnv() });
  if (result.error || result.status !== 0) throw failure('native_identity_unavailable');
  const rows = parseLines(result.stdout); if (rows.length !== 1 || !validIdentity(rows[0].identity) || rows[0].identity.pid !== process.pid) throw failure('native_identity_invalid');
  return rows[0];
}
function verifyProcessExit(value) {
  try { return runIdentityOperation('--observe', value, value.identity || value, 5000); } catch (e) { return { status: 'unconfirmed', code: e.code || 'native_observer_unavailable' }; }
}
function queryCommandScope(descriptor, lineage, { timeoutMs = 5000 } = {}) {
  const unconfirmed = code => ({ status: 'unconfirmed', method: 'linux_pid_namespace', code });
  try {
    if (!validDescriptor(descriptor) || !Array.isArray(lineage)) return unconfirmed('command_scope_invalid');
    const helper = preparePackagedHelper();
    if (descriptor.helper.source_sha256 !== helper.source_sha256 || descriptor.helper.binary_sha256 !== helper.binary_sha256 ||
        descriptor.helper.architecture !== helper.architecture) return unconfirmed('native_helper_pin_mismatch');
    const result = spawnSync(helper.executable, ['--identity'], { encoding: 'utf8', timeout: timeoutMs, maxBuffer: 65536, env: nativeEnv() });
    const rows = parseLines(result.stdout), observer = rows.length === 1 ? rows[0] : null;
    if (result.error || result.status !== 0 || !observer || observer.boot_id !== descriptor.boot_id || observer.procfs_dev !== descriptor.procfs_dev ||
        !validIdentity(observer.identity)) return unconfirmed('native_observer_mismatch');
    const frame = lineage.find(row => row.namespace.dev === observer.observer_pid_namespace.dev && row.namespace.ino === observer.observer_pid_namespace.ino);
    if (!frame || frame.depth !== observer.identity.proc_pid_chain?.length) return unconfirmed('command_scope_observer_outside_lineage');
    const chain = descriptor.init.proc_pid_chain;
    if (!Array.isArray(chain) || !Number.isSafeInteger(chain[frame.depth - 1]) || chain[0] !== descriptor.init.proc_pid) return unconfirmed('command_scope_identity_invalid');
    // NSpid was captured by the same native authority before permit. Select
    // its entry only for an exact recorded namespace frame. Existing native
    // observe then performs its full procfs qualification + exact pidfd path;
    // no PID enumeration or new inferred-absence shortcut is introduced.
    const context = { ...descriptor, observer_pid_namespace: observer.observer_pid_namespace };
    const identity = { ...descriptor.init, pid: chain[frame.depth - 1] };
    const proof = runIdentityOperation('--observe', context, identity, timeoutMs, helper);
    if (proof.status === 'active') return { ...proof, status: 'active', method: 'linux_pid_namespace' };
    if (proof.status !== 'exited') return unconfirmed(proof.code || 'native_scope_exit_unconfirmed');
    return { status: 'completed', method: 'linux_pid_namespace', active_processes: 0, namespace_drained: true,
      descriptor_sha256: hash(JSON.stringify(descriptor)), init_exit_basis: proof.method,
      process_reaped: proof.process_reaped === true, release_inferred: proof.release_inferred === true };
  } catch (error) { return unconfirmed(error.code || 'native_scope_observer_unavailable'); }
}
function recoverContainer(descriptor, options = {}) {
  const start = clock(), allowance = Math.max(1, Math.min(600000, Math.floor(Number(options.cleanup_timeout_ms) || 30000)));
  const unconfirmed = code => ({ status: 'unconfirmed', method: 'linux_pid_namespace', code, ack_released: false });
  try {
    if (!validDescriptor(descriptor)) return unconfirmed('native_descriptor_invalid');
    const helper = prepareHelper();
    if (helper.source_sha256 !== descriptor.helper.source_sha256 || helper.binary_sha256 !== descriptor.helper.binary_sha256 || helper.architecture !== descriptor.helper.architecture) return unconfirmed('native_helper_pin_mismatch');
    const exits = []; let initProof;
    // Fence in control first. Only the exact outside controller and keeper are
    // stopped; no PID enumeration, process-group kill or age-based inference.
    for (const role of ['init', 'controller', 'keeper']) {
      if (descriptor[role].pid === process.pid) return unconfirmed('native_recovery_self_target');
      const left = allowance - elapsed(start); if (left <= 0) return unconfirmed('native_cleanup_timeout');
      const result = runIdentityOperation('--stop', descriptor, descriptor[role], left);
      if (result.status !== 'exited') return unconfirmed(result.code || 'native_exit_unconfirmed');
      if (role === 'init') initProof = result;
      exits.push({ role, ...descriptor[role], method: result.method });
    }
    if (elapsed(start) > allowance) return unconfirmed('native_cleanup_timeout');
    // The worker's birth was bound before exec. Namespace-init final exit
    // includes all detached, reparented and nested-namespace descendants.
    exits.push({ role: 'worker', ...descriptor.worker, method: 'linux_namespace_init_exit' });
    return { status: 'completed', method: 'linux_pid_namespace', backend: 'linux_pid_namespace', descriptor_sha256: hash(JSON.stringify(descriptor)),
      active_processes: 0, namespace_drained: true, init_exit_observed: initProof.method === 'linux_pidfd_exit',
      init_exit_inferred: initProof.method !== 'linux_pidfd_exit', init_reaped: initProof.process_reaped === true,
      init_release_inferred: initProof.release_inferred === true,
      init_exit_basis: initProof.method, worker_exited: true, keeper_exited: true, controller_exited: true,
      init_reap_basis: 'kernel_namespace_init_final_exit', process_exits: exits, ack_released: false };
  } catch (e) { return unconfirmed(e.code || 'native_recovery_unavailable'); }
}
module.exports = { SCHEMA, prepareHelper, preparePackagedHelper, admitPreparedHelper, cleanupPreparedHelper, containmentCapability, spawnLinuxContainedWorker, queryCommandScope, recoverContainer, currentProcessIdentity, verifyProcessExit, validDescriptor };
