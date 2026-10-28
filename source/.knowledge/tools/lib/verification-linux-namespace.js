'use strict';

// Linux kernel-owned descendant containment. A PID namespace is not a network
// or filesystem sandbox. macOS must never be routed through this backend.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const PROTOCOL = 'knowledge-linux-namespace-helper.v2';
const SCHEMA = 'knowledge-linux-pid-namespace.v2';
const LEGACY_SCHEMA = 'knowledge-linux-pid-namespace.v1';
const NAMESPACE_PROVIDER = 'linux_procfs_pid_namespace_link.v1';
const SOURCE = path.join(__dirname, 'verification-linux-namespace.c');
const hash = data => crypto.createHash('sha256').update(data).digest('hex');
const clock = () => process.hrtime.bigint();
const elapsed = start => Number(clock() - start) / 1e6;
const failure = (code, detail) => Object.assign(new Error(detail || code), { code });
let invocationHelper;
const admittedHelpers = new WeakSet();

// Runtime execution uses a pinned packaged executable. Production invocation
// snapshots are created in the isolated preparer; no runtime compiler fallback.
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
function setInvocationHelper(record) {
  const helper = admittedHelpers.has(record) ? record : admitPreparedHelper(record);
  if (invocationHelper && (helper.executable !== invocationHelper.executable || helper.binary_sha256 !== invocationHelper.binary_sha256 ||
      helper.source_sha256 !== invocationHelper.source_sha256)) throw failure('command_native_invocation_changed');
  invocationHelper = helper; return helper;
}
function getInvocationHelper() { return invocationHelper; }
function prepareHelper() {
  if (process.platform !== 'linux') throw failure('verification_containment_unavailable', 'Linux PID namespaces require Linux');
  // Public production work receives the isolated preparer's pinned private
  // snapshot through fixed trusted IPC. Standalone maintainer entrypoints
  // may verify the bundled executable; compilation is a build-time action.
  return invocationHelper || preparePackagedHelper();
}

function parseLines(value) {
  return String(value || '').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
}
function containmentCapability() {
  if (process.platform !== 'linux') return { platform: process.platform, backend: null, status: 'unavailable', reason: 'linux_pid_namespace_requires_linux' };
  try {
    const helper = prepareHelper();
    const result = spawnSync(helper.executable, ['--probe-nested'], { encoding: 'utf8', timeout: 20000, maxBuffer: 65536, env: nativeEnv() });
    const rows = parseLines(result.stdout);
    if (result.error || result.status !== 0 || !validNestedProbe(rows, helper, result.pid)) {
      return { platform: 'linux', backend: 'linux_pid_namespace', status: 'unavailable', reason: rows.find(x => x.code)?.code || result.error?.code || 'namespace_nested_probe_unconfirmed' };
    }
    return { platform: 'linux', backend: 'linux_pid_namespace', status: 'requires_runtime_setup', reason: 'nested_namespace_init_pidfd_exit_required', probe_depth: 2,
      helper_source_sha256: helper.source_sha256, helper_binary_sha256: helper.binary_sha256 };
  } catch (e) { return { platform: 'linux', backend: 'linux_pid_namespace', status: 'unavailable', reason: e.code || 'namespace_probe_failed' }; }
}
function validNestedProbe(rows, helper, keeperPid) {
  // Ordered native receipts only. One successful namespace probe cannot admit
  // a backend whose actual authority needs to create a nested namespace.
  if (rows.length !== 4 || rows.some(row => !row || row.protocol !== PROTOCOL) ||
      rows.map(row => row.status).join(',') !== 'ready,ready,closed,closed') return false;
  const [outer, inner, innerClose, outerClose] = rows;
  if ([innerClose, outerClose].some(row => row.active_processes !== 0 || row.init_exit_observed !== true || row.init_reaped !== true) ||
      Object.hasOwn(innerClose, 'probe_depth') || outerClose.probe_depth !== 2) return false;
  const descriptor = value => ({ schema_version: SCHEMA, backend: 'linux_pid_namespace',
    boot_id: value.boot_id, procfs_dev: value.procfs_dev, observer_pid_namespace: value.observer_pid_namespace,
    namespace_identity_provider: value.namespace_identity_provider, capability_profile: value.capability_profile,
    no_new_privileges: value.no_new_privileges, ...value.identities, helper });
  if (!validDescriptor(descriptor(outer)) || !validDescriptor(descriptor(inner)) ||
      outer.identities.controller.pid !== process.pid || outer.identities.keeper.pid !== keeperPid ||
      outer.capability_profile !== (process.getuid() === 0 ? 'authority_setfcap' : 'authority_none') ||
      inner.capability_profile !== 'worker_none' || inner.boot_id !== outer.boot_id || inner.procfs_dev !== outer.procfs_dev ||
      !sameNamespaceIdentity(inner.observer_pid_namespace, outer.identities.init.pid_namespace)) return false;
  const sameBirth = (left, right) => left.proc_pid === right.proc_pid && left.start_ticks === right.start_ticks;
  // The fixed native controller keeps the outer worker birth and forks the
  // inner keeper, matching the real Node authority -> helper relationship.
  return sameBirth(inner.identities.controller, outer.identities.worker) &&
    inner.identities.keeper.proc_pid !== outer.identities.worker.proc_pid &&
    inner.identities.keeper.proc_pid !== outer.identities.init.proc_pid;
}
function validNamespaceIdentity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort().join(',');
  if (keys === 'ino,provider') return value.provider === NAMESPACE_PROVIDER && typeof value.ino === 'string' &&
    /^[1-9]\d{0,9}$/.test(value.ino) && BigInt(value.ino) <= 4294967295n;
  return keys === 'dev,ino' && typeof value.dev === 'string' && typeof value.ino === 'string' &&
    /^(0|[1-9]\d*)$/.test(value.dev) && /^(0|[1-9]\d*)$/.test(value.ino);
}
function sameNamespaceIdentity(left, right) {
  return validNamespaceIdentity(left) && validNamespaceIdentity(right) && left.ino === right.ino &&
    (left.provider === NAMESPACE_PROVIDER ? right.provider === NAMESPACE_PROVIDER : right.provider === undefined && left.dev === right.dev);
}
function validIdentity(value) {
  // A controller may itself be namespace PID1. This metadata validation is
  // separate from native stop/observe, which still refuses target PID1.
  return value && Number.isSafeInteger(value.pid) && value.pid >= 1 && Number.isSafeInteger(value.proc_pid) && value.proc_pid >= 1 &&
    /^\d+$/.test(value.start_ticks || '') && Number.isFinite(Date.parse(value.os_creation_time)) && Number.isSafeInteger(value.namespace_pid) && value.namespace_pid > 0 &&
    validNamespaceIdentity(value.pid_namespace);
}
function validDescriptor(value) {
  if (!value || ![SCHEMA, LEGACY_SCHEMA].includes(value.schema_version)) return false;
  const linked = value.schema_version === SCHEMA;
  const namespaces = [value.observer_pid_namespace, ...['controller', 'keeper', 'init', 'worker'].map(role => value[role]?.pid_namespace)];
  if (linked ? value.namespace_identity_provider !== NAMESPACE_PROVIDER || namespaces.some(ns => ns?.provider !== NAMESPACE_PROVIDER)
    : value.namespace_identity_provider !== undefined || namespaces.some(ns => ns?.provider !== undefined)) return false;
  return value.backend === 'linux_pid_namespace' && /^[a-f0-9-]{36}$/.test(value.boot_id || '') &&
    /^\d+$/.test(value.procfs_dev || '') && validNamespaceIdentity(value.observer_pid_namespace) &&
    ['controller', 'keeper', 'init', 'worker'].every(role => validIdentity(value[role])) && value.init.namespace_pid === 1 &&
    value.worker.namespace_pid === 2 && ['worker_none', 'authority_setfcap', 'authority_none'].includes(value.capability_profile) && value.no_new_privileges === true &&
    ['controller', 'keeper'].every(role => sameNamespaceIdentity(value[role].pid_namespace, value.observer_pid_namespace)) &&
    sameNamespaceIdentity(value.worker.pid_namespace, value.init.pid_namespace) &&
    !sameNamespaceIdentity(value.init.pid_namespace, value.observer_pid_namespace) && /^[a-f0-9]{64}$/.test(value.helper?.source_sha256 || '') && /^[a-f0-9]{64}$/.test(value.helper?.binary_sha256 || '');
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
  // Operational worker/keeper exit still notifies the work owner, but does
  // not corrupt an independently complete native cleanup transcript.
  const reject = (code, details = {}, invalidatesProtocol = true) => { if (invalidatesProtocol) protocolFailure ||= code; const error = Object.assign(failure(code), details); readyReject(error); startedReject(error); if (!stopping && typeof settings.onFailure === 'function') settings.onFailure(error); };
  worker.once('error', error => { reject(error.code || 'verification_namespace_spawn_failed'); for (const fn of listeners) fn(); });
  worker.once('exit', (code, signal) => { exited = true; exitCode = code; exitSignal = signal; if (!stopping) reject('verification_namespace_keeper_exited', {}, false); for (const fn of listeners) fn(); });
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
          namespace_identity_provider: message.namespace_identity_provider,
          capability_profile: message.capability_profile, no_new_privileges: message.no_new_privileges,
          ...identities, helper: { source_sha256: helper.source_sha256, binary_sha256: helper.binary_sha256, architecture: helper.architecture } };
        if (!validDescriptor(descriptor) || identities.controller.pid !== process.pid || identities.keeper.pid !== worker.pid ||
            message.capability_profile !== (settings.trustedAuthority === true ? (process.getuid() === 0 ? 'authority_setfcap' : 'authority_none') : 'worker_none')) { descriptor = undefined; reject('verification_namespace_identity_invalid'); continue; }
        descriptor = JSON.parse(JSON.stringify(descriptor)); readyResolve(JSON.parse(JSON.stringify(descriptor)));
      } else if (message.status === 'started' && permitted) { if (!stopping) startedResolve(); }
      else if (message.status === 'closed') { closeMessage = message; for (const fn of listeners) fn(); }
      else if (message.status === 'worker_exit') { if (!stopping) reject('verification_worker_exited', {}, false); }
      else if (message.status === 'unconfirmed') { reject(message.code || 'verification_namespace_failed', {
        ...(Number.isSafeInteger(message.errno) && message.errno >= 0 ? { native_errno: message.errno } : {}),
        ...(Number.isSafeInteger(message.observer_stage) && message.observer_stage >= 0 && message.observer_stage <= 32 ? { native_observer_stage: message.observer_stage } : {}),
        ...(Number.isSafeInteger(message.setup_stage) && message.setup_stage >= 0 && message.setup_stage <= 8 ? { native_setup_stage: message.setup_stage } : {})
      }); }
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

function identityOperationArgs(mode, context, identity, timeoutMs) {
  if (!['--observe', '--stop'].includes(mode) || !validIdentity(identity) || !/^[a-f0-9-]{36}$/.test(context?.boot_id || '') ||
      !/^\d+$/.test(context.procfs_dev || '') || !validNamespaceIdentity(context.observer_pid_namespace) ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483000) throw failure('native_identity_invalid');
  const observer = context.observer_pid_namespace, target = identity.pid_namespace;
  const linked = observer.provider === NAMESPACE_PROVIDER;
  if (linked !== (target.provider === NAMESPACE_PROVIDER) || (linked ? context.namespace_identity_provider !== NAMESPACE_PROVIDER : context.namespace_identity_provider !== undefined)) throw failure('native_identity_invalid');
  return ['--parent', String(process.pid), linked ? `${mode}-link` : mode, context.boot_id,
    ...(linked ? [observer.ino] : [observer.dev, observer.ino]), context.procfs_dev,
    String(identity.pid), String(identity.proc_pid), identity.start_ticks,
    ...(linked ? [target.ino] : [target.dev, target.ino]), String(identity.namespace_pid), String(timeoutMs)];
}
function runIdentityOperation(mode, context, identity, timeoutMs, suppliedHelper) {
  const helper = suppliedHelper || prepareHelper();
  const allowance = Math.max(1, Math.min(2147483000, Math.floor(Number(timeoutMs) || 1)));
  let args;
  try { args = identityOperationArgs(mode, context, identity, allowance); }
  catch { return { status: 'unconfirmed', code: 'native_identity_invalid' }; }
  const result = spawnSync(helper.executable, args, { encoding: 'utf8', timeout: allowance + 1000, maxBuffer: 65536, env: nativeEnv() });
  try {
    const rows = parseLines(result.stdout); const record = rows.length === 1 ? rows[0] : null;
    if (result.error || result.status !== 0 || !record || !['active', 'exited'].includes(record.status)) return { status: 'unconfirmed', code: record?.code || result.error?.code || 'native_observation_failed' };
    return record;
  } catch { return { status: 'unconfirmed', code: 'native_observation_invalid' }; }
}
function currentProcessIdentity({ timeoutMs = 15000 } = {}) {
  const started = clock();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) throw failure('native_identity_invalid');
  const helper = prepareHelper();
  const remaining = Math.floor(timeoutMs - elapsed(started));
  if (remaining < 1) throw failure('native_identity_timeout');
  const result = spawnSync(helper.executable, ['--identity-link'], { encoding: 'utf8', timeout: remaining, maxBuffer: 65536, env: nativeEnv() });
  if (elapsed(started) >= timeoutMs) throw failure('native_identity_timeout');
  if (result.error || result.status !== 0) throw failure('native_identity_unavailable');
  const rows = parseLines(result.stdout); if (rows.length !== 1 || !validIdentity(rows[0].identity) || rows[0].identity.pid !== process.pid ||
    rows[0].namespace_identity_provider !== NAMESPACE_PROVIDER || !sameNamespaceIdentity(rows[0].observer_pid_namespace, rows[0].identity.pid_namespace)) throw failure('native_identity_invalid');
  return rows[0];
}
function verifyProcessExit(value, { timeoutMs = 5000 } = {}) {
  const started = clock();
  try {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600000) throw failure('native_identity_invalid');
    const helper = prepareHelper(), remaining = Math.floor(timeoutMs - elapsed(started));
    if (remaining < 1) throw failure('native_identity_timeout');
    const result = runIdentityOperation('--observe', value, value.identity || value, remaining, helper);
    if (elapsed(started) >= timeoutMs) throw failure('native_identity_timeout');
    return result;
  } catch (e) { return { status: 'unconfirmed', code: e.code || 'native_observer_unavailable' }; }
}
function queryCommandScope(descriptor, lineage, { timeoutMs = 5000 } = {}) {
  const unconfirmed = code => ({ status: 'unconfirmed', method: 'linux_pid_namespace', code });
  const started = clock(); let helper;
  const remaining = () => Math.max(0, Math.floor(timeoutMs - elapsed(started)));
  const result = (() => {
  try {
    if (!validDescriptor(descriptor) || !Array.isArray(lineage)) return unconfirmed('command_scope_invalid');
    helper = preparePackagedHelper({ snapshot: true });
    if (descriptor.helper.source_sha256 !== helper.source_sha256 || descriptor.helper.binary_sha256 !== helper.binary_sha256 ||
        descriptor.helper.architecture !== helper.architecture) return unconfirmed('native_helper_pin_mismatch');
    if (!remaining()) return unconfirmed('command_scope_query_timeout');
    const identityMode = descriptor.schema_version === SCHEMA ? '--identity-link' : '--identity';
    const result = spawnSync(helper.executable, ['--parent', String(process.pid), identityMode], { encoding: 'utf8', timeout: remaining(), maxBuffer: 65536, env: nativeEnv() });
    const rows = parseLines(result.stdout), observer = rows.length === 1 ? rows[0] : null;
    if (result.error || result.status !== 0 || !observer || observer.boot_id !== descriptor.boot_id || observer.procfs_dev !== descriptor.procfs_dev ||
        !validIdentity(observer.identity) || observer.namespace_identity_provider !== descriptor.namespace_identity_provider) return unconfirmed('native_observer_mismatch');
    const frame = lineage.find(row => sameNamespaceIdentity(row.namespace, observer.observer_pid_namespace));
    if (!frame || frame.depth !== observer.identity.proc_pid_chain?.length) return unconfirmed('command_scope_observer_outside_lineage');
    const chain = descriptor.init.proc_pid_chain;
    if (!Array.isArray(chain) || !Number.isSafeInteger(chain[frame.depth - 1]) || chain[0] !== descriptor.init.proc_pid) return unconfirmed('command_scope_identity_invalid');
    // NSpid was captured by the same native authority before permit. Select
    // its entry only for an exact recorded namespace frame. Existing native
    // observe then performs its full procfs qualification + exact pidfd path;
    // no PID enumeration or new inferred-absence shortcut is introduced.
    const context = { ...descriptor, observer_pid_namespace: observer.observer_pid_namespace };
    const identity = { ...descriptor.init, pid: chain[frame.depth - 1] };
    if (!remaining()) return unconfirmed('command_scope_query_timeout');
    const proof = runIdentityOperation('--observe', context, identity, remaining(), helper);
    if (!remaining()) return unconfirmed('command_scope_query_timeout');
    if (proof.status === 'active') return { ...proof, status: 'active', method: 'linux_pid_namespace' };
    if (proof.status !== 'exited') return unconfirmed(proof.code || 'native_scope_exit_unconfirmed');
    return { status: 'completed', method: 'linux_pid_namespace', active_processes: 0, namespace_drained: true,
      descriptor_sha256: hash(JSON.stringify(descriptor)), init_exit_basis: proof.method,
      process_reaped: proof.process_reaped === true, release_inferred: proof.release_inferred === true };
  } catch (error) { return unconfirmed(error.code || 'native_scope_observer_unavailable'); }
  })();
  const cleanup = helper?.snapshot ? cleanupPreparedHelper(helper) : { status: 'not_owned' };
  if (cleanup.status === 'unconfirmed') return { ...unconfirmed('command_native_snapshot_cleanup_unconfirmed'), artifact_cleanup: cleanup };
  if (!remaining()) return unconfirmed('command_scope_query_timeout');
  return result;
}
function recoverContainer(descriptor, options = {}) {
  const start = clock(), allowance = Math.max(1, Math.min(600000, Math.floor(Number(options.cleanup_timeout_ms) || 30000)));
  const unconfirmed = code => ({ status: 'unconfirmed', method: 'linux_pid_namespace', code, ack_released: false });
  try {
    if (!validDescriptor(descriptor)) return unconfirmed('native_descriptor_invalid');
    const helper = prepareHelper();
    if (helper.source_sha256 !== descriptor.helper.source_sha256 || helper.binary_sha256 !== descriptor.helper.binary_sha256 || helper.architecture !== descriptor.helper.architecture) return unconfirmed('native_helper_pin_mismatch');
    let context = descriptor, observerDepth;
    if (descriptor.schema_version === SCHEMA) {
      const left = Math.floor(allowance - elapsed(start)); if (left < 1) return unconfirmed('native_cleanup_timeout');
      const native = spawnSync(helper.executable, ['--parent', String(process.pid), '--identity-link'], {
        encoding: 'utf8', timeout: left, maxBuffer: 65536, env: nativeEnv()
      });
      const rows = parseLines(native.stdout), observer = rows.length === 1 ? rows[0] : null;
      if (native.error || native.status !== 0 || !observer || !validIdentity(observer.identity) ||
          observer.namespace_identity_provider !== NAMESPACE_PROVIDER || observer.boot_id !== descriptor.boot_id ||
          observer.procfs_dev !== descriptor.procfs_dev || !sameNamespaceIdentity(observer.observer_pid_namespace, observer.identity.pid_namespace) ||
          !Array.isArray(observer.identity.proc_pid_chain) || !observer.identity.proc_pid_chain.length || observer.identity.proc_pid_chain.length > 64) return unconfirmed('native_observer_mismatch');
      observerDepth = observer.identity.proc_pid_chain.length;
      context = { ...descriptor, observer_pid_namespace: observer.observer_pid_namespace };
    }
    const exits = []; let initProof;
    // Fence in control first. Only the exact outside controller and keeper are
    // stopped; no PID enumeration, process-group kill or age-based inference.
    for (const role of ['init', 'controller', 'keeper']) {
      let identity = descriptor[role];
      if (observerDepth !== undefined) {
        const chain = identity.proc_pid_chain;
        if (!Array.isArray(chain) || chain.length < observerDepth || chain.length > 64 ||
            chain.some(pid => !Number.isSafeInteger(pid) || pid < 1 || pid > 2147483647) ||
            chain[0] !== identity.proc_pid || chain[chain.length - 1] !== identity.namespace_pid) return unconfirmed('native_observer_translation_unconfirmed');
        // This index is only a candidate PID. The v2 native observer binds its
        // pidfd back to this exact procfs PID and whole NSpid chain before it
        // can signal or accept finality. An unrelated namespace cannot turn
        // a coincident numeric PID/namespace inum into authority.
        identity = { ...identity, pid: chain[observerDepth - 1] };
      }
      if (identity.pid === process.pid) return unconfirmed('native_recovery_self_target');
      const left = allowance - elapsed(start); if (left <= 0) return unconfirmed('native_cleanup_timeout');
      const result = runIdentityOperation('--stop', context, identity, left, helper);
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
module.exports = { SCHEMA, LEGACY_SCHEMA, NAMESPACE_PROVIDER, setInvocationHelper, getInvocationHelper, prepareHelper, preparePackagedHelper, admitPreparedHelper, cleanupPreparedHelper, containmentCapability, spawnLinuxContainedWorker, queryCommandScope, recoverContainer, currentProcessIdentity, verifyProcessExit, validDescriptor, validNamespaceIdentity, sameNamespaceIdentity, identityOperationArgs };
