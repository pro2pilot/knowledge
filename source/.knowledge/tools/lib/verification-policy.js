'use strict';

// Pure timing policy and progress state. Neither stdout nor a heartbeat is a
// semantic checkpoint. All native timers share monotonic timestamps; timers
// longer than the platform's signed 32-bit range are rearmed in chunks.
const defaults = require('../../verification-policy.json');
const { copyInertData } = require('./inert-data');
const path = require('node:path');
const { isProxy } = require('node:util').types;
const COPY_DEFAULTS = Object.freeze({ max_files: 20000, max_bytes: 1073741824, max_file_bytes: 67108864 });
const COPY_CAPS = Object.freeze({ max_files: 50000, max_bytes: 2147483648, max_file_bytes: 268435456 });
const MAX_WORK_MS = 600000 * 100000;
const MAX_CLEANUP_MS = 3600000;
const TIMER_MAX_MS = 2147483647;
function requestError(code) { return Object.assign(new Error(code), { code }); }
function copyLimits(value) {
  let data;
  try { data = value === undefined ? {} : copyInertData(value); }
  catch { throw requestError('verification_copy_limits_invalid'); }
  if (!data || Array.isArray(data) || typeof data !== 'object' ||
      Object.keys(data).some(k => !Object.hasOwn(COPY_DEFAULTS, k))) {
    throw requestError('verification_copy_limits_invalid');
  }
  const result = {};
  for (const key of Object.keys(COPY_DEFAULTS)) {
    const n = data[key] === undefined ? (key === 'max_file_bytes'
      ? Math.min(COPY_DEFAULTS[key], result.max_bytes) : COPY_DEFAULTS[key]) : data[key];
    if (!Number.isSafeInteger(n) || n < 1 || n > COPY_CAPS[key]) throw requestError('verification_copy_limits_invalid');
    result[key] = n;
  }
  if (result.max_file_bytes > result.max_bytes) throw requestError('verification_copy_limits_invalid');
  return Object.freeze(result);
}

// Keep execution-policy admission in this existing pinned authority module.
// Legacy Windows/Linux acceptance must not acquire an unpinned Darwin client
// dependency merely because a public request now preserves an explicit opt-in.
function nativeExecutionConfig(value) {
  if (value === undefined) return { darwin: { enabled: false } };
  const fail = () => { throw requestError('verification_darwin_config_invalid'); };
  let data;
  try { data = copyInertData(value, null, 64 * 1024); } catch { fail(); }
  const exact = (object, keys) => object && typeof object === 'object' && !Array.isArray(object) &&
    Object.keys(object).sort().join(',') === [...keys].sort().join(',');
  if (exact(data, [])) return { darwin: { enabled: false } };
  if (exact(data, ['linux'])) {
    const linux = data.linux;
    const linuxFail = () => { throw requestError('verification_linux_service_config_invalid'); };
    if (exact(linux, ['enabled']) && linux.enabled === false) return { linux: { enabled: false } };
    if (!exact(linux, ['enabled', 'mode', 'broker_path', 'copy']) || linux.enabled !== true ||
        linux.mode !== 'isolated_copy' || linux.broker_path !== '/var/lib/knowledge-linux-native-v1/broker' ||
        !linux.copy || typeof linux.copy !== 'object' || Array.isArray(linux.copy)) linuxFail();
    let copy;
    try { copy = copyLimits({ max_files: 20000, max_bytes: 32 * 1024 * 1024,
      max_file_bytes: 32 * 1024 * 1024, ...linux.copy }); } catch { linuxFail(); }
    if (copy.max_bytes > 32 * 1024 * 1024 || copy.max_file_bytes > 32 * 1024 * 1024) linuxFail();
    return { linux: { enabled: true, mode: 'isolated_copy', broker_path: linux.broker_path, copy } };
  }
  if (!exact(data, ['darwin'])) fail();
  const input = data.darwin;
  if (!input || Array.isArray(input) || typeof input !== 'object') fail();
  if (input.enabled === false) {
    if (!exact(input, ['enabled'])) fail();
    return { darwin: { enabled: false } };
  }
  if (!exact(input, ['enabled', 'mode', 'broker_path', 'broker_socket', 'copy']) ||
      input.enabled !== true || input.mode !== 'isolated_copy') fail();
  const absoluteMacPath = p => typeof p === 'string' && p.length <= 4096 && !p.includes('\0') &&
    !p.includes('\\') && p === p.normalize('NFC') && path.posix.isAbsolute(p) &&
    p !== '/' && !p.endsWith('/') && p === path.posix.normalize(p) && !/\/\/|[\x00-\x1f\x7f]/.test(p);
  if (!absoluteMacPath(input.broker_path) || !absoluteMacPath(input.broker_socket) ||
      Buffer.byteLength(input.broker_socket) >= 104 || !input.copy ||
      Array.isArray(input.copy) || typeof input.copy !== 'object') fail();
  let copy;
  try { copy = copyLimits(input.copy); } catch { fail(); }
  return { darwin: { enabled: true, mode: 'isolated_copy', broker_path: input.broker_path,
    broker_socket: input.broker_socket, copy } };
}

function nativeExecutionRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request) || isProxy(request) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(request))) {
    throw requestError('verification_darwin_config_invalid');
  }
  const snake = Object.getOwnPropertyDescriptor(request, 'native_execution');
  const camel = Object.getOwnPropertyDescriptor(request, 'nativeExecution');
  if (snake && camel) throw requestError('verification_native_execution_conflict');
  const descriptor = snake || camel;
  if (!descriptor) return undefined;
  if (!Object.hasOwn(descriptor, 'value') || descriptor.value === undefined) {
    throw requestError('verification_darwin_config_invalid');
  }
  return nativeExecutionConfig(descriptor.value);
}
function invalid() {
  throw Object.assign(new Error('Invalid native verification timing policy'), { code: 'verification_policy_invalid' });
}
function duration(value, max, zero = false) {
  if (!Number.isSafeInteger(value) || value < (zero ? 0 : 1) || value > max) invalid();
  return value;
}
function resolvePolicy(override, legacyBudget) {
  const value = override === undefined ? {} : copyInertData(override);
  if (!value || Array.isArray(value) || typeof value !== 'object') invalid();
  if (Object.keys(value).some(k => !['profile', 'work_budget_ms', 'no_progress_ms', 'cleanup_budget_ms'].includes(k))) invalid();
  if (Object.values(value).some(v => v === null)) invalid();
  const profile = value.profile === undefined ? defaults.default_profile : value.profile;
  if (typeof profile !== 'string' || !Object.prototype.hasOwnProperty.call(defaults.profiles, profile)) invalid();
  const baseline = defaults.profiles[profile];
  // Existing callers retain their explicitly calculated batch budget. An
  // explicitly chosen profile supplies the budget when no override is given.
  const work = value.work_budget_ms ?? (value.profile === undefined && legacyBudget !== undefined ? legacyBudget : baseline.work_budget_ms);
  return Object.freeze({
    schema_version: defaults.schema_version, profile,
    work_budget_ms: duration(work, MAX_WORK_MS),
    no_progress_ms: duration(value.no_progress_ms ?? baseline.no_progress_ms, MAX_WORK_MS, true),
    cleanup_budget_ms: duration(value.cleanup_budget_ms ?? baseline.cleanup_budget_ms, MAX_CLEANUP_MS),
    automatic_work_budget_extension: false, command_progress_signal: 'unavailable',
    control_poll_ms: defaults.control_poll_ms
  });
}
function timerDelay(milliseconds) {
  if (!Number.isFinite(milliseconds)) invalid();
  return Math.max(1, Math.min(TIMER_MAX_MS, Math.ceil(milliseconds)));
}
function createProgress(policy, startedNs) {
  let lastNs = startedNs, phase = 'preparation', ordinal = -1, rank = -1, committed = 0;
  let signalAvailable = true;
  const executions = new Set();
  const ranks = { test_setup: 0, command: 1, finalization: 2, receipt_commit: 3 };
  return {
    advance(event, nowNs) {
      if (!event || nowNs < lastNs) return false;
      if (event.type === 'phase' && Number.isSafeInteger(event.ordinal) && event.ordinal >= 0 &&
          Object.prototype.hasOwnProperty.call(ranks, event.phase)) {
        const nextRank = ranks[event.phase];
        if (event.ordinal !== committed || event.ordinal < ordinal ||
            (event.ordinal === ordinal ? nextRank !== rank + 1 : nextRank !== 0)) return false;
        ordinal = event.ordinal; rank = nextRank; phase = event.phase;
        // A silent command has no trusted item/checkpoint channel. Its work
        // budget is enforced, but silence is never classified as a hang.
        signalAvailable = phase !== 'command';
      } else if (event.type === 'committed' && event.ordinal === committed &&
          event.ordinal === ordinal && rank === ranks.receipt_commit &&
          /^KVE-[a-f0-9]{64}$/.test(event.execution_id || '') && !executions.has(event.execution_id)) {
        executions.add(event.execution_id);
        committed++; phase = 'between_tests'; signalAvailable = true;
      } else return false;
      lastNs = nowNs;
      return true;
    },
    snapshot(nowNs) {
      return { phase, committed, last_meaningful_progress_elapsed_ms: Number(lastNs - startedNs) / 1e6,
        since_meaningful_progress_ms: Number(nowNs - lastNs) / 1e6,
        progress_signal_available: signalAvailable };
    },
    isStalled(nowNs) {
      return signalAvailable && policy.no_progress_ms > 0 &&
        nowNs - lastNs >= BigInt(policy.no_progress_ms) * 1000000n;
    }
  };
}
module.exports = { resolvePolicy, timerDelay, createProgress, MAX_WORK_MS, MAX_CLEANUP_MS,
  nativeExecutionConfig, nativeExecutionRequest, copyLimits, COPY_DEFAULTS, COPY_CAPS };
