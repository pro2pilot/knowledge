'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { copyInertData } = require('./inert-data');
const { nativeExecutionConfig: config, nativeExecutionRequest } = require('./verification-policy');

const SCHEMA = 'knowledge-darwin-broker.v1';
const MAX_REPLY_BYTES = 64 * 1024;
// Capability discovery shares the helper's generous lifecycle budget. It must
// not silently impose the former 20-second ceiling on a healthy slow host.
// The native helper still guards its own monotonic lifecycle before success.
const PROBE_LIFECYCLE_TIMEOUT_MS = 120_000;
const PROBE_TRANSPORT_TIMEOUT_MS = 30_000;
const ACCOUNT_POLICY = 'admin_reserved_interval_no_runtime_nss.v1';
const SOURCE_FILE = path.join(__dirname, 'verification-darwin-broker.m');
const STUB_SOURCE_FILE = path.join(__dirname, 'verification-darwin-stub.c');
const UID_HEADER_FILE = path.join(__dirname, 'verification-darwin-uid-history.h');
const UID_SOURCE_FILE = path.join(__dirname, 'verification-darwin-uid-history.m');
const TRANSPORT_HEADER_FILE = path.join(__dirname, 'verification-darwin-transport.h');
const HOST_ENVIRONMENT = process.env;
const { isProxy } = require('node:util').types;
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const invalid = code => Object.assign(new Error(code), { code });
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function nativeEnv(source = HOST_ENVIRONMENT) {
  let data;
  try {
    // Only this captured host capability has Node's native exotic prototype.
    // Snapshot its own data descriptors; arbitrary caller objects still enter
    // the unchanged strict inert-data validator without getters or proxy traps.
    if (source === HOST_ENVIRONMENT) {
      if (isProxy(source)) throw invalid('verification_darwin_environment_invalid');
      const descriptors = Object.getOwnPropertyDescriptors(source), snapshot = Object.create(null);
      for (const key of Reflect.ownKeys(descriptors)) {
        const descriptor = descriptors[key];
        if (typeof key !== 'string' || !Object.hasOwn(descriptor, 'value') ||
            !descriptor.enumerable || typeof descriptor.value !== 'string') {
          throw invalid('verification_darwin_environment_invalid');
        }
        Object.defineProperty(snapshot, key, { value: descriptor.value, enumerable: true });
      }
      data = copyInertData(snapshot, null, 1024 * 1024);
    } else data = copyInertData(source, null, 1024 * 1024);
  }
  catch { throw invalid('verification_darwin_environment_invalid'); }
  if (!data || Array.isArray(data) || typeof data !== 'object') throw invalid('verification_darwin_environment_invalid');
  const result = Object.create(null);
  for (const [key, value] of Object.entries(data)) {
    if (/^(?:DYLD_|LD_)/i.test(key) || /^(?:NODE_OPTIONS|NODE_PATH|BASH_ENV|ENV)$/i.test(key)) continue;
    if (typeof value !== 'string' || !key || key.includes('=') || key.includes('\0') || value.includes('\0')) {
      throw invalid('verification_darwin_environment_invalid');
    }
    result[key] = value;
  }
  return result;
}

function bundledSourceHash(file = SOURCE_FILE) {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 2 * 1024 * 1024) {
      throw invalid('verification_darwin_source_unavailable');
    }
    return hash(fs.readFileSync(file));
  } catch (error) {
    if (error.code === 'verification_darwin_source_unavailable') throw error;
    throw invalid('verification_darwin_source_unavailable');
  }
}

function decodeReply(buffer, sourcePins = null) {
  if (!Buffer.isBuffer(buffer) || buffer.length > MAX_REPLY_BYTES) throw invalid('verification_darwin_reply_oversized');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer)); }
  catch { throw invalid('verification_darwin_protocol_invalid'); }
  try { value = copyInertData(value, null, MAX_REPLY_BYTES); }
  catch { throw invalid('verification_darwin_protocol_invalid'); }
  const allowed = ['schema', 'ok', 'source_sha256', 'capability_qualified', 'qualification_mode',
    'transport_header_sha256',
    'binary_sha256', 'stub_source_sha256', 'stub_binary_sha256', 'stub_wire_version',
    'host_id', 'boot_id', 'allowed_runtimes', 'registry_healthy', 'registry_quarantine_reason',
    'entry_store_loaded', 'uid_history', 'account_policy', 'error', 'daemon_epoch', 'guardian_protocol',
    'qa_persistence_gate', 'qa_build_id'];
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !allowed.includes(key)) ||
      value.schema !== SCHEMA || typeof value.ok !== 'boolean' || !/^[a-f0-9]{64}$/.test(value.source_sha256 || '')) {
    throw invalid('verification_darwin_protocol_invalid');
  }
  if (value.ok && (typeof value.capability_qualified !== 'boolean' || typeof value.registry_healthy !== 'boolean' ||
      typeof value.entry_store_loaded !== 'boolean' ||
      !(value.registry_quarantine_reason === null || typeof value.registry_quarantine_reason === 'string' &&
        /^[A-Z0-9_]{1,128}$/.test(value.registry_quarantine_reason)) ||
      value.registry_healthy === true && value.registry_quarantine_reason !== null ||
      typeof value.host_id !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.host_id) ||
      typeof value.boot_id !== 'string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value.boot_id) ||
      !validUIDHistory(value.uid_history, value.host_id) ||
      !validAccountPolicy(value.account_policy) ||
      typeof value.qualification_mode !== 'boolean' || value.stub_wire_version !== 'KVS2' ||
      value.guardian_protocol !== 'KVR2' || !/^[a-f0-9]{64}$/.test(value.daemon_epoch || '') ||
      typeof value.qa_persistence_gate !== 'boolean' ||
      (value.qa_persistence_gate ? !/^[a-f0-9]{64}$/.test(value.qa_build_id || '') : value.qa_build_id !== null) ||
      !/^[a-f0-9]{64}$/.test(value.stub_source_sha256 || '') || !/^[a-f0-9]{64}$/.test(value.stub_binary_sha256 || '') ||
      typeof value.transport_header_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.transport_header_sha256) ||
      !value.allowed_runtimes || Array.isArray(value.allowed_runtimes) || typeof value.allowed_runtimes !== 'object' ||
      !/^[a-f0-9]{64}$/.test(value.binary_sha256 || ''))) throw invalid('verification_darwin_protocol_invalid');
  if (!value.ok && (typeof value.error !== 'string' || !/^[A-Z0-9_]{1,96}$/.test(value.error))) {
    throw invalid('verification_darwin_protocol_invalid');
  }
  // Async production session discovery supplies hashes obtained by bounded,
  // stable reads. Legacy synchronous discovery remains in its setup process.
  const pin = (name, file) => sourcePins ? sourcePins[name] : bundledSourceHash(file);
  if (value.source_sha256 !== pin('source_sha256', SOURCE_FILE)) throw invalid('verification_darwin_source_pin_mismatch');
  if (value.ok && value.stub_source_sha256 !== pin('stub_source_sha256', STUB_SOURCE_FILE)) {
    throw invalid('verification_darwin_stub_source_pin_mismatch');
  }
  if (value.ok && value.transport_header_sha256 !== pin('transport_header_sha256', TRANSPORT_HEADER_FILE)) {
    throw invalid('verification_darwin_transport_source_pin_mismatch');
  }
  if (value.ok && (value.uid_history.header_sha256 !== pin('uid_history_header_sha256', UID_HEADER_FILE) ||
      value.uid_history.source_sha256 !== pin('uid_history_source_sha256', UID_SOURCE_FILE))) {
    throw invalid('verification_darwin_uid_source_pin_mismatch');
  }
  return value;
}

function validUIDHistory(history, host) {
  const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  if (!exact(history, ['healthy_cached', 'reason', 'health_source', 'last_refresh_attempt_started_monotonic_ms',
    'installation_id_cached', 'checkpoint_cached', 'header_sha256', 'source_sha256']) ||
      typeof history.healthy_cached !== 'boolean' || typeof history.reason !== 'string' ||
      !/^[A-Z0-9_]{1,128}$/.test(history.reason) ||
      !['disk_refresh_attempt', 'cached_unchecked', 'cached_quarantine'].includes(history.health_source) ||
      !hex(history.header_sha256) || !hex(history.source_sha256) ||
      !(history.last_refresh_attempt_started_monotonic_ms === null ||
        Number.isSafeInteger(history.last_refresh_attempt_started_monotonic_ms) &&
        history.last_refresh_attempt_started_monotonic_ms >= 0) ||
      !(history.installation_id_cached === null || hex(history.installation_id_cached))) return false;
  const cp = history.checkpoint_cached;
  if (cp !== null && (!exact(cp, ['schema', 'installation_id', 'host_id', 'seq', 'tip_sha256', 'next_uid']) ||
      cp.schema !== 'knowledge-darwin-uid-checkpoint.v1' || cp.installation_id !== history.installation_id_cached ||
      !hex(cp.installation_id) || cp.host_id !== host || typeof cp.seq !== 'string' ||
      !/^(?:0|[1-9][0-9]{0,5})$/.test(cp.seq) || Number(cp.seq) > 100000 ||
      !hex(cp.tip_sha256) || !Number.isSafeInteger(cp.next_uid) || cp.next_uid !== 1000000000 + Number(cp.seq))) return false;
  return !history.healthy_cached || cp !== null && history.reason === 'HEALTHY';
}

function validAccountPolicy(policy) {
  if (!exact(policy, ['id', 'healthy', 'reason', 'sha256', 'configured_owner_count', 'runtime_directory_lookups']) ||
      policy.id !== ACCOUNT_POLICY || typeof policy.healthy !== 'boolean' || typeof policy.reason !== 'string' ||
      !/^[A-Z0-9_]{1,128}$/.test(policy.reason) || policy.runtime_directory_lookups !== false ||
      !Number.isSafeInteger(policy.configured_owner_count) || policy.configured_owner_count < 0 ||
      policy.configured_owner_count > 64 || !(policy.sha256 === null || typeof policy.sha256 === 'string' &&
        /^[a-f0-9]{64}$/.test(policy.sha256))) return false;
  return !policy.healthy || policy.reason === 'HEALTHY' && policy.sha256 !== null && policy.configured_owner_count > 0;
}

function protectedBrokerHash(binaryPath) {
  // The independently pinned package addon observes root ancestry, ACLs and
  // bounded bytes on the same descriptors. The broker cannot attest itself.
  return require('./lock-publication').verifyProtectedExecutable(binaryPath,
    { maxBytes: 268435456, remainingMs: 30000 }).sha256;
}

function unavailable(reason) {
  return { platform: process.platform, backend: 'darwin_private_ruid', status: 'unavailable', reason };
}

function containmentCapability(value) {
  if (process.platform !== 'darwin') return unavailable('darwin_required');
  const normalized = config(value).darwin;
  if (!normalized.enabled) return unavailable('explicit_opt_in_required');
  try {
    const source_sha256 = bundledSourceHash();
    const binary_sha256 = protectedBrokerHash(normalized.broker_path);
    const runtime_sha256 = hash(fs.readFileSync(process.execPath));
    const result = childProcess.spawnSync(normalized.broker_path,
      ['--request', `--socket=${normalized.broker_socket}`,
        `--lifecycle-timeout-ms=${PROBE_LIFECYCLE_TIMEOUT_MS}`,
        `--transport-timeout-ms=${PROBE_TRANSPORT_TIMEOUT_MS}`], {
        shell: false, input: Buffer.from(JSON.stringify({ op: 'probe' }), 'utf8'), encoding: 'buffer',
        timeout: PROBE_LIFECYCLE_TIMEOUT_MS,
        maxBuffer: MAX_REPLY_BYTES, windowsHide: true, env: nativeEnv()
      });
    if (result.error || result.status !== 0) return unavailable('broker_probe_failed');
    const reply = decodeReply(result.stdout);
    if (!reply.ok) return unavailable('broker_probe_rejected');
    if (reply.capability_qualified !== true) return unavailable('broker_unqualified');
    if (reply.qualification_mode !== false) return unavailable('broker_diagnostic_mode');
    if (reply.qa_persistence_gate !== false) return unavailable('broker_qa_build');
    if (reply.registry_healthy !== true) return unavailable('broker_registry_unhealthy');
    if (reply.entry_store_loaded !== true || reply.uid_history.healthy_cached !== true ||
        reply.uid_history.health_source !== 'disk_refresh_attempt' ||
        reply.uid_history.last_refresh_attempt_started_monotonic_ms === null) return unavailable('broker_uid_history_unhealthy');
    if (reply.account_policy.healthy !== true) return unavailable('broker_account_policy_unhealthy');
    if (reply.binary_sha256 !== binary_sha256) return unavailable('broker_binary_pin_mismatch');
    // An administrator installs a protected byte-identical runtime copy. Its
    // pathname deliberately differs from the ordinary user's executable.
    const runtime_path = Object.keys(reply.allowed_runtimes).sort().find(file =>
      path.posix.isAbsolute(file) && !file.includes('\0') && reply.allowed_runtimes[file] === runtime_sha256);
    if (!runtime_path) return unavailable('runtime_pin_mismatch');
    return { platform: process.platform, backend: 'darwin_private_ruid', status: 'available',
      source_sha256, binary_sha256, stub_source_sha256: reply.stub_source_sha256,
      transport_header_sha256: reply.transport_header_sha256,
      stub_binary_sha256: reply.stub_binary_sha256, stub_wire_version: reply.stub_wire_version,
      uid_history_header_sha256: reply.uid_history.header_sha256,
      uid_history_source_sha256: reply.uid_history.source_sha256,
      installation_id: reply.uid_history.installation_id_cached,
      account_policy_id: reply.account_policy.id, account_policy_sha256: reply.account_policy.sha256,
      runtime_path, host_id: reply.host_id, boot_id: reply.boot_id, daemon_epoch: reply.daemon_epoch,
      guardian_protocol: reply.guardian_protocol };
  } catch (error) {
    return unavailable(/^[a-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'broker_probe_unavailable');
  }
}

module.exports = { SCHEMA, MAX_REPLY_BYTES, config, nativeExecutionRequest, nativeEnv, decodeReply, containmentCapability };
