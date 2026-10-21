'use strict';

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { copyInertData } = require('./inert-data');
const { limits } = require('./verification-isolated-copy');

const SCHEMA = 'knowledge-darwin-broker.v1';
const MAX_REPLY_BYTES = 64 * 1024;
const SOURCE_FILE = path.join(__dirname, 'verification-darwin-broker.m');
const STUB_SOURCE_FILE = path.join(__dirname, 'verification-darwin-stub.c');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const invalid = code => Object.assign(new Error(code), { code });
const exact = (value, keys) => value && !Array.isArray(value) && typeof value === 'object' &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function config(value) {
  if (value === undefined) return { darwin: { enabled: false } };
  let data;
  try { data = copyInertData(value, null, MAX_REPLY_BYTES); }
  catch { throw invalid('verification_darwin_config_invalid'); }
  if (exact(data, [])) return { darwin: { enabled: false } };
  if (!exact(data, ['darwin'])) throw invalid('verification_darwin_config_invalid');
  const input = data.darwin;
  if (!input || Array.isArray(input) || typeof input !== 'object') throw invalid('verification_darwin_config_invalid');
  if (input.enabled === false) {
    if (!exact(input, ['enabled'])) throw invalid('verification_darwin_config_invalid');
    return { darwin: { enabled: false } };
  }
  if (!exact(input, ['enabled', 'mode', 'broker_path', 'broker_socket', 'copy']) || input.enabled !== true ||
      input.mode !== 'isolated_copy') throw invalid('verification_darwin_config_invalid');
  const absoluteMacPath = value => typeof value === 'string' && value.length <= 4096 && !value.includes('\0') &&
    !value.includes('\\') && value === value.normalize('NFC') && path.posix.isAbsolute(value) &&
    value !== '/' && !value.endsWith('/') && value === path.posix.normalize(value) && !/\/\/|[\x00-\x1f\x7f]/.test(value);
  if (!absoluteMacPath(input.broker_path) || !absoluteMacPath(input.broker_socket) ||
      Buffer.byteLength(input.broker_socket) >= 104) throw invalid('verification_darwin_config_invalid');
  let copy;
  try {
    if (!input.copy || Array.isArray(input.copy) || typeof input.copy !== 'object' ||
        Object.keys(input.copy).some(key => !['max_files', 'max_bytes', 'max_file_bytes'].includes(key))) {
      throw invalid('verification_darwin_config_invalid');
    }
    copy = limits(input.copy);
  }
  catch { throw invalid('verification_darwin_config_invalid'); }
  return { darwin: { enabled: true, mode: 'isolated_copy', broker_path: input.broker_path,
    broker_socket: input.broker_socket, copy } };
}

function nativeEnv(source = process.env) {
  let data;
  try { data = copyInertData(source, null, 1024 * 1024); }
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

function decodeReply(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length > MAX_REPLY_BYTES) throw invalid('verification_darwin_reply_oversized');
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer)); }
  catch { throw invalid('verification_darwin_protocol_invalid'); }
  try { value = copyInertData(value, null, MAX_REPLY_BYTES); }
  catch { throw invalid('verification_darwin_protocol_invalid'); }
  const allowed = ['schema', 'ok', 'source_sha256', 'capability_qualified', 'qualification_mode',
    'binary_sha256', 'stub_source_sha256', 'stub_binary_sha256', 'stub_wire_version',
    'host_id', 'boot_id', 'allowed_runtimes', 'registry_healthy', 'error'];
  if (!value || Array.isArray(value) || typeof value !== 'object' || Object.keys(value).some(key => !allowed.includes(key)) ||
      value.schema !== SCHEMA || typeof value.ok !== 'boolean' || !/^[a-f0-9]{64}$/.test(value.source_sha256 || '')) {
    throw invalid('verification_darwin_protocol_invalid');
  }
  if (value.ok && (typeof value.capability_qualified !== 'boolean' || typeof value.registry_healthy !== 'boolean' ||
      typeof value.qualification_mode !== 'boolean' || value.stub_wire_version !== 'KVS1' ||
      !/^[a-f0-9]{64}$/.test(value.stub_source_sha256 || '') || !/^[a-f0-9]{64}$/.test(value.stub_binary_sha256 || '') ||
      !value.allowed_runtimes || Array.isArray(value.allowed_runtimes) || typeof value.allowed_runtimes !== 'object' ||
      !/^[a-f0-9]{64}$/.test(value.binary_sha256 || ''))) throw invalid('verification_darwin_protocol_invalid');
  if (!value.ok && (typeof value.error !== 'string' || !/^[A-Z0-9_]{1,96}$/.test(value.error))) {
    throw invalid('verification_darwin_protocol_invalid');
  }
  if (value.source_sha256 !== bundledSourceHash()) throw invalid('verification_darwin_source_pin_mismatch');
  if (value.ok && value.stub_source_sha256 !== bundledSourceHash(STUB_SOURCE_FILE)) {
    throw invalid('verification_darwin_stub_source_pin_mismatch');
  }
  return value;
}

function protectedBrokerHash(binaryPath) {
  const parts = binaryPath.split('/').filter(Boolean);
  let current = '/';
  for (let i = 0; i < parts.length; i++) {
    current = path.posix.join(current, parts[i]);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022)) throw invalid('verification_darwin_broker_unsafe');
    if (i < parts.length - 1 && !stat.isDirectory()) throw invalid('verification_darwin_broker_unsafe');
    if (i === parts.length - 1 && (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o6000))) {
      throw invalid('verification_darwin_broker_unsafe');
    }
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(binaryPath, flags);
  try {
    const live = fs.fstatSync(fd), leaf = fs.lstatSync(binaryPath);
    if (!live.isFile() || live.uid !== 0 || live.nlink !== 1 || (live.mode & 0o6022) ||
        live.dev !== leaf.dev || live.ino !== leaf.ino || live.size !== leaf.size) throw invalid('verification_darwin_broker_unsafe');
    return hash(fs.readFileSync(fd));
  } finally { fs.closeSync(fd); }
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
      ['--request', `--socket=${normalized.broker_socket}`], {
        shell: false, input: JSON.stringify({ op: 'probe' }), encoding: 'buffer', timeout: 20_000,
        maxBuffer: MAX_REPLY_BYTES, windowsHide: true, env: nativeEnv()
      });
    if (result.error || result.status !== 0) return unavailable('broker_probe_failed');
    const reply = decodeReply(result.stdout);
    if (!reply.ok) return unavailable('broker_probe_rejected');
    if (reply.capability_qualified !== true) return unavailable('broker_unqualified');
    if (reply.qualification_mode !== false) return unavailable('broker_diagnostic_mode');
    if (reply.registry_healthy !== true) return unavailable('broker_registry_unhealthy');
    if (reply.binary_sha256 !== binary_sha256) return unavailable('broker_binary_pin_mismatch');
    // An administrator installs a protected byte-identical runtime copy. Its
    // pathname deliberately differs from the ordinary user's executable.
    const runtime_path = Object.keys(reply.allowed_runtimes).sort().find(file =>
      path.posix.isAbsolute(file) && !file.includes('\0') && reply.allowed_runtimes[file] === runtime_sha256);
    if (!runtime_path) return unavailable('runtime_pin_mismatch');
    return { platform: process.platform, backend: 'darwin_private_ruid', status: 'available',
      source_sha256, binary_sha256, stub_source_sha256: reply.stub_source_sha256,
      stub_binary_sha256: reply.stub_binary_sha256, stub_wire_version: reply.stub_wire_version,
      runtime_path, host_id: reply.host_id, boot_id: reply.boot_id };
  } catch (error) {
    return unavailable(/^[a-z0-9_]{1,96}$/.test(error?.code || '') ? error.code : 'broker_probe_unavailable');
  }
}

module.exports = { SCHEMA, MAX_REPLY_BYTES, config, nativeEnv, decodeReply, containmentCapability };
