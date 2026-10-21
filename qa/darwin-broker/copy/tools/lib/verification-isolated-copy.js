'use strict';

// The ordinary UID reads project bytes. The privileged broker receives only
// validated relative names and bytes; it never opens a caller's source path.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { copyInertData } = require('./inert-data');
const SCHEMA = 'knowledge-isolated-copy-manifest.v1';
const DEFAULTS = Object.freeze({ max_files: 20000, max_bytes: 1073741824, max_file_bytes: 67108864 });
const CAPS = Object.freeze({ max_files: 50000, max_bytes: 2147483648, max_file_bytes: 268435456 });
const KNOWLEDGE_SOURCE_DIRS = new Set(['tools', 'tests', 'docs', 'models', 'schemas', 'templates',
  'agent-integrations', 'commands', 'skills', 'assets', 'flows', 'github-action-templates', 'memory-providers', '.release-notes']);
const KNOWLEDGE_SOURCE_FILES = new Set(['package.json', 'config.yaml', 'verification-policy.json', 'install-manifest.json',
  'release-policy.json', 'install-policy.json', 'lock-policy.json', 'README.md', 'INSTALL.md', 'Quick-Start.md', 'RELEASE_NOTES.md', 'SECURITY.md',
  'LICENSE', 'LICENSE.md', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'Portal.md', 'SBOM.memory.json',
  '.gitignore', '.gitattributes', 'inspector.js', 'open-inspector.vbs']);
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
const compareNames = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
function failure(code, message, details) {
  return Object.assign(new Error(message), { code, ...(details ? { validation: details } : {}) });
}
function limits(value) {
  const data = value === undefined ? {} : copyInertData(value);
  if (!data || Array.isArray(data) || typeof data !== 'object' || Object.keys(data).some(k => !(k in DEFAULTS))) {
    throw failure('verification_copy_limits_invalid', 'Invalid isolated-copy limits');
  }
  const result = {};
  for (const key of Object.keys(DEFAULTS)) {
    const n = data[key] === undefined ? (key === 'max_file_bytes' ? Math.min(DEFAULTS[key], result.max_bytes) : DEFAULTS[key]) : data[key];
    if (!Number.isSafeInteger(n) || n < 1 || n > CAPS[key]) throw failure('verification_copy_limits_invalid', `Invalid ${key}`);
    result[key] = n;
  }
  if (result.max_file_bytes > result.max_bytes) throw failure('verification_copy_limits_invalid', 'Per-file limit exceeds total copy limit');
  return Object.freeze(result);
}
function relativeName(value, cwd = false) {
  if (cwd && value === '.') return '.';
  if (typeof value !== 'string' || !value || value.includes('\\') || path.posix.isAbsolute(value) ||
      value !== value.normalize('NFC') || /[\x00-\x1f\x7f]/.test(value)) {
    throw failure('verification_copy_path_unsupported', 'Isolated copy requires canonical portable relative paths');
  }
  const parts = value.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || /[<>:"|?*]/.test(p) || /[. ]$/.test(p) ||
      /^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³]|CONIN\$|CONOUT\$)(?:\.|$)/i.test(p))) {
    throw failure('verification_copy_path_unsupported', 'Isolated copy path is not portable');
  }
  return value;
}
function inside(root, file) {
  const rel = path.relative(root, file);
  return rel === '' || (!path.isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${path.sep}`));
}
function exclusion(name) {
  const parts = name.split('/'), folded = parts.map(p => p.toLowerCase()), leaf = parts.at(-1);
  if (folded.includes('.git')) return 'git_metadata';
  if (folded.some(p => ['.aws', '.ssh', '.gnupg', '.codex', '.claude', '.azure'].includes(p))) return 'agent_or_credential_state';
  // Unknown .knowledge roots are state by default. An ever-growing denylist
  // otherwise imports leases, UI caches or future signing/control material.
  for (let i = 0; i < parts.length - 1; i++) if (folded[i] === '.knowledge' &&
      !KNOWLEDGE_SOURCE_DIRS.has(parts[i + 1]) &&
      !(parts.length === i + 2 && KNOWLEDGE_SOURCE_FILES.has(parts[i + 1]))) return 'knowledge_runtime_state';
  if (parts.includes('node_modules') && parts.includes('.cache')) return 'dependency_cache';
  if (/^\.env(?:\.|$)/i.test(leaf) && !/\.(?:example|sample|template)$/i.test(leaf)) return 'secret_configuration';
  if (/^(?:id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|credentials|credentials\.json|\.npmrc|\.netrc)$/i.test(leaf) || /\.(?:pem|p12|pfx|key)$/i.test(leaf)) return 'sensitive_file';
  return null;
}
function identity(stat) {
  return { dev: String(stat.dev), ino: String(stat.ino), bytes: Number(stat.size) };
}
function sameIdentity(a, b) { return a.dev === b.dev && a.ino === b.ino && a.bytes === b.bytes; }
async function verifyParents(root, name) {
  let current = root;
  for (const part of name.split('/').slice(0, -1)) {
    current = path.join(current, part);
    const s = await fs.promises.lstat(current);
    if (!s.isDirectory() || s.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Copy source has a nonphysical parent');
  }
  if (!inside(root, await fs.promises.realpath(path.dirname(path.join(root, name))))) throw failure('verification_copy_source_escape', 'Copy source escaped its project');
}
async function readFile(root, name, expected, maximum, checkpoint) {
  relativeName(name);
  await verifyParents(root, name);
  const absolute = path.join(root, name);
  const before = await fs.promises.lstat(absolute);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maximum || before.size < 0) {
    throw failure('verification_copy_source_unsafe', 'Copy accepts bounded ordinary files with one link', { path: name });
  }
  const handle = await fs.promises.open(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.nlink !== 1 || !sameIdentity(identity(before), identity(opened)) ||
        (expected && !sameIdentity(expected.identity, identity(opened)))) {
      throw failure('verification_copy_source_changed', 'Copy source identity changed', { path: name });
    }
    const blocks = [], hash = crypto.createHash('sha256');
    let offset = 0;
    for (;;) {
      checkpoint?.();
      const buffer = Buffer.allocUnsafe(Math.min(65536, maximum + 1 - offset));
      if (!buffer.length) throw failure('verification_copy_source_changed', 'Copy source grew beyond its limit', { path: name });
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      if (!bytesRead) break;
      const block = buffer.subarray(0, bytesRead);
      blocks.push(block); hash.update(block); offset += bytesRead;
      if (offset > maximum) throw failure('verification_copy_limit_exceeded', 'Copy file exceeds its limit', { path: name });
    }
    const digest = hash.digest('hex');
    const after = await handle.stat(), current = await fs.promises.lstat(absolute);
    await verifyParents(root, name);
    if (offset !== before.size || !sameIdentity(identity(before), identity(after)) ||
        !sameIdentity(identity(before), identity(current)) || current.nlink !== 1 || current.isSymbolicLink() ||
        (expected && digest !== expected.sha256)) {
      throw failure('verification_copy_source_changed', 'Copy source changed while reading', { path: name });
    }
    return { body: Buffer.concat(blocks, offset), sha256: digest, identity: identity(after), mode: (after.mode & 0o111) ? 0o755 : 0o644 };
  } finally { await handle.close(); }
}
function manifestDigest(files) {
  return sha(Buffer.from(JSON.stringify([...files].sort((a, b) => compareNames(a.path, b.path))
    .map(({ path: name, bytes, sha256, mode }) => ({ bytes, mode, path: name, sha256 }))), 'utf8'));
}
function directoriesDigest(names) { return sha(Buffer.from(JSON.stringify([...names].sort(compareNames)), 'utf8')); }
async function planProject(repoRoot, options = {}) {
  const bounds = limits(options.limits);
  const root = await fs.promises.realpath(repoRoot);
  const rootStat = await fs.promises.lstat(repoRoot);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Project root must be an ordinary directory');
  const required = new Set((options.required || []).map(n => relativeName(n)));
  const files = [], directories = [], skipped = [], keys = new Set();
  let bytes = 0;
  async function visit(dir, prefix) {
    options.checkpoint?.();
    const names = (await fs.promises.readdir(dir)).sort();
    for (const leaf of names) {
      options.checkpoint?.();
      const name = relativeName(prefix ? `${prefix}/${leaf}` : leaf);
      const why = exclusion(name);
      if (why) { skipped.push({ path: name, reason: why }); continue; }
      const key = name.normalize('NFD').toUpperCase().toLowerCase();
      if (keys.has(key)) throw failure('verification_copy_path_collision', 'Copy paths collide under portable comparison', { path: name });
      keys.add(key);
      if (keys.size > bounds.max_files) throw failure('verification_copy_limit_exceeded', 'Project exceeds its file and directory entry limit');
      const s = await fs.promises.lstat(path.join(root, name));
      if (s.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Symlink imports are unsupported in isolated copy', { path: name });
      if (s.isDirectory()) { directories.push(name); await visit(path.join(root, name), name); continue; }
      if (!s.isFile() || s.nlink !== 1) throw failure('verification_copy_source_unsafe', 'Special and hardlinked imports are unsupported', { path: name });
      if (files.length >= bounds.max_files || bytes + s.size > bounds.max_bytes || s.size > bounds.max_file_bytes) {
        throw failure('verification_copy_limit_exceeded', 'Project exceeds isolated-copy limits', { path: name, files: files.length, bytes });
      }
      const read = await readFile(root, name, null, bounds.max_file_bytes, options.checkpoint);
      bytes += read.body.length;
      if (bytes > bounds.max_bytes) throw failure('verification_copy_limit_exceeded', 'Project grew beyond isolated-copy limits');
      files.push({ path: name, bytes: read.body.length, sha256: read.sha256, mode: read.mode, identity: read.identity });
      options.progress?.({ files: files.length, bytes });
    }
  }
  await visit(root, '');
  files.sort((a, b) => compareNames(a.path, b.path)); directories.sort(compareNames);
  for (const name of required) {
    if (!files.some(f => f.path === name)) throw failure('verification_copy_required_source_excluded', 'A required source is missing or excluded from the isolated copy', { path: name, reason: exclusion(name) || 'not_copied' });
  }
  return { schema_version: SCHEMA, root, files, directories, skipped, total_bytes: bytes, limits: bounds,
    manifest_sha256: manifestDigest(files), directories_sha256: directoriesDigest(directories), no_writeback: true };
}
async function transferProject(plan, request, options = {}) {
  if (!plan || plan.schema_version !== SCHEMA || manifestDigest(plan.files) !== plan.manifest_sha256 ||
      directoriesDigest(plan.directories) !== plan.directories_sha256) throw failure('verification_copy_manifest_invalid', 'Invalid copy manifest');
  for (const name of plan.directories) { options.checkpoint?.(); await request({ op: 'mkdir', path: relativeName(name) }); }
  let transferred = 0;
  for (const [index, entry] of plan.files.entries()) {
    const read = await readFile(plan.root, entry.path, entry, plan.limits.max_file_bytes, options.checkpoint);
    await request({ op: 'put_begin', path: entry.path, mode: entry.mode, bytes: entry.bytes, sha256: entry.sha256 });
    for (let offset = 0; offset < read.body.length; offset += 65536) {
      options.checkpoint?.();
      await request({ op: 'put_chunk', path: entry.path, offset, data: read.body.subarray(offset, offset + 65536).toString('base64') });
    }
    await request({ op: 'put_commit', path: entry.path, sha256: entry.sha256 });
    transferred += entry.bytes;
    options.progress?.({ files: index + 1, bytes: transferred });
  }
  await request({ op: 'seal', manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 });
  return { files: plan.files.length, bytes: transferred, manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 };
}
async function snapshotCopy(workspace, sourcePaths) {
  const root = await fs.promises.realpath(workspace), result = [];
  for (const name of sourcePaths) {
    const read = await readFile(root, relativeName(name), null, CAPS.max_file_bytes);
    result.push({ path: name, sha256: read.sha256 });
  }
  return result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
module.exports = { SCHEMA, DEFAULTS, CAPS, limits, relativeName, exclusion, manifestDigest, directoriesDigest, planProject, transferProject, snapshotCopy, inside };
