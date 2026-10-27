'use strict';

// The ordinary UID reads project bytes. The privileged broker receives only
// validated relative names and bytes; it never opens a caller's source path.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { copyInertData } = require('./inert-data');
const SCHEMA = 'knowledge-isolated-copy-manifest.v1';
const { COPY_DEFAULTS: DEFAULTS, COPY_CAPS: CAPS, copyLimits: limits } = require('./verification-policy');
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
function relativeName(value, cwd = false) {
  if (cwd && value === '.') return '.';
  if (typeof value !== 'string' || !value || value.includes('\\') || path.posix.isAbsolute(value) ||
      value !== value.normalize('NFC') || /[\x00-\x1f\x7f]/.test(value) ||
      Buffer.from(value, 'utf8').toString('utf8') !== value) {
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
function directoryIdentity(stat) { return { dev: String(stat.dev), ino: String(stat.ino) }; }
function sameDirectory(a, b) { return a.dev === b.dev && a.ino === b.ino; }
async function physicalRoot(input) {
  const source_root = path.resolve(input);
  const before = await fs.promises.lstat(source_root, { bigint: true });
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw failure('verification_copy_source_unsafe', 'Project root must be an ordinary directory');
  }
  // Resolve ordinary platform aliases (for example macOS /var) once, then bind
  // the physical chain. The requested root itself must never be a symlink.
  const root = await fs.promises.realpath(source_root), root_ancestors = [];
  const base = path.parse(root).root;
  let current = base;
  for (const part of ['', ...path.relative(base, root).split(path.sep).filter(Boolean)]) {
    if (part) current = path.join(current, part);
    const stat = await fs.promises.lstat(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Copy root has a nonphysical ancestor');
    root_ancestors.push({ path: current, identity: directoryIdentity(stat) });
  }
  const after = await fs.promises.lstat(source_root, { bigint: true });
  if (after.isSymbolicLink() || !sameDirectory(directoryIdentity(before), directoryIdentity(after)) ||
      !sameDirectory(directoryIdentity(after), root_ancestors.at(-1).identity)) {
    throw failure('verification_copy_source_changed', 'Copy root changed while binding its identity');
  }
  return { root, source_root, root_ancestors };
}
async function verifyRoot(binding) {
  for (const entry of binding.root_ancestors) {
    const stat = await fs.promises.lstat(entry.path, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink() || !sameDirectory(entry.identity, directoryIdentity(stat))) {
      throw failure('verification_copy_source_changed', 'Copy root or its physical ancestor changed');
    }
  }
  const stat = await fs.promises.lstat(binding.source_root, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      !sameDirectory(directoryIdentity(stat), binding.root_ancestors.at(-1).identity) ||
      await fs.promises.realpath(binding.source_root) !== binding.root) {
    throw failure('verification_copy_source_changed', 'Requested copy root changed');
  }
}
async function verifyDirectory(root, name, expected) {
  const stat = await fs.promises.lstat(name === '.' ? root : path.join(root, name), { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Copy source has a nonphysical parent');
  if (expected && !sameDirectory(expected, directoryIdentity(stat))) {
    throw failure('verification_copy_source_changed', 'Copy directory identity changed', { path: name });
  }
  return directoryIdentity(stat);
}
async function verifyParents(root, name, binding) {
  if (binding) await verifyRoot(binding);
  let current = root;
  let relative = '';
  for (const part of name.split('/').slice(0, -1)) {
    current = path.join(current, part);
    relative = relative ? `${relative}/${part}` : part;
    await verifyDirectory(root, relative, binding?.directoryMap.get(relative));
  }
  if (!inside(root, await fs.promises.realpath(path.dirname(path.join(root, name))))) throw failure('verification_copy_source_escape', 'Copy source escaped its project');
}
async function readFile(root, name, expected, maximum, checkpoint, binding) {
  relativeName(name);
  await verifyParents(root, name, binding);
  const absolute = path.join(root, name);
  const before = await fs.promises.lstat(absolute, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > maximum || before.size < 0) {
    throw failure('verification_copy_source_unsafe', 'Copy accepts bounded ordinary files with one link', { path: name });
  }
  // O_NONBLOCK prevents a raced regular-file -> FIFO replacement from hanging
  // open before fstat can reject it. It does not alter regular-file semantics.
  const handle = await fs.promises.open(absolute, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(identity(before), identity(opened)) ||
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
    const after = await handle.stat({ bigint: true }), current = await fs.promises.lstat(absolute, { bigint: true });
    await verifyParents(root, name, binding);
    if (offset !== Number(before.size) || !sameIdentity(identity(before), identity(after)) ||
        !sameIdentity(identity(before), identity(current)) || current.nlink !== 1n || current.isSymbolicLink() ||
        (expected && digest !== expected.sha256)) {
      throw failure('verification_copy_source_changed', 'Copy source changed while reading', { path: name });
    }
    return { body: Buffer.concat(blocks, offset), sha256: digest, identity: identity(after), mode: (after.mode & 0o111n) ? 0o755 : 0o644 };
  } finally { await handle.close(); }
}
function manifestDigest(files) {
  return sha(Buffer.from(JSON.stringify([...files].sort((a, b) => compareNames(a.path, b.path))
    .map(({ path: name, bytes, sha256, mode }) => ({ bytes, mode, path: name, sha256 }))), 'utf8'));
}
function directoriesDigest(names) { return sha(Buffer.from(JSON.stringify([...names].sort(compareNames)), 'utf8')); }
function physicalBindingDigest(plan) {
  return sha(Buffer.from(JSON.stringify({ root: plan.root, source_root: plan.source_root,
    root_ancestors: plan.root_ancestors, directory_identities: plan.directory_identities,
    file_identities: plan.files.map(({ path: name, identity }) => ({ path: name, identity })),
    required: plan.required, cwd: plan.cwd }), 'utf8'));
}
function planBinding(plan) { return { ...plan, directoryMap: new Map(plan.directory_identities.map(entry => [entry.path, entry.identity])) }; }
function validatePlan(plan) {
  try {
    if (!plan || plan.schema_version !== SCHEMA || !Array.isArray(plan.files) || !Array.isArray(plan.directories) ||
        !Array.isArray(plan.root_ancestors) || !plan.root_ancestors.length || !Array.isArray(plan.directory_identities) ||
        !Array.isArray(plan.required) || relativeName(plan.cwd, true) !== plan.cwd ||
        manifestDigest(plan.files) !== plan.manifest_sha256 || directoriesDigest(plan.directories) !== plan.directories_sha256 ||
        physicalBindingDigest(plan) !== plan.physical_binding_sha256) throw new Error('invalid');
    return planBinding(plan);
  } catch { throw failure('verification_copy_manifest_invalid', 'Invalid copy manifest or physical binding'); }
}
async function planProject(repoRoot, options = {}) {
  const bounds = limits(options.limits);
  const rootBinding = await physicalRoot(repoRoot), { root } = rootBinding;
  const required = new Set((options.required || []).map(n => relativeName(n)));
  const cwd = relativeName(options.cwd === undefined ? '.' : options.cwd, true);
  const files = [], directories = [], skipped = [], keys = new Set();
  const directoryMap = new Map([['.', rootBinding.root_ancestors.at(-1).identity]]);
  const binding = { ...rootBinding, directoryMap };
  let bytes = 0;
  async function visit(dir, prefix) {
    options.checkpoint?.();
    await verifyRoot(binding);
    const directory = prefix || '.';
    directoryMap.set(directory, await verifyDirectory(root, directory, directoryMap.get(directory)));
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
      const s = await fs.promises.lstat(path.join(root, name), { bigint: true });
      if (s.isSymbolicLink()) throw failure('verification_copy_source_unsafe', 'Symlink imports are unsupported in isolated copy', { path: name });
      if (s.isDirectory()) { directories.push(name); await visit(path.join(root, name), name); continue; }
      if (!s.isFile() || s.nlink !== 1n) throw failure('verification_copy_source_unsafe', 'Special and hardlinked imports are unsupported', { path: name });
      if (files.length >= bounds.max_files || bytes + Number(s.size) > bounds.max_bytes || s.size > bounds.max_file_bytes) {
        throw failure('verification_copy_limit_exceeded', 'Project exceeds isolated-copy limits', { path: name, files: files.length, bytes });
      }
      const read = await readFile(root, name, null, bounds.max_file_bytes, options.checkpoint, binding);
      bytes += read.body.length;
      if (bytes > bounds.max_bytes) throw failure('verification_copy_limit_exceeded', 'Project grew beyond isolated-copy limits');
      files.push({ path: name, bytes: read.body.length, sha256: read.sha256, mode: read.mode, identity: read.identity });
      options.progress?.({ files: files.length, bytes });
    }
    await verifyDirectory(root, directory, directoryMap.get(directory));
  }
  await visit(root, '');
  files.sort((a, b) => compareNames(a.path, b.path)); directories.sort(compareNames);
  for (const name of required) {
    if (!files.some(f => f.path === name)) throw failure('verification_copy_required_source_excluded', 'A required source is missing or excluded from the isolated copy', { path: name, reason: exclusion(name) || 'not_copied' });
  }
  if (!directoryMap.has(cwd)) throw failure('verification_copy_required_cwd_excluded', 'The physical working directory is missing or excluded', { path: cwd });
  await verifyRoot(binding);
  const directory_identities = [...directoryMap].map(([name, identity]) => ({ path: name, identity }))
    .sort((a, b) => compareNames(a.path, b.path));
  for (const entry of directory_identities) await verifyDirectory(root, entry.path, entry.identity);
  const plan = { schema_version: SCHEMA, ...rootBinding, files, directories, directory_identities, skipped,
    required: [...required].sort(compareNames), cwd, total_bytes: bytes, limits: bounds,
    manifest_sha256: manifestDigest(files), directories_sha256: directoriesDigest(directories), no_writeback: true };
  plan.physical_binding_sha256 = physicalBindingDigest(plan);
  return plan;
}
async function verifyProjectPlan(plan, options = {}) {
  const binding = validatePlan(plan);
  try {
    await verifyRoot(binding);
    for (const entry of plan.directory_identities) await verifyDirectory(plan.root, entry.path, entry.identity);
    const current = await planProject(plan.source_root, { limits: plan.limits, required: plan.required, cwd: plan.cwd,
      checkpoint: options.checkpoint });
    if (current.manifest_sha256 !== plan.manifest_sha256 || current.directories_sha256 !== plan.directories_sha256 ||
        current.physical_binding_sha256 !== plan.physical_binding_sha256) {
      throw failure('verification_copy_source_changed', 'Project bytes, entries, modes, or physical identities changed');
    }
  } catch (error) {
    if (['ENOENT', 'ENOTDIR', 'ELOOP', 'verification_copy_required_source_excluded',
      'verification_copy_required_cwd_excluded'].includes(error.code)) {
      throw failure('verification_copy_source_changed', 'A previously bound source or working directory disappeared');
    }
    throw error;
  }
  return { manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256,
    physical_binding_sha256: plan.physical_binding_sha256 };
}
async function transferProject(plan, request, options = {}) {
  const binding = validatePlan(plan);
  // Whole-source readback catches additions/deletions and replacements before
  // any remote mutation, and repeats before seal after asynchronous RPC work.
  await verifyProjectPlan(plan, options);
  for (const name of plan.directories) { options.checkpoint?.(); await request({ op: 'mkdir', path: relativeName(name) }); }
  let transferred = 0;
  for (const [index, entry] of plan.files.entries()) {
    const read = await readFile(plan.root, entry.path, entry, plan.limits.max_file_bytes, options.checkpoint, binding);
    await request({ op: 'put_begin', path: entry.path, mode: entry.mode, bytes: entry.bytes, sha256: entry.sha256 });
    for (let offset = 0; offset < read.body.length; offset += 65536) {
      options.checkpoint?.();
      await request({ op: 'put_chunk', path: entry.path, offset, data: read.body.subarray(offset, offset + 65536).toString('base64') });
    }
    await request({ op: 'put_commit', path: entry.path, sha256: entry.sha256 });
    transferred += entry.bytes;
    options.progress?.({ files: index + 1, bytes: transferred });
  }
  await verifyProjectPlan(plan, options);
  options.checkpoint?.();
  await request({ op: 'seal', manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 });
  // Seal itself may wait on the broker. Never report a current source binding
  // solely from an observation taken before that asynchronous operation.
  await verifyProjectPlan(plan, options);
  return { files: plan.files.length, bytes: transferred, manifest_sha256: plan.manifest_sha256, directories_sha256: plan.directories_sha256 };
}
async function snapshotCopy(workspace, sourcePaths, options = {}) {
  const binding = await physicalRoot(workspace), { root } = binding, result = [];
  binding.directoryMap = new Map([['.', binding.root_ancestors.at(-1).identity]]);
  for (const name of sourcePaths) {
    relativeName(name);
    let parent = '';
    for (const part of name.split('/').slice(0, -1)) {
      parent = parent ? `${parent}/${part}` : part;
      binding.directoryMap.set(parent, await verifyDirectory(root, parent, binding.directoryMap.get(parent)));
    }
    const read = await readFile(root, name, null, CAPS.max_file_bytes, options.checkpoint, binding);
    result.push({ path: name, sha256: read.sha256 });
  }
  await verifyRoot(binding);
  for (const [name, expected] of binding.directoryMap) await verifyDirectory(root, name, expected);
  return result.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}
module.exports = { SCHEMA, DEFAULTS, CAPS, limits, relativeName, exclusion, manifestDigest, directoriesDigest,
  physicalBindingDigest, planProject, verifyProjectPlan, transferProject, snapshotCopy, inside };
