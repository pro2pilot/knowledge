'use strict';

// Read-only discovery, not recovery authority. The immutable operation writer
// may read this fixed Team lock before asynchronous parent observation. It
// cannot create directories, query a native helper, or authorize reclamation.
// File/parent identity and byte limits are checked here; slow storage remains
// behind the writer's independent native guardian, not a JS time guarantee.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { copyInertData } = require('./inert-data');
const { readStableFile, decodeUtf8 } = require('./stable-file');
const { assertSafeContainmentRoot, assertSafeContainedPath } = require('./json-store');
const { assertSafePathSegment } = require('./path-segment');
const { LOCK_POLICY, LOCKS } = require('./lock-policy');
const { validateOwner, canonicalOwnerText } = require('./lock-owner-schema');
const { validateCommandScope } = require('./macos-command-scope');
const fail = (code, cause) => Object.assign(new Error(code), { code, ...(cause ? { cause } : {}) });
const same = (a, b) => a.dev === b.dev && a.ino === b.ino;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function frozen(value) {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) frozen(child);Object.freeze(value); }
  return value;
}
function tokenFree(value) {
  if (!value || typeof value !== 'object') return true;
  return Object.entries(value).every(([key, child]) => !['token', 'auth', 'auth_token'].includes(key.toLowerCase()) && tokenFree(child));
}
function readTeamFlowScope(rawContext) {
  let context;
  try { context = copyInertData(rawContext, null, 4 * 1024 * 1024); }
  catch (error) { throw fail('macos_lock_preflight_context_invalid', error); }
  if (!context || context.mode !== 'team' || typeof context.teamRoot !== 'string' ||
      !path.isAbsolute(context.teamRoot) || path.resolve(context.teamRoot) !== context.teamRoot ||
      typeof context.repoId !== 'string') throw fail('macos_lock_preflight_context_invalid');
  let repoId;
  try { repoId = assertSafePathSegment(context.repoId, 'repoId'); }
  catch (error) { throw fail('macos_lock_preflight_context_invalid', error); }
  let root;
  try { root = assertSafeContainmentRoot(context.teamRoot); }
  catch (error) { if (error.code === 'ENOENT') return null;throw error; }
  const directory = path.join(root, 'repos', repoId, 'locks', 'v' + LOCK_POLICY.layout_version, 'team-flow.lock');
  assertSafeContainedPath(root, directory, { allowMissing: true });
  let beforeDirectory;
  try { beforeDirectory = fs.lstatSync(directory, { bigint: true }); }
  catch (error) { if (error.code === 'ENOENT') return null;throw error; }
  if (!beforeDirectory.isDirectory() || beforeDirectory.isSymbolicLink()) throw fail('macos_lock_preflight_path_unsafe');
  const ownerPath = path.join(directory, 'owner.json'), scopePath = path.join(directory, 'execution-scope.json');
  let ownerBytes, ownerBefore;
  try {
    ownerBefore = fs.lstatSync(ownerPath, { bigint: true });
    ownerBytes = readStableFile(root, ownerPath, { maxBytes: LOCK_POLICY.owner_max_bytes });
  } catch (error) { throw fail('macos_lock_preflight_owner_invalid', error); }
  let owner;
  try {
    owner = JSON.parse(decodeUtf8(ownerBytes));
    validateOwner(owner, { lockName: 'team-flow', purpose: LOCKS['team-flow'].purpose });
    if (canonicalOwnerText(owner) !== ownerBytes.toString('utf8')) throw new Error('noncanonical owner');
  } catch (error) { throw fail('macos_lock_preflight_owner_invalid', error); }
  if (owner.schema_version !== 'knowledge-lock-owner.v3' || owner.execution_scope === null) return null;
  if (owner.kernel_lease.owner_dev !== String(ownerBefore.dev) || owner.kernel_lease.owner_ino !== String(ownerBefore.ino) ||
      owner.kernel_lease.directory_dev !== String(beforeDirectory.dev) || owner.kernel_lease.directory_ino !== String(beforeDirectory.ino)) {
    throw fail('macos_lock_preflight_owner_binding_invalid');
  }
  let scope;
  try {
    const bytes = readStableFile(root, scopePath, { maxBytes: LOCK_POLICY.execution_scope_max_bytes });
    scope = JSON.parse(decodeUtf8(bytes));
    if (scope.backend !== 'macos_uid_guardian' || owner.execution_scope.backend !== scope.backend ||
        owner.execution_scope.sha256 !== sha(bytes) || JSON.stringify(scope, null, 2) + '\n' !== bytes.toString('utf8') ||
        !validateCommandScope(scope) || !tokenFree(scope)) throw new Error('scope binding invalid');
  } catch (error) { throw fail('macos_lock_preflight_scope_invalid', error); }
  // A successful observation of a replaced old scope must never be used as
  // authority for a new owner. The actual lock acquisition will independently
  // revalidate again after the asynchronous parent query.
  const ownerAfter = fs.lstatSync(ownerPath, { bigint: true }), directoryAfter = fs.lstatSync(directory, { bigint: true });
  const finalOwnerBytes = readStableFile(root, ownerPath, { maxBytes: LOCK_POLICY.owner_max_bytes });
  if (!same(ownerBefore, ownerAfter) || !same(beforeDirectory, directoryAfter) ||
      !ownerBytes.equals(finalOwnerBytes) || !directoryAfter.isDirectory() || directoryAfter.isSymbolicLink()) {
    throw fail('macos_lock_preflight_owner_changed');
  }
  assertSafeContainedPath(root, scopePath);
  return frozen(scope);
}
module.exports = { readTeamFlowScope };
