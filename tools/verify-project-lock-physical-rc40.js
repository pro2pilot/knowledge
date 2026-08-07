#!/usr/bin/env node
'use strict';

// Candidate-only physical matrix for the RC40 project-root inspection change.
// Each case extracts the ZIP afresh and invokes its public install-check child.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC40_PROJECT_LOCK_PHYSICAL_SECRET_MUST_NOT_LEAK';

function parseArgs(argv) {
  const args = { zip: null, out: null, workRoot: null, keep: false };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--zip') args.zip = argv[++index] || null;
    else if (value.startsWith('--zip=')) args.zip = value.slice(6);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice(6);
    else if (value === '--work-root') args.workRoot = argv[++index] || null;
    else if (value.startsWith('--work-root=')) args.workRoot = value.slice(12);
    else if (value === '--keep' || value === '--keep-fixtures') args.keep = true;
  }
  if (!args.zip) throw new Error('--zip=<candidate ZIP> is required');
  return args;
}

function sha256(filePath) { return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex'); }
function cleanName(value) { return String(value).replace(/\\/g, '/'); }
function containedOutput(root, name) {
  const normalized = cleanName(name);
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) throw new Error(`unsafe ZIP entry: ${name}`);
  const output = path.resolve(root, ...normalized.split('/'));
  if (output !== root && !output.startsWith(`${root}${path.sep}`)) throw new Error(`ZIP entry escapes root: ${name}`);
  return output;
}
function extract(zipPath, root) {
  const artifact = validate(zipPath);
  if (artifact.status !== 'ok') throw new Error('candidate validation failed before physical project-lock matrix');
  for (const entry of readZipEntries(zipPath).entries) {
    if (entry.name.endsWith('/')) continue;
    const output = containedOutput(root, entry.name);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, entry.body);
  }
}
function publicEnvironment(root, extra = {}) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) if (/^KNOWLEDGE_(?:MODE|SYSTEM_ROOT|TARGET_ROOT|PROJECT_KNOWLEDGE_ROOT|STATE_ROOT|TEAM_ROOT|WORKSPACE_ID|REPO_ID)$/i.test(key)) delete environment[key];
  return {
    ...environment,
    KNOWLEDGE_MODE: 'repo',
    KNOWLEDGE_SYSTEM_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_AGENT_ID: 'rc40-project-lock-physical',
    KNOWLEDGE_LOCK_TIMEOUT_MS: '60',
    ...extra
  };
}
function runInstallCheck(root, extra = {}) {
  const child = spawnSync(process.execPath, [path.join(root, '.knowledge', 'tools', 'install-check.js'), '--json'], {
    cwd: root, env: publicEnvironment(root, extra), encoding: 'utf8', windowsHide: true, timeout: 60000
  });
  let output = null;
  try { output = JSON.parse(String(child.stdout || '').trim()); } catch (_) { /* surfaced below */ }
  return { exit_code: child.status, stdout: child.stdout || '', stderr: child.stderr || '', output, spawn_error: child.error ? { code: child.error.code || null, message: child.error.message } : null };
}
function modules(root) {
  const tools = path.join(root, '.knowledge', 'tools');
  return {
    manager: require(path.join(tools, 'lib', 'contained-lock-manager.js')),
    policy: require(path.join(tools, 'lib', 'lock-policy.js')),
    owner: require(path.join(tools, 'lib', 'lock-owner-schema.js')),
    context: require(path.join(tools, 'lib', 'path-context.js'))
  };
}
function contextFor(root, lib, overrides = {}) {
  const knowledge = path.join(root, '.knowledge');
  return lib.context.resolveKnowledgeContext({ __skipCli: true, systemRoot: knowledge, targetRoot: root, projectKnowledgeRoot: knowledge, stateRoot: knowledge, agentId: 'rc40-project-lock-physical', ...overrides });
}
function request(lib, context, rootKind, lockName, options = {}) {
  const rootPath = options.rootPath || (rootKind === 'project' ? context.projectKnowledgeRoot : context.stateRoot);
  return { context, rootKind, rootPath, lockName, purpose: lib.policy.LOCKS[lockName].purpose, timeoutMs: 60, staleMs: 10, ...(options.resourceId ? { resourceId: options.resourceId } : {}) };
}
function owner(lib, lockName, extra = {}) {
  const now = new Date().toISOString();
  return lib.owner.canonicalOwnerText({ schema_version: 'knowledge-lock-owner.v1', lock_id: '123e4567-e89b-42d3-a456-426614174000', lock_name: lockName, purpose: lib.policy.LOCKS[lockName].purpose, pid: process.pid, hostname: os.hostname(), agent_id: null, workspace_id: null, process_started_at: now, acquired_at: now, nonce: 'a'.repeat(64), ...extra });
}
function stale(target) { const old = new Date(Date.now() - 172800000); fs.utimesSync(target, old, old); }
function codes(check) { return check.output?.lock_safety?.findings?.map((item) => item.code) || []; }
function rootSections(check) { return check.output?.lock_safety?.roots || []; }
function result(id, expected, actual, observation, pass) { return { id, expected, actual, observation, pass: Boolean(pass) }; }

function main() {
  const args = parseArgs(process.argv.slice(2));
  const zip = path.resolve(args.zip);
  if (!fs.existsSync(zip)) throw new Error(`candidate ZIP not found: ${zip}`);
  const work = args.workRoot ? path.resolve(args.workRoot) : fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-project-lock-rc40-'));
  if (args.workRoot) { if (fs.existsSync(work)) throw new Error(`refusing existing --work-root: ${work}`); fs.mkdirSync(work, { recursive: true }); }
  const results = [];
  let fixtureNo = 0;
  function fresh(id) {
    const root = path.join(work, `${String(++fixtureNo).padStart(2, '0')}-${id}`, 'repo');
    extract(zip, root);
    const lib = modules(root);
    return { root, lib, context: contextFor(root, lib) };
  }
  function seedUnsafe(fixture, setup, expectedCode, id) {
    const req = request(fixture.lib, fixture.context, 'project', 'apply-template');
    const paths = fixture.lib.manager.lockPaths(req);
    const sentinel = path.join(work, `${id}-sentinel.txt`);
    fs.writeFileSync(sentinel, SECRET, 'utf8');
    const before = sha256(sentinel);
    setup(paths, req, sentinel);
    const check = runInstallCheck(fixture.root);
    const text = `${check.stdout}\n${check.stderr}`;
    return { check, sentinel_unchanged: before === sha256(sentinel), secret_leaked: text.includes(SECRET), code_present: codes(check).includes(expectedCode), pass: check.exit_code !== 0 && check.output?.lock_safety?.status === 'unsafe' && codes(check).includes(expectedCode) && before === sha256(sentinel) && !text.includes(SECRET) };
  }
  function activeProject(id) {
    const fixture = fresh(id); const req = request(fixture.lib, fixture.context, 'project', 'apply-template'); const handle = fixture.lib.manager.acquireContainedLock(req);
    try { const check = runInstallCheck(fixture.root); return result(id, { exit_code: 0, status: 'active' }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'active'); } finally { handle.release(); }
  }
  function staleProject(id) {
    const fixture = fresh(id); const req = request(fixture.lib, fixture.context, 'project', 'apply-template'); const paths = fixture.lib.manager.lockPaths(req); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), owner(fixture.lib, 'apply-template', { pid: 2147483647 }), 'utf8'); stale(paths.lockDir); const check = runInstallCheck(fixture.root); return result(id, { exit_code: 0, status: 'stale' }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'stale');
  }
  function unsafeOwner(id, attack) {
    const fixture = fresh(id); const expectedCode = attack === 'hardlink' ? 'lock_owner_hardlinked' : 'unsafe_lock_owner';
    const detail = seedUnsafe(fixture, (paths) => { fs.mkdirSync(paths.lockDir, { recursive: true }); const external = path.join(work, `${id}-external-owner.json`); const payload = { ...JSON.parse(owner(fixture.lib, 'apply-template')), secret: SECRET }; fs.writeFileSync(external, `${JSON.stringify(payload)}\n`, 'utf8'); if (attack === 'hardlink') fs.linkSync(external, path.join(paths.lockDir, 'owner.json')); else fs.symlinkSync(external, path.join(paths.lockDir, 'owner.json'), 'file'); }, expectedCode, id);
    return result(id, { status: 'unsafe', code: expectedCode, secret_leaked: false }, { exit_code: detail.check.exit_code, status: detail.check.output?.lock_safety?.status || null, code_present: detail.code_present, sentinel_unchanged: detail.sentinel_unchanged, secret_leaked: detail.secret_leaked }, detail.check, detail.pass);
  }
  function lockLink(id, nested) {
    const fixture = fresh(id); const detail = seedUnsafe(fixture, (paths) => { const external = path.join(work, `${id}-external-lock`); fs.mkdirSync(external, { recursive: true }); const payload = { ...JSON.parse(owner(fixture.lib, 'apply-template')), secret: SECRET }; fs.writeFileSync(path.join(external, 'owner.json'), `${JSON.stringify(payload)}\n`, 'utf8'); const target = nested ? paths.layoutRoot : paths.lockDir; fs.mkdirSync(path.dirname(target), { recursive: true }); fs.symlinkSync(external, target, process.platform === 'win32' ? 'junction' : 'dir'); }, nested ? 'unsafe_lock_parent' : 'unsafe_lock_path', id);
    return result(id, { status: 'unsafe', code: nested ? 'unsafe_lock_parent' : 'unsafe_lock_path', secret_leaked: false }, { exit_code: detail.check.exit_code, status: detail.check.output?.lock_safety?.status || null, code_present: detail.code_present, sentinel_unchanged: detail.sentinel_unchanged, secret_leaked: detail.secret_leaked }, detail.check, detail.pass);
  }
  function malformed(id, text, expectedCode) {
    const fixture = fresh(id); const detail = seedUnsafe(fixture, (paths) => { fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), text, 'utf8'); }, expectedCode, id);
    return result(id, { status: 'unsafe', code: expectedCode, secret_leaked: false }, { exit_code: detail.check.exit_code, status: detail.check.output?.lock_safety?.status || null, code_present: detail.code_present, sentinel_unchanged: detail.sentinel_unchanged, secret_leaked: detail.secret_leaked }, detail.check, detail.pass);
  }
  function sameRoot(id, caseVariant = false) {
    const fixture = fresh(id); const rootPath = fixture.context.projectKnowledgeRoot; const extra = caseVariant && process.platform === 'win32' ? { KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: rootPath.toUpperCase(), KNOWLEDGE_STATE_ROOT: rootPath.toLowerCase() } : {}; const check = runInstallCheck(fixture.root, extra); const summary = check.output?.lock_safety?.summary || {}; const roots = rootSections(check); const hasProjectOnly = roots[0]?.locks?.some((lock) => lock.lock_name === 'apply-template') || false;
    return result(id, { status: 'safe', roots_checked: 1, project_definition: true }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null, roots_checked: summary.roots_checked || null, duplicates_avoided: summary.duplicates_avoided || null, project_definition: hasProjectOnly }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'safe' && summary.roots_checked === 1 && hasProjectOnly);
  }
  function distinctTeam(id) {
    const fixture = fresh(id); const state = path.join(work, `${id}-state`); const team = path.join(work, `${id}-team`); fs.mkdirSync(state, { recursive: true }); fs.mkdirSync(team, { recursive: true }); const projectContext = contextFor(fixture.root, fixture.lib, { mode: 'team', teamRoot: team, workspaceId: 'physical', stateRoot: state }); const handle = fixture.lib.manager.acquireContainedLock(request(fixture.lib, projectContext, 'project', 'ingest'));
    try { const check = runInstallCheck(fixture.root, { KNOWLEDGE_MODE: 'team', KNOWLEDGE_TEAM_ROOT: team, KNOWLEDGE_WORKSPACE_ID: 'physical', KNOWLEDGE_STATE_ROOT: state }); const roots = rootSections(check); const kinds = roots.flatMap((item) => item.root_kinds || [item.root_kind]); return result(id, { exit_code: 0, status: 'active', root_kinds: ['state', 'project'] }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null, root_kinds: kinds }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'active' && kinds.includes('state') && kinds.includes('project') && roots.length === 2); } finally { handle.release(); }
  }
  function dynamicResource(id) {
    const fixture = fresh(id); const req = request(fixture.lib, fixture.context, 'state', 'task-routing', { resourceId: 'e'.repeat(64) }); const handle = fixture.lib.manager.acquireContainedLock(req);
    try { const check = runInstallCheck(fixture.root); const visible = rootSections(check).some((section) => section.locks?.some((lock) => lock.lock_name === 'task-routing' && lock.resource_id)); return result(id, { exit_code: 0, status: 'active', resource_visible: true }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null, resource_visible: visible }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'active' && visible); } finally { handle.release(); }
  }
  function concurrentInspection(id) {
    const fixture = fresh(id); const req = request(fixture.lib, fixture.context, 'project', 'git-hooks'); const handle = fixture.lib.manager.acquireContainedLock(req);
    try { const check = runInstallCheck(fixture.root); return result(id, { exit_code: 0, status: 'active', lock_survives: true }, { exit_code: check.exit_code, status: check.output?.lock_safety?.status || null, lock_survives: fs.existsSync(handle.path) }, check, check.exit_code === 0 && check.output?.lock_safety?.status === 'active' && fs.existsSync(handle.path)); } finally { handle.release(); }
  }
  try {
    if (process.platform === 'win32') {
      results.push(activeProject('win01_active_project_lock'));
      results.push(staleProject('win02_stale_project_lock'));
      results.push(unsafeOwner('win03_owner_file_symlink', 'symlink'));
      results.push(unsafeOwner('win04_owner_file_hardlink', 'hardlink'));
      results.push(lockLink('win05_lock_directory_junction', false));
      results.push(lockLink('win06_nested_parent_junction', true));
      results.push(unsafeOwner('win07_reparse_owner_equivalent', 'symlink'));
      results.push(distinctTeam('win08_distinct_external_team_state'));
      results.push(sameRoot('win09_identical_state_project_root'));
      results.push(sameRoot('win10_case_normalized_duplicate_paths', true));
      results.push(concurrentInspection('win11_concurrent_inspection'));
      results.push(malformed('win12_secret_not_emitted', `${JSON.stringify({ secret: SECRET })}\n`, 'lock_owner_invalid'));
    } else {
      results.push(unsafeOwner('linux01_owner_symlink', 'symlink'));
      results.push(unsafeOwner('linux02_owner_hardlink', 'hardlink'));
      results.push(lockLink('linux03_lock_directory_symlink', false));
      results.push(lockLink('linux04_nested_parent_symlink', true));
      results.push(activeProject('linux05_active_project_lock'));
      results.push(staleProject('linux06_stale_project_lock'));
      results.push(distinctTeam('linux07_distinct_state_project_roots'));
      results.push(sameRoot('linux08_same_physical_root'));
      results.push(malformed('linux09_malformed_owner', '{malformed', 'lock_owner_invalid'));
      results.push(malformed('linux10_oversized_owner', 'x'.repeat(4097), 'lock_owner_oversized'));
      results.push(malformed('linux11_secret_unknown_owner_field', `${JSON.stringify({ secret: SECRET })}\n`, 'lock_owner_invalid'));
      results.push(dynamicResource('linux12_dynamic_resource_lock'));
      results.push(concurrentInspection('linux13_concurrent_state_change'));
      results.push(sameRoot('linux14_no_duplicate_findings'));
      results.push(lockLink('linux15_no_external_read_write', false));
    }
    const report = { schema_version: 'knowledge-project-lock-physical-rc40.v1', generated_at: new Date().toISOString(), platform: process.platform, arch: process.arch, node: process.version, candidate: { path: zip, sha256: sha256(zip) }, checks_total: results.length, passed: results.filter((item) => item.pass).length, failed: results.filter((item) => !item.pass).length, status: results.every((item) => item.pass) ? 'pass' : 'fail', results, fixtures_preserved: Boolean(args.workRoot || args.keep), work_root: work };
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
    process.stdout.write(text);
    if (report.failed) process.exitCode = 1;
  } finally {
    if (!args.workRoot && !args.keep) removeTempDirStrict(work);
  }
}

if (require.main === module) { try { main(); } catch (error) { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; } }
module.exports = { main };
