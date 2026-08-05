#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { inspectContextLockSafety, acquireContainedLock, lockPaths } = require('./lib/contained-lock-manager');
const { LOCKS } = require('./lib/lock-policy');
const { canonicalOwnerText } = require('./lib/lock-owner-schema');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC40_CONTEXT_LOCK_SELFTEST_SECRET';

function parseArgs(argv) {
  const args = { out: null };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--out') args.out = argv[++index] || null;
    else if (argv[index].startsWith('--out=')) args.out = argv[index].slice(6);
  }
  return args;
}

function request(context, rootKind, lockName, options = {}) {
  const rootPath = rootKind === 'state' ? context.stateRoot : (rootKind === 'project' ? context.projectKnowledgeRoot : context.systemRoot);
  return {
    context,
    rootKind,
    rootPath,
    lockName,
    purpose: LOCKS[lockName].purpose,
    timeoutMs: options.timeoutMs || 50,
    staleMs: options.staleMs || 10,
    ...(options.resourceId ? { resourceId: options.resourceId } : {}),
    ...(rootKind === 'system' ? { maintainer: true } : {})
  };
}

function owner(lockName, extra = {}) {
  const now = new Date().toISOString();
  return {
    schema_version: 'knowledge-lock-owner.v1',
    lock_id: '123e4567-e89b-42d3-a456-426614174000',
    lock_name: lockName,
    purpose: LOCKS[lockName].purpose,
    pid: process.pid,
    hostname: os.hostname(),
    agent_id: null,
    workspace_id: null,
    process_started_at: now,
    acquired_at: now,
    nonce: 'a'.repeat(64),
    ...extra
  };
}

function contextFor(base, options = {}) {
  const project = options.projectRoot || path.join(base, 'project', '.knowledge');
  const state = options.stateRoot || project;
  const system = options.systemRoot || path.join(base, 'system');
  fs.mkdirSync(project, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(system, { recursive: true });
  return {
    mode: options.mode || 'repo',
    targetRoot: path.join(base, 'project'),
    projectKnowledgeRoot: project,
    stateRoot: state,
    systemRoot: system,
    teamRoot: options.teamRoot || null,
    workspaceId: options.workspaceId || null,
    agentId: 'context-lock-self-test'
  };
}

function seed(context, rootKind, lockName, text, ageMs = 0, options = {}) {
  const paths = lockPaths(request(context, rootKind, lockName, options));
  fs.mkdirSync(paths.lockDir, { recursive: true });
  fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), text, 'utf8');
  if (ageMs) {
    const old = new Date(Date.now() - ageMs);
    fs.utimesSync(paths.lockDir, old, old);
  }
  return paths;
}

function rootFor(status, rootKind) {
  return status.roots.find((item) => (item.root_kinds || [item.root_kind]).includes(rootKind)) || null;
}

function runCase(results, id, expected, execute) {
  try {
    const actual = execute();
    results.push({ id, expected, actual, pass: actual.pass === true });
  } catch (error) {
    results.push({ id, expected, actual: { error_code: error.code || null, message: error.message }, pass: false });
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-context-lock-safety-'));
  const results = [];
  const fixture = (id, options = {}) => contextFor(path.join(temp, id), options);
  const inspect = (context) => inspectContextLockSafety(context);
  try {
    runCase(results, 'repo_no_locks_safe', { status: 'safe' }, () => {
      const status = inspect(fixture('one'));
      return { status: status.status, pass: status.status === 'safe' };
    });
    runCase(results, 'repo_active_apply_template', { status: 'active' }, () => {
      const context = fixture('two'); const handle = acquireContainedLock(request(context, 'project', 'apply-template'));
      try { const status = inspect(context); return { status: status.status, pass: status.status === 'active' }; } finally { handle.release(); }
    });
    runCase(results, 'repo_stale_apply_template', { status: 'stale' }, () => {
      const context = fixture('three'); seed(context, 'project', 'apply-template', canonicalOwnerText(owner('apply-template', { pid: 2147483647 })), 130000);
      const status = inspect(context); return { status: status.status, pass: status.status === 'stale' };
    });
    runCase(results, 'repo_project_owner_symlink_unsafe', { status: 'unsafe', code: 'unsafe_lock_owner' }, () => {
      const context = fixture('four'); const paths = lockPaths(request(context, 'project', 'apply-template')); const outside = path.join(temp, 'four-external'); fs.writeFileSync(outside, `${JSON.stringify({ ...owner('apply-template'), secret: SECRET })}\n`); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.symlinkSync(outside, path.join(paths.lockDir, 'owner.json'), 'file');
      const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.status === 'unsafe' && status.findings.some((item) => item.code === 'unsafe_lock_owner') };
    });
    runCase(results, 'repo_project_owner_hardlink_unsafe', { status: 'unsafe', code: 'lock_owner_hardlinked' }, () => {
      const context = fixture('five'); const paths = lockPaths(request(context, 'project', 'apply-template')); const outside = path.join(temp, 'five-external'); fs.writeFileSync(outside, canonicalOwnerText(owner('apply-template'))); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.linkSync(outside, path.join(paths.lockDir, 'owner.json'));
      const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.findings.some((item) => item.code === 'lock_owner_hardlinked') };
    });
    runCase(results, 'repo_project_owner_malformed_unsafe', { status: 'unsafe', code: 'lock_owner_invalid' }, () => {
      const context = fixture('six'); seed(context, 'project', 'apply-template', '{malformed'); const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.findings.some((item) => item.code === 'lock_owner_invalid') };
    });
    runCase(results, 'repo_project_owner_oversized_unsafe', { status: 'unsafe', code: 'lock_owner_oversized' }, () => {
      const context = fixture('seven'); seed(context, 'project', 'apply-template', 'x'.repeat(4097)); const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.findings.some((item) => item.code === 'lock_owner_oversized') };
    });
    runCase(results, 'repo_project_lock_directory_symlink_unsafe', { status: 'unsafe' }, () => {
      const context = fixture('eight'); const paths = lockPaths(request(context, 'project', 'apply-template')); const outside = path.join(temp, 'eight-outside'); fs.mkdirSync(outside); fs.mkdirSync(path.dirname(paths.lockDir), { recursive: true }); fs.symlinkSync(outside, paths.lockDir, 'junction'); const status = inspect(context); return { status: status.status, pass: status.status === 'unsafe' };
    });
    runCase(results, 'repo_project_lock_directory_junction_unsafe', { status: 'unsafe' }, () => {
      const context = fixture('nine'); const paths = lockPaths(request(context, 'project', 'git-hooks')); const outside = path.join(temp, 'nine-outside'); fs.mkdirSync(outside); fs.mkdirSync(path.dirname(paths.lockDir), { recursive: true }); fs.symlinkSync(outside, paths.lockDir, 'junction'); const status = inspect(context); return { status: status.status, pass: status.status === 'unsafe' };
    });
    runCase(results, 'state_unsafe_project_safe_aggregate_unsafe', { status: 'unsafe' }, () => {
      const context = fixture('ten', { stateRoot: path.join(temp, 'ten-state') }); seed(context, 'state', 'doctor', '{bad'); const status = inspect(context); return { status: status.status, pass: status.status === 'unsafe' && rootFor(status, 'project')?.status === 'safe' };
    });
    runCase(results, 'state_safe_project_unsafe_aggregate_unsafe', { status: 'unsafe' }, () => {
      const context = fixture('eleven', { stateRoot: path.join(temp, 'eleven-state') }); seed(context, 'project', 'ingest', '{bad'); const status = inspect(context); return { status: status.status, pass: status.status === 'unsafe' && rootFor(status, 'state')?.status === 'safe' };
    });
    runCase(results, 'state_active_project_active_aggregate_active', { status: 'active' }, () => {
      const context = fixture('twelve', { stateRoot: path.join(temp, 'twelve-state') }); const one = acquireContainedLock(request(context, 'state', 'doctor')); const two = acquireContainedLock(request(context, 'project', 'apply-template')); try { const status = inspect(context); return { status: status.status, pass: status.status === 'active' }; } finally { two.release(); one.release(); }
    });
    runCase(results, 'state_stale_project_safe_aggregate_stale', { status: 'stale' }, () => {
      const context = fixture('thirteen', { stateRoot: path.join(temp, 'thirteen-state') }); seed(context, 'state', 'doctor', canonicalOwnerText(owner('doctor', { pid: 2147483647 })), 130000); const status = inspect(context); return { status: status.status, pass: status.status === 'stale' };
    });
    runCase(results, 'state_active_project_stale_retains_project_state', { status: 'active', project: 'stale' }, () => {
      const context = fixture('fourteen', { stateRoot: path.join(temp, 'fourteen-state') }); const handle = acquireContainedLock(request(context, 'state', 'doctor')); seed(context, 'project', 'apply-template', canonicalOwnerText(owner('apply-template', { pid: 2147483647 })), 130000); try { const status = inspect(context); return { status: status.status, project_status: rootFor(status, 'project')?.status || null, pass: status.status === 'active' && rootFor(status, 'project')?.status === 'stale' }; } finally { handle.release(); }
    });
    runCase(results, 'identical_roots_no_duplicate_physical_inspection', { roots_checked: 1, duplicates_avoided: 1 }, () => {
      const context = fixture('fifteen'); const status = inspect(context); return { roots_checked: status.summary.roots_checked, duplicates_avoided: status.summary.duplicates_avoided, pass: status.summary.roots_checked === 1 && status.summary.duplicates_avoided === 1 };
    });
    runCase(results, 'identical_roots_project_definitions_retained', { definitions: ['apply-template', 'git-hooks', 'ingest'] }, () => {
      const context = fixture('sixteen'); const status = inspect(context); const definitions = status.roots[0]?.definitions || []; return { definitions, pass: ['apply-template', 'git-hooks', 'ingest'].every((name) => definitions.includes(name)) };
    });
    runCase(results, 'team_distinct_roots_both_checked', { roots_checked: 2 }, () => {
      const context = fixture('seventeen', { mode: 'team', stateRoot: path.join(temp, 'seventeen-state'), teamRoot: path.join(temp, 'seventeen-team'), workspaceId: 'one' }); fs.mkdirSync(context.teamRoot, { recursive: true }); const status = inspect(context); return { roots_checked: status.summary.roots_checked, pass: status.summary.roots_checked === 2 };
    });
    runCase(results, 'team_distinct_roots_separate_sections', { root_kinds: ['state', 'project'] }, () => {
      const context = fixture('eighteen', { mode: 'team', stateRoot: path.join(temp, 'eighteen-state'), teamRoot: path.join(temp, 'eighteen-team'), workspaceId: 'one' }); fs.mkdirSync(context.teamRoot, { recursive: true }); const status = inspect(context); return { root_kinds: status.roots.map((item) => item.root_kind), pass: Boolean(status.roots.length === 2 && rootFor(status, 'state') && rootFor(status, 'project')) };
    });
    runCase(results, 'task_routing_resource_lock_visible', { lock_name: 'task-routing' }, () => {
      const context = fixture('nineteen'); const resourceId = crypto.createHash('sha256').update('rc40-resource').digest('hex'); const handle = acquireContainedLock(request(context, 'state', 'task-routing', { resourceId })); try { const status = inspect(context); return { locks: status.locks.filter((item) => item.lock_name === 'task-routing'), pass: status.locks.some((item) => item.lock_name === 'task-routing' && item.resource_id === resourceId && item.status === 'active') }; } finally { handle.release(); }
    });
    runCase(results, 'dynamic_resource_unsafe_owner_is_unsafe', { status: 'unsafe', code: 'lock_owner_hardlinked' }, () => {
      const context = fixture('twenty'); const resourceId = crypto.createHash('sha256').update('rc40-unsafe-resource').digest('hex'); const paths = lockPaths(request(context, 'state', 'task-routing', { resourceId })); const outside = path.join(temp, 'twenty-owner'); fs.writeFileSync(outside, canonicalOwnerText(owner('task-routing'))); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.linkSync(outside, path.join(paths.lockDir, 'owner.json')); const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.status === 'unsafe' && status.findings.some((item) => item.code === 'lock_owner_hardlinked') };
    });
    runCase(results, 'system_only_omitted_installed_mode', { status: 'safe', system_root_absent: true }, () => {
      const context = fixture('twentyone'); const status = inspect(context); return { root_kinds: status.roots.flatMap((item) => item.root_kinds), pass: status.status === 'safe' && !status.roots.some((item) => item.root_kinds.includes('system')) };
    });
    runCase(results, 'secret_absent_from_stdout_representation', { secret_leaked: false }, () => {
      const context = fixture('twentytwo'); seed(context, 'project', 'apply-template', `${JSON.stringify(owner('apply-template', { secret: SECRET }))}\n`); const rendered = JSON.stringify(inspect(context)); return { secret_leaked: rendered.includes(SECRET), pass: !rendered.includes(SECRET) };
    });
    runCase(results, 'secret_absent_from_stderr_representation', { secret_leaked: false }, () => {
      const context = fixture('twentythree'); seed(context, 'project', 'apply-template', `${JSON.stringify(owner('apply-template', { secret: SECRET }))}\n`); let stderr = ''; const original = process.stderr.write; process.stderr.write = (chunk) => { stderr += String(chunk); return true; }; try { inspect(context); } finally { process.stderr.write = original; } return { secret_leaked: stderr.includes(SECRET), pass: !stderr.includes(SECRET) };
    });
    runCase(results, 'state_root_attack_regression', { status: 'unsafe', code: 'unsafe_lock_owner' }, () => {
      const context = fixture('twentyfour', { stateRoot: path.join(temp, 'twentyfour-state') }); const paths = lockPaths(request(context, 'state', 'doctor')); const outside = path.join(temp, 'twentyfour-owner'); fs.writeFileSync(outside, canonicalOwnerText(owner('doctor'))); fs.mkdirSync(paths.lockDir, { recursive: true }); fs.symlinkSync(outside, path.join(paths.lockDir, 'owner.json'), 'file'); const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.status === 'unsafe' && status.findings.some((item) => item.code === 'unsafe_lock_owner') };
    });
    runCase(results, 'unresolved_project_root_fails_without_ambient_guess', { status: 'unsafe', code: 'unsafe_lock_root' }, () => {
      const context = fixture('twentyfive'); context.projectKnowledgeRoot = ''; const status = inspect(context); return { status: status.status, codes: status.findings.map((item) => item.code), pass: status.status === 'unsafe' && status.findings.some((item) => item.code === 'unsafe_lock_root') };
    });
    const report = {
      schema_version: 'knowledge-context-lock-safety-self-test.v1',
      generated_at: new Date().toISOString(),
      platform: process.platform,
      node: process.version,
      checks_total: results.length,
      passed: results.filter((item) => item.pass).length,
      failed: results.filter((item) => !item.pass).length,
      status: results.every((item) => item.pass) ? 'pass' : 'fail',
      results
    };
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (args.out) { fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true }); fs.writeFileSync(path.resolve(args.out), text, 'utf8'); }
    process.stdout.write(text);
    if (report.failed) process.exitCode = 1;
  } finally {
    removeTempDirStrict(temp);
  }
}

if (require.main === module) main();
module.exports = { main };
