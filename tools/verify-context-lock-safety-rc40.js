#!/usr/bin/env node
'use strict';

// Physical black-box verifier for the RC40 context-lock inspection contract.
// It intentionally executes only the candidate's tools after extraction.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC40_CONTEXT_LOCK_SECRET_MUST_NOT_LEAK';
const EXPECTED_RC39_SHA = 'cae91f7a0de8e61eaf29c6c85ad21ecd664d5053a1b0badb29fb43e5e6200703';

function parseArgs(argv) {
  const args = { zip: null, out: null, workRoot: null, keep: false, expect: 'pass' };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--zip') args.zip = argv[++index] || null;
    else if (value.startsWith('--zip=')) args.zip = value.slice(6);
    else if (value === '--out') args.out = argv[++index] || null;
    else if (value.startsWith('--out=')) args.out = value.slice(6);
    else if (value === '--work-root') args.workRoot = argv[++index] || null;
    else if (value.startsWith('--work-root=')) args.workRoot = value.slice(12);
    else if (value === '--keep' || value === '--keep-fixtures') args.keep = true;
    else if (value === '--expect') args.expect = argv[++index] || args.expect;
    else if (value.startsWith('--expect=')) args.expect = value.slice(9);
  }
  if (!args.zip) throw new Error('--zip=<physical candidate ZIP> is required');
  if (!['pass', 'expected-failure'].includes(args.expect)) throw new Error('--expect must be pass or expected-failure');
  return args;
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function containedOutput(root, entryName) {
  const normalized = String(entryName || '').replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    throw new Error(`unsafe ZIP entry: ${entryName}`);
  }
  const output = path.resolve(root, ...normalized.split('/'));
  const base = path.resolve(root);
  if (output !== base && !output.startsWith(`${base}${path.sep}`)) throw new Error(`ZIP entry escapes extraction root: ${entryName}`);
  return output;
}

function extract(zipPath, root) {
  const artifact = validate(zipPath);
  if (artifact.status !== 'ok') throw new Error('candidate validation failed before context-lock verification');
  const zip = readZipEntries(zipPath);
  fs.mkdirSync(root, { recursive: true });
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const output = containedOutput(root, entry.name);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, entry.body);
  }
  return artifact;
}

function baseEnvironment(root, extra = {}) {
  const environment = { ...process.env };
  for (const key of [
    'KNOWLEDGE_MODE', 'KNOWLEDGE_SYSTEM_ROOT', 'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_TEAM_ROOT', 'KNOWLEDGE_WORKSPACE_ID', 'KNOWLEDGE_REPO_ID'
  ]) delete environment[key];
  return {
    ...environment,
    KNOWLEDGE_SYSTEM_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_TARGET_ROOT: root,
    KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_STATE_ROOT: path.join(root, '.knowledge'),
    KNOWLEDGE_AGENT_ID: 'rc40-context-lock-verifier',
    KNOWLEDGE_LOCK_TIMEOUT_MS: '50',
    ...extra
  };
}

function runInstallCheck(root, environment = {}) {
  const result = spawnSync(process.execPath, [path.join(root, '.knowledge', 'tools', 'install-check.js'), '--json'], {
    cwd: root,
    env: baseEnvironment(root, environment),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 60000
  });
  return {
    exit_code: result.status,
    signal: result.signal || null,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    spawn_error: result.error ? { code: result.error.code || null, message: result.error.message } : null
  };
}

function parseJson(text) {
  try { return JSON.parse(String(text || '').trim()); } catch { return null; }
}

function fixture(workRoot, id, zipPath) {
  const root = path.join(workRoot, id, 'repo');
  extract(zipPath, root);
  return root;
}

function candidateModules(root) {
  const tools = path.join(root, '.knowledge', 'tools');
  return {
    manager: require(path.join(tools, 'lib', 'contained-lock-manager.js')),
    policy: require(path.join(tools, 'lib', 'lock-policy.js')),
    owner: require(path.join(tools, 'lib', 'lock-owner-schema.js')),
    context: require(path.join(tools, 'lib', 'path-context.js'))
  };
}

function resolvedContext(root, overrides = {}) {
  const modules = candidateModules(root);
  const knowledge = path.join(root, '.knowledge');
  const context = modules.context.resolveKnowledgeContext({
    __skipCli: true,
    systemRoot: knowledge,
    targetRoot: root,
    projectKnowledgeRoot: knowledge,
    stateRoot: knowledge,
    agentId: 'rc40-context-lock-verifier',
    ...overrides
  });
  return { ...modules, context };
}

function requestFor(modules, context, rootKind, lockName, rootPath = null) {
  const key = rootKind === 'state' ? 'stateRoot' : (rootKind === 'project' ? 'projectKnowledgeRoot' : 'systemRoot');
  return {
    context,
    rootKind,
    rootPath: rootPath || context[key],
    lockName,
    purpose: modules.policy.LOCKS[lockName].purpose,
    timeoutMs: 50,
    staleMs: 10
  };
}

function activeProjectCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'active-project-lock', zipPath);
  const modules = resolvedContext(root);
  const handle = modules.manager.acquireContainedLock(requestFor(modules, modules.context, 'project', 'apply-template'));
  try {
    const check = runInstallCheck(root);
    const output = parseJson(check.stdout);
    const lock = output?.lock_safety || null;
    const projectVisible = Array.isArray(lock?.roots) && lock.roots.some((item) =>
      (item.root_kind === 'project' || (item.root_kinds || []).includes('project')));
    return {
      id: 'active_project_lock_visibility',
      expected: { exit_code: 0, lock_status: 'active', project_visible: true },
      actual: { exit_code: check.exit_code, lock_status: lock?.status || null, project_visible: projectVisible },
      observation: check,
      pass: check.exit_code === 0 && lock?.status === 'active' && projectVisible
    };
  } finally {
    handle.release();
  }
}

function unsafeProjectOwnerCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'unsafe-project-owner', zipPath);
  const modules = resolvedContext(root);
  const request = requestFor(modules, modules.context, 'project', 'apply-template');
  const paths = modules.manager.lockPaths(request);
  const external = path.join(workRoot, 'unsafe-project-owner-external.json');
  const owner = {
    schema_version: 'knowledge-lock-owner.v1',
    lock_id: '123e4567-e89b-42d3-a456-426614174000',
    lock_name: 'apply-template',
    purpose: modules.policy.LOCKS['apply-template'].purpose,
    pid: process.pid,
    hostname: os.hostname(),
    agent_id: null,
    workspace_id: null,
    process_started_at: new Date().toISOString(),
    acquired_at: new Date().toISOString(),
    nonce: 'a'.repeat(64),
    secret: SECRET
  };
  fs.mkdirSync(paths.lockDir, { recursive: true });
  fs.writeFileSync(external, `${JSON.stringify(owner)}\n`, 'utf8');
  let attack = 'symlink';
  try {
    fs.symlinkSync(external, path.join(paths.lockDir, 'owner.json'), 'file');
  } catch (error) {
    attack = 'hardlink';
    fs.linkSync(external, path.join(paths.lockDir, 'owner.json'));
  }
  const direct = modules.manager.inspectLockSafety(request);
  const check = runInstallCheck(root);
  const output = parseJson(check.stdout);
  const combined = `${check.stdout}\n${check.stderr}`;
  const findingCodes = output?.lock_safety?.findings?.map((item) => item.code) || [];
  const expectedCode = attack === 'symlink' ? 'unsafe_lock_owner' : 'lock_owner_hardlinked';
  return {
    id: 'unsafe_project_owner_visibility',
    expected: { direct_status: 'unsafe', exit_nonzero: true, lock_status: 'unsafe', finding_code: expectedCode, secret_leaked: false },
    actual: {
      direct_status: direct.status,
      exit_code: check.exit_code,
      lock_status: output?.lock_safety?.status || null,
      finding_codes: findingCodes,
      secret_leaked: combined.includes(SECRET),
      attack
    },
    observation: check,
    pass: direct.status === 'unsafe' && check.exit_code !== 0 && output?.lock_safety?.status === 'unsafe' && findingCodes.includes(expectedCode) && !combined.includes(SECRET)
  };
}

function sameRootCoverageCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'same-root-project-definitions', zipPath);
  const modules = resolvedContext(root);
  const handle = modules.manager.acquireContainedLock(requestFor(modules, modules.context, 'project', 'git-hooks'));
  try {
    const check = runInstallCheck(root);
    const output = parseJson(check.stdout);
    const roots = output?.lock_safety?.roots || [];
    const sameRoot = roots.find((item) => (item.root_kinds || []).includes('state') && (item.root_kinds || []).includes('project'));
    const projectDefinition = sameRoot?.locks?.some((item) => item.lock_name === 'git-hooks') || false;
    return {
      id: 'identical_root_project_definition_coverage',
      expected: { lock_status: 'active', merged_root: true, project_definition: 'git-hooks' },
      actual: { lock_status: output?.lock_safety?.status || null, merged_root: Boolean(sameRoot), project_definition_visible: projectDefinition },
      observation: check,
      pass: check.exit_code === 0 && output?.lock_safety?.status === 'active' && Boolean(sameRoot) && projectDefinition
    };
  } finally {
    handle.release();
  }
}

function distinctTeamRootsCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'team-distinct-roots', zipPath);
  const stateRoot = path.join(workRoot, 'team-distinct-state');
  const teamRoot = path.join(workRoot, 'team-root');
  fs.mkdirSync(stateRoot, { recursive: true });
  fs.mkdirSync(teamRoot, { recursive: true });
  const modules = resolvedContext(root, { mode: 'team', teamRoot, workspaceId: 'rc40', stateRoot });
  const project = modules.manager.acquireContainedLock(requestFor(modules, modules.context, 'project', 'ingest'));
  const state = modules.manager.acquireContainedLock(requestFor(modules, modules.context, 'state', 'doctor'));
  try {
    const check = runInstallCheck(root, {
      KNOWLEDGE_MODE: 'team',
      KNOWLEDGE_TEAM_ROOT: teamRoot,
      KNOWLEDGE_WORKSPACE_ID: 'rc40',
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
      KNOWLEDGE_STATE_ROOT: stateRoot
    });
    const output = parseJson(check.stdout);
    const rootKinds = (output?.lock_safety?.roots || []).map((item) => item.root_kind || (item.root_kinds || []).join('+'));
    const visibleProject = (output?.lock_safety?.roots || []).some((item) => (item.root_kinds || [item.root_kind]).includes('project') && item.locks?.some((lock) => lock.lock_name === 'ingest'));
    const visibleState = (output?.lock_safety?.roots || []).some((item) => (item.root_kinds || [item.root_kind]).includes('state') && item.locks?.some((lock) => lock.lock_name === 'doctor'));
    return {
      id: 'team_mode_distinct_roots_coverage',
      expected: { lock_status: 'active', root_sections: ['state', 'project'], project_definition: 'ingest', state_definition: 'doctor' },
      actual: { lock_status: output?.lock_safety?.status || null, root_sections: rootKinds, project_definition_visible: visibleProject, state_definition_visible: visibleState },
      observation: check,
      pass: check.exit_code === 0 && output?.lock_safety?.status === 'active' && visibleProject && visibleState && rootKinds.length === 2
    };
  } finally {
    state.release();
    project.release();
  }
}

function sanitizedResult(result, expect) {
  const desired = result.pass === true;
  const expectationMet = expect === 'pass' ? desired : !desired;
  return {
    id: result.id,
    expected: result.expected,
    actual: result.actual,
    expectation_met: expectationMet,
    ...(expect === 'pass' ? { pass: desired } : {}),
    observation: result.observation
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const zipPath = path.resolve(args.zip);
  if (!fs.existsSync(zipPath)) throw new Error(`candidate ZIP not found: ${zipPath}`);
  const workRoot = args.workRoot ? path.resolve(args.workRoot) : fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-context-lock-rc40-'));
  if (args.workRoot) {
    if (fs.existsSync(workRoot)) throw new Error(`refusing existing --work-root: ${workRoot}`);
    fs.mkdirSync(workRoot, { recursive: true });
  }
  try {
    const cases = [activeProjectCase, unsafeProjectOwnerCase, sameRootCoverageCase, distinctTeamRootsCase];
    const raw = [];
    for (const execute of cases) {
      try { raw.push(execute(workRoot, zipPath)); }
      catch (error) {
        raw.push({ id: execute.name, expected: {}, actual: { error_code: error.code || null, message: error.message }, observation: { stdout: '', stderr: error.stack || error.message }, pass: false });
      }
    }
    const results = raw.map((item) => sanitizedResult(item, args.expect));
    const expectationMet = results.every((item) => item.expectation_met);
    const report = {
      schema_version: 'knowledge-context-lock-safety-verification.v1',
      generated_at: new Date().toISOString(),
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      candidate: { path: zipPath, sha256: sha256(zipPath), is_rc39_baseline: sha256(zipPath) === EXPECTED_RC39_SHA },
      status: args.expect === 'expected-failure' ? (expectationMet ? 'expected_failure' : 'fail') : (expectationMet ? 'pass' : 'fail'),
      expectation_met: expectationMet,
      checks_total: results.length,
      passed: results.filter((item) => item.expectation_met).length,
      failed: results.filter((item) => !item.expectation_met).length,
      results,
      fixtures_preserved: Boolean(args.keep || args.workRoot),
      work_root: workRoot
    };
    const text = `${JSON.stringify(report, null, 2)}\n`;
    if (args.out) {
      fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
      fs.writeFileSync(path.resolve(args.out), text, 'utf8');
    }
    process.stdout.write(text);
    if (!expectationMet) process.exitCode = 1;
  } finally {
    if (!args.keep && !args.workRoot) removeTempDirStrict(workRoot);
  }
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main };
