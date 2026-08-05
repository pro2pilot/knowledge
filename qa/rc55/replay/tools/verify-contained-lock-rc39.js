#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC39_EXTERNAL_SECRET_MUST_NOT_LEAK';
const HARDLINK_SECRET = 'RC39_HARDLINK_CONTENT_MUST_NOT_IMPORT';

function parseArgs(argv) {
  const out = { zip: null, out: null, workRoot: null, keep: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--zip') out.zip = argv[++index] || null;
    else if (arg.startsWith('--zip=')) out.zip = arg.slice(6);
    else if (arg === '--out') out.out = argv[++index] || null;
    else if (arg.startsWith('--out=')) out.out = arg.slice(6);
    else if (arg === '--work-root') out.workRoot = argv[++index] || null;
    else if (arg.startsWith('--work-root=')) out.workRoot = arg.slice(12);
    else if (arg === '--keep' || arg === '--keep-fixtures') out.keep = true;
  }
  if (!out.zip) throw new Error('--zip=<physical candidate ZIP> is required');
  return out;
}

function containedOutput(root, entryName) {
  const normalized = String(entryName || '').replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('/') || normalized.split('/').includes('..')) {
    throw new Error(`Unsafe ZIP entry: ${entryName}`);
  }
  const target = path.resolve(root, ...normalized.split('/'));
  const base = path.resolve(root);
  if (target !== base && !target.startsWith(`${base}${path.sep}`)) {
    throw new Error(`ZIP entry escapes extraction root: ${entryName}`);
  }
  return target;
}

function extract(zipPath, root) {
  const validation = validate(zipPath);
  if (validation.status !== 'ok') throw new Error('Candidate validation failed before RC39 verification');
  const zip = readZipEntries(zipPath);
  fs.mkdirSync(root, { recursive: true });
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) continue;
    const target = containedOutput(root, entry.name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, entry.body);
  }
  return validation;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function run(root, relativeScript, args = [], env = {}) {
  const script = path.join(root, '.knowledge', 'tools', relativeScript);
  const isolatedEnv = { ...process.env };
  for (const key of [
    'KNOWLEDGE_SYSTEM_ROOT', 'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT', 'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_TEAM_ROOT', 'KNOWLEDGE_WORKSPACE_ID', 'KNOWLEDGE_REPO_ID'
  ]) delete isolatedEnv[key];
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    env: {
      ...isolatedEnv,
      KNOWLEDGE_SYSTEM_ROOT: path.join(root, '.knowledge'),
      KNOWLEDGE_TARGET_ROOT: root,
      KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: path.join(root, '.knowledge'),
      KNOWLEDGE_STATE_ROOT: path.join(root, '.knowledge'),
      KNOWLEDGE_AGENT_ID: 'rc39-contained-lock-verifier',
      KNOWLEDGE_LOCK_TIMEOUT_MS: '60',
      ...env,
    },
  });
  return {
    exit_code: result.status,
    signal: result.signal || null,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    spawn_error: result.error ? { code: result.error.code || null, message: result.error.message } : null,
  };
}

function parseJson(text) {
  try { return JSON.parse(String(text || '').trim()); } catch { return null; }
}

function combined(result) {
  return `${result.stdout || ''}\n${result.stderr || ''}`;
}

function fixture(workRoot, id, zipPath) {
  const root = path.join(workRoot, id, 'repo');
  extract(zipPath, root);
  return root;
}

function activeLegacyOwner(secret = SECRET) {
  return {
    lock_id: 'external-lock-id',
    hostname: 'external-host',
    pid: 2147483000,
    agent_id: 'external-agent',
    started_at: '2099-01-01T00:00:00.000Z',
    secret,
  };
}

function lockDirectoryRedirectCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'lock-directory-redirect', zipPath);
  const external = path.join(workRoot, 'lock-directory-redirect', 'external-lock');
  fs.mkdirSync(external, { recursive: true });
  fs.writeFileSync(path.join(external, 'owner.json'), `${JSON.stringify(activeLegacyOwner(), null, 2)}\n`);
  const lockPath = path.join(root, '.knowledge', '.lock');
  fs.symlinkSync(external, lockPath, process.platform === 'win32' ? 'junction' : 'dir');
  const before = run(root, 'install-check.js', ['--json']);
  const installer = run(root, 'install-agent-integrations.js', ['--runtime', 'windsurf', '--no-install-check']);
  const after = run(root, 'install-check.js', ['--json']);
  const beforeJson = parseJson(before.stdout);
  const afterJson = parseJson(after.stdout);
  const leaked = combined(installer).includes(SECRET) || combined(before).includes(SECRET) || combined(after).includes(SECRET);
  const findings = [
    ...(beforeJson?.lock_safety?.findings || []),
    ...(afterJson?.lock_safety?.findings || []),
    ...(beforeJson?.issues || []),
    ...(afterJson?.issues || []),
  ];
  const detected = findings.some((item) => ['unsafe_lock_path', 'unsafe_lock_parent', 'lock_path_outside_state_root'].includes(item.code));
  return {
    id: 'lock_directory_redirect',
    pass: installer.exit_code !== 0 && detected && !leaked,
    external_read_detected: leaked,
    external_write_detected: !fs.existsSync(path.join(external, 'owner.json')),
    secret_leaked: leaked,
    install_check_detected: detected,
    install_check_before: before,
    installer,
    install_check_after: after,
  };
}

function doctorSharedPrimitiveCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'doctor-shared-primitive', zipPath);
  const external = path.join(workRoot, 'doctor-shared-primitive', 'external-lock');
  fs.mkdirSync(external, { recursive: true });
  fs.writeFileSync(path.join(external, 'owner.json'), `${JSON.stringify(activeLegacyOwner(), null, 2)}\n`);
  fs.symlinkSync(external, path.join(root, '.knowledge', '.lock'), process.platform === 'win32' ? 'junction' : 'dir');
  const doctor = run(root, 'doctor.js', ['--json']);
  const leaked = combined(doctor).includes(SECRET);
  return {
    id: 'doctor_shared_primitive',
    pass: doctor.exit_code !== 0 && !leaked,
    external_read_detected: leaked,
    secret_leaked: leaked,
    doctor,
  };
}

function ownerSymlinkCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'owner-symlink', zipPath);
  const base = path.join(workRoot, 'owner-symlink');
  const external = path.join(base, 'external-owner.json');
  const lockPath = path.join(root, '.knowledge', '.lock');
  fs.mkdirSync(lockPath, { recursive: true });
  fs.writeFileSync(external, `${JSON.stringify(activeLegacyOwner(), null, 2)}\n`);
  try {
    fs.symlinkSync(external, path.join(lockPath, 'owner.json'), 'file');
  } catch (error) {
    return {
      id: 'owner_symlink',
      pass: false,
      supported: false,
      limitation: { code: error.code || null, message: error.message },
    };
  }
  const installer = run(root, 'install-agent-integrations.js', ['--runtime', 'windsurf', '--no-install-check']);
  const check = run(root, 'install-check.js', ['--json']);
  const parsed = parseJson(check.stdout);
  const leaked = combined(installer).includes(SECRET) || combined(check).includes(SECRET);
  const findings = [...(parsed?.lock_safety?.findings || []), ...(parsed?.issues || [])];
  const detected = findings.some((item) => ['unsafe_lock_owner', 'lock_owner_invalid'].includes(item.code));
  return {
    id: 'owner_symlink',
    pass: installer.exit_code !== 0 && detected && !leaked,
    supported: true,
    external_read_detected: leaked,
    secret_leaked: leaked,
    install_check_detected: detected,
    installer,
    install_check: check,
  };
}

function malformedPackageCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'malformed-package', zipPath);
  const packagePath = path.join(root, 'package.json');
  fs.writeFileSync(packagePath, '{ malformed package');
  const targets = [
    'AGENTS.md', 'CLAUDE.md', 'GEMINI.md', 'CONVENTIONS.md',
    '.windsurf/rules/knowledge.md', '.devin/rules/knowledge.rules',
    '.github/copilot-instructions.md', '.aider.conf.yml', '.gitattributes',
  ];
  const before = new Map(targets.map((item) => [item, fs.existsSync(path.join(root, item)) ? fs.readFileSync(path.join(root, item)) : null]));
  const installer = run(root, 'install-agent-integrations.js', ['--all', '--confirm-all', '--no-install-check']);
  const changed = [];
  for (const item of targets) {
    const target = path.join(root, item);
    const prior = before.get(item);
    const now = fs.existsSync(target) ? fs.readFileSync(target) : null;
    if ((prior === null) !== (now === null) || (prior && !prior.equals(now))) changed.push(item);
  }
  return {
    id: 'malformed_package_zero_write',
    pass: installer.exit_code !== 0 && changed.length === 0 && fs.readFileSync(packagePath, 'utf8') === '{ malformed package',
    files_created_or_modified: changed,
    installer,
  };
}

function hardlinkInstructionCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'hardlink-instruction', zipPath);
  const external = path.join(workRoot, 'hardlink-instruction', 'external-agents.md');
  const target = path.join(root, 'AGENTS.md');
  const body = `# External instructions\n${HARDLINK_SECRET}\n`;
  fs.writeFileSync(external, body);
  fs.linkSync(external, target);
  const installer = run(root, 'install-agent-integrations.js', ['--runtime', 'codex', '--no-install-check']);
  const targetBody = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '';
  const externalBody = fs.readFileSync(external, 'utf8');
  const outputLeaked = combined(installer).includes(HARDLINK_SECRET);
  const imported = targetBody.includes(HARDLINK_SECRET);
  return {
    id: 'hardlink_instruction_blocked_before_read',
    pass: installer.exit_code !== 0 && !outputLeaked && externalBody === body && targetBody === body,
    external_unchanged: externalBody === body,
    repository_imported_external_content: imported && targetBody !== body,
    output_leaked: outputLeaked,
    target_nlink_after: fs.statSync(target).nlink,
    installer,
  };
}

function ownerHardlinkCase(workRoot, zipPath) {
  const root = fixture(workRoot, 'owner-hardlink', zipPath);
  const base = path.join(workRoot, 'owner-hardlink');
  const external = path.join(base, 'external-owner.json');
  const lockPath = path.join(root, '.knowledge', '.lock');
  fs.mkdirSync(lockPath, { recursive: true });
  fs.writeFileSync(external, `${JSON.stringify(activeLegacyOwner(), null, 2)}\n`);
  fs.linkSync(external, path.join(lockPath, 'owner.json'));
  const installer = run(root, 'install-agent-integrations.js', ['--runtime', 'windsurf', '--no-install-check']);
  const check = run(root, 'install-check.js', ['--json']);
  const parsed = parseJson(check.stdout);
  const leaked = combined(installer).includes(SECRET) || combined(check).includes(SECRET);
  const findings = [...(parsed?.lock_safety?.findings || []), ...(parsed?.issues || [])];
  const detected = findings.some((item) => ['lock_owner_hardlinked', 'unsafe_lock_owner'].includes(item.code));
  return {
    id: 'owner_hardlink',
    pass: installer.exit_code !== 0 && detected && !leaked,
    secret_leaked: leaked,
    install_check_detected: detected,
    installer,
    install_check: check,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const zipPath = path.resolve(args.zip);
  if (!fs.existsSync(zipPath)) throw new Error(`Candidate ZIP not found: ${zipPath}`);
  const workRoot = args.workRoot
    ? path.resolve(args.workRoot)
    : fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-contained-lock-rc39-'));
  if (args.workRoot) {
    if (fs.existsSync(workRoot)) throw new Error(`Refusing existing --work-root: ${workRoot}`);
    fs.mkdirSync(workRoot, { recursive: true });
  }
  const results = [];
  try {
    const cases = [
      lockDirectoryRedirectCase,
      ownerSymlinkCase,
      ownerHardlinkCase,
      doctorSharedPrimitiveCase,
      malformedPackageCase,
      hardlinkInstructionCase,
    ];
    for (const execute of cases) {
      try { results.push(execute(workRoot, zipPath)); }
      catch (error) {
        results.push({ id: execute.name, pass: false, harness_error: { code: error.code || null, message: error.message, stack: error.stack } });
      }
    }
    const report = {
      schema_version: 'knowledge-contained-lock-rc39-verification.v1',
      generated_at: new Date().toISOString(),
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      candidate: { path: zipPath, sha256: sha256File(zipPath) },
      checks_total: results.length,
      checks_passed: results.filter((item) => item.pass).length,
      checks_failed: results.filter((item) => !item.pass).length,
      status: results.every((item) => item.pass) ? 'pass' : 'fail',
      work_root: workRoot,
      fixtures_preserved: Boolean(args.keep || args.workRoot),
      results: results.map((item) => ({
        expected: true,
        semantic_outcome: 'expected_failure_observed',
        ...item,
      })),
    };
    if (args.out) {
      fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
      fs.writeFileSync(path.resolve(args.out), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (report.status !== 'pass') process.exitCode = 1;
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
