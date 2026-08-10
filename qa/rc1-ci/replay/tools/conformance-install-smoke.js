#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');

const root = path.resolve(__dirname, '..');
const PINNED_3211_SHA256 =
  'b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79';

function parseArgs(argv = process.argv.slice(2)) {
  const args = {
    artifact: null,
    previousArtifact: null,
    json: false,
    keepFailed: false
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--json') args.json = true;
    else if (arg === '--keep-failed' || arg === '--keep') args.keepFailed = true;
    else if (arg === '--previous-artifact') {
      args.previousArtifact = argv[++index] || null;
    } else if (arg.startsWith('--previous-artifact=')) {
      args.previousArtifact = arg.slice('--previous-artifact='.length);
    }
    else if (!args.artifact) args.artifact = arg;
  }
  return args;
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function sanitizeText(value) {
  return String(value || '')
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"',}]*/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"',}]*/gi, '<local-path>');
}

function sha256File(filePath) {
  return require('crypto')
    .createHash('sha256')
    .update(fs.readFileSync(filePath))
    .digest('hex');
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(
    filePath,
    `${JSON.stringify(value, null, 2)}\n`,
    'utf8'
  );
}

function safeOutputPath(dest, entryName) {
  const normalized = String(entryName || '').replace(/\\/g, '/');
  const target = path.resolve(dest, ...normalized.split('/'));
  const rootPath = path.resolve(dest);
  if (target !== rootPath && !target.startsWith(rootPath + path.sep)) throw new Error(`Unsafe zip entry: ${entryName}`);
  return target;
}

function extractZipEntries(zip, dest) {
  ensureDir(dest);
  for (const entry of zip.entries) {
    if (entry.name.endsWith('/')) {
      ensureDir(safeOutputPath(dest, entry.name));
      continue;
    }
    const outPath = safeOutputPath(dest, entry.name);
    ensureDir(path.dirname(outPath));
    fs.writeFileSync(outPath, entry.body);
  }
  return {
    entries: zip.entries.length,
    total_uncompressed_bytes: zip.total_uncompressed_bytes
  };
}

function extractZip(zipPath, dest) {
  const validation = validate(zipPath);
  if (validation.status !== 'ok') {
    const error = new Error('release artifact validation failed before install smoke');
    error.validation = validation;
    throw error;
  }
  const zip = readZipEntries(zipPath);
  return extractZipEntries(zip, dest);
}

function repairArtifactBoundary(zipPath) {
  const zip = readZipEntries(zipPath);
  const names = new Set(zip.entries.map((entry) => entry.name));
  const required = [
    '.knowledge/tools/repair-on-touch.js',
    '.knowledge/tools/lib/repair-on-touch.js',
    '.knowledge/tools/lib/dedicated-verification.js',
    '.knowledge/tools/self-test-repair-on-touch.js',
    '.knowledge/tools/self-test-dedicated-verification.js',
    '.knowledge/tools/self-test-repair-session-isolation.js',
    '.knowledge/schemas/verification-execution.schema.json',
    '.knowledge/schemas/verification-receipt.schema.json',
    '.knowledge/schemas/dedicated-verification-receipt.schema.json'
  ];
  const forbiddenPrefixes = [
    '.knowledge/maintenance/dedicated_verification_receipts',
    '.knowledge/maintenance/repair_sessions'
  ];
  const missing = required.filter((entry) => !names.has(entry));
  const leaked = Array.from(names).filter((entry) =>
    forbiddenPrefixes.some((prefix) =>
      entry === prefix || entry.startsWith(`${prefix}/`)));
  return {
    status: missing.length || leaked.length ? 'fail' : 'pass',
    required_entries_checked: required.length,
    forbidden_prefixes_checked: forbiddenPrefixes.length,
    missing,
    leaked
  };
}

function findPreviousArtifact(explicitPath = null) {
  const candidates = [
    explicitPath,
    process.env.KNOWLEDGE_PREVIOUS_RELEASE_ARTIFACT
  ].filter(Boolean).map((value) => path.resolve(value));
  let cursor = path.resolve(root, '..');
  for (let depth = 0; depth < 7; depth += 1) {
    candidates.push(
      path.join(
        cursor,
        'internal',
        'pro2pilot-public-consistency',
        'cache',
        'knowledge-v3.2.11.zip'
      ),
      path.join(
        cursor,
        'knowledge-3.2.11-spark-battle',
        'knowledge-v3.2.11.zip'
      )
    );
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return candidates.find((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch {
      return false;
    }
  }) || null;
}

function previousReleaseInfo(zipPath) {
  const artifactSha256 = sha256File(zipPath);
  if (artifactSha256 !== PINNED_3211_SHA256) {
    throw new Error(
      `previous release artifact SHA-256 mismatch: ${artifactSha256}`
    );
  }
  const zip = readZipEntries(zipPath);
  if ((zip.violations || []).length) {
    throw new Error(
      `previous release artifact is structurally invalid: ${
        JSON.stringify(zip.violations)
      }`
    );
  }
  const packageEntry = zip.entries.find(
    (entry) => entry.name === '.knowledge/package.json'
  );
  if (!packageEntry) {
    throw new Error('previous release artifact has no .knowledge/package.json');
  }
  const packageJson = JSON.parse(packageEntry.body.toString('utf8'));
  if (packageJson.version !== '3.2.11') {
    throw new Error(
      `expected previous release 3.2.11, received ${packageJson.version}`
    );
  }
  return {
    zip,
    version: packageJson.version,
    sha256: artifactSha256
  };
}

function isolatedChildEnv(overrides = {}) {
  const env = { ...process.env };
  const controlledKeys = new Set([
    'KNOWLEDGE_MODE',
    'KNOWLEDGE_SYSTEM_ROOT',
    'KNOWLEDGE_TARGET_ROOT',
    'KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT',
    'KNOWLEDGE_STATE_ROOT',
    'KNOWLEDGE_AGENT_ID',
    'KNOWLEDGE_DISABLE_GIT_DISCOVERY',
    'KNOWLEDGE_FLOW_NO_OPEN',
    'KNOWLEDGE_INSPECTOR_NO_OPEN',
    'KNOWLEDGE_TEAM_ROOT',
    'KNOWLEDGE_WORKSPACE_ID',
    'KNOWLEDGE_REPO_ID',
    'KNOWLEDGE_SPARK_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_REPORT',
    'KNOWLEDGE_MEMORY_BATTLE_MAX_AGE_HOURS'
  ]);
  for (const key of Object.keys(env)) {
    if (controlledKeys.has(key.toUpperCase())) delete env[key];
  }
  return {
    ...env,
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1',
    ...overrides
  };
}

function run(command, args, options = {}) {
  const started = Date.now();
  const attempts = [];
  const emptyFailureRetries = Number(options.emptyFailureRetries || 0);
  let result;
  for (let attempt = 1; attempt <= emptyFailureRetries + 1; attempt += 1) {
    result = spawnSync(command, args, {
      cwd: options.cwd,
      env: isolatedChildEnv(options.env || {}),
      encoding: 'utf8',
      windowsHide: true,
      timeout: options.timeoutMs || 180000,
      maxBuffer: 32 * 1024 * 1024
    });
    const stdout = String(result.stdout || '');
    const stderr = String(result.stderr || '');
    attempts.push({
      attempt,
      exit_code: result.status,
      signal: result.signal || null,
      error_code: result.error?.code || null,
      error_message: sanitizeText(result.error?.message || ''),
      stdout_tail: sanitizeText(stdout.slice(-2000)),
      stderr_tail: sanitizeText(stderr.slice(-2000))
    });
    const retryableEmptyFailure = result.status !== 0 && !stdout && !stderr;
    if (!retryableEmptyFailure || attempt > emptyFailureRetries) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
  }
  return {
    id: options.id || path.basename(command),
    command: sanitizeText([path.basename(command), ...args].join(' ')),
    status: result.status === 0 ? 'pass' : 'fail',
    exit_code: result.status,
    duration_ms: Date.now() - started,
    stdout_tail: sanitizeText(String(result.stdout || '').slice(-2000)),
    stderr_tail: sanitizeText(String(result.stderr || '').slice(-2000)),
    attempts
  };
}

function matchesExpectedFailure(result, payload, expectedCode) {
  return Boolean(
    Number.isInteger(result?.exit_code) &&
    result.exit_code !== 0 &&
    payload?.status === 'error' &&
    payload?.code === expectedCode
  );
}

function expectedFailureStep(command, args, expectedCode, options = {}) {
  const result = run(command, args, options);
  let payload = null;
  for (const candidate of [result.stderr_tail, result.stdout_tail]) {
    try {
      payload = JSON.parse(candidate);
      break;
    } catch {}
  }
  const matched = matchesExpectedFailure(
    result,
    payload,
    expectedCode
  );
  return {
    ...result,
    status: matched ? 'pass' : 'fail',
    expected_failure: matched,
    expected_nonzero_exit: true,
    expected_failure_code: expectedCode,
    observed_failure_code: payload?.code || null
  };
}

function staticStep(id, status, details = {}) {
  return {
    id,
    command: '<internal assertion>',
    status,
    exit_code: status === 'pass' ? 0 : 2,
    duration_ms: 0,
    stdout_tail: '',
    stderr_tail: '',
    ...details
  };
}

function upgradeApplyInvocation(candidateKnowledgeRoot, upgradeRoot) {
  return {
    file: process.execPath,
    args: [
      path.join(candidateKnowledgeRoot, 'tools', 'update-system-files.js'),
      '--target-knowledge-root',
      path.join(upgradeRoot, '.knowledge'),
      '--from',
      candidateKnowledgeRoot,
      '--apply',
      '--yes',
      '--json'
    ]
  };
}

function runUpgradeSmoke({
  previousArtifact,
  candidateKnowledgeRoot,
  upgradeRoot
}) {
  const steps = [];
  const previous = previousReleaseInfo(previousArtifact);
  const candidateVersion = JSON.parse(
    fs.readFileSync(path.join(candidateKnowledgeRoot, 'package.json'), 'utf8')
  ).version;
  extractZipEntries(previous.zip, upgradeRoot);
  // The upgrade target represents a real project, not a bare .knowledge
  // directory. Keep this source canary aligned with the clean-install fixture
  // so legacy runtime bootstrap can discover and register the root module.
  fs.writeFileSync(
    path.join(upgradeRoot, 'app.js'),
    'module.exports = 1;\n',
    'utf8'
  );
  steps.push(staticStep('upgrade-previous-release', 'pass', {
    previous_version: previous.version,
    previous_artifact_sha256: previous.sha256,
    target_source_fixture: 'app.js'
  }));

  const canaries = [
    'maintenance/dedicated_verification_receipts/KDVR-upgrade-canary.json',
    'maintenance/repair_sessions/task-upgrade/session-upgrade/canary.json'
  ];
  const hashesBefore = {};
  for (const relative of canaries) {
    const target = path.join(upgradeRoot, '.knowledge', relative);
    writeJson(target, {
      fixture: relative,
      immutable_across_upgrade: true
    });
    hashesBefore[relative] = sha256File(target);
  }

  const upgradeApply = upgradeApplyInvocation(candidateKnowledgeRoot, upgradeRoot);
  const apply = run(
    upgradeApply.file,
    upgradeApply.args,
    {
      cwd: upgradeRoot,
      id: `upgrade-${previous.version}-to-${candidateVersion}`,
      timeoutMs: 360000
    }
  );
  steps.push(apply);

  const hashMismatches = canaries.filter((relative) => {
    const target = path.join(upgradeRoot, '.knowledge', relative);
    return !fs.existsSync(target) ||
      sha256File(target) !== hashesBefore[relative];
  });
  const installedPackagePath = path.join(
    upgradeRoot,
    '.knowledge',
    'package.json'
  );
  let installedVersion = null;
  try {
    installedVersion = JSON.parse(
      fs.readFileSync(installedPackagePath, 'utf8')
    ).version;
  } catch {}
  const requiredInstalled = [
    'tools/lib/dedicated-verification.js',
    'tools/self-test-dedicated-verification.js',
    'tools/self-test-repair-session-isolation.js',
    'schemas/dedicated-verification-receipt.schema.json'
  ];
  const missingInstalled = requiredInstalled.filter((relative) =>
    !fs.existsSync(path.join(upgradeRoot, '.knowledge', relative)));
  const preservationPass = (
    apply.status === 'pass' &&
    installedVersion === candidateVersion &&
    hashMismatches.length === 0 &&
    missingInstalled.length === 0
  );
  steps.push(staticStep(
    'upgrade-repair-state-preservation',
    preservationPass ? 'pass' : 'fail',
    {
      installed_version: installedVersion,
      canaries_checked: canaries.length,
      hash_mismatches: hashMismatches,
      missing_installed_runtime: missingInstalled
    }
  ));

  steps.push(run(
    process.execPath,
    [
      '.knowledge/tools/update-system-files.js',
      '--verify-upgrade',
      '--from',
      candidateKnowledgeRoot,
      '--json'
    ],
    {
      cwd: upgradeRoot,
      id: 'upgrade-verify',
      timeoutMs: 240000
    }
  ));
  steps.push(run(
    process.execPath,
    ['.knowledge/tools/install-check.js', '--json'],
    {
      cwd: upgradeRoot,
      id: 'upgrade-install-check',
      timeoutMs: 180000
    }
  ));
  return {
    steps,
    evidence: {
      previous_version: previous.version,
      previous_artifact_sha256: previous.sha256,
      candidate_version: installedVersion,
      canaries_checked: canaries.length,
      canary_hashes_unchanged: hashMismatches.length === 0,
      required_runtime_files_checked: requiredInstalled.length
    }
  };
}

function smoke(artifactPath, options = {}) {
  const smokeRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), 'knowledge-live-asset-smoke-')
  );
  const cleanInstallRoot = path.join(smokeRoot, 'clean-install');
  const upgradeRoot = path.join(smokeRoot, 'upgrade-3.2.11-to-3.3.0');
  const steps = [];
  let extract = null;
  let upgradeEvidence = null;
  try {
    const boundary = repairArtifactBoundary(artifactPath);
    steps.push(staticStep(
      'repair-artifact-boundary',
      boundary.status,
      boundary
    ));
    extract = extractZip(artifactPath, cleanInstallRoot);
    fs.writeFileSync(
      path.join(cleanInstallRoot, 'app.js'),
      'module.exports = 1;\n',
      'utf8'
    );
    const gitSteps = [
      ['git-init', 'git', ['init'], 120000],
      ['git-config-email', 'git', ['config', 'user.email', 'knowledge-smoke@example.invalid'], 120000],
      ['git-config-name', 'git', ['config', 'user.name', 'Knowledge Smoke'], 120000],
      ['git-add-fixture', 'git', ['add', 'app.js', '.knowledge'], 120000],
      ['git-commit-fixture', 'git', ['commit', '-m', 'clean install smoke fixture'], 120000]
    ];
    for (const [id, cmd, args, timeoutMs] of gitSteps) {
      steps.push(run(cmd, args, {
        cwd: cleanInstallRoot,
        id,
        timeoutMs
      }));
    }

    const nodeSteps = [
      ['install-check', ['.knowledge/tools/install-check.js', '--json'], 180000],
      ['flow-import', ['.knowledge/tools/flow.js', 'import', '--no-color', '--json'], 180000, { emptyFailureRetries: 2 }],
      ['repair-on-touch-plan', [
        '.knowledge/tools/repair-on-touch.js',
        'plan',
        '--task-id', 'conformance-task',
        '--session-id', 'conformance-session',
        '--task', 'Conformance install scope',
        '--changed-file', 'app.js',
        '--json'
      ], 180000],
      ['repair-on-touch-status', [
        '.knowledge/tools/repair-on-touch.js',
        'status',
        '--task-id', 'conformance-task',
        '--session-id', 'conformance-session',
        '--json'
      ], 180000],
      ['repair-on-touch-self-test', ['.knowledge/tools/self-test-repair-on-touch.js'], 240000],
      ['dedicated-verification-self-test', ['.knowledge/tools/self-test-dedicated-verification.js'], 240000],
      ['repair-session-isolation-self-test', ['.knowledge/tools/self-test-repair-session-isolation.js'], 120000],
      ['field-report-start', ['.knowledge/tools/field-report.js', 'start', '--new', '--json'], 180000],
      ['field-report-self-test', ['.knowledge/tools/self-test-field-report.js'], 180000],
      ['doctor', ['.knowledge/tools/doctor.js', '--json'], 180000],
      ['build-inspector', ['.knowledge/tools/build-visual-inspector.js'], 180000],
      ['self-test-inspector-ui', ['.knowledge/tools/self-test-inspector-ui.js'], 180000],
      ['self-test-team-mode', ['.knowledge/tools/self-test-team-mode.js'], 300000],
      ['memory-status-all', ['.knowledge/tools/memory-provider.js', 'status-all', '--json'], 180000]
    ];
    for (const [id, args, timeoutMs, stepOptions = {}] of nodeSteps) {
      steps.push(run(process.execPath, args, {
        cwd: cleanInstallRoot,
        id,
        timeoutMs,
        ...stepOptions
      }));
    }
    steps.push(expectedFailureStep(
      process.execPath,
      [
        '.knowledge/tools/repair-on-touch.js',
        'status',
        '--json'
      ],
      'repair_plan_scope_required',
      {
        cwd: cleanInstallRoot,
        id: 'repair-on-touch-status-requires-scope',
        timeoutMs: 180000
      }
    ));

    const previousArtifact = findPreviousArtifact(
      options.previousArtifact || null
    );
    if (!previousArtifact) {
      steps.push(staticStep(
        'upgrade-previous-release',
        'fail',
        { error: 'knowledge-v3.2.11.zip was not found' }
      ));
    } else {
      const upgrade = runUpgradeSmoke({
        previousArtifact,
        candidateKnowledgeRoot: path.join(
          cleanInstallRoot,
          '.knowledge'
        ),
        upgradeRoot
      });
      steps.push(...upgrade.steps);
      upgradeEvidence = upgrade.evidence;
    }
  } finally {
    const failed = steps.some((step) => step.status !== 'pass');
    if (!failed || !options.keepFailed) fs.rmSync(smokeRoot, { recursive: true, force: true });
  }
  const failures = steps.filter((step) => step.status !== 'pass');
  return {
    schema_version: 'conformance-install-smoke.v1',
    status: failures.length ? 'fail' : 'pass',
    artifact: path.basename(artifactPath),
    root: failures.length && options.keepFailed ? smokeRoot : '<clean-install-smoke>',
    extract,
    upgrade: upgradeEvidence,
    steps,
    failures
  };
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (!args.artifact) throw new Error(
    'Usage: node tools/conformance-install-smoke.js ' +
    '<knowledge-vX.Y.Z.zip> [--previous-artifact <knowledge-v3.2.11.zip>] ' +
    '[--json] [--keep-failed]'
  );
  const result = smoke(path.resolve(args.artifact), {
    keepFailed: args.keepFailed,
    previousArtifact: args.previousArtifact
  });
  if (args.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`conformance install smoke ${result.status}`);
  if (result.status !== 'pass') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const parsed = parseArgs(process.argv.slice(2));
    const result = {
      schema_version: 'conformance-install-smoke.v1',
      status: 'fail',
      error: error.message,
      validation: error.validation || null
    };
    if (parsed.json) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = {
  smoke,
  extractZip,
  matchesExpectedFailure,
  upgradeApplyInvocation
};
