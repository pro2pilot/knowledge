#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const knowledgeRoot = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..'
);
const {
  readZipEntries
} = require(path.join(
  knowledgeRoot,
  'tools',
  'validate-release-artifact.js'
));
const {
  canonicalReleaseProducerClosure
} = require(path.join(
  knowledgeRoot,
  'tools',
  'release-gate.js'
));
const {
  __test: {
    exactUpgradeCommandSemanticOk,
    persistedApplyReportOk,
    exactRuntimeProofChainOk
  }
} = require(path.join(
  __dirname,
  '..',
  '..',
  'finalize-evidence-pack.js'
));

const PINNED_3211_SHA256 =
  'b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79';
const UPDATER_EVIDENCE_PATHS = Object.freeze({
  old_3_2_11:
    'raw/updaters/3.2.11-update-system-files.source.txt',
  candidate_3_3_0:
    'raw/updaters/3.3.0-candidate-update-system-files.source.txt',
  installed_3_3_0:
    'raw/updaters/3.3.0-installed-update-system-files.source.txt'
});
const RELEASE_CODE_EXTENSIONS = new Set([
  '.js',
  '.cjs',
  '.mjs',
  '.ps1',
  '.vbs'
]);

for (const relativePath of Object.values(
  UPDATER_EVIDENCE_PATHS
)) {
  if (
    RELEASE_CODE_EXTENSIONS.has(
      path.extname(relativePath).toLowerCase()
    )
  ) {
    throw new Error(
      `Updater evidence path is executable release code: ${relativePath}`
    );
  }
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const equal = arg.indexOf('=');
    if (equal !== -1) out[arg.slice(2, equal)] = arg.slice(equal + 1);
    else out[arg.slice(2)] = argv[++index];
  }
  return out;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function evidenceFileBinding(evidenceRoot, relativePath) {
  const target = path.join(
    evidenceRoot,
    ...String(relativePath).split('/')
  );
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Evidence file is not regular: ${relativePath}`);
  }
  return {
    path: String(relativePath),
    bytes: stat.size,
    sha256: sha256File(target)
  };
}

function copyEvidenceFile(sourcePath, evidenceRoot, relativePath) {
  const target = path.join(
    evidenceRoot,
    ...String(relativePath).split('/')
  );
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(
    sourcePath,
    target,
    fs.constants.COPYFILE_EXCL
  );
  return evidenceFileBinding(evidenceRoot, relativePath);
}

function readStableRegularFile(filePath) {
  const noFollow = Number(fs.constants.O_NOFOLLOW || 0);
  let handle = null;
  try {
    handle = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | noFollow
    );
    const before = fs.fstatSync(handle, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) {
      throw new Error(
        `Evidence source is not a regular file: ${filePath}`
      );
    }
    const body = fs.readFileSync(handle);
    const after = fs.fstatSync(handle, { bigint: true });
    const live = fs.lstatSync(filePath, { bigint: true });
    if (
      !after.isFile() ||
      !live.isFile() ||
      live.isSymbolicLink() ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== live.dev ||
      after.ino !== live.ino ||
      after.size !== live.size ||
      after.mtimeNs !== live.mtimeNs ||
      after.ctimeNs !== live.ctimeNs
    ) {
      throw new Error(
        `Evidence source changed while it was read: ${filePath}`
      );
    }
    return body;
  } finally {
    if (handle !== null) fs.closeSync(handle);
  }
}

function snapshotJsonEvidenceFile(
  sourcePath,
  evidenceRoot,
  relativePath
) {
  const body = readStableRegularFile(sourcePath);
  const value = JSON.parse(body.toString('utf8'));
  const target = path.join(
    evidenceRoot,
    ...String(relativePath).split('/')
  );
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, body, { flag: 'wx' });
  const binding = evidenceFileBinding(
    evidenceRoot,
    relativePath
  );
  const bodySha256 = crypto.createHash('sha256')
    .update(body)
    .digest('hex');
  if (
    binding.bytes !== body.length ||
    binding.sha256 !== bodySha256
  ) {
    throw new Error(
      `Evidence snapshot binding failed: ${relativePath}`
    );
  }
  return {
    value,
    sha256: bodySha256,
    binding
  };
}

function commandRecordMatches(
  record,
  label,
  args,
  cwd,
  entrypointSha256
) {
  return Boolean(
    record &&
    record.schema_version === 'knowledge-evidenced-command.v1' &&
    record.label === label &&
    record.cwd === cwd &&
    record.entrypoint_sha256 === entrypointSha256 &&
    record.runtime?.node_version === process.version &&
    record.runtime?.platform === process.platform &&
    record.runtime?.arch === process.arch &&
    record.runtime?.exec_path === process.execPath &&
    record.runtime?.exec_sha256 === sha256File(process.execPath) &&
    JSON.stringify(record.command) ===
      JSON.stringify([process.execPath, ...args])
  );
}

function physicalIdentity(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function extract(zipPath, destination) {
  const archive = readZipEntries(zipPath);
  if (archive.violations.length) {
    throw new Error(
      `Unsafe archive ${path.basename(zipPath)}: ` +
      archive.violations.map((item) =>
        `${item.type}:${item.entry || item.reason || 'unknown'}`
      ).join(', ')
    );
  }
  fs.mkdirSync(destination, { recursive: true });
  const root = fs.realpathSync(destination);
  for (const entry of archive.entries) {
    const relative = String(entry.name || '').replace(/\\/g, '/');
    if (
      !relative ||
      relative.endsWith('/') ||
      path.posix.isAbsolute(relative) ||
      relative.split('/').includes('..') ||
      /^[a-z]:/i.test(relative)
    ) {
      throw new Error(`Unsafe archive file entry: ${relative}`);
    }
    const target = path.resolve(root, ...relative.split('/'));
    if (!physicalIdentity(target).startsWith(
      `${physicalIdentity(root)}${path.sep}`
    )) {
      throw new Error(`Archive entry escaped extraction root: ${relative}`);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    if (
      physicalIdentity(fs.realpathSync(path.dirname(target))) !==
      physicalIdentity(path.dirname(target))
    ) {
      throw new Error(
        `Archive entry parent is not a physical directory: ${relative}`
      );
    }
    fs.writeFileSync(target, entry.body, { flag: 'wx' });
  }
}

function runNode(label, args, cwd, evidenceRoot) {
  const started = new Date();
  const entrypointSha256 = sha256File(args[0]);
  const runtime = {
    node_version: process.version,
    platform: process.platform,
    arch: process.arch,
    exec_path: process.execPath,
    exec_sha256: sha256File(process.execPath)
  };
  const result = spawnSync(process.execPath, args, {
    cwd,
    env: {
      ...process.env,
      KNOWLEDGE_FLOW_NO_OPEN: '1',
      KNOWLEDGE_INSPECTOR_NO_OPEN: '1'
    },
    encoding: 'utf8',
    windowsHide: true,
    timeout: 600000
  });
  const completed = new Date();
  const stdoutPath = path.join(evidenceRoot, 'raw', `${label}.stdout.json`);
  const stderrPath = path.join(evidenceRoot, 'raw', `${label}.stderr.txt`);
  fs.mkdirSync(path.dirname(stdoutPath), { recursive: true });
  fs.writeFileSync(stdoutPath, String(result.stdout || ''), 'utf8');
  fs.writeFileSync(stderrPath, String(result.stderr || ''), 'utf8');
  const record = {
    schema_version: 'knowledge-evidenced-command.v1',
    label,
    command: [process.execPath, ...args],
    cwd,
    entrypoint_sha256: entrypointSha256,
    runtime,
    started_at: started.toISOString(),
    completed_at: completed.toISOString(),
    duration_ms: completed.getTime() - started.getTime(),
    exit_code: result.status,
    signal: result.signal || null,
    error: result.error
      ? { code: result.error.code || null, message: result.error.message }
      : null,
    stdout: {
      path: path.relative(evidenceRoot, stdoutPath).replace(/\\/g, '/'),
      bytes: fs.statSync(stdoutPath).size,
      sha256: sha256File(stdoutPath)
    },
    stderr: {
      path: path.relative(evidenceRoot, stderrPath).replace(/\\/g, '/'),
      bytes: fs.statSync(stderrPath).size,
      sha256: sha256File(stderrPath)
    }
  };
  writeJson(path.join(evidenceRoot, 'raw', `${label}.result.json`), record);
  let parsed = null;
  try { parsed = JSON.parse(String(result.stdout || '')); } catch { /* retained raw */ }
  return { ...record, parsed };
}

function buildManifest(root) {
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile() && entry.name !== 'sha-manifest.json') files.push(absolute);
    }
  }
  walk(root);
  files.sort();
  return {
    schema_version: 'knowledge-evidence-manifest.v1',
    generated_at: new Date().toISOString(),
    files: files.map((filePath) => ({
      path: path.relative(root, filePath).replace(/\\/g, '/'),
      bytes: fs.statSync(filePath).size,
      sha256: sha256File(filePath)
    }))
  };
}

function updaterEnvelope(parsed, {
  schemaVersion,
  phase,
  installedVersion
}) {
  return Boolean(
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    parsed.schema_version === schemaVersion &&
    parsed.status === 'ok' &&
    parsed.phase === phase &&
    parsed.mode === phase &&
    parsed.source_version === '3.3.0' &&
    parsed.installed_version === installedVersion
  );
}

function buildExactUpgradeProofAssertions({
  verifyParsed,
  verifyAgainParsed,
  persistedAfterApply,
  persistedAfterFirstVerify,
  persistedAfterRepeat,
  persistedAfterApplySha,
  persistedAfterFirstVerifySha,
  persistedAfterRepeatSha,
  persistedAfterApplyBindingSha,
  persistedAfterFirstVerifyBindingSha,
  persistedAfterRepeatBindingSha
}) {
  const firstVerifyOk = exactUpgradeCommandSemanticOk(
    '04-new-updater-verify',
    verifyParsed
  );
  const repeatVerifyOk = exactUpgradeCommandSemanticOk(
    '05-new-updater-verify-repeat',
    verifyAgainParsed
  );
  const afterApplyOk = persistedApplyReportOk(
    persistedAfterApply,
    false
  );
  const afterFirstOk = persistedApplyReportOk(
    persistedAfterFirstVerify,
    true,
    persistedAfterApplySha
  );
  const afterRepeatOk = persistedApplyReportOk(
    persistedAfterRepeat,
    true,
    persistedAfterApplySha
  );
  const chainOk = exactRuntimeProofChainOk({
    firstVerify: verifyParsed,
    repeatVerify: verifyAgainParsed,
    afterApply: persistedAfterApply,
    afterFirst: persistedAfterFirstVerify,
    afterRepeat: persistedAfterRepeat,
    afterApplySha: persistedAfterApplySha
  });
  return {
    new_verify_semantic_success: firstVerifyOk,
    new_verify_status_ok:
      firstVerifyOk && verifyParsed?.status === 'ok',
    new_verify_reconstructed:
      firstVerifyOk &&
      verifyParsed?.runtime_preservation_proof
        ?.proof_source === 'reconstructed_legacy_backup',
    persisted_report_remains_apply: afterFirstOk,
    persisted_report_contains_reconstructed_proof:
      afterFirstOk &&
      persistedAfterFirstVerify
        ?.runtime_preservation_proof?.proof_source ===
          'reconstructed_legacy_backup',
    new_verify_repeat_semantic_success: repeatVerifyOk,
    repeat_revalidates_persisted_proof:
      repeatVerifyOk &&
      verifyAgainParsed?.verify?.runtime_proof_source ===
        'previous_update_report_revalidated',
    repeat_does_not_rewrite_apply_report:
      chainOk &&
      persistedAfterRepeatSha ===
        persistedAfterFirstVerifySha,
    persisted_apply_snapshot_bound:
      afterApplyOk &&
      persistedAfterApplyBindingSha ===
        persistedAfterApplySha,
    persisted_first_verify_snapshot_bound:
      afterFirstOk &&
      chainOk &&
      persistedAfterFirstVerifyBindingSha ===
        persistedAfterFirstVerifySha,
    persisted_repeat_snapshot_bound:
      afterRepeatOk &&
      chainOk &&
      persistedAfterRepeatBindingSha ===
        persistedAfterRepeatSha &&
      persistedAfterRepeatBindingSha ===
        persistedAfterFirstVerifyBindingSha
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.baseline || !args.candidate || !args.output) {
    throw new Error(
      'Usage: capture-exact-upgrade.js --baseline <knowledge-v3.2.11.zip> ' +
      '--candidate <knowledge-v3.3.0.zip> --output <durable-evidence-dir>'
    );
  }
  const baselineZip = path.resolve(args.baseline);
  const candidateZip = path.resolve(args.candidate);
  const outputRoot = path.resolve(args.output);
  if (fs.existsSync(outputRoot)) {
    throw new Error(`Evidence output already exists: ${outputRoot}`);
  }
  const baselineSha = sha256File(baselineZip);
  if (baselineSha !== PINNED_3211_SHA256) {
    throw new Error(`Unexpected 3.2.11 SHA-256: ${baselineSha}`);
  }
  const candidateSha = sha256File(candidateZip);
  const producerClosureBefore =
    canonicalReleaseProducerClosure();
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-upgrade-3211-'));
  const targetRoot = path.join(temporaryRoot, 'target');
  const candidateRoot = path.join(temporaryRoot, 'candidate');
  fs.mkdirSync(outputRoot, { recursive: true });
  try {
    extract(baselineZip, targetRoot);
    extract(candidateZip, candidateRoot);
    const targetKnowledge = path.join(targetRoot, '.knowledge');
    const candidateKnowledge = path.join(candidateRoot, '.knowledge');
    const operatorProfile = path.join(targetKnowledge, 'settings', 'operator-profile.json');
    const profile = JSON.parse(fs.readFileSync(operatorProfile, 'utf8'));
    profile.upgrade_preservation_probe = {
      source: 'public-3.2.11-exact-asset',
      expected: 'unchanged'
    };
    writeJson(operatorProfile, profile);
    const operatorBefore = sha256File(operatorProfile);
    const oldUpdater = path.join(targetKnowledge, 'tools', 'update-system-files.js');
    const candidateUpdater = path.join(
      candidateKnowledge,
      'tools',
      'update-system-files.js'
    );
    const operatorProfileBinding = copyEvidenceFile(
      operatorProfile,
      outputRoot,
      'raw/state/operator-profile.before.json'
    );
    const oldUpdaterBinding = copyEvidenceFile(
      oldUpdater,
      outputRoot,
      UPDATER_EVIDENCE_PATHS.old_3_2_11
    );
    const candidateUpdaterBinding = copyEvidenceFile(
      candidateUpdater,
      outputRoot,
      UPDATER_EVIDENCE_PATHS.candidate_3_3_0
    );
    const common = ['--from', candidateKnowledge, '--json'];
    const dryRunArgs = [oldUpdater, ...common, '--dry-run'];
    const dryRun = runNode(
      '01-old-updater-dry-run',
      dryRunArgs,
      targetRoot,
      outputRoot
    );
    const preflightArgs = [oldUpdater, ...common, '--preflight'];
    const preflight = runNode(
      '02-old-updater-preflight',
      preflightArgs,
      targetRoot,
      outputRoot
    );
    const applyArgs = [oldUpdater, ...common, '--apply', '--yes'];
    const apply = runNode(
      '03-old-updater-apply',
      applyArgs,
      targetRoot,
      outputRoot
    );
    const persistedReportPath = path.join(
      targetKnowledge,
      'maintenance',
      'update_system_files_report.json'
    );
    const afterApplySnapshot = snapshotJsonEvidenceFile(
      persistedReportPath,
      outputRoot,
      'raw/state/update-report.after-apply.json'
    );
    const persistedAfterApply = afterApplySnapshot.value;
    const persistedAfterApplySha = afterApplySnapshot.sha256;
    const persistedAfterApplyBinding =
      afterApplySnapshot.binding;
    const installedUpdater = path.join(targetKnowledge, 'tools', 'update-system-files.js');
    const installedUpdaterBinding = copyEvidenceFile(
      installedUpdater,
      outputRoot,
      UPDATER_EVIDENCE_PATHS.installed_3_3_0
    );
    const verifyArgs = [
      installedUpdater,
      '--verify-upgrade',
      ...common
    ];
    const verify = runNode(
      '04-new-updater-verify',
      verifyArgs,
      targetRoot,
      outputRoot
    );
    const afterFirstSnapshot = snapshotJsonEvidenceFile(
      persistedReportPath,
      outputRoot,
      'raw/state/update-report.after-first-verify.json'
    );
    const persistedAfterFirstVerify =
      afterFirstSnapshot.value;
    const persistedAfterFirstVerifySha =
      afterFirstSnapshot.sha256;
    const persistedApplyReportBinding =
      afterFirstSnapshot.binding;
    const verifyAgainArgs = [
      installedUpdater,
      '--verify-upgrade',
      ...common
    ];
    const verifyAgain = runNode(
      '05-new-updater-verify-repeat',
      verifyAgainArgs,
      targetRoot,
      outputRoot
    );
    const afterRepeatSnapshot = snapshotJsonEvidenceFile(
      persistedReportPath,
      outputRoot,
      'raw/state/update-report.after-repeat.json'
    );
    const persistedAfterRepeat = afterRepeatSnapshot.value;
    const persistedAfterRepeatSha = afterRepeatSnapshot.sha256;
    const persistedAfterRepeatBinding =
      afterRepeatSnapshot.binding;
    const operatorAfter = sha256File(operatorProfile);
    const operatorProfileAfterBinding = copyEvidenceFile(
      operatorProfile,
      outputRoot,
      'raw/state/operator-profile.after.json'
    );
    const baselineShaAfter = sha256File(baselineZip);
    const candidateShaAfter = sha256File(candidateZip);
    const producerClosureAfter =
      canonicalReleaseProducerClosure();
    const proofAssertions =
      buildExactUpgradeProofAssertions({
        verifyParsed: verify.parsed,
        verifyAgainParsed: verifyAgain.parsed,
        persistedAfterApply,
        persistedAfterFirstVerify,
        persistedAfterRepeat,
        persistedAfterApplySha,
        persistedAfterFirstVerifySha,
        persistedAfterRepeatSha,
        persistedAfterApplyBindingSha:
          persistedAfterApplyBinding.sha256,
        persistedAfterFirstVerifyBindingSha:
          persistedApplyReportBinding.sha256,
        persistedAfterRepeatBindingSha:
          persistedAfterRepeatBinding.sha256
      });
    const assertions = {
      baseline_archive_unchanged:
        baselineShaAfter === baselineSha,
      candidate_archive_unchanged:
        candidateShaAfter === candidateSha,
      producer_source_unchanged:
        producerClosureBefore.aggregate_sha256 ===
          producerClosureAfter.aggregate_sha256,
      dry_run_exit_zero: dryRun.exit_code === 0,
      dry_run_semantic_success: updaterEnvelope(
        dryRun.parsed,
        {
          schemaVersion: '3.2.11',
          phase: 'dry_run',
          installedVersion: '3.2.11'
        }
      ),
      preflight_exit_zero: preflight.exit_code === 0,
      preflight_semantic_success:
        updaterEnvelope(
          preflight.parsed,
          {
            schemaVersion: '3.2.11',
            phase: 'preflight',
            installedVersion: '3.2.11'
          }
        ) &&
        preflight.parsed?.permission_preflight?.status ===
          'ok',
      old_apply_exit_zero: apply.exit_code === 0,
      old_apply_semantic_success:
        updaterEnvelope(
          apply.parsed,
          {
            schemaVersion: '3.2.11',
            phase: 'apply',
            installedVersion: '3.3.0'
          }
        ) &&
        apply.parsed?.permission_preflight?.status === 'ok',
      old_apply_schema_is_3_2_11: apply.parsed?.schema_version === '3.2.11',
      old_apply_has_no_runtime_proof:
        !Object.prototype.hasOwnProperty.call(
          apply.parsed || {},
          'runtime_preservation_proof'
        ),
      new_verify_exit_zero: verify.exit_code === 0,
      new_verify_semantic_success:
        proofAssertions.new_verify_semantic_success,
      new_verify_status_ok:
        proofAssertions.new_verify_status_ok,
      new_verify_reconstructed:
        proofAssertions.new_verify_reconstructed,
      persisted_report_remains_apply:
        proofAssertions.persisted_report_remains_apply,
      persisted_report_contains_reconstructed_proof:
        proofAssertions
          .persisted_report_contains_reconstructed_proof,
      new_verify_repeat_exit_zero: verifyAgain.exit_code === 0,
      new_verify_repeat_semantic_success:
        proofAssertions.new_verify_repeat_semantic_success,
      repeat_revalidates_persisted_proof:
        proofAssertions.repeat_revalidates_persisted_proof,
      repeat_does_not_rewrite_apply_report:
        proofAssertions.repeat_does_not_rewrite_apply_report,
      operator_profile_unchanged: operatorBefore === operatorAfter,
      installed_version_is_3_3_0: verify.parsed?.installed_version === '3.3.0',
      updater_entrypoint_transition_bound:
        oldUpdaterBinding.sha256 !==
          installedUpdaterBinding.sha256 &&
        candidateUpdaterBinding.sha256 ===
          installedUpdaterBinding.sha256,
      persisted_apply_snapshot_bound:
        proofAssertions.persisted_apply_snapshot_bound,
      persisted_first_verify_snapshot_bound:
        proofAssertions.persisted_first_verify_snapshot_bound,
      persisted_repeat_snapshot_bound:
        proofAssertions.persisted_repeat_snapshot_bound,
      operator_profile_snapshots_bound:
        operatorProfileBinding.sha256 === operatorBefore &&
        operatorProfileAfterBinding.sha256 === operatorAfter &&
        operatorProfileBinding.sha256 ===
          operatorProfileAfterBinding.sha256,
      command_records_bound:
        commandRecordMatches(
          dryRun,
          '01-old-updater-dry-run',
          dryRunArgs,
          targetRoot,
          oldUpdaterBinding.sha256
        ) &&
        commandRecordMatches(
          preflight,
          '02-old-updater-preflight',
          preflightArgs,
          targetRoot,
          oldUpdaterBinding.sha256
        ) &&
        commandRecordMatches(
          apply,
          '03-old-updater-apply',
          applyArgs,
          targetRoot,
          oldUpdaterBinding.sha256
        ) &&
        commandRecordMatches(
          verify,
          '04-new-updater-verify',
          verifyArgs,
          targetRoot,
          installedUpdaterBinding.sha256
        ) &&
        commandRecordMatches(
          verifyAgain,
          '05-new-updater-verify-repeat',
          verifyAgainArgs,
          targetRoot,
          installedUpdaterBinding.sha256
        )
    };
    const executionContextPath =
      'raw/state/execution-context.json';
    writeJson(
      path.join(
        outputRoot,
        ...executionContextPath.split('/')
      ),
      {
        schema_version:
          'knowledge-exact-upgrade-execution-context.v1',
        cwd: targetRoot,
        candidate_knowledge: candidateKnowledge,
        runtime: {
          node_executable: process.execPath,
          node_executable_sha256: sha256File(process.execPath),
          node_version: process.version,
          platform: process.platform,
          arch: process.arch
        },
        updater_entrypoints: {
          old_3_2_11: oldUpdaterBinding,
          candidate_3_3_0: candidateUpdaterBinding,
          installed_3_3_0: installedUpdaterBinding
        }
      }
    );
    const executionContextBinding = evidenceFileBinding(
      outputRoot,
      executionContextPath
    );
    const failed = Object.entries(assertions)
      .filter(([, passed]) => !passed)
      .map(([name]) => name);
    const report = {
      schema_version: 'knowledge-public-upgrade-evidence.v2',
      generated_at: new Date().toISOString(),
      producer: {
        path:
          '.knowledge/docs/release/3.3.0/test-evidence/release-gates/capture-exact-upgrade.js',
        sha256: sha256File(__filename)
      },
      producer_closure: producerClosureBefore,
      producer_source_unchanged:
        assertions.producer_source_unchanged,
      producer_closure_after_sha256:
        producerClosureAfter.aggregate_sha256,
      status: failed.length ? 'fail' : 'pass',
      public_upgrade_path: '3.2.11 -> 3.3.0',
      baseline: {
        path: path.basename(baselineZip),
        bytes: fs.statSync(baselineZip).size,
        sha256: baselineSha
      },
      candidate: {
        path: path.basename(candidateZip),
        bytes: fs.statSync(candidateZip).size,
        sha256: candidateSha
      },
      assertions,
      failed_assertions: failed,
      operator_profile_sha256_before: operatorBefore,
      operator_profile_sha256_after: operatorAfter,
      operator_profile_before: operatorProfileBinding,
      operator_profile_after: operatorProfileAfterBinding,
      persisted_apply_report_after_apply:
        persistedAfterApplyBinding,
      persisted_apply_report_sha256_after_apply:
        persistedAfterApplySha,
      persisted_apply_report_sha256_after_first_verify:
        persistedAfterFirstVerifySha,
      persisted_apply_report_sha256_after_repeat:
        persistedAfterRepeatSha,
      persisted_apply_report_after_first_verify:
        persistedApplyReportBinding,
      persisted_apply_report_after_repeat:
        persistedAfterRepeatBinding,
      updater_entrypoints: {
        old_3_2_11: oldUpdaterBinding,
        candidate_3_3_0: candidateUpdaterBinding,
        installed_3_3_0: installedUpdaterBinding
      },
      runtime: {
        node_executable: process.execPath,
        node_executable_sha256: sha256File(process.execPath),
        node_version: process.version,
        platform: process.platform,
        arch: process.arch
      },
      execution_context: executionContextBinding,
      commands: [
        dryRun.label,
        preflight.label,
        apply.label,
        verify.label,
        verifyAgain.label
      ],
      limitations: [
        `Executed on ${process.platform}/${process.arch}, Node ${process.version}.`,
        'This run does not substitute for native Linux or macOS validation.'
      ]
    };
    writeJson(path.join(outputRoot, 'report.json'), report);
    const manifest = buildManifest(outputRoot);
    manifest.aggregate_sha256 = crypto.createHash('sha256')
      .update(manifest.files.map((item) =>
        `${item.path}\0${item.sha256}\n`).join(''))
      .digest('hex');
    writeJson(path.join(outputRoot, 'sha-manifest.json'), manifest);
    if (
      canonicalReleaseProducerClosure().aggregate_sha256 !==
        producerClosureBefore.aggregate_sha256
    ) {
      throw new Error(
        'Release producer source changed during exact-upgrade capture'
      );
    }
    console.log(JSON.stringify(report, null, 2));
    if (failed.length) process.exitCode = 2;
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.stack || error.message);
    process.exit(1);
  }
}

module.exports = {
  main,
  UPDATER_EVIDENCE_PATHS,
  buildExactUpgradeProofAssertions,
  snapshotJsonEvidenceFile
};
