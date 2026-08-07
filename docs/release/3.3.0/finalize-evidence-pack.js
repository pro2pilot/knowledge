#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PINNED_3211_SHA256 =
  'b7f4e912e8bcffff1e2ffb35756d68850a980b6b841306ac7a51c9d88fc59d79';
const releaseDocs = __dirname;
const knowledgeRoot = path.resolve(releaseDocs, '..', '..', '..');
const releaseSource = path.dirname(knowledgeRoot);
const releaseWorkspace = path.dirname(releaseSource);
const gateRoot = path.join(
  releaseDocs,
  'test-evidence',
  'release-gates'
);
const focusedRoot = path.join(
  releaseDocs,
  'test-evidence',
  'repair-on-touch'
);
const outputPath = path.join(releaseDocs, 'evidence-pack.json');
const manifestPath = path.join(
  releaseDocs,
  'evidence-pack-manifest.json'
);
const parityPath = path.join(
  releaseDocs,
  'candidate-source-parity.json'
);
const candidatePath = path.join(
  knowledgeRoot,
  'dist',
  'knowledge-v3.3.0.zip'
);
const baselinePath = path.join(
  releaseWorkspace,
  'release-source-3.2.11',
  '.knowledge',
  'dist',
  'knowledge-v3.2.11.zip'
);
const EVIDENCE_TRANSACTION_PREFIX =
  'evidence-pack-3.3.0-';
const EVIDENCE_PUBLICATION_TREE_EXCLUSIONS = Object.freeze([
  'maintenance/transactions',
  'maintenance/evidence-publication/.lock',
  'docs/release/3.3.0/evidence-pack.json',
  'docs/release/3.3.0/evidence-pack-manifest.json',
  'docs/release/3.3.0/candidate-source-parity.json'
]);
const evidencePublicationLockPath = path.join(
  knowledgeRoot,
  'maintenance',
  'evidence-publication',
  '.lock'
);
const {
  buildPackageEntries,
  readEntryData
} = require(path.join(
  knowledgeRoot,
  'tools',
  'package-release.js'
));
const {
  validate: validateArtifact,
  readZipEntries
} = require(path.join(
  knowledgeRoot,
  'tools',
  'validate-release-artifact.js'
));
const {
  commitJsonTransaction,
  recoverTransactions,
  treeGuardHash
} = require(path.join(
  knowledgeRoot,
  'tools',
  'lib',
  'json-transaction.js'
));
const {
  withLock
} = require(path.join(
  knowledgeRoot,
  'tools',
  'lib',
  'json-store.js'
));
const {
  canonicalFullEvidencePlan,
  canonicalReleaseProducerClosure
} = require(path.join(
  knowledgeRoot,
  'tools',
  'release-gate.js'
));
const {
  assertAcceptedGateReport,
  assertSourceBootstrapLogCorrelation,
  assertStepDecisionCorrelation,
  assertStepLogHash,
  assertSyntheticStepLogCorrelation,
  readStableRegularFile
} = require(path.join(
  knowledgeRoot,
  'tools',
  'lib',
  'release-step-evidence.js'
));
const EXACT_UPGRADE_ASSERTION_KEYS = Object.freeze([
  'baseline_archive_unchanged',
  'candidate_archive_unchanged',
  'producer_source_unchanged',
  'dry_run_exit_zero',
  'dry_run_semantic_success',
  'preflight_exit_zero',
  'preflight_semantic_success',
  'old_apply_exit_zero',
  'old_apply_semantic_success',
  'old_apply_schema_is_3_2_11',
  'old_apply_has_no_runtime_proof',
  'new_verify_exit_zero',
  'new_verify_semantic_success',
  'new_verify_status_ok',
  'new_verify_reconstructed',
  'persisted_report_remains_apply',
  'persisted_report_contains_reconstructed_proof',
  'new_verify_repeat_exit_zero',
  'new_verify_repeat_semantic_success',
  'repeat_revalidates_persisted_proof',
  'repeat_does_not_rewrite_apply_report',
  'operator_profile_unchanged',
  'installed_version_is_3_3_0',
  'updater_entrypoint_transition_bound',
  'persisted_apply_snapshot_bound',
  'persisted_first_verify_snapshot_bound',
  'persisted_repeat_snapshot_bound',
  'operator_profile_snapshots_bound',
  'command_records_bound'
]);
const EXACT_RUNTIME_REQUIRED_PATHS = Object.freeze([
  'maintenance/dedicated_verification_receipts',
  'maintenance/recertifications.json',
  'maintenance/repair_on_touch_telemetry.json',
  'maintenance/repair_opportunities.json',
  'maintenance/repair_sessions',
  'maintenance/transactions',
  'maintenance/verification_executions',
  'maintenance/verification_receipts',
  'settings/operator-profile.json'
]);
const recordSources = new WeakMap();

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(filePath));
}

function isPlainObject(value) {
  return Boolean(
    value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactTrueAssertions(value) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...EXACT_UPGRADE_ASSERTION_KEYS].sort();
  return (
    JSON.stringify(actual) === JSON.stringify(expected) &&
    EXACT_UPGRADE_ASSERTION_KEYS.every((key) =>
      value[key] === true)
  );
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const equal = arg.indexOf('=');
    if (equal !== -1) {
      out[arg.slice(2, equal)] = arg.slice(equal + 1);
    } else {
      out[arg.slice(2)] = argv[++index];
    }
  }
  return out;
}

function readJson(filePath) {
  return JSON.parse(
    fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '')
  );
}

function physicalIdentity(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function safeRegular(root, relative) {
  const canonical = String(relative || '').replace(/\\/g, '/');
  if (
    !canonical ||
    path.posix.isAbsolute(canonical) ||
    canonical.split('/').includes('..') ||
    /^[a-z]:/i.test(canonical)
  ) {
    throw new Error(`Unsafe evidence path: ${relative}`);
  }
  const base = path.resolve(root);
  const target = path.resolve(base, ...canonical.split('/'));
  if (!target.startsWith(`${base}${path.sep}`)) {
    throw new Error(`Evidence path escaped its root: ${relative}`);
  }
  let cursor = base;
  for (const segment of canonical.split('/')) {
    cursor = path.join(cursor, segment);
    const stat = fs.lstatSync(cursor);
    const final = physicalIdentity(cursor) ===
      physicalIdentity(target);
    if (stat.isSymbolicLink()) {
      throw new Error(`Evidence path contains a link: ${relative}`);
    }
    if (!final && !stat.isDirectory()) {
      throw new Error(
        `Evidence parent is not a directory: ${relative}`
      );
    }
    if (final && !stat.isFile()) {
      throw new Error(
        `Evidence path is not a regular file: ${relative}`
      );
    }
  }
  if (physicalIdentity(fs.realpathSync(target)) !==
      physicalIdentity(target)) {
    throw new Error(`Evidence path is not physical: ${relative}`);
  }
  return target;
}

function record(filePath, root = releaseSource) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Required evidence is not a regular file: ${filePath}`);
  }
  const binding = {
    path: path.relative(root, filePath).replace(/\\/g, '/'),
    bytes: stat.size,
    sha256: sha256File(filePath)
  };
  recordSources.set(binding, path.resolve(filePath));
  return binding;
}

function recordJsonValue(filePath, value, root = releaseSource) {
  const body = `${JSON.stringify(value, null, 2)}\n`;
  return {
    path: path.relative(root, filePath).replace(/\\/g, '/'),
    bytes: Buffer.byteLength(body),
    sha256: sha256(body)
  };
}

function verifyProducerBinding(
  binding,
  filePath,
  expectedRelative
) {
  if (
    binding?.path !== expectedRelative ||
    binding?.sha256 !== sha256File(filePath)
  ) {
    throw new Error(
      `Evidence producer binding failed: ${expectedRelative}`
    );
  }
  return record(filePath);
}

function verifyManifest(
  root,
  manifestFile,
  { expectedRunId = null } = {}
) {
  const manifest = readJson(manifestFile);
  if (
    manifest?.schema_version !==
      'knowledge-evidence-manifest.v1' ||
    !Array.isArray(manifest.files) ||
    !manifest.files.length
  ) {
    throw new Error(`Invalid evidence manifest: ${manifestFile}`);
  }
  if (
    expectedRunId &&
    manifest.run_id !== expectedRunId
  ) {
    throw new Error(
      `Evidence manifest run mismatch: ${manifest.run_id} != ${expectedRunId}`
    );
  }
  const seen = new Set();
  const verified = new Map();
  for (const item of manifest.files) {
    const relative = String(item?.path || '')
      .replace(/\\/g, '/');
    const collision = relative.normalize('NFC').toLowerCase();
    if (seen.has(collision)) {
      throw new Error(`Duplicate evidence path: ${relative}`);
    }
    seen.add(collision);
    const target = safeRegular(root, relative);
    const stat = fs.statSync(target);
    const digest = sha256File(target);
    if (
      stat.size !== item.bytes ||
      digest !== item.sha256
    ) {
      throw new Error(`Evidence entry drifted: ${relative}`);
    }
    verified.set(relative, {
      target,
      bytes: stat.size,
      sha256: digest
    });
  }
  const aggregate = sha256(manifest.files.map((item) =>
    `${item.path}\0${item.sha256}\n`).join(''));
  if (manifest.aggregate_sha256 !== aggregate) {
    throw new Error(
      `Evidence manifest aggregate drifted: ${manifestFile}`
    );
  }
  return { manifest, verified };
}

function assertFullGateEnvelopeSchemas(
  index,
  manifest = null,
  capture = null
) {
  if (
    index?.schema_version !==
      'knowledge-release-gate-evidence-index.v1' ||
    !Array.isArray(index.runs)
  ) {
    throw new Error(
      'Full-gate index schema is invalid'
    );
  }
  if (
    manifest &&
    (
      manifest.schema_version !==
        'knowledge-evidence-manifest.v1' ||
      manifest.classification !== 'accepted'
    )
  ) {
    throw new Error(
      'Full-gate manifest envelope is not accepted'
    );
  }
  if (
    capture &&
    (
      capture.schema_version !==
        'knowledge-release-gate-evidence.v1' ||
      capture.classification !== 'accepted'
    )
  ) {
    throw new Error(
      'Full-gate capture envelope is not accepted'
    );
  }
}

function packageSourceClosure() {
  const { entries } = buildPackageEntries(knowledgeRoot);
  const seen = new Set();
  const rows = entries.map((entry) => {
    const collision = entry.name.toLowerCase();
    if (seen.has(collision)) {
      throw new Error(
        `Package source has a colliding entry: ${entry.name}`
      );
    }
    seen.add(collision);
    const body = readEntryData(entry);
    return {
      path: entry.name,
      source_path: path.relative(
        knowledgeRoot,
        entry.abs
      ).replace(/\\/g, '/'),
      source_file_path: entry.abs,
      source_file_sha256: sha256File(entry.abs),
      bytes: body.length,
      sha256: sha256(body),
      body
    };
  });
  return {
    rows,
    files: rows.length,
    bytes: rows.reduce((sum, item) =>
      sum + item.bytes, 0),
    sha256: sha256(rows.map((item) =>
      `${item.path}\0${item.sha256}\n`).join(''))
  };
}

function verifyCandidateParity(
  candidateSha,
  closure = packageSourceClosure()
) {
  const validation = validateArtifact(candidatePath, {
    profile: 'public_runtime'
  });
  if (
    validation.status !== 'ok' ||
    !Array.isArray(validation.violations) ||
    validation.violations.length !== 0
  ) {
    throw new Error('Candidate ZIP failed public-runtime validation');
  }
  const archive = readZipEntries(candidatePath);
  if (archive.violations.length) {
    throw new Error(
      `Candidate ZIP structure is invalid: ${
        archive.violations.map((item) => item.type).join(', ')
      }`
    );
  }
  const zipByName = new Map();
  for (const entry of archive.entries) {
    if (zipByName.has(entry.name.toLowerCase())) {
      throw new Error(`Candidate ZIP entry collision: ${entry.name}`);
    }
    zipByName.set(entry.name.toLowerCase(), entry);
  }
  if (zipByName.size !== closure.rows.length) {
    throw new Error(
      `Candidate/source entry count mismatch: ${zipByName.size} != ${closure.rows.length}`
    );
  }
  for (const source of closure.rows) {
    const archived = zipByName.get(source.path.toLowerCase());
    if (
      !archived ||
      archived.name !== source.path ||
      archived.body.length !== source.bytes ||
      sha256(archived.body) !== source.sha256
    ) {
      throw new Error(
        `Candidate/source parity mismatch: ${source.path}`
      );
    }
  }
  return {
    schema_version: 'knowledge-candidate-source-parity.v1',
    generated_at: new Date().toISOString(),
    status: 'pass',
    profile: 'public_runtime',
    candidate_sha256: candidateSha,
    source_closure: {
      schema_version: 'knowledge-package-source-closure.v1',
      files: closure.files,
      bytes: closure.bytes,
      sha256: closure.sha256
    },
    zip: {
      entries: archive.entries.length,
      total_uncompressed_bytes:
        archive.total_uncompressed_bytes,
      violations: archive.violations
    },
    mapping:
      'package-release.js buildPackageEntries/readEntryData'
  };
}

function verifyFocused(runId, sourceClosureSha) {
  const expectedProducerClosure =
    canonicalReleaseProducerClosure();
  const pointerPath = path.join(focusedRoot, 'latest.json');
  const pointer = readJson(pointerPath);
  if (
    pointer.run_id !== runId ||
    pointer.status !== 'pass'
  ) {
    throw new Error('Focused pointer does not select the requested run');
  }
  const expectedRelative =
    `.knowledge/docs/release/3.3.0/test-evidence/repair-on-touch/runs/${runId}`;
  if (pointer.run_path !== expectedRelative) {
    throw new Error('Focused pointer run path is non-canonical');
  }
  const runRoot = path.join(focusedRoot, 'runs', runId);
  const focusedManifestPath = path.join(
    runRoot,
    'manifest.json'
  );
  if (
    sha256File(focusedManifestPath) !==
    pointer.manifest_sha256
  ) {
    throw new Error('Focused manifest/pointer SHA mismatch');
  }
  const checked = verifyManifest(
    runRoot,
    focusedManifestPath,
    { expectedRunId: runId }
  );
  if (!checked.verified.has('summary.json')) {
    throw new Error('Focused manifest does not bind summary.json');
  }
  const summaryPath = checked.verified.get(
    'summary.json'
  ).target;
  const summary = readJson(summaryPath);
  const producerPath = path.join(
    focusedRoot,
    'capture-focused-evidence.js'
  );
  const producer = verifyProducerBinding(
    summary.producer,
    producerPath,
    '.knowledge/docs/release/3.3.0/test-evidence/repair-on-touch/capture-focused-evidence.js'
  );
  const expectedIds = new Set([
    'repair-on-touch',
    'field-report',
    'recertify-lifecycle',
    'trust-transaction',
    'dedicated-verification',
    'repair-session-isolation',
    'adaptive-routing',
    'wiki-structural-status'
  ]);
  if (
    summary?.schema_version !==
      'knowledge-focused-test-evidence.v1' ||
    summary.run_id !== runId ||
    summary.status !== 'pass' ||
    summary.source_unchanged !== true ||
    summary.model_execution?.performed !== false ||
    summary.source_fingerprint_before?.sha256 !==
      sourceClosureSha ||
    summary.source_fingerprint_after?.sha256 !==
      sourceClosureSha ||
    JSON.stringify(summary.producer_closure) !==
      JSON.stringify(expectedProducerClosure) ||
    summary.producer_source_unchanged !== true ||
    summary.producer_closure_after_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    pointer.source_sha256 !== sourceClosureSha ||
    !Array.isArray(summary.tests) ||
    summary.tests.length !== expectedIds.size
  ) {
    throw new Error('Focused summary semantic contract failed');
  }
  for (const test of summary.tests) {
    if (
      !expectedIds.delete(test.id) ||
      test.exit_code !== 0 ||
      test.signal !== null ||
      test.structured_json !== true ||
      test.contract_passed !== true
    ) {
      throw new Error(`Focused test contract failed: ${test.id}`);
    }
    const entrypoint = safeRegular(
      releaseSource,
      test.entrypoint.path
    );
    if (sha256File(entrypoint) !== test.entrypoint.sha256) {
      throw new Error(
        `Focused entrypoint drifted: ${test.entrypoint.path}`
      );
    }
  }
  if (expectedIds.size) {
    throw new Error('Focused suite is missing required test IDs');
  }
  return {
    run_id: runId,
    producer,
    pointer: record(pointerPath),
    manifest: record(focusedManifestPath),
    summary: record(summaryPath)
  };
}

function verifyFullGate(runId, candidateSha) {
  const indexPath = path.join(gateRoot, 'index.json');
  const index = readJson(indexPath);
  assertFullGateEnvelopeSchemas(index);
  const indexed = (index.runs || []).filter((item) =>
    item.run_id === runId);
  if (
    indexed.length !== 1 ||
    indexed[0].classification !== 'accepted' ||
    indexed[0].status !== 'pass' ||
    indexed[0].mode !== 'full' ||
    indexed[0].artifact_sha256 !== candidateSha
  ) {
    throw new Error('Requested full gate is not uniquely accepted');
  }
  const runRoot = path.join(gateRoot, 'runs', runId);
  const fullManifestPath = path.join(
    runRoot,
    'manifest.json'
  );
  if (
    sha256File(fullManifestPath) !==
    indexed[0].manifest_sha256
  ) {
    throw new Error('Full-gate manifest/index SHA mismatch');
  }
  const checked = verifyManifest(
    runRoot,
    fullManifestPath,
    { expectedRunId: runId }
  );
  for (const required of [
    'report.json',
    'capture.json'
  ]) {
    if (!checked.verified.has(required)) {
      throw new Error(`Full-gate manifest misses ${required}`);
    }
  }
  const reportPath = checked.verified.get('report.json').target;
  const capturePath = checked.verified.get('capture.json').target;
  const report = readJson(reportPath);
  const capture = readJson(capturePath);
  assertFullGateEnvelopeSchemas(
    index,
    checked.manifest,
    capture
  );
  const expectedStepPlan = canonicalFullEvidencePlan();
  const expectedProducerClosure =
    canonicalReleaseProducerClosure();
  if (
    indexed[0].step_plan_sha256 !== expectedStepPlan.sha256 ||
    indexed[0].producer_closure_sha256 !==
      expectedProducerClosure.aggregate_sha256
  ) {
    throw new Error(
      'Full-gate index plan/producer binding failed'
    );
  }
  const stepIds = (report.steps || []).map((item) => item.id);
  const expectedStepIds = expectedStepPlan.steps.map(
    (item) => item.id
  );
  const captureProducerPath = path.join(
    gateRoot,
    'capture-release-gate-evidence.js'
  );
  const captureProducer = verifyProducerBinding(
    capture.producer,
    captureProducerPath,
    '.knowledge/docs/release/3.3.0/test-evidence/release-gates/capture-release-gate-evidence.js'
  );
  assertAcceptedGateReport(
    report,
    expectedStepPlan,
    expectedProducerClosure
  );
  if (
    report.run_id !== runId ||
    report.status !== 'pass' ||
    report.mode !== 'full' ||
    report.artifact_sha256 !== candidateSha ||
    !Array.isArray(report.failures) ||
    report.failures.length !== 0 ||
    !Array.isArray(report.skipped) ||
    report.skipped.length !== 0 ||
    !Array.isArray(report.steps) ||
    report.steps.some((item) =>
      item.status !== 'pass' || item.exit_code !== 0) ||
    JSON.stringify(stepIds) !==
      JSON.stringify(expectedStepIds) ||
    JSON.stringify(report.step_plan) !==
      JSON.stringify(expectedStepPlan) ||
    JSON.stringify(report.producer_closure) !==
      JSON.stringify(expectedProducerClosure) ||
    report.producer_source_unchanged !== true ||
    report.producer_closure_after_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    capture.run_id !== runId ||
    capture.gate_status !== 'pass' ||
    capture.gate_mode !== 'full' ||
    JSON.stringify(capture.producer_closure) !==
      JSON.stringify(expectedProducerClosure) ||
    capture.producer_source_unchanged !== true ||
    capture.producer_closure_after_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    capture.steps !== expectedStepIds.length ||
    capture.step_plan_sha256 !== expectedStepPlan.sha256 ||
    capture.producer_closure_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    capture.artifact?.sha256 !== candidateSha ||
    capture.artifact?.matches_report !== true
  ) {
    throw new Error('Full-gate semantic contract failed');
  }
  const expectedLogs = [];
  for (const step of report.steps) {
    const streamBodies = {};
    for (const stream of [
      'stdout',
      'stderr',
      'decision'
    ]) {
      const field = `${stream}_path`;
      const relative = String(step[field] || '')
        .replace(/\\/g, '/');
      const prefix =
        `docs/release/3.3.0/test-evidence/release-gates/runs/${runId}/`;
      if (!relative.startsWith(prefix)) {
        throw new Error(
          `Full-gate ${step.id} ${field} is non-canonical`
        );
      }
      const manifestRelative = relative.slice(prefix.length);
      const entry = checked.verified.get(manifestRelative);
      if (!entry) {
        throw new Error(
          `Full-gate manifest misses ${manifestRelative}`
        );
      }
      const body = readStableRegularFile(
        entry.target
      );
      assertStepLogHash(step, stream, body);
      streamBodies[stream] = body;
      expectedLogs.push({
        step_id: step.id,
        stream,
        path: manifestRelative,
        bytes: entry.bytes,
        sha256: entry.sha256
      });
    }
    assertSourceBootstrapLogCorrelation(
      step,
      streamBodies.stdout,
      streamBodies.stderr
    );
    assertSyntheticStepLogCorrelation(
      step,
      streamBodies.stdout,
      streamBodies.stderr
    );
    assertStepDecisionCorrelation(
      step,
      streamBodies.decision
    );
  }
  if (
    JSON.stringify(capture.step_logs) !==
      JSON.stringify(expectedLogs)
  ) {
    throw new Error('Full-gate step log binding failed');
  }
  const expectedFlowLogs = [];
  const capturedFlowLogs = Array.isArray(
    capture.supporting_flow_logs
  )
    ? capture.supporting_flow_logs
    : [];
  for (const step of report.steps) {
    const binding = step.flow_log_evidence;
    if (!binding) continue;
    const rows = capturedFlowLogs.filter(
      (item) => item?.step_id === step.id
    );
    if (rows.length !== 1) {
      throw new Error(
        `Full-gate ${step.id} flow-log capture is not unique`
      );
    }
    const row = rows[0];
    const capturedPath = String(
      row.captured_path || ''
    ).replace(/\\/g, '/');
    if (
      !capturedPath.startsWith(
        'supporting/flow-logs/'
      ) ||
      capturedPath.split('/').includes('..')
    ) {
      throw new Error(
        `Full-gate ${step.id} flow-log capture path is invalid`
      );
    }
    const entry = checked.verified.get(capturedPath);
    if (
      row.source_path !== binding.path ||
      row.bytes !== binding.bytes ||
      row.sha256 !== binding.sha256 ||
      !entry ||
      entry.bytes !== binding.bytes ||
      entry.sha256 !== binding.sha256
    ) {
      throw new Error(
        `Full-gate ${step.id} flow-log binding failed`
      );
    }
    expectedFlowLogs.push({
      step_id: step.id,
      source_path: binding.path,
      captured_path: capturedPath,
      bytes: binding.bytes,
      sha256: binding.sha256
    });
  }
  if (
    JSON.stringify(capturedFlowLogs) !==
      JSON.stringify(expectedFlowLogs)
  ) {
    throw new Error(
      'Full-gate supporting flow-log set is not exact'
    );
  }
  const producerFiles = expectedProducerClosure.files.map(
    (item) => {
      const filePath = path.join(
        knowledgeRoot,
        ...item.path.split('/')
      );
      const current = record(filePath);
      if (
        current.bytes !== item.bytes ||
        current.sha256 !== item.sha256
      ) {
        throw new Error(
          `Full-gate producer drifted: ${item.path}`
        );
      }
      return current;
    }
  );
  return {
    run_id: runId,
    producers: [captureProducer, ...producerFiles],
    index: record(indexPath),
    manifest: record(fullManifestPath),
    report: record(reportPath),
    capture: record(capturePath)
  };
}

function runtimePreservationProofOk(
  proof,
  expectedSource
) {
  if (
    !isPlainObject(proof) ||
    proof.status !== 'preserved' ||
    proof.proof_source !== expectedSource ||
    proof.hash_set_unchanged !== true ||
    typeof proof.backup_path !== 'string' ||
    proof.backup_path.length === 0
  ) {
    return false;
  }
  for (const [listKey, countKey] of [
    ['changed_files', 'changed_files_count'],
    ['removed_files', 'removed_files_count'],
    ['added_files', 'added_files_count']
  ]) {
    if (
      !Array.isArray(proof[listKey]) ||
      proof[listKey].length !== 0 ||
      proof[countKey] !== 0
    ) {
      return false;
    }
  }
  if (
    !Array.isArray(proof.required_paths) ||
    proof.required_paths.length !==
      EXACT_RUNTIME_REQUIRED_PATHS.length ||
    JSON.stringify(
      Array.from(new Set(proof.required_paths)).sort()
    ) !==
      JSON.stringify([...EXACT_RUNTIME_REQUIRED_PATHS].sort()) ||
    !Array.isArray(proof.paths) ||
    proof.paths.length !== EXACT_RUNTIME_REQUIRED_PATHS.length
  ) {
    return false;
  }
  const expectedPathSet = new Set(
    EXACT_RUNTIME_REQUIRED_PATHS
  );
  const seen = new Set();
  for (const row of proof.paths) {
    if (
      !isPlainObject(row) ||
      JSON.stringify(Object.keys(row).sort()) !==
        JSON.stringify([
          'added_files',
          'after_files',
          'backup_exists',
          'before_files',
          'changed_files',
          'current_exists',
          'path',
          'removed_files'
        ]) ||
      !expectedPathSet.has(row.path) ||
      seen.has(row.path) ||
      typeof row.backup_exists !== 'boolean' ||
      typeof row.current_exists !== 'boolean' ||
      row.backup_exists !== row.current_exists ||
      !Number.isSafeInteger(row.before_files) ||
      row.before_files < 0 ||
      (!row.backup_exists && row.before_files !== 0) ||
      row.after_files !== row.before_files ||
      !Array.isArray(row.changed_files) ||
      row.changed_files.length !== 0 ||
      !Array.isArray(row.removed_files) ||
      row.removed_files.length !== 0 ||
      !Array.isArray(row.added_files) ||
      row.added_files.length !== 0
    ) {
      return false;
    }
    seen.add(row.path);
  }
  if (expectedSource === 'reconstructed_legacy_backup') {
    const reconstructedAt = new Date(proof.reconstructed_at);
    return (
      Number.isFinite(reconstructedAt.getTime()) &&
      reconstructedAt.toISOString() ===
        proof.reconstructed_at &&
      proof.legacy_report_schema_version === '3.2.11' &&
      proof.legacy_report_phase === 'apply'
    );
  }
  return expectedSource ===
    'previous_update_report_revalidated';
}

function runtimeProofProvenanceOk(
  provenance,
  proof,
  expectedApplyReportSha
) {
  const reconstructedAt = new Date(
    provenance?.reconstructed_at
  );
  return Boolean(
    isPlainObject(provenance) &&
    provenance.schema_version ===
      'knowledge-runtime-proof-provenance.v1' &&
    provenance.source ===
      'reconstructed_legacy_backup' &&
    Number.isFinite(reconstructedAt.getTime()) &&
    reconstructedAt.toISOString() ===
      provenance.reconstructed_at &&
    /^[a-f0-9]{64}$/.test(
      String(
        provenance
          .apply_report_sha256_before_enrichment || ''
      )
    ) &&
    provenance.apply_report_sha256_before_enrichment ===
      expectedApplyReportSha &&
    provenance.backup_path === proof?.backup_path
  );
}

function runtimeProofCheckOk(verify, expectedSource) {
  const rows = Array.isArray(verify?.checks)
    ? verify.checks.filter((row) =>
        row?.check ===
          'runtime_evidence_preservation_proof')
    : [];
  if (rows.length !== 1) return false;
  const row = rows[0];
  return Boolean(
    row.status === 'pass' &&
    row.proof_source === expectedSource &&
    Array.isArray(row.validation_errors) &&
    row.validation_errors.length === 0 &&
    row.changed_files === 0 &&
    row.removed_files === 0 &&
    row.added_files === 0 &&
    (expectedSource === 'reconstructed_legacy_backup'
      ? (
          row.recovery_status === 'reconstructed' &&
          row.recovery_reason === null &&
          row.validation_status === null &&
          row.validation_reason === null
        )
      : (
          row.recovery_status === null &&
          row.recovery_reason === null &&
          row.validation_status === 'revalidated' &&
          row.validation_reason === null
        ))
  );
}

function exactUpgradeCommandSemanticOk(label, parsed) {
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    Array.isArray(parsed) ||
    parsed.status !== 'ok' ||
    parsed.source_version !== '3.3.0'
  ) {
    return false;
  }
  const expected = {
    '01-old-updater-dry-run': {
      schema: '3.2.11',
      phase: 'dry_run',
      installed: '3.2.11'
    },
    '02-old-updater-preflight': {
      schema: '3.2.11',
      phase: 'preflight',
      installed: '3.2.11'
    },
    '03-old-updater-apply': {
      schema: '3.2.11',
      phase: 'apply',
      installed: '3.3.0'
    },
    '04-new-updater-verify': {
      schema: '3.3.0',
      phase: 'verify_upgrade',
      installed: '3.3.0'
    },
    '05-new-updater-verify-repeat': {
      schema: '3.3.0',
      phase: 'verify_upgrade',
      installed: '3.3.0'
    }
  }[label];
  if (
    !expected ||
    parsed.schema_version !== expected.schema ||
    parsed.phase !== expected.phase ||
    parsed.mode !== expected.phase ||
    parsed.installed_version !== expected.installed
  ) {
    return false;
  }
  if (
    ['02-old-updater-preflight', '03-old-updater-apply']
      .includes(label) &&
    parsed.permission_preflight?.status !== 'ok'
  ) {
    return false;
  }
  if (
    label === '03-old-updater-apply' &&
    Object.prototype.hasOwnProperty.call(
      parsed,
      'runtime_preservation_proof'
    )
  ) {
    return false;
  }
  if (label === '04-new-updater-verify') {
    const proof = parsed.runtime_preservation_proof;
    return (
      runtimePreservationProofOk(
        proof,
        'reconstructed_legacy_backup'
      ) &&
      JSON.stringify(
        parsed.verify?.runtime_preservation_proof
      ) === JSON.stringify(proof) &&
      parsed.verify?.runtime_proof_source ===
        'reconstructed_legacy_backup' &&
      runtimeProofCheckOk(
        parsed.verify,
        'reconstructed_legacy_backup'
      ) &&
      parsed.verify?.legacy_recovery?.status ===
        'reconstructed' &&
      JSON.stringify(
        parsed.verify.legacy_recovery.proof
      ) === JSON.stringify(proof)
    );
  }
  if (label === '05-new-updater-verify-repeat') {
    const proof = parsed.runtime_preservation_proof;
    return (
      runtimePreservationProofOk(
        proof,
        'previous_update_report_revalidated'
      ) &&
      JSON.stringify(
        parsed.verify?.runtime_preservation_proof
      ) === JSON.stringify(proof) &&
      parsed.verify?.runtime_proof_source ===
        'previous_update_report_revalidated' &&
      runtimeProofCheckOk(
        parsed.verify,
        'previous_update_report_revalidated'
      ) &&
      parsed.verify?.legacy_recovery === null &&
      parsed.verify?.runtime_proof_validation?.status ===
        'revalidated' &&
      parsed.verify.runtime_proof_validation.reason ===
        null &&
      JSON.stringify(
        parsed.verify.runtime_proof_validation.proof
      ) === JSON.stringify(proof)
    );
  }
  return true;
}

function verifyExactFileBinding(
  checked,
  binding,
  expectedPath
) {
  if (
    !isPlainObject(binding) ||
    JSON.stringify(Object.keys(binding).sort()) !==
      JSON.stringify(['bytes', 'path', 'sha256']) ||
    binding.path !== expectedPath ||
    !Number.isSafeInteger(binding.bytes) ||
    binding.bytes < 0 ||
    !/^[a-f0-9]{64}$/.test(binding.sha256)
  ) {
    throw new Error(
      `Exact-upgrade file binding is invalid: ${expectedPath}`
    );
  }
  const entry = checked.verified.get(expectedPath);
  if (
    !entry ||
    entry.bytes !== binding.bytes ||
    entry.sha256 !== binding.sha256
  ) {
    throw new Error(
      `Exact-upgrade manifest binding failed: ${expectedPath}`
    );
  }
  return record(entry.target);
}

function updaterShaFromZip(zipPath) {
  const archive = readZipEntries(zipPath);
  if (archive.violations.length) {
    throw new Error(
      `Updater source ZIP is invalid: ${path.basename(zipPath)}`
    );
  }
  const updater = archive.entries.find((entry) =>
    entry.name === '.knowledge/tools/update-system-files.js');
  if (!updater) {
    throw new Error(
      `Updater entrypoint missing from ${path.basename(zipPath)}`
    );
  }
  return sha256(updater.body);
}

function persistedApplyReportOk(
  value,
  proofExpected,
  expectedApplyReportSha = null
) {
  if (
    !isPlainObject(value) ||
    value.schema_version !== '3.2.11' ||
    value.status !== 'ok' ||
    value.phase !== 'apply' ||
    value.mode !== 'apply' ||
    value.source_version !== '3.3.0' ||
    value.installed_version !== '3.3.0' ||
    typeof value.backup_path !== 'string' ||
    value.backup_path.length === 0
  ) {
    return false;
  }
  if (!proofExpected) {
    return !Object.prototype.hasOwnProperty.call(
      value,
      'runtime_preservation_proof'
    ) &&
      !Object.prototype.hasOwnProperty.call(
        value,
        'runtime_proof_provenance'
      );
  }
  return (
    runtimePreservationProofOk(
      value.runtime_preservation_proof,
      'reconstructed_legacy_backup'
    ) &&
    runtimeProofProvenanceOk(
      value.runtime_proof_provenance,
      value.runtime_preservation_proof,
      expectedApplyReportSha
    ) &&
    value.backup_path ===
      value.runtime_preservation_proof.backup_path
  );
}

function comparableRuntimeProofPayload(proof) {
  return {
    status: proof.status,
    backup_path: proof.backup_path,
    required_paths: [...proof.required_paths].sort(),
    paths: proof.paths.map((row) => ({
      path: row.path,
      backup_exists: row.backup_exists,
      current_exists: row.current_exists,
      before_files: row.before_files,
      after_files: row.after_files,
      changed_files: [...row.changed_files],
      removed_files: [...row.removed_files],
      added_files: [...row.added_files]
    })).sort((left, right) =>
      left.path < right.path
        ? -1
        : left.path > right.path
          ? 1
          : 0),
    changed_files: [...proof.changed_files],
    changed_files_count: proof.changed_files_count,
    removed_files: [...proof.removed_files],
    removed_files_count: proof.removed_files_count,
    added_files: [...proof.added_files],
    added_files_count: proof.added_files_count,
    hash_set_unchanged: proof.hash_set_unchanged
  };
}

function exactRuntimeProofChainOk({
  firstVerify,
  repeatVerify,
  afterApply,
  afterFirst,
  afterRepeat,
  afterApplySha
}) {
  if (
    !exactUpgradeCommandSemanticOk(
      '04-new-updater-verify',
      firstVerify
    ) ||
    !exactUpgradeCommandSemanticOk(
      '05-new-updater-verify-repeat',
      repeatVerify
    ) ||
    !persistedApplyReportOk(afterApply, false) ||
    !persistedApplyReportOk(
      afterFirst,
      true,
      afterApplySha
    ) ||
    !persistedApplyReportOk(
      afterRepeat,
      true,
      afterApplySha
    )
  ) {
    return false;
  }
  return Boolean(
    afterApply.backup_path === afterFirst.backup_path &&
    afterFirst.backup_path === afterRepeat.backup_path &&
    JSON.stringify(afterFirst) ===
      JSON.stringify(afterRepeat) &&
    firstVerify?.backup_path === afterFirst.backup_path &&
    JSON.stringify(
      firstVerify?.runtime_preservation_proof
    ) === JSON.stringify(
      afterFirst.runtime_preservation_proof
    ) &&
    repeatVerify?.backup_path ===
      afterFirst.backup_path &&
    repeatVerify.runtime_preservation_proof
      .backup_path === afterFirst.backup_path &&
    JSON.stringify(comparableRuntimeProofPayload(
      repeatVerify.runtime_preservation_proof
    )) === JSON.stringify(comparableRuntimeProofPayload(
      afterFirst.runtime_preservation_proof
    ))
  );
}

function operatorProfileCanaryOk(value) {
  const canary = value?.upgrade_preservation_probe;
  return Boolean(
    isPlainObject(canary) &&
    JSON.stringify(Object.keys(canary).sort()) ===
      JSON.stringify(['expected', 'source']) &&
    canary.source === 'public-3.2.11-exact-asset' &&
    canary.expected === 'unchanged'
  );
}

function exactUpgradePathOk(value) {
  return value === '3.2.11 -> 3.3.0';
}

function verifyExactStateArtifacts(checked, report) {
  const before = verifyExactFileBinding(
    checked,
    report.operator_profile_before,
    'raw/state/operator-profile.before.json'
  );
  const after = verifyExactFileBinding(
    checked,
    report.operator_profile_after,
    'raw/state/operator-profile.after.json'
  );
  const afterApply = verifyExactFileBinding(
    checked,
    report.persisted_apply_report_after_apply,
    'raw/state/update-report.after-apply.json'
  );
  const afterFirst = verifyExactFileBinding(
    checked,
    report.persisted_apply_report_after_first_verify,
    'raw/state/update-report.after-first-verify.json'
  );
  const afterRepeat = verifyExactFileBinding(
    checked,
    report.persisted_apply_report_after_repeat,
    'raw/state/update-report.after-repeat.json'
  );
  const executionContext = verifyExactFileBinding(
    checked,
    report.execution_context,
    'raw/state/execution-context.json'
  );
  if (
    !isPlainObject(report.updater_entrypoints) ||
    JSON.stringify(Object.keys(report.updater_entrypoints).sort()) !==
      JSON.stringify([
        'candidate_3_3_0',
        'installed_3_3_0',
        'old_3_2_11'
      ])
  ) {
    throw new Error('Exact-upgrade updater binding set is invalid');
  }
  const oldUpdater = verifyExactFileBinding(
    checked,
    report.updater_entrypoints.old_3_2_11,
    'raw/updaters/3.2.11-update-system-files.source.txt'
  );
  const candidateUpdater = verifyExactFileBinding(
    checked,
    report.updater_entrypoints.candidate_3_3_0,
    'raw/updaters/3.3.0-candidate-update-system-files.source.txt'
  );
  const installedUpdater = verifyExactFileBinding(
    checked,
    report.updater_entrypoints.installed_3_3_0,
    'raw/updaters/3.3.0-installed-update-system-files.source.txt'
  );
  const beforeObject = readJson(
    checked.verified.get(
      'raw/state/operator-profile.before.json'
    ).target
  );
  const afterObject = readJson(
    checked.verified.get(
      'raw/state/operator-profile.after.json'
    ).target
  );
  const applyObject = readJson(
    checked.verified.get(
      'raw/state/update-report.after-apply.json'
    ).target
  );
  const firstObject = readJson(
    checked.verified.get(
      'raw/state/update-report.after-first-verify.json'
    ).target
  );
  const repeatObject = readJson(
    checked.verified.get(
      'raw/state/update-report.after-repeat.json'
    ).target
  );
  const contextObject = readJson(
    checked.verified.get(
      'raw/state/execution-context.json'
    ).target
  );
  if (
    before.sha256 !== after.sha256 ||
    JSON.stringify(beforeObject) !== JSON.stringify(afterObject) ||
    !operatorProfileCanaryOk(beforeObject) ||
    !operatorProfileCanaryOk(afterObject) ||
    report.operator_profile_sha256_before !== before.sha256 ||
    report.operator_profile_sha256_after !== after.sha256 ||
    report.persisted_apply_report_sha256_after_apply !==
      afterApply.sha256 ||
    report.persisted_apply_report_sha256_after_first_verify !==
      afterFirst.sha256 ||
    report.persisted_apply_report_sha256_after_repeat !==
      afterRepeat.sha256 ||
    afterFirst.sha256 !== afterRepeat.sha256 ||
    JSON.stringify(firstObject) !== JSON.stringify(repeatObject) ||
    !persistedApplyReportOk(applyObject, false) ||
    !persistedApplyReportOk(
      firstObject,
      true,
      afterApply.sha256
    ) ||
    !persistedApplyReportOk(
      repeatObject,
      true,
      afterApply.sha256
    ) ||
    applyObject.backup_path !== firstObject.backup_path ||
    firstObject.backup_path !== repeatObject.backup_path
  ) {
    throw new Error(
      'Exact-upgrade persisted state contract failed'
    );
  }
  const baselineUpdaterSha = updaterShaFromZip(baselinePath);
  const candidateUpdaterSha = updaterShaFromZip(candidatePath);
  if (
    oldUpdater.sha256 !== baselineUpdaterSha ||
    candidateUpdater.sha256 !== candidateUpdaterSha ||
    installedUpdater.sha256 !== candidateUpdaterSha ||
    oldUpdater.sha256 === installedUpdater.sha256
  ) {
    throw new Error(
      'Exact-upgrade updater entrypoint provenance failed'
    );
  }
  if (
    !isPlainObject(report.runtime) ||
    JSON.stringify(Object.keys(report.runtime).sort()) !==
      JSON.stringify([
        'arch',
        'node_executable',
        'node_executable_sha256',
        'node_version',
        'platform'
      ]) ||
    !isPlainObject(contextObject) ||
    JSON.stringify(Object.keys(contextObject).sort()) !==
      JSON.stringify([
        'candidate_knowledge',
        'cwd',
        'runtime',
        'schema_version',
        'updater_entrypoints'
      ]) ||
    contextObject.schema_version !==
      'knowledge-exact-upgrade-execution-context.v1' ||
    JSON.stringify(contextObject.runtime) !==
      JSON.stringify(report.runtime) ||
    JSON.stringify(contextObject.updater_entrypoints) !==
      JSON.stringify(report.updater_entrypoints) ||
    physicalIdentity(report.runtime.node_executable) !==
      physicalIdentity(process.execPath) ||
    report.runtime.node_executable_sha256 !==
      sha256File(process.execPath) ||
    report.runtime.node_version !== process.version ||
    report.runtime.platform !== process.platform ||
    report.runtime.arch !== process.arch
  ) {
    throw new Error(
      'Exact-upgrade execution context contract failed'
    );
  }
  return {
    operator_profile_before: before,
    operator_profile_after: after,
    persisted_apply_report_after_apply: afterApply,
    persisted_apply_report_after_first_verify: afterFirst,
    persisted_apply_report_after_repeat: afterRepeat,
    execution_context: executionContext,
    updater_entrypoints: {
      old_3_2_11: oldUpdater,
      candidate_3_3_0: candidateUpdater,
      installed_3_3_0: installedUpdater
    },
    context: contextObject,
    persisted_values: {
      after_apply: applyObject,
      after_first: firstObject,
      after_repeat: repeatObject
    }
  };
}

function exactCommandRecordOk(
  label,
  result,
  state
) {
  const started = new Date(result.started_at);
  const completed = new Date(result.completed_at);
  const expectedArgs = {
    '01-old-updater-dry-run': [
      '--from',
      state.context.candidate_knowledge,
      '--json',
      '--dry-run'
    ],
    '02-old-updater-preflight': [
      '--from',
      state.context.candidate_knowledge,
      '--json',
      '--preflight'
    ],
    '03-old-updater-apply': [
      '--from',
      state.context.candidate_knowledge,
      '--json',
      '--apply',
      '--yes'
    ],
    '04-new-updater-verify': [
      '--verify-upgrade',
      '--from',
      state.context.candidate_knowledge,
      '--json'
    ],
    '05-new-updater-verify-repeat': [
      '--verify-upgrade',
      '--from',
      state.context.candidate_knowledge,
      '--json'
    ]
  }[label];
  const old = label.startsWith('0') &&
    ['01', '02', '03'].includes(label.slice(0, 2));
  const expectedEntrypointSha = old
    ? state.updater_entrypoints.old_3_2_11.sha256
    : state.updater_entrypoints.installed_3_3_0.sha256;
  const updaterPath = path.join(
    state.context.cwd,
    '.knowledge',
    'tools',
    'update-system-files.js'
  );
  const runtime = {
    node_version: state.context.runtime.node_version,
    platform: state.context.runtime.platform,
    arch: state.context.runtime.arch,
    exec_path: state.context.runtime.node_executable,
    exec_sha256:
      state.context.runtime.node_executable_sha256
  };
  return Boolean(
    isPlainObject(result) &&
    result.schema_version === 'knowledge-evidenced-command.v1' &&
    result.label === label &&
    Array.isArray(result.command) &&
    JSON.stringify(result.command) === JSON.stringify([
      state.context.runtime.node_executable,
      updaterPath,
      ...expectedArgs
    ]) &&
    path.isAbsolute(result.cwd) &&
    result.cwd === state.context.cwd &&
    path.resolve(
      path.dirname(result.cwd),
      'candidate',
      '.knowledge'
    ) === state.context.candidate_knowledge &&
    result.entrypoint_sha256 === expectedEntrypointSha &&
    JSON.stringify(result.runtime) === JSON.stringify(runtime) &&
    Number.isSafeInteger(result.duration_ms) &&
    result.duration_ms >= 0 &&
    Number.isFinite(started.getTime()) &&
    Number.isFinite(completed.getTime()) &&
    started.toISOString() === result.started_at &&
    completed.toISOString() === result.completed_at &&
    completed.getTime() - started.getTime() ===
      result.duration_ms
  );
}

function verifyExactUpgrade(runId, candidateSha, baselineSha) {
  const expectedProducerClosure =
    canonicalReleaseProducerClosure();
  if (!/^exact-upgrade-[A-Za-z0-9._-]+$/.test(runId)) {
    throw new Error('Exact-upgrade run ID is invalid');
  }
  const runRoot = path.join(gateRoot, runId);
  const exactManifestPath = path.join(
    runRoot,
    'sha-manifest.json'
  );
  const checked = verifyManifest(runRoot, exactManifestPath);
  if (!checked.verified.has('report.json')) {
    throw new Error('Exact-upgrade manifest misses report.json');
  }
  const reportPath = checked.verified.get('report.json').target;
  const report = readJson(reportPath);
  const producerPath = path.join(
    gateRoot,
    'capture-exact-upgrade.js'
  );
  const producer = verifyProducerBinding(
    report.producer,
    producerPath,
    '.knowledge/docs/release/3.3.0/test-evidence/release-gates/capture-exact-upgrade.js'
  );
  const commands = [
    '01-old-updater-dry-run',
    '02-old-updater-preflight',
    '03-old-updater-apply',
    '04-new-updater-verify',
    '05-new-updater-verify-repeat'
  ];
  if (
    report?.schema_version !==
      'knowledge-public-upgrade-evidence.v2' ||
    report.status !== 'pass' ||
    !exactUpgradePathOk(report.public_upgrade_path) ||
    report.baseline?.path !== path.basename(baselinePath) ||
    report.baseline?.bytes !== fs.statSync(baselinePath).size ||
    report.baseline?.sha256 !== baselineSha ||
    report.candidate?.path !== path.basename(candidatePath) ||
    report.candidate?.bytes !== fs.statSync(candidatePath).size ||
    report.candidate?.sha256 !== candidateSha ||
    JSON.stringify(report.producer_closure) !==
      JSON.stringify(expectedProducerClosure) ||
    report.producer_source_unchanged !== true ||
    report.producer_closure_after_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    !Array.isArray(report.failed_assertions) ||
    report.failed_assertions.length !== 0 ||
    !exactTrueAssertions(report.assertions) ||
    JSON.stringify(report.commands) !== JSON.stringify(commands)
  ) {
    throw new Error('Exact-upgrade semantic contract failed');
  }
  const state = verifyExactStateArtifacts(checked, report);
  const commandStdout = new Map();
  for (const label of commands) {
    const resultPath = `raw/${label}.result.json`;
    const resultEntry = checked.verified.get(resultPath);
    if (!resultEntry) {
      throw new Error(`Exact-upgrade manifest misses ${resultPath}`);
    }
    const result = readJson(resultEntry.target);
    if (
      result.label !== label ||
      result.schema_version !==
        'knowledge-evidenced-command.v1' ||
      result.exit_code !== 0 ||
      result.signal !== null ||
      result.error !== null ||
      !exactCommandRecordOk(label, result, state)
    ) {
      throw new Error(`Exact-upgrade command failed: ${label}`);
    }
    let stdoutEntry = null;
    for (const stream of ['stdout', 'stderr']) {
      const expectedStreamPath = stream === 'stdout'
        ? `raw/${label}.stdout.json`
        : `raw/${label}.stderr.txt`;
      if (result[stream]?.path !== expectedStreamPath) {
        throw new Error(
          `Exact-upgrade ${label} ${stream} path is non-canonical`
        );
      }
      const streamEntry = checked.verified.get(
        result[stream]?.path
      );
      if (
        !streamEntry ||
        streamEntry.bytes !== result[stream].bytes ||
        streamEntry.sha256 !== result[stream].sha256
      ) {
        throw new Error(
          `Exact-upgrade ${label} ${stream} binding failed`
        );
      }
      if (stream === 'stdout') stdoutEntry = streamEntry;
    }
    let parsedStdout;
    try {
      parsedStdout = readJson(stdoutEntry.target);
    } catch (error) {
      throw new Error(
        `Exact-upgrade ${label} stdout is invalid JSON: ${error.message}`
      );
    }
    if (!exactUpgradeCommandSemanticOk(label, parsedStdout)) {
      throw new Error(
        `Exact-upgrade ${label} semantic contract failed`
      );
    }
    commandStdout.set(label, parsedStdout);
  }
  if (
    !exactRuntimeProofChainOk({
      firstVerify: commandStdout.get(
        '04-new-updater-verify'
      ),
      repeatVerify: commandStdout.get(
        '05-new-updater-verify-repeat'
      ),
      afterApply: state.persisted_values.after_apply,
      afterFirst: state.persisted_values.after_first,
      afterRepeat: state.persisted_values.after_repeat,
      afterApplySha:
        state.persisted_apply_report_after_apply.sha256
    })
  ) {
    throw new Error(
      'Exact-upgrade runtime proof chain binding failed'
    );
  }
  return {
    run_id: runId,
    producer,
    manifest: record(exactManifestPath),
    report: record(reportPath),
    state_artifacts: {
      operator_profile_before: state.operator_profile_before,
      operator_profile_after: state.operator_profile_after,
      persisted_apply_report_after_apply:
        state.persisted_apply_report_after_apply,
      persisted_apply_report_after_first_verify:
        state.persisted_apply_report_after_first_verify,
      persisted_apply_report_after_repeat:
        state.persisted_apply_report_after_repeat,
      execution_context: state.execution_context,
      updater_entrypoints: state.updater_entrypoints
    }
  };
}

function verifySmoke(
  smokeRunId,
  fullRunId,
  candidateSha
) {
  const expectedProducerClosure =
    canonicalReleaseProducerClosure();
  const pointerPath = path.join(
    gateRoot,
    'final-artifact-smoke.json'
  );
  const pointer = readJson(pointerPath);
  if (
    pointer.run_id !== smokeRunId ||
    pointer.source_full_gate_run_id !== fullRunId ||
    pointer.status !== 'pass' ||
    pointer.candidate_sha256 !== candidateSha
  ) {
    throw new Error('Final smoke pointer contract failed');
  }
  const manifestFile = safeRegular(
    knowledgeRoot,
    pointer.manifest_path
  );
  const summaryFile = safeRegular(
    knowledgeRoot,
    pointer.summary_path
  );
  if (
    sha256File(manifestFile) !== pointer.manifest_sha256 ||
    sha256File(summaryFile) !== pointer.summary_sha256
  ) {
    throw new Error('Final smoke pointer hashes drifted');
  }
  const checked = verifyManifest(
    path.dirname(manifestFile),
    manifestFile,
    { expectedRunId: smokeRunId }
  );
  if (
    checked.verified.get('summary.json')?.sha256 !==
      pointer.summary_sha256
  ) {
    throw new Error('Final smoke manifest does not bind summary');
  }
  const summary = readJson(summaryFile);
  const producerPath = path.join(
    gateRoot,
    'capture-final-artifact-smoke.js'
  );
  const producer = verifyProducerBinding(
    summary.producer,
    producerPath,
    '.knowledge/docs/release/3.3.0/test-evidence/release-gates/capture-final-artifact-smoke.js'
  );
  if (
    summary?.schema_version !==
      'knowledge-final-artifact-smoke-summary.v2' ||
    summary.source_full_gate?.run_id !== fullRunId ||
    JSON.stringify(summary.producer_closure) !==
      JSON.stringify(expectedProducerClosure) ||
    summary.producer_source_unchanged !== true ||
    summary.producer_closure_after_sha256 !==
      expectedProducerClosure.aggregate_sha256 ||
    summary.candidate?.sha256 !== candidateSha ||
    summary.artifact_validation?.status !== 'ok' ||
    summary.artifact_validation?.profile !==
      'public_runtime' ||
    !Array.isArray(summary.artifact_validation?.violations) ||
    summary.artifact_validation.violations.length !== 0 ||
    summary.clean_install_conformance?.status !== 'pass' ||
    summary.clean_install_conformance?.exit_code !== 0 ||
    !Array.isArray(
      summary.clean_install_conformance?.failures
    ) ||
    summary.clean_install_conformance.failures.length !== 0
  ) {
    throw new Error('Final smoke summary semantic contract failed');
  }
  return {
    run_id: smokeRunId,
    producer,
    pointer: record(pointerPath),
    manifest: record(manifestFile),
    summary: record(summaryFile)
  };
}

function addPublicationGuard(
  guards,
  filePath,
  expectedSha256,
  containmentRoot = releaseWorkspace
) {
  const target = path.resolve(filePath);
  const stat = fs.lstatSync(target);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(
      `Publication guard is not a regular file: ${target}`
    );
  }
  const observed = sha256File(target);
  if (observed !== expectedSha256) {
    throw new Error(
      `Publication guard drifted before commit: ${target}`
    );
  }
  const key = physicalIdentity(target);
  const prior = guards.get(key);
  if (prior && prior.expected_sha256 !== expectedSha256) {
    throw new Error(
      `Publication guard has conflicting hashes: ${target}`
    );
  }
  guards.set(key, {
    path: target,
    containmentRoot,
    expected_sha256: expectedSha256
  });
}

function addMissingPublicationGuard(
  guards,
  filePath,
  containmentRoot = releaseWorkspace
) {
  const target = path.resolve(filePath);
  const key = physicalIdentity(target);
  const prior = guards.get(key);
  if (prior && prior.expected_exists !== false) {
    throw new Error(
      `Publication guard has conflicting presence: ${target}`
    );
  }
  guards.set(key, {
    path: target,
    containmentRoot,
    expected_exists: false
  });
}

function buildPublicationGuards({
  publicationTreeSha256,
  producerClosure,
  packageClosure,
  manifestFiles,
  historicalFieldManifestSnapshots,
  candidate,
  baseline
}) {
  const guards = new Map();
  for (const item of producerClosure.files) {
    addPublicationGuard(
      guards,
      path.join(knowledgeRoot, ...item.path.split('/')),
      item.sha256
    );
  }
  for (const item of packageClosure.rows) {
    addPublicationGuard(
      guards,
      item.source_file_path,
      item.source_file_sha256
    );
  }
  for (const item of manifestFiles) {
    const source = recordSources.get(item);
    if (source) {
      addPublicationGuard(guards, source, item.sha256);
    }
  }
  for (const snapshot of historicalFieldManifestSnapshots) {
    if (snapshot.exists) {
      addPublicationGuard(
        guards,
        snapshot.file_path,
        snapshot.manifest.sha256
      );
    } else {
      addMissingPublicationGuard(
        guards,
        snapshot.file_path
      );
    }
  }
  addPublicationGuard(guards, candidatePath, candidate.sha256);
  addPublicationGuard(guards, baselinePath, baseline.sha256);
  return [
    {
      kind: 'tree',
      path: knowledgeRoot,
      containmentRoot: knowledgeRoot,
      expected_sha256: publicationTreeSha256,
      excluded_paths: EVIDENCE_PUBLICATION_TREE_EXCLUSIONS
    },
    ...Array.from(guards.values())
  ];
}

function commitEvidencePublication({
  stateRoot,
  containmentRoot,
  transactionId,
  writes,
  guards,
  faultAt = null
}) {
  try {
    return commitJsonTransaction({
      stateRoot,
      transactionId,
      writes,
      guards,
      metadata: {
        kind: 'knowledge-evidence-pack-publication',
        schema_version: 'knowledge-evidence-publication.v1'
      },
      faultAt,
      allowedContainmentRoots: [containmentRoot]
    });
  } catch (error) {
    try {
      recoverEvidencePublications({
        stateRoot,
        containmentRoot,
        transactionIdPrefixes: [transactionId]
      });
    } catch (recoveryError) {
      const failure = new Error(
        `Evidence publication failed and recovery was not completed: ${recoveryError.message}`
      );
      failure.code =
        'evidence_publication_recovery_failed';
      failure.commit_error_code = error.code || null;
      failure.recovery_error_code =
        recoveryError.code || null;
      throw failure;
    }
    throw error;
  }
}

function recoverEvidencePublications({
  stateRoot,
  containmentRoot,
  transactionIdPrefixes = [
    EVIDENCE_TRANSACTION_PREFIX
  ]
}) {
  return recoverTransactions(stateRoot, {
    transactionIdPrefixes,
    allowedContainmentRoots: [containmentRoot]
  });
}

function withEvidencePublicationLock(
  fn,
  lockPath = evidencePublicationLockPath,
  options = {}
) {
  return withLock(lockPath, fn, options);
}

function finalizeEvidencePackUnlocked() {
  // Capture the complete physical input tree first while the publication
  // lock is held. Every narrower producer/package/evidence snapshot below is
  // invalidated if an includable file is added, removed, or changed later.
  const publicationTreeSha256 =
    treeGuardHash(
      knowledgeRoot,
      EVIDENCE_PUBLICATION_TREE_EXCLUSIONS
    );
  const finalizerProducerClosureBefore =
    canonicalReleaseProducerClosure();
  const args = parseArgs(process.argv.slice(2));
  for (const required of [
    'focused-run',
    'full-run',
    'exact-run',
    'smoke-run'
  ]) {
    if (!args[required]) {
      throw new Error(
        `Evidence finalization requires --${required}`
      );
    }
  }
  const candidate = record(candidatePath);
  const baseline = record(baselinePath, releaseWorkspace);
  if (baseline.sha256 !== PINNED_3211_SHA256) {
    throw new Error(
      `Pinned 3.2.11 baseline SHA mismatch: ${baseline.sha256}`
    );
  }
  const packageClosureBefore = packageSourceClosure();
  const parity = verifyCandidateParity(
    candidate.sha256,
    packageClosureBefore
  );
  const parityBinding = recordJsonValue(parityPath, parity);
  const focused = verifyFocused(
    args['focused-run'],
    parity.source_closure.sha256
  );
  const fullGate = verifyFullGate(
    args['full-run'],
    candidate.sha256
  );
  const exact = verifyExactUpgrade(
    args['exact-run'],
    candidate.sha256,
    baseline.sha256
  );
  const smoke = verifySmoke(
    args['smoke-run'],
    args['full-run'],
    candidate.sha256
  );

  const reportNames = [
    'audit-findings-matrix.md',
    'decision-log.md',
    'model-ab-report.md',
    'junior-model-adjudication.md',
    'claims-evidence-matrix.md',
    'known-limitations.md',
    'reproduction-guide.md',
    'github-release-post.md',
    'github-announcement-short.md',
    'release-readiness.md'
  ];
  const reports = reportNames.map((name) =>
    record(path.join(releaseDocs, name)));
  const historicalFieldManifestPaths = [
    path.join(
      releaseWorkspace,
      'field-tests',
      '3.3.0',
      'retest-fixes-black-box',
      'evidence',
      'sha-manifest'
    ),
    path.join(
      releaseWorkspace,
      'field-tests',
      '3.3.0',
      'retest-novice-clean',
      'evidence',
      'sha-manifest.json'
    ),
    path.join(
      releaseWorkspace,
      'field-tests',
      '3.3.0',
      'persona-5-team-windows',
      'sanitized-public',
      'sha-manifest.json'
    )
  ];
  const historicalFieldManifestSnapshots =
    historicalFieldManifestPaths.map((filePath) => {
      if (!fs.existsSync(filePath)) {
        return {
          file_path: filePath,
          exists: false,
          manifest: null
        };
      }
      return {
        file_path: filePath,
        exists: true,
        manifest: record(filePath, releaseWorkspace)
      };
    });
  const historicalFieldManifests =
    historicalFieldManifestSnapshots
      .filter((snapshot) => snapshot.exists)
      .map((snapshot) => ({
      classification:
        'historical_advisory_unbound_to_final_candidate',
      manifest: snapshot.manifest
    }));

  const publicationTransactionId =
    `${EVIDENCE_TRANSACTION_PREFIX}${crypto.randomUUID()}`;
  const pack = {
    schema_version: 'knowledge-3.3.0-evidence-pack.v2',
    generated_at: new Date().toISOString(),
    release_status: 'BLOCKED',
    publication_authorized: false,
    publication_transaction_id: publicationTransactionId,
    public_predecessor: {
      version: '3.2.11',
      pinned_sha256: PINNED_3211_SHA256,
      asset: baseline
    },
    candidate,
    candidate_source_parity: parityBinding,
    finalization_producer: {
      path:
        '.knowledge/docs/release/3.3.0/finalize-evidence-pack.js',
      sha256: sha256File(__filename)
    },
    producer_closure: finalizerProducerClosureBefore,
    producer_source_unchanged: true,
    producer_closure_after_sha256:
      finalizerProducerClosureBefore.aggregate_sha256,
    focused,
    full_gate: fullGate,
    exact_public_upgrade: exact,
    final_artifact_smoke: smoke,
    historical_field_evidence: historicalFieldManifests,
    reports,
    model_study: {
      required_sessions: 72,
      measured_sessions: 0,
      claims_allowed: false
    },
    integrity_scope: {
      content_addressing:
        'local content integrity and replay identity',
      not_proven:
        'human/model authorship, cryptographic signature, or organizational reviewer independence'
    },
    blockers: [
      'evidence-grade model study remains 0/72; comparative benefit claims are not allowed',
      'owner-authorized real GitHub Field Report publication canary is absent',
      'native Linux/macOS and Node 18/20 physical evidence is absent'
    ]
  };
  const outputBinding = recordJsonValue(outputPath, pack);

  const manifestFiles = [
    outputBinding,
    parityBinding,
    ...reports,
    focused.pointer,
    focused.manifest,
    focused.summary,
    fullGate.index,
    fullGate.manifest,
    fullGate.report,
    fullGate.capture,
    exact.manifest,
    exact.report,
    exact.state_artifacts.operator_profile_before,
    exact.state_artifacts.operator_profile_after,
    exact.state_artifacts.persisted_apply_report_after_apply,
    exact.state_artifacts.persisted_apply_report_after_first_verify,
    exact.state_artifacts.persisted_apply_report_after_repeat,
    exact.state_artifacts.execution_context,
    ...Object.values(exact.state_artifacts.updater_entrypoints),
    smoke.pointer,
    smoke.manifest,
    smoke.summary,
    ...fullGate.producers,
    record(__filename),
    record(path.join(
      focusedRoot,
      'capture-focused-evidence.js'
    )),
    record(path.join(
      gateRoot,
      'capture-release-gate-evidence.js'
    )),
    record(path.join(
      gateRoot,
      'capture-exact-upgrade.js'
    )),
    record(path.join(
      gateRoot,
      'capture-final-artifact-smoke.js'
    ))
  ];
  const unique = new Map();
  const collisionMap = new Map();
  for (const item of manifestFiles) {
    const collision = item.path
      .normalize('NFC')
      .toLowerCase();
    const priorPath = collisionMap.get(collision);
    if (priorPath && priorPath !== item.path) {
      throw new Error(
        `Evidence manifest path collision: ${priorPath} / ${item.path}`
      );
    }
    collisionMap.set(collision, item.path);
    const prior = unique.get(item.path);
    if (
      prior &&
      (
        prior.bytes !== item.bytes ||
        prior.sha256 !== item.sha256
      )
    ) {
      throw new Error(
        `Evidence manifest duplicate drift: ${item.path}`
      );
    }
    unique.set(item.path, item);
  }
  const files = Array.from(unique.values())
    .sort((a, b) => a.path.localeCompare(b.path));
  const manifest = {
    schema_version: 'knowledge-evidence-manifest.v1',
    generated_at: new Date().toISOString(),
    release_status: 'BLOCKED',
    publication_transaction_id: publicationTransactionId,
    files,
    aggregate_sha256: sha256(files.map((item) =>
      `${item.path}\0${item.sha256}\n`).join(''))
  };
  const guards = buildPublicationGuards({
    publicationTreeSha256,
    producerClosure: finalizerProducerClosureBefore,
    packageClosure: packageClosureBefore,
    manifestFiles,
    historicalFieldManifestSnapshots,
    candidate,
    baseline
  });
  const publication = commitEvidencePublication({
    stateRoot: knowledgeRoot,
    containmentRoot: releaseWorkspace,
    transactionId: publicationTransactionId,
    writes: [
      {
        path: outputPath,
        value: pack,
        containmentRoot: releaseWorkspace
      },
      {
        path: parityPath,
        value: parity,
        containmentRoot: releaseWorkspace
      },
      {
        path: manifestPath,
        value: manifest,
        containmentRoot: releaseWorkspace
      }
    ],
    guards
  });
  if (
    publication.status !== 'committed' ||
    sha256File(outputPath) !== outputBinding.sha256 ||
    sha256File(parityPath) !== parityBinding.sha256 ||
    sha256File(manifestPath) !==
      sha256(`${JSON.stringify(manifest, null, 2)}\n`)
  ) {
    throw new Error(
      'Evidence publication transaction did not commit all targets'
    );
  }
  console.log(JSON.stringify({
    status: 'ok',
    release_status: pack.release_status,
    candidate_sha256: candidate.sha256,
    source_closure_sha256:
      parity.source_closure.sha256,
    focused_run_id: focused.run_id,
    full_gate_run_id: fullGate.run_id,
    exact_upgrade_run_id: exact.run_id,
    smoke_run_id: smoke.run_id,
    publication_transaction_id: publicationTransactionId,
    evidence_pack_sha256: sha256File(outputPath),
    manifest_sha256: sha256File(manifestPath)
  }, null, 2));
}

function main() {
  return withEvidencePublicationLock(() => {
    recoverEvidencePublications({
      stateRoot: knowledgeRoot,
      containmentRoot: releaseWorkspace
    });
    return finalizeEvidencePackUnlocked();
  });
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
  __test: {
    EXACT_UPGRADE_ASSERTION_KEYS,
    EXACT_RUNTIME_REQUIRED_PATHS,
    EVIDENCE_PUBLICATION_TREE_EXCLUSIONS,
    exactTrueAssertions,
    exactUpgradeCommandSemanticOk,
    runtimePreservationProofOk,
    runtimeProofProvenanceOk,
    runtimeProofCheckOk,
    exactCommandRecordOk,
    persistedApplyReportOk,
    exactRuntimeProofChainOk,
    operatorProfileCanaryOk,
    exactUpgradePathOk,
    commitEvidencePublication,
    recoverEvidencePublications,
    withEvidencePublicationLock,
    assertFullGateEnvelopeSchemas
  }
};
