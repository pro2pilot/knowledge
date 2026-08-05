'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const RELEASE_PACKAGE_VERSION = JSON.parse(
  fs.readFileSync(
    path.resolve(
      __dirname,
      '..',
      '..',
      'package.json'
    ),
    'utf8'
  )
).version;

function sha256(value) {
  return crypto.createHash('sha256')
    .update(value)
    .digest('hex');
}

function physical(value) {
  const resolved = path.resolve(value);
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function readStableRegularFile(filePath, options = {}) {
  const target = path.resolve(filePath);
  const label = path.basename(target);
  const maxBytes = Number(
    options.maxBytes || 64 * 1024 * 1024
  );
  const noFollow = Number(fs.constants.O_NOFOLLOW || 0);
  let handle = null;
  try {
    const initial = fs.lstatSync(target, { bigint: true });
    if (
      !initial.isFile() ||
      initial.isSymbolicLink() ||
      initial.nlink !== 1n ||
      physical(fs.realpathSync(target)) !== physical(target)
    ) {
      throw new Error(
        `Evidence source is not one physical regular file: ${label}`
      );
    }
    handle = fs.openSync(
      target,
      fs.constants.O_RDONLY | noFollow
    );
    const before = fs.fstatSync(handle, { bigint: true });
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.nlink !== 1n ||
      initial.dev !== before.dev ||
      initial.ino !== before.ino ||
      initial.size !== before.size ||
      initial.mtimeNs !== before.mtimeNs ||
      initial.ctimeNs !== before.ctimeNs ||
      before.size > BigInt(maxBytes)
    ) {
      throw new Error(
        `Evidence source is not a bounded regular file: ${label}`
      );
    }
    const body = fs.readFileSync(handle);
    const after = fs.fstatSync(handle, { bigint: true });
    const live = fs.lstatSync(target, { bigint: true });
    if (
      !after.isFile() ||
      !live.isFile() ||
      live.isSymbolicLink() ||
      after.nlink !== 1n ||
      live.nlink !== 1n ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      BigInt(body.length) !== after.size ||
      after.dev !== live.dev ||
      after.ino !== live.ino ||
      after.size !== live.size ||
      after.mtimeNs !== live.mtimeNs ||
      after.ctimeNs !== live.ctimeNs ||
      physical(fs.realpathSync(target)) !== physical(target)
    ) {
      throw new Error(
        `Evidence source changed while it was read: ${label}`
      );
    }
    return body;
  } finally {
    if (handle !== null) fs.closeSync(handle);
  }
}

function assertStepLogHash(step, stream, body) {
  const field = `${stream}_sha256`;
  const expected = String(step?.[field] || '')
    .toLowerCase();
  const actual = sha256(body);
  if (
    !/^[a-f0-9]{64}$/.test(expected) ||
    expected !== actual
  ) {
    throw new Error(
      `release gate step ${step?.id || 'unknown'} ${field} does not match its physical stream`
    );
  }
  return actual;
}

function parseObject(body, label) {
  let value;
  try {
    value = JSON.parse(body.toString('utf8'));
  } catch (error) {
    throw new Error(
      `${label} is invalid JSON: ${error.message}`
    );
  }
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function stepWithoutDecisionBinding(step) {
  const value = { ...step };
  for (const field of [
    'decision_path',
    'decision_sha256'
  ]) {
    delete value[field];
  }
  return value;
}

function assertStepDecisionCorrelation(step, decisionBody) {
  const payload = parseObject(
    decisionBody,
    `release gate step ${step?.id || 'unknown'} decision`
  );
  if (
    canonicalJson(Object.keys(payload).sort()) !==
      canonicalJson(['schema_version', 'step']) ||
    payload.schema_version !==
      'release-gate-step-decision.v1' ||
    canonicalJson(payload.step) !==
      canonicalJson(stepWithoutDecisionBinding(step))
  ) {
    throw new Error(
      `release gate step ${step?.id || 'unknown'} decision stream disagrees with the step report`
    );
  }
}

function assertSyntheticStepLogCorrelation(
  step,
  stdoutBody,
  stderrBody
) {
  if (
    !['spark-battle-report', 'memory-battle-report']
      .includes(String(step?.id || ''))
  ) {
    return;
  }
  const payload = parseObject(
    stdoutBody,
    `${step.id} stdout`
  );
  const expectedKeys = ['schema_version', 'step'];
  const semanticStep = { ...step };
  for (const field of [
    'stdout_path',
    'stderr_path',
    'stdout_sha256',
    'stderr_sha256',
    'stdout_tail',
    'stderr_tail',
    'decision_path',
    'decision_sha256'
  ]) {
    delete semanticStep[field];
  }
  const errors = Array.isArray(step.json_contract_errors)
    ? step.json_contract_errors
    : [];
  if (
    canonicalJson(Object.keys(payload).sort()) !==
      canonicalJson(expectedKeys) ||
    payload.schema_version !==
      'release-gate-validator-step-stream.v1' ||
    canonicalJson(payload.step) !==
      canonicalJson(semanticStep) ||
    stderrBody.toString('utf8') !== errors.join('; ')
  ) {
    throw new Error(
      `${step.id} streams disagree with the step report`
    );
  }
}

function assertAcceptedGateReport(
  report,
  canonicalStepPlan,
  producerClosure
) {
  const valid = (
    report?.schema_version ===
      'release-gate-report.v2' &&
    report.package_version ===
      RELEASE_PACKAGE_VERSION &&
    report.status === 'pass' &&
    report.mode === 'full' &&
    Array.isArray(report.failures) &&
    report.failures.length === 0 &&
    Array.isArray(report.skipped) &&
    report.skipped.length === 0 &&
    Array.isArray(report.steps) &&
    report.steps.every((step) =>
      step?.status === 'pass' &&
      step.exit_code === 0 &&
      Array.isArray(step.json_contract_errors) &&
      step.json_contract_errors.length === 0
    ) &&
    report.producer_source_unchanged === true &&
    JSON.stringify(report.step_plan) ===
      JSON.stringify(canonicalStepPlan) &&
    JSON.stringify(
      report.steps.map((item) => item.id)
    ) === JSON.stringify(
      canonicalStepPlan.steps.map((item) => item.id)
    ) &&
    JSON.stringify(report.producer_closure) ===
      JSON.stringify(producerClosure) &&
    report.producer_closure_after_sha256 ===
      producerClosure.aggregate_sha256
  );
  if (!valid) {
    throw new Error(
      'Only a passing full release gate can be classified accepted'
    );
  }
}

function assertSourceBootstrapLogCorrelation(
  step,
  stdoutBody,
  stderrBody
) {
  if (step?.id !== 'source-bootstrap') return;
  if (step.bootstrap_action === 'noop') {
    const payload = parseObject(
      stdoutBody,
      'source-bootstrap stdout'
    );
    const expectedKeys = [
      'bootstrap_action',
      'errors',
      'project_index_path',
      'status'
    ];
    if (
      JSON.stringify(Object.keys(payload).sort()) !==
        JSON.stringify(expectedKeys)
    ) {
      throw new Error(
        'source-bootstrap noop stdout has unexpected fields'
      );
    }
    const errors = Array.isArray(step.json_contract_errors)
      ? step.json_contract_errors
      : [];
    if (
      payload.status !== step.status ||
      payload.status !== step.json_status ||
      payload.bootstrap_action !== step.bootstrap_action ||
      payload.project_index_path !== step.project_index_path ||
      JSON.stringify(payload.errors) !==
        JSON.stringify(errors) ||
      stderrBody.toString('utf8') !== errors.join('; ')
    ) {
      throw new Error(
        'source-bootstrap noop streams disagree with the step report'
      );
    }
    return;
  }
  if (step.bootstrap_action !== 'ingest') {
    throw new Error(
      'source-bootstrap report has an unknown bootstrap action'
    );
  }
  const stepErrors = Array.isArray(
    step.json_contract_errors
  )
    ? step.json_contract_errors
    : [];
  if (step.status === 'fail') {
    if (
      !Number.isInteger(step.exit_code) ||
      step.exit_code === 0 ||
      stepErrors.length === 0
    ) {
      throw new Error(
        'source-bootstrap failed ingest lacks a nonzero decision and errors'
      );
    }
    return;
  }
  const payload = parseObject(
    stdoutBody,
    'source-bootstrap stdout'
  );
  const expectedKeys = [
    'auto_track',
    'generated_at',
    'ignored_source_checkouts',
    'mode',
    'modules_detected',
    'modules_total',
    'root_module',
    'routing_bundle',
    'search_documents',
    'technologies'
  ];
  const nonNegativeInteger = (value) =>
    Number.isInteger(value) && value >= 0;
  const autoTrack = payload.auto_track;
  const autoTrackOk = (
    autoTrack &&
    typeof autoTrack === 'object' &&
    !Array.isArray(autoTrack) &&
    typeof autoTrack.enabled === 'boolean' &&
    nonNegativeInteger(autoTrack.limit) &&
    nonNegativeInteger(autoTrack.added) &&
    nonNegativeInteger(autoTrack.considered) &&
    typeof autoTrack.capped === 'boolean' &&
    nonNegativeInteger(autoTrack.tracked_total)
  );
  if (
    JSON.stringify(Object.keys(payload).sort()) !==
      JSON.stringify(expectedKeys) ||
    !Number.isFinite(Date.parse(payload.generated_at || '')) ||
    payload.mode !== 'merge' ||
    !nonNegativeInteger(payload.modules_detected) ||
    !nonNegativeInteger(payload.modules_total) ||
    payload.modules_total < payload.modules_detected ||
    typeof payload.root_module !== 'boolean' ||
    !Array.isArray(payload.ignored_source_checkouts) ||
    !payload.ignored_source_checkouts.every(
      (item) => typeof item === 'string'
    ) ||
    !Array.isArray(payload.technologies) ||
    !payload.technologies.every(
      (item) => typeof item === 'string'
    ) ||
    !(
      payload.routing_bundle === null ||
      typeof payload.routing_bundle === 'string'
    ) ||
    !(
      payload.search_documents === null ||
      nonNegativeInteger(payload.search_documents)
    ) ||
    !autoTrackOk ||
    step.status !== 'pass' ||
    step.exit_code !== 0 ||
    step.json_status !== null ||
    step.project_index_path !== 'project_index.json' ||
    stepErrors.length !== 0 ||
    stderrBody.length !== 0
  ) {
    throw new Error(
      'source-bootstrap ingest streams disagree with the producer contract'
    );
  }
}

module.exports = {
  assertAcceptedGateReport,
  assertSourceBootstrapLogCorrelation,
  assertStepDecisionCorrelation,
  assertStepLogHash,
  assertSyntheticStepLogCorrelation,
  readStableRegularFile,
  sha256
};
