#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { ensureDir, stripBom, writeJsonAtomic } = require('./lib/json-store');
const { parseCliArgs } = require('./lib/path-context');
const { inspectSemanticJson, isExpectedRow, parseJsonOutput } = require('./lib/semantic-json');
const {
  readStableRegularFile,
  sha256: evidenceSha256
} = require('./lib/release-step-evidence');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const version = pkg.version || '3.3.0';
const artifactRel = process.env.KNOWLEDGE_RELEASE_ARTIFACT_REL || `dist/knowledge-v${version}.zip`;
if (!/^dist\/knowledge-v\d+\.\d+\.\d+(?:-step\d+-rc\d+(?:-r\d+)?)?\.zip$/.test(artifactRel)) {
  throw new Error(`Invalid KNOWLEDGE_RELEASE_ARTIFACT_REL: ${artifactRel}`);
}
const durableGateRoot = path.join(
  root,
  'docs',
  'release',
  version,
  'test-evidence',
  'release-gates'
);
const SPARK_TRACE_SCHEMA = 'knowledge-spark-command-trace.v1';
const SPARK_COVERAGE_AREAS = Object.freeze([
  'trust_layer',
  'inspector',
  'updater',
  'mem0_local',
  'pinecone_offline',
  'pinecone_live_local'
]);
const SPARK_COVERAGE_COMMAND_PATTERNS = Object.freeze({
  trust_layer: /(doctor|routing|search-knowledge|flow)/i,
  inspector: /inspector/i,
  updater: /(check-updates|update-system-files|self-test-update|\bupdater?\b)/i,
  mem0_local: /(memory-mem0|\bmem0\b)/i,
  pinecone_offline: /(memory-pinecone|\bpinecone\b)/i,
  pinecone_live_local: /(memory-pinecone|\bpinecone\b)/i
});

function sanitizeText(value) {
  return String(value || '')
    .replace(/[A-Z]:\\(?:Users\\[^\s"',}\\]+|MyProject)[^\s"',}]+/gi, '<local-path>')
    .replace(/\/mnt\/data[^\s"',}]*/gi, '<local-path>')
    .replace(/\/tmp\/knowledge[^\s"',}]*/gi, '<local-path>')
    .replace(/Users\\[^\\\s"',}]+/gi, 'Users\\<local-user>')
    .replace(/Users\/[^\/\s"',}]+/gi, 'Users/<local-user>')
    .replace(new RegExp(`knowledge${'-'}kit`, 'gi'), 'workspace');
}

function safeId(value) {
  return String(value || 'step').toLowerCase().replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'step';
}

function relPath(absPath) {
  return path.relative(root, absPath).replace(/\\/g, '/');
}

function comparablePath(value) {
  const resolved = path.resolve(String(value || ''));
  return process.platform === 'win32'
    ? resolved.toLowerCase()
    : resolved;
}

function canonicalReleaseEnv(
  extra = {},
  ambient = process.env,
  releaseContext = {}
) {
  const knowledgeRoot = path.resolve(
    releaseContext.knowledgeRoot || root
  );
  const targetRoot = path.resolve(
    releaseContext.targetRoot ||
      path.dirname(knowledgeRoot)
  );
  const systemRoot = path.resolve(
    releaseContext.systemRoot ||
      knowledgeRoot
  );
  const env = {
    ...ambient,
    ...extra
  };
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
    if (controlledKeys.has(key.toUpperCase())) {
      delete env[key];
    }
  }
  return {
    ...env,
    KNOWLEDGE_MODE: 'repo',
    KNOWLEDGE_SYSTEM_ROOT: systemRoot,
    KNOWLEDGE_TARGET_ROOT: targetRoot,
    KNOWLEDGE_AGENT_ID: String(
      extra.KNOWLEDGE_AGENT_ID ||
        'release-gate'
    ),
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '0',
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1'
  };
}

function sha256IfExists(filePath) {
  return fs.existsSync(filePath) ? crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex') : null;
}

function isSha256(value) {
  return /^[a-f0-9]{64}$/i.test(String(value || ''));
}

function isRecord(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function stableCanonicalStringify(value) {
  if (value === null || value === undefined) return 'null';
  if (Array.isArray(value)) return `[${value.map((item) => stableCanonicalStringify(item)).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableCanonicalStringify(value[key])}`)
      .join(',')}}`;
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonical observation contains a non-finite number');
    return String(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  throw new Error(`canonical observation contains unsupported type ${typeof value}`);
}

const RELEASE_CODE_EXTENSIONS = new Set([
  '.js',
  '.cjs',
  '.mjs',
  '.ps1',
  '.vbs'
]);

function collectReleaseCodeFiles(relativeDir, output) {
  const absoluteDir = path.join(
    root,
    ...relativeDir.split('/')
  );
  const directoryStat = fs.lstatSync(absoluteDir);
  if (
    !directoryStat.isDirectory() ||
    directoryStat.isSymbolicLink()
  ) {
    throw new Error(
      `Release code root is not a physical directory: ${relativeDir}`
    );
  }
  for (const entry of fs.readdirSync(
    absoluteDir,
    { withFileTypes: true }
  )) {
    const relative = `${relativeDir}/${entry.name}`
      .replace(/\\/g, '/');
    if (entry.isSymbolicLink()) {
      throw new Error(
        `Release code closure contains a link: ${relative}`
      );
    }
    if (entry.isDirectory()) {
      collectReleaseCodeFiles(relative, output);
    } else if (
      entry.isFile() &&
      RELEASE_CODE_EXTENSIONS.has(
        path.extname(entry.name).toLowerCase()
      )
    ) {
      output.add(relative);
    }
  }
}

function releaseProducerClosureFromSpecs(specs = []) {
  const producerFiles = new Set([
    'inspector.js',
    'open-inspector.vbs',
    'package.json',
    'release-policy.json'
  ]);
  for (const codeRoot of [
    'tools',
    'benchmarks',
    'docs/release/3.3.0'
  ]) {
    collectReleaseCodeFiles(codeRoot, producerFiles);
  }
  for (const spec of specs) {
    const entrypoint = String(spec?.args?.[0] || '')
      .replace(/\\/g, '/');
    if (
      entrypoint &&
      !path.posix.isAbsolute(entrypoint) &&
      !entrypoint.split('/').includes('..') &&
      /^[a-z0-9_./-]+\.js$/i.test(entrypoint)
    ) {
      if (!producerFiles.has(entrypoint)) {
        throw new Error(
          `Release step entrypoint is outside the producer closure: ${entrypoint}`
        );
      }
    }
  }
  const files = Array.from(producerFiles)
    .sort()
    .map((relative) => {
    const target = path.resolve(
      root,
      ...relative.split('/')
    );
    const stat = fs.lstatSync(target);
    const actual = path.resolve(fs.realpathSync(target));
    const expectedIdentity = process.platform === 'win32'
      ? target.toLowerCase()
      : target;
    const actualIdentity = process.platform === 'win32'
      ? actual.toLowerCase()
      : actual;
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      actualIdentity !== expectedIdentity
    ) {
      throw new Error(
        `Release producer is not a physical file: ${relative}`
      );
    }
    const body = fs.readFileSync(target);
    return {
      path: relative,
      bytes: body.length,
      sha256: crypto.createHash('sha256')
        .update(body)
        .digest('hex')
    };
  });
  return {
    schema_version:
      'knowledge-release-gate-producer-closure.v1',
    files,
    aggregate_sha256: crypto.createHash('sha256')
      .update(files.map((item) =>
        `${item.path}\0${item.sha256}\n`).join(''))
      .digest('hex')
  };
}

function releaseProducerClosure(mode = 'full', flags = {}) {
  return releaseProducerClosureFromSpecs(
    modeSteps(mode, flags)
  );
}

function canonicalFullEvidencePlan() {
  return buildReleaseStepPlan(
    'full',
    { ignoreAmbientEvidence: true }
  );
}

function canonicalReleaseProducerClosure() {
  return releaseProducerClosure(
    'full',
    { ignoreAmbientEvidence: true }
  );
}

function buildReleaseStepPlanFromSpecs(mode, specs) {
  const plan = {
    schema_version: 'knowledge-release-gate-step-plan.v1',
    mode: String(mode || '').toLowerCase(),
    steps: specs.map((spec) => ({
      id: spec.id,
      kind: spec.special ? 'special' : 'command',
      special: spec.special || null,
      command: spec.special
        ? null
        : spec.command === process.execPath
          ? 'process.exec_path'
          : path.basename(spec.command || ''),
      args: Array.isArray(spec.args) ? spec.args : [],
      timeout_ms: spec.timeoutMs ?? null,
      expect_json: spec.special
        ? null
        : spec.expectJson !== false,
      allowed_statuses:
        spec.allowedStatuses || null,
      required_fields:
        spec.requiredFields || null,
      semantic_checks: spec.special
        ? null
        : spec.semanticChecks !== false,
      allow_failures_array:
        Boolean(spec.allowFailuresArray),
      flow_log_evidence:
        Boolean(spec.flowLogEvidence),
      requires: Array.isArray(spec.requires)
        ? spec.requires
        : []
    }))
  };
  return {
    ...plan,
    sha256: crypto.createHash('sha256')
      .update(stableCanonicalStringify(plan))
      .digest('hex')
  };
}

function buildReleaseStepPlan(mode, flags = {}) {
  return buildReleaseStepPlanFromSpecs(
    mode,
    modeSteps(mode, flags)
  );
}

function canonicalObservationSha256(value, label, errors) {
  if (!isRecord(value)) {
    errors.push(`${label} canonical_observation must be a JSON object`);
    return null;
  }
  try {
    return crypto.createHash('sha256').update(stableCanonicalStringify(value)).digest('hex');
  } catch (error) {
    errors.push(`${label} canonical_observation cannot be hashed: ${error.message}`);
    return null;
  }
}

function portableRelativePath(value) {
  const raw = String(value || '').trim();
  if (!raw || raw.includes('\0') || /^[A-Za-z]:/.test(raw) || path.posix.isAbsolute(raw) || path.win32.isAbsolute(raw)) return null;
  const normalized = path.posix.normalize(raw.replace(/\\/g, '/'));
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../')) return null;
  return normalized;
}

function isContainedPath(basePath, candidatePath) {
  const relative = path.relative(basePath, candidatePath);
  return Boolean(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function validateHashedEvidenceFile(baseDir, relativePath, expectedSha256, label, errors) {
  const portablePath = portableRelativePath(relativePath);
  if (!portablePath) {
    errors.push(`${label} must use a contained relative path`);
    return null;
  }
  const absolutePath = path.resolve(baseDir, ...portablePath.split('/'));
  if (!isContainedPath(path.resolve(baseDir), absolutePath)) {
    errors.push(`${label} escapes its evidence directory`);
    return null;
  }
  if (!fs.existsSync(absolutePath)) {
    errors.push(`${label} does not exist: ${portablePath}`);
    return null;
  }
  let body;
  try {
    body = readStableRegularFile(absolutePath);
  } catch (error) {
    errors.push(`${label} cannot be read safely: ${error.message}`);
    return null;
  }
  if (body.length <= 0) errors.push(`${label} must not be empty`);
  try {
    const realBase = fs.realpathSync(baseDir);
    const realFile = fs.realpathSync(absolutePath);
    if (!isContainedPath(realBase, realFile)) {
      errors.push(`${label} resolves outside its evidence directory`);
      return null;
    }
  } catch (error) {
    errors.push(`${label} real path cannot be inspected: ${error.message}`);
    return null;
  }
  const actualSha256 = evidenceSha256(body);
  if (!isSha256(expectedSha256)) errors.push(`${label} is missing a valid SHA-256`);
  else if (actualSha256 !== String(expectedSha256).toLowerCase()) errors.push(`${label} SHA-256 does not match`);
  return {
    absolutePath,
    portablePath,
    actualSha256,
    body
  };
}

function validateSparkCommandTrace(baseDir, row, expected, label, errors, seenTracePaths) {
  const evidence = validateHashedEvidenceFile(
    baseDir,
    row?.log_path,
    row?.log_sha256,
    `${label} trace`,
    errors
  );
  if (!evidence) return null;
  if (seenTracePaths) {
    if (seenTracePaths.has(evidence.portablePath)) {
      errors.push(`${label} reuses trace path ${evidence.portablePath}`);
    }
    seenTracePaths.add(evidence.portablePath);
  }

  let trace = null;
  try {
    trace = JSON.parse(stripBom(evidence.body.toString('utf8')));
  } catch (error) {
    errors.push(`${label} trace is not valid JSON: ${error.message}`);
    return null;
  }
  if (!isRecord(trace)) {
    errors.push(`${label} trace must be a JSON object`);
    return null;
  }
  if (trace.schema_version !== SPARK_TRACE_SCHEMA) {
    errors.push(`${label} trace schema_version must be ${SPARK_TRACE_SCHEMA}`);
  }

  const stringBindings = [
    ['command_id', trace.command_id, expected.command_id],
    ['case_id', trace.case_id, expected.case_id],
    ['scenario', trace.scenario, expected.scenario],
    ['coverage_area', trace.coverage_area, expected.coverage_area],
    ['arm', trace.arm, expected.arm],
    ['command', trace.command, expected.command],
    ['semantic_outcome', trace.semantic_outcome, expected.semantic_outcome]
  ];
  for (const [field, actual, wanted] of stringBindings) {
    if (!String(wanted || '').trim()) errors.push(`${label} is missing bound ${field}`);
    else if (String(actual || '') !== String(wanted)) errors.push(`${label} trace ${field} does not match its row`);
  }

  const repeat = Number(trace.repeat);
  if (!Number.isInteger(repeat) || repeat < 1) errors.push(`${label} trace repeat is invalid`);
  else if (repeat !== Number(expected.repeat)) errors.push(`${label} trace repeat does not match its row`);
  const exitCode = Number(trace.exit_code);
  if (!Number.isInteger(exitCode)) errors.push(`${label} trace exit_code is invalid`);
  else if (exitCode !== Number(expected.exit_code)) errors.push(`${label} trace exit_code does not match its row`);
  const durationMs = Number(trace.duration_ms);
  if (!Number.isFinite(durationMs) || durationMs < 0) errors.push(`${label} trace duration_ms is invalid`);
  else if (durationMs !== Number(expected.duration_ms)) errors.push(`${label} trace duration_ms does not match its row`);
  if (typeof trace.semantic_pass !== 'boolean') errors.push(`${label} trace semantic_pass must be boolean`);
  else if (trace.semantic_pass !== expected.semantic_pass) errors.push(`${label} trace semantic_pass does not match its row`);
  const rowSourceSha256 = String(row?.source_sha256 || '').toLowerCase();
  const traceSourceSha256 = String(trace.source_sha256 || '').toLowerCase();
  if (!isSha256(rowSourceSha256)) errors.push(`${label} is missing a valid source_sha256`);
  if (!isSha256(traceSourceSha256)) errors.push(`${label} trace is missing a valid source_sha256`);
  if (isSha256(rowSourceSha256) && isSha256(traceSourceSha256) && rowSourceSha256 !== traceSourceSha256) {
    errors.push(`${label} trace source_sha256 does not match its row`);
  }
  if (isSha256(expected.source_sha256) && isSha256(rowSourceSha256) && rowSourceSha256 !== expected.source_sha256) {
    errors.push(`${label} source_sha256 does not match its bound oracle/source fingerprint`);
  }

  const traceObservationSha = canonicalObservationSha256(trace.canonical_observation, `${label} trace`, errors);
  const rowObservationSha = canonicalObservationSha256(row?.canonical_observation, label, errors);
  const rowObservedSha = String(row?.observed_sha256 || '').toLowerCase();
  const traceObservedSha = String(trace.observed_sha256 || '').toLowerCase();
  if (!isSha256(rowObservedSha)) errors.push(`${label} is missing a valid observed_sha256`);
  if (!isSha256(traceObservedSha)) errors.push(`${label} trace is missing a valid observed_sha256`);
  if (rowObservationSha && isSha256(rowObservedSha) && rowObservationSha !== rowObservedSha) {
    errors.push(`${label} observed_sha256 does not match canonical_observation`);
  }
  if (traceObservationSha && isSha256(traceObservedSha) && traceObservationSha !== traceObservedSha) {
    errors.push(`${label} trace observed_sha256 does not match canonical_observation`);
  }
  if (rowObservationSha && traceObservationSha && rowObservationSha !== traceObservationSha) {
    errors.push(`${label} trace canonical_observation does not match its row`);
  }
  if (isSha256(rowObservedSha) && isSha256(traceObservedSha) && rowObservedSha !== traceObservedSha) {
    errors.push(`${label} trace observed_sha256 does not match its row`);
  }
  return { evidence, trace, observationSha256: rowObservationSha };
}

function validateFlowLogEvidence(
  parsed,
  errors,
  options = {}
) {
  if (parsed?.flow_log_status !== 'written') {
    errors.push(`flow log evidence status is ${parsed?.flow_log_status || 'missing'}, expected written`);
    return null;
  }
  const mode = String(parsed.mode || '');
  const targetRoot = String(parsed.target_root || '');
  const projectKnowledgeRoot = String(
    parsed.project_knowledge_root || ''
  );
  const stateRoot = String(parsed.state_root || '');
  const flowLog = String(parsed.flow_log || '');
  if (!mode) errors.push('flow log evidence mode is missing');
  if (!targetRoot || !path.isAbsolute(targetRoot)) errors.push('flow log evidence target_root must be absolute');
  if (!projectKnowledgeRoot || !path.isAbsolute(projectKnowledgeRoot)) {
    errors.push('flow log evidence project_knowledge_root must be absolute');
  }
  if (!stateRoot || !path.isAbsolute(stateRoot)) errors.push('flow log evidence state_root must be absolute');
  if (!flowLog) errors.push('flow log evidence path is missing');
  const expectedMode = String(
    options.expectedMode || ''
  );
  if (expectedMode && mode !== expectedMode) {
    errors.push(
      `flow log evidence mode must be ${expectedMode}`
    );
  }
  if (
    options.expectedTargetRoot &&
    targetRoot &&
    comparablePath(targetRoot) !==
      comparablePath(options.expectedTargetRoot)
  ) {
    errors.push(
      'flow log evidence target_root does not match the release source'
    );
  }
  if (
    options.expectedProjectKnowledgeRoot &&
    projectKnowledgeRoot &&
    comparablePath(projectKnowledgeRoot) !==
      comparablePath(
        options.expectedProjectKnowledgeRoot
      )
  ) {
    errors.push(
      'flow log evidence project_knowledge_root does not match the release source'
    );
  }
  if (
    options.expectedStateRoot &&
    stateRoot &&
    comparablePath(stateRoot) !==
      comparablePath(options.expectedStateRoot)
  ) {
    errors.push(
      'flow log evidence state_root does not match the release source'
    );
  }
  if (errors.some((error) => error.startsWith('flow log evidence'))) return null;

  let absoluteLogPath;
  if (path.isAbsolute(flowLog)) {
    absoluteLogPath = path.resolve(flowLog);
  } else {
    const portablePath = portableRelativePath(flowLog);
    if (!portablePath) {
      errors.push('flow log evidence must use a safe relative path or an absolute path inside stateRoot');
      return null;
    }
    absoluteLogPath = path.resolve(targetRoot, ...portablePath.split('/'));
  }
  const expectedRoot = path.resolve(stateRoot, 'maintenance', 'flow-logs');
  if (!isContainedPath(expectedRoot, absoluteLogPath)) {
    errors.push('flow log evidence path escapes stateRoot/maintenance/flow-logs');
    return null;
  }
  if (!fs.existsSync(absoluteLogPath)) {
    errors.push('flow log evidence file does not exist');
    return null;
  }
  let flowLogBody;
  try {
    flowLogBody = readStableRegularFile(absoluteLogPath);
  } catch (error) {
    errors.push(
      `flow log evidence cannot be read safely: ${error.message}`
    );
    return null;
  }
  if (flowLogBody.length === 0) {
    errors.push('flow log evidence must not be empty');
    return null;
  }
  const claimedFlowLogBytes =
    parsed.flow_log_bytes;
  if (
    !Number.isInteger(claimedFlowLogBytes) ||
    claimedFlowLogBytes <= 0
  ) {
    errors.push(
      'flow log evidence stdout flow_log_bytes is invalid'
    );
  } else if (claimedFlowLogBytes !== flowLogBody.length) {
    errors.push(
      'flow log evidence bytes do not match child readback'
    );
  }
  const claimedFlowLogSha256 = String(
    parsed.flow_log_sha256 || ''
  ).toLowerCase();
  const physicalFlowLogSha256 =
    evidenceSha256(flowLogBody);
  if (!isSha256(claimedFlowLogSha256)) {
    errors.push(
      'flow log evidence stdout flow_log_sha256 is invalid'
    );
  } else if (
    claimedFlowLogSha256 !== physicalFlowLogSha256
  ) {
    errors.push(
      'flow log evidence SHA-256 does not match child readback'
    );
  }
  let persisted;
  try {
    persisted = JSON.parse(stripBom(
      flowLogBody.toString('utf8')
    ));
  } catch (error) {
    errors.push(`flow log evidence is invalid JSON: ${error.message}`);
    return null;
  }
  const comparisons = [
    ['flow', persisted.flow, parsed.flow],
    ['started_at', persisted.started_at, parsed.started_at],
    ['duration_total_ms', persisted.duration_total_ms, parsed.duration_total_ms],
    ['steps_total', persisted.steps_total, parsed.steps_total],
    ['steps_ok', persisted.steps_ok, parsed.steps_ok],
    ['overall_status', persisted.overall_status, parsed.overall_status]
  ];
  for (const [field, actual, expected] of comparisons) {
    if (actual !== expected) errors.push(`flow log evidence ${field} does not match stdout`);
  }
  const persistedSemantic = inspectSemanticJson(
    persisted
  );
  errors.push(
    ...persistedSemantic.errors.map(
      (error) =>
        `flow log evidence persisted semantic failure: ${error}`
    )
  );
  const persistedContext =
    persisted.context &&
    typeof persisted.context === 'object' &&
    !Array.isArray(persisted.context)
      ? persisted.context
      : null;
  if (!persistedContext) {
    errors.push(
      'flow log evidence persisted context is missing'
    );
  } else {
    if (persistedContext.mode !== mode) {
      errors.push(
        'flow log evidence context mode does not match stdout'
      );
    }
    const contextScalars = [
      [
        'repoId',
        persistedContext.repoId,
        parsed.repo_id
      ],
      [
        'workspaceId',
        persistedContext.workspaceId,
        parsed.workspace_id
      ],
      [
        'agentId',
        persistedContext.agentId,
        parsed.agent_id
      ],
      [
        'branch',
        persistedContext.branch,
        parsed.branch
      ],
      [
        'headSha',
        persistedContext.headSha,
        parsed.head_sha
      ]
    ];
    for (const [field, actual, expected] of contextScalars) {
      if (actual !== expected) {
        errors.push(
          `flow log evidence context ${field} does not match stdout`
        );
      }
    }
    const contextPaths = [
      [
        'targetRoot',
        persistedContext.targetRoot,
        targetRoot
      ],
      [
        'projectKnowledgeRoot',
        persistedContext.projectKnowledgeRoot,
        projectKnowledgeRoot
      ],
      [
        'stateRoot',
        persistedContext.stateRoot,
        stateRoot
      ]
    ];
    for (const [field, actual, expected] of contextPaths) {
      if (
        !actual ||
        !path.isAbsolute(String(actual)) ||
        comparablePath(actual) !==
          comparablePath(expected)
      ) {
        errors.push(
          `flow log evidence context ${field} does not match stdout`
        );
      }
    }
    if (
      options.expectedSystemRoot &&
      (
        !persistedContext.systemRoot ||
        comparablePath(persistedContext.systemRoot) !==
          comparablePath(options.expectedSystemRoot)
      )
    ) {
      errors.push(
        'flow log evidence context systemRoot does not match the release source'
      );
    }
    const expectedContextScalars = [
      ['agentId', 'expectedAgentId'],
      ['teamRoot', 'expectedTeamRoot'],
      ['workspaceId', 'expectedWorkspaceId']
    ];
    for (const [field, option] of expectedContextScalars) {
      if (
        Object.prototype.hasOwnProperty.call(
          options,
          option
        ) &&
        persistedContext[field] !== options[option]
      ) {
        errors.push(
          `flow log evidence context ${field} does not match the canonical release environment`
        );
      }
    }
  }
  const persistedSteps = Array.isArray(persisted.steps)
    ? persisted.steps
    : null;
  const stdoutSteps = Array.isArray(parsed.steps)
    ? parsed.steps
    : null;
  if (!persistedSteps) {
    errors.push('flow log evidence steps is not an array');
  } else {
    if (persistedSteps.length !== persisted.steps_total) {
      errors.push(
        'flow log evidence steps_total does not match steps length'
      );
    }
    const derivedStepsOk = persistedSteps.filter(
      (step) => step?.success === true
    ).length;
    const derivedOverall =
      derivedStepsOk === persistedSteps.length
        ? 'ok'
        : 'failed';
    if (persisted.steps_ok !== derivedStepsOk) {
      errors.push(
        'flow log evidence steps_ok does not match persisted step outcomes'
      );
    }
    if (persisted.overall_status !== derivedOverall) {
      errors.push(
        'flow log evidence overall_status does not match persisted step outcomes'
      );
    }
  }
  if (!stdoutSteps) {
    errors.push(
      'flow log evidence stdout steps is not an array'
    );
  } else if (stdoutSteps.length !== parsed.steps_total) {
    errors.push(
      'flow log evidence stdout steps_total does not match steps length'
    );
  }
  if (
    persistedSteps &&
    stdoutSteps &&
    persistedSteps.length !== stdoutSteps.length
  ) {
    errors.push(
      'flow log evidence persisted steps length does not match stdout'
    );
  } else if (persistedSteps && stdoutSteps) {
    const correlatedFields = [
      'step',
      'command',
      'exit',
      'success',
      'status',
      'json_status',
      'semantic_errors',
      'duration_ms'
    ];
    for (
      let index = 0;
      index < persistedSteps.length;
      index += 1
    ) {
      const persistedStep = persistedSteps[index];
      const stdoutStep = stdoutSteps[index];
      if (!isRecord(persistedStep) || !isRecord(stdoutStep)) {
        errors.push(
          `flow log evidence steps[${index}] is not a record in both persisted log and stdout`
        );
        continue;
      }
      for (const field of correlatedFields) {
        if (
          !Object.prototype.hasOwnProperty.call(
            persistedStep,
            field
          ) ||
          !Object.prototype.hasOwnProperty.call(
            stdoutStep,
            field
          )
        ) {
          errors.push(
            `flow log evidence steps[${index}].${field} is missing from persisted log or stdout`
          );
          continue;
        }
        if (
          stableCanonicalStringify(
            persistedStep[field]
          ) !==
          stableCanonicalStringify(
            stdoutStep[field]
          )
        ) {
          errors.push(
            `flow log evidence steps[${index}].${field} does not match stdout`
          );
        }
      }
    }
  }
  return {
    path: relPath(absoluteLogPath),
    bytes: flowLogBody.length,
    sha256: physicalFlowLogSha256
  };
}

function deleteCandidateArtifact() {
  const artifactPath = path.join(root, artifactRel);
  fs.rmSync(artifactPath, { force: true });
  return {
    path: artifactRel,
    removed_before_run: !fs.existsSync(artifactPath)
  };
}

function cleanupFailedCandidateArtifact({
  mode,
  keepFailed,
  failures,
  artifactPath = path.join(root, artifactRel)
}) {
  const packagingMode = ['quick', 'full', 'release'].includes(String(mode || '').toLowerCase());
  const hasFailures = Array.isArray(failures) && failures.length > 0;
  const existed = fs.existsSync(artifactPath);
  if (!packagingMode || !hasFailures || keepFailed) {
    return {
      path: artifactPath === path.join(root, artifactRel) ? artifactRel : artifactPath,
      attempted: false,
      existed,
      removed: false,
      reason: !packagingMode ? 'non_packaging_mode' : !hasFailures ? 'gate_passed' : 'keep_failed'
    };
  }
  fs.rmSync(artifactPath, { force: true });
  return {
    path: artifactPath === path.join(root, artifactRel) ? artifactRel : artifactPath,
    attempted: true,
    existed,
    removed: existed && !fs.existsSync(artifactPath),
    reason: 'gate_failed'
  };
}

function gitHead() {
  const result = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 30000 });
  return result.status === 0 ? result.stdout.trim() : null;
}

function parseJson(stdout) {
  return parseJsonOutput(stdout);
}

function validateJsonContract(spec, stdout) {
  if (!spec.expectJson) {
    return {
      ok: true,
      parsed: null,
      errors: [],
      flowLogEvidence: null
    };
  }
  const errors = [];
  let parsed = null;
  let flowLogEvidence = null;
  try {
    parsed = parseJson(stdout);
  } catch (error) {
    return {
      ok: false,
      parsed: null,
      errors: [`invalid JSON stdout: ${error.message}`],
      flowLogEvidence
    };
  }
  for (const field of spec.requiredFields || ['status']) {
    if (parsed[field] === undefined) errors.push(`missing JSON field: ${field}`);
  }
  if (spec.allowedStatuses && parsed.status !== undefined && !spec.allowedStatuses.includes(parsed.status)) {
    errors.push(`unexpected JSON status: ${parsed.status}`);
  }
  if (spec.semanticChecks !== false) {
    const semantic = inspectSemanticJson(parsed, { allowFailuresArray: Boolean(spec.allowFailuresArray) });
    errors.push(...semantic.errors.map((error) => `semantic JSON failure: ${error}`));
  }
  if (spec.flowLogEvidence) {
    flowLogEvidence = validateFlowLogEvidence(
      parsed,
      errors,
      {
        expectedMode: 'repo',
        expectedTargetRoot: path.dirname(root),
        expectedProjectKnowledgeRoot: root,
        expectedStateRoot: root,
        expectedSystemRoot: root,
        expectedAgentId: 'release-gate',
        expectedTeamRoot: null,
        expectedWorkspaceId: null
      }
    );
  }
  return {
    ok: errors.length === 0,
    parsed,
    errors,
    flowLogEvidence
  };
}

function runCommand(spec, context) {
  const started = Date.now();
  const stdoutPath = path.join(context.logDir, `${safeId(spec.id)}.stdout.txt`);
  const stderrPath = path.join(context.logDir, `${safeId(spec.id)}.stderr.txt`);
  const result = spawnSync(spec.command, spec.args || [], {
    cwd: spec.cwd || root,
    env: canonicalReleaseEnv(spec.env || {}),
    encoding: 'utf8',
    windowsHide: true,
    timeout: spec.timeoutMs || 300000,
    // Full evidence is retained per step. Some clean-install scenarios emit a
    // multi-megabyte JSON receipt, so the Node default 1 MiB capture limit is
    // not sufficient for a release gate.
    maxBuffer: 32 * 1024 * 1024
  });
  const stdoutBody = Buffer.from(
    String(result.stdout || ''),
    'utf8'
  );
  const stderrBody = Buffer.from(
    String(result.stderr || result.error?.message || ''),
    'utf8'
  );
  // A source-only self-test can legitimately replace or clean the durable
  // evidence subtree while it is running. Recreate the per-run log directory
  // after the child exits so the gate retains stdout/stderr instead of
  // crashing with ENOENT and losing the actual step decision.
  ensureDir(context.logDir);
  fs.writeFileSync(stdoutPath, stdoutBody);
  fs.writeFileSync(stderrPath, stderrBody);

  const jsonContract = validateJsonContract(
    spec,
    stdoutBody.toString('utf8')
  );
  const exitOk = result.status === 0;
  const status = exitOk && jsonContract.ok ? 'pass' : 'fail';
  return {
    id: spec.id,
    name: spec.name || spec.id,
    command: [path.basename(spec.command), ...(spec.args || [])].join(' '),
    status,
    exit_code: result.status,
    duration_ms: Date.now() - started,
    expect_json: Boolean(spec.expectJson),
    json_status: jsonContract.parsed?.status || null,
    json_contract_errors: jsonContract.errors,
    classified_mode: spec.id === 'classify-release-impact' ? jsonContract.parsed?.mode || null : null,
    classification_complete: spec.id === 'classify-release-impact' ? jsonContract.parsed?.classification_complete ?? null : null,
    required_gates: spec.id === 'classify-release-impact' && Array.isArray(jsonContract.parsed?.required_gates)
      ? jsonContract.parsed.required_gates
      : [],
    flow_log_evidence: jsonContract.flowLogEvidence,
    stdout_path: relPath(stdoutPath),
    stderr_path: relPath(stderrPath),
    stdout_sha256: evidenceSha256(stdoutBody),
    stderr_sha256: evidenceSha256(stderrBody),
    stdout_tail: sanitizeText(stdoutBody.toString('utf8').slice(-3000)),
    stderr_tail: sanitizeText(stderrBody.toString('utf8').slice(-3000))
  };
}

function bindSyntheticStepStreams(stepResult, context) {
  if (!stepResult || stepResult.status === 'skipped') {
    return stepResult;
  }
  const stdoutPath = path.join(
    context.logDir,
    `${safeId(stepResult.id)}.stdout.txt`
  );
  const stderrPath = path.join(
    context.logDir,
    `${safeId(stepResult.id)}.stderr.txt`
  );
  const semanticStep = { ...stepResult };
  for (const field of [
    'stdout_path',
    'stderr_path',
    'stdout_sha256',
    'stderr_sha256',
    'stdout_tail',
    'stderr_tail'
  ]) {
    delete semanticStep[field];
  }
  const stdoutBody = Buffer.from(
    `${JSON.stringify({
      schema_version:
        'release-gate-validator-step-stream.v1',
      step: semanticStep
    }, null, 2)}\n`,
    'utf8'
  );
  const stderrBody = Buffer.from(
    (Array.isArray(stepResult.json_contract_errors)
      ? stepResult.json_contract_errors
      : []).join('; '),
    'utf8'
  );
  ensureDir(context.logDir);
  fs.writeFileSync(stdoutPath, stdoutBody);
  fs.writeFileSync(stderrPath, stderrBody);
  return {
    ...stepResult,
    stdout_path: relPath(stdoutPath),
    stderr_path: relPath(stderrPath),
    stdout_sha256: evidenceSha256(stdoutBody),
    stderr_sha256: evidenceSha256(stderrBody),
    stdout_tail: sanitizeText(
      stdoutBody.toString('utf8').slice(-3000)
    ),
    stderr_tail: sanitizeText(
      stderrBody.toString('utf8').slice(-3000)
    )
  };
}

function bindStepDecision(stepResult, context) {
  if (!stepResult || stepResult.status === 'skipped') {
    return stepResult;
  }
  const decisionPath = path.join(
    context.logDir,
    `${safeId(stepResult.id)}.decision.json`
  );
  const semanticStep = JSON.parse(
    JSON.stringify(stepResult)
  );
  const decisionBody = Buffer.from(
    `${JSON.stringify({
      schema_version: 'release-gate-step-decision.v1',
      step: semanticStep
    }, null, 2)}\n`,
    'utf8'
  );
  ensureDir(context.logDir);
  fs.writeFileSync(decisionPath, decisionBody);
  return {
    ...semanticStep,
    decision_path: relPath(decisionPath),
    decision_sha256: evidenceSha256(decisionBody)
  };
}

function bindLateInternalReportSteps(report, context) {
  const replacements = new Map();
  report.steps = (report.steps || []).map((stepResult) => {
    if (
      !stepResult ||
      stepResult.status === 'skipped' ||
      stepResult.decision_path
    ) {
      return stepResult;
    }
    if (
      stepResult.stdout_path ||
      stepResult.stderr_path ||
      stepResult.stdout_sha256 ||
      stepResult.stderr_sha256
    ) {
      throw new Error(
        `late release step ${stepResult.id || 'unknown'} has a partial stream binding`
      );
    }
    const bound = bindStepDecision(
      bindSyntheticStepStreams(
        stepResult,
        context
      ),
      context
    );
    replacements.set(bound.id, bound);
    return bound;
  });
  report.failures = (report.failures || []).map(
    (failure) =>
      replacements.get(failure?.id) || failure
  );
  return report;
}

function memoryBattleReportPath(flags = {}) {
  const value = flags.ignoreAmbientEvidence
    ? flags.memoryBattleReport
    : flags.memoryBattleReport ||
      process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT;
  return value ? path.resolve(String(value)) : null;
}

function sparkBattleReportPath(flags = {}) {
  const value = flags.ignoreAmbientEvidence
    ? flags.sparkBattleReport
    : flags.sparkBattleReport ||
      process.env.KNOWLEDGE_SPARK_BATTLE_REPORT;
  return value ? path.resolve(String(value)) : null;
}

function percentile(values, ratio) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * ratio) - 1));
  return sorted[index];
}

function validateBenchmarkFile(filePath, expectedMode, errors) {
  const name = path.basename(filePath);
  let benchmark = null;
  let benchmarkBody = null;
  try {
    benchmarkBody = readStableRegularFile(
      filePath
    );
    benchmark = JSON.parse(stripBom(
      benchmarkBody.toString('utf8')
    ));
  }
  catch (error) {
    errors.push(`${name} is invalid JSON: ${error.message}`);
    return null;
  }
  if (benchmark.schema_version !== 'knowledge-comparative-benchmark.v2') {
    errors.push(`${name} schema_version must be knowledge-comparative-benchmark.v2`);
  }
  if (benchmark.mode !== expectedMode) errors.push(`${name} mode must be ${expectedMode}`);
  const oracleEvidence = validateHashedEvidenceFile(
    path.dirname(filePath),
    benchmark.oracle_path,
    benchmark.oracle_sha256,
    `${name} oracle sidecar`,
    errors
  );
  let oracle = null;
  const oracleCases = new Map();
  if (oracleEvidence) {
    try {
      oracle = JSON.parse(stripBom(
        oracleEvidence.body.toString('utf8')
      ));
    }
    catch (error) { errors.push(`${name} oracle sidecar is invalid JSON: ${error.message}`); }
  }
  if (oracle) {
    if (oracle.schema_version !== 'knowledge-comparative-oracle.v1') {
      errors.push(`${name} oracle sidecar schema_version must be knowledge-comparative-oracle.v1`);
    }
    if (!Array.isArray(oracle.cases) || oracle.cases.length === 0) {
      errors.push(`${name} oracle sidecar cases are missing`);
    }
    const oracleBaseDir = path.dirname(oracleEvidence.absolutePath);
    const preregistrationEvidence = validateHashedEvidenceFile(
      oracleBaseDir,
      oracle.preregistration_path,
      oracle.preregistration_sha256,
      `${name} oracle preregistration`,
      errors
    );
    let preregistration = null;
    const preregistrationCases = new Set();
    const preregistrationByCase = new Map();
    if (preregistrationEvidence) {
      try {
        preregistration = JSON.parse(stripBom(
          preregistrationEvidence.body.toString('utf8')
        ));
      } catch (error) {
        errors.push(`${name} oracle preregistration is invalid JSON: ${error.message}`);
      }
    }
    if (preregistration) {
      if (preregistration.schema_version !== 'knowledge-comparative-preregistration.v1') {
        errors.push(`${name} oracle preregistration schema_version must be knowledge-comparative-preregistration.v1`);
      }
      if (!Array.isArray(preregistration.cases) || preregistration.cases.length === 0) {
        errors.push(`${name} oracle preregistration cases are missing`);
      }
      for (const [index, item] of (preregistration.cases || []).entries()) {
        const caseId = String(item?.case_id || '').trim();
        const scenario = String(item?.scenario || '').trim();
        const sourcePath = portableRelativePath(item?.source_path);
        const sourceSha256 = String(item?.source_sha256 || '').toLowerCase();
        const expectedSha256 = String(item?.expected_sha256 || '').toLowerCase();
        if (!caseId) errors.push(`${name} oracle preregistration cases[${index}] is missing case_id`);
        else if (preregistrationCases.has(caseId)) errors.push(`${name} oracle preregistration has duplicate case_id ${caseId}`);
        else {
          preregistrationCases.add(caseId);
          preregistrationByCase.set(caseId, {
            scenario,
            sourcePath,
            sourceSha256,
            expectedSha256
          });
        }
        if (!scenario) errors.push(`${name} oracle preregistration case ${caseId || index} is missing scenario`);
        if (!sourcePath) errors.push(`${name} oracle preregistration case ${caseId || index} has invalid source_path`);
        if (!isSha256(sourceSha256)) errors.push(`${name} oracle preregistration case ${caseId || index} has invalid source_sha256`);
        if (!isSha256(expectedSha256)) errors.push(`${name} oracle preregistration case ${caseId || index} has invalid expected_sha256`);
      }
    }
    const oracleEvidencePaths = new Set();
    const oracleSourcePaths = new Set();
    for (const [index, item] of (oracle.cases || []).entries()) {
      const caseId = String(item?.case_id || '').trim();
      const scenario = String(item?.scenario || '').trim();
      const expectedSha256 = String(item?.expected_sha256 || '').toLowerCase();
      if (!caseId) {
        errors.push(`${name} oracle sidecar cases[${index}] is missing case_id`);
        continue;
      }
      if (oracleCases.has(caseId)) errors.push(`${name} oracle sidecar has duplicate case_id ${caseId}`);
      if (preregistration && !preregistrationCases.has(caseId)) {
        errors.push(`${name} oracle sidecar case ${caseId} is absent from preregistration`);
      }
      if (!scenario) errors.push(`${name} oracle sidecar case ${caseId} is missing scenario`);
      if (!isSha256(expectedSha256)) errors.push(`${name} oracle sidecar case ${caseId} has invalid expected_sha256`);
      const computedSha256 = canonicalObservationSha256(
        item?.canonical_observation,
        `${name} oracle sidecar case ${caseId}`,
        errors
      );
      if (computedSha256 && isSha256(expectedSha256) && computedSha256 !== expectedSha256) {
        errors.push(`${name} oracle sidecar case ${caseId} expected_sha256 does not match canonical_observation`);
      }
      const sourceEvidence = validateHashedEvidenceFile(
        oracleBaseDir,
        item?.source_path,
        item?.source_sha256,
        `${name} oracle sidecar case ${caseId} source`,
        errors
      );
      const caseEvidence = validateHashedEvidenceFile(
        oracleBaseDir,
        item?.evidence_path,
        item?.evidence_sha256,
        `${name} oracle sidecar case ${caseId} evidence`,
        errors
      );
      if (sourceEvidence) {
        if (oracleSourcePaths.has(sourceEvidence.portablePath)) {
          errors.push(`${name} oracle sidecar cases reuse source path ${sourceEvidence.portablePath}`);
        }
        oracleSourcePaths.add(sourceEvidence.portablePath);
      }
      const preregisteredCase = preregistrationByCase.get(caseId);
      if (preregisteredCase) {
        if (preregisteredCase.scenario !== scenario) {
          errors.push(`${name} oracle sidecar case ${caseId} scenario disagrees with preregistration`);
        }
        if (preregisteredCase.sourcePath !== sourceEvidence?.portablePath) {
          errors.push(`${name} oracle sidecar case ${caseId} source_path disagrees with preregistration`);
        }
        if (preregisteredCase.sourceSha256 !== sourceEvidence?.actualSha256) {
          errors.push(`${name} oracle sidecar case ${caseId} source_sha256 disagrees with preregistration`);
        }
        if (preregisteredCase.expectedSha256 !== expectedSha256) {
          errors.push(`${name} oracle sidecar case ${caseId} expected_sha256 disagrees with preregistration`);
        }
      }
      if (caseEvidence) {
        if (oracleEvidencePaths.has(caseEvidence.portablePath)) {
          errors.push(`${name} oracle sidecar cases reuse evidence path ${caseEvidence.portablePath}`);
        }
        oracleEvidencePaths.add(caseEvidence.portablePath);
        try {
          const evidence = JSON.parse(stripBom(
            caseEvidence.body.toString('utf8')
          ));
          if (evidence.schema_version !== 'knowledge-comparative-oracle-evidence.v1') {
            errors.push(`${name} oracle sidecar case ${caseId} evidence has invalid schema_version`);
          }
          if (String(evidence.case_id || '') !== caseId) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence case_id does not match`);
          }
          if (String(evidence.scenario || '') !== scenario) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence scenario does not match`);
          }
          if (
            String(evidence.preregistration_sha256 || '').toLowerCase()
            !== String(preregistrationEvidence?.actualSha256 || '').toLowerCase()
          ) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence preregistration_sha256 does not match`);
          }
          if (portableRelativePath(evidence.source_path) !== sourceEvidence?.portablePath) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence source_path does not match`);
          }
          if (String(evidence.source_sha256 || '').toLowerCase() !== String(item?.source_sha256 || '').toLowerCase()) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence source_sha256 does not match`);
          }
          if (String(evidence.expected_sha256 || '').toLowerCase() !== expectedSha256) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence expected_sha256 does not match`);
          }
          const evidenceObservationSha256 = canonicalObservationSha256(
            evidence.canonical_observation,
            `${name} oracle sidecar case ${caseId} evidence`,
            errors
          );
          if (evidenceObservationSha256 && computedSha256 && evidenceObservationSha256 !== computedSha256) {
            errors.push(`${name} oracle sidecar case ${caseId} evidence canonical_observation does not match`);
          }
        } catch (error) {
          errors.push(`${name} oracle sidecar case ${caseId} evidence is invalid JSON: ${error.message}`);
        }
      }
      oracleCases.set(caseId, {
        scenario,
        expectedSha256,
        canonicalObservation: item?.canonical_observation,
        computedSha256,
        sourceSha256: sourceEvidence?.actualSha256 || null,
        sourcePath: sourceEvidence?.portablePath || null,
        evidencePath: caseEvidence?.portablePath || null
      });
    }
    for (const caseId of preregistrationCases) {
      if (!oracleCases.has(caseId)) errors.push(`${name} preregistration case_id ${caseId} has no oracle case`);
    }
  }
  const entries = Array.isArray(benchmark.entries) ? benchmark.entries : [];
  if (entries.length !== Number(benchmark.command_count || -1)) {
    errors.push(`${name} entries do not match command_count`);
  }
  const keys = new Set();
  const commandIds = new Set();
  const cases = new Map();
  const uncoveredOracleCases = new Set();
  const usedOracleCases = new Set();
  const tracePaths = new Set();
  let executionFailures = 0;
  let taskSuccesses = 0;
  let unverifiedClaims = 0;
  for (const [index, entry] of entries.entries()) {
    const label = `${name} entries[${index}]`;
    const commandId = String(entry.command_id || '').trim();
    const caseId = String(entry.case_id || '').trim();
    const repeat = Number(entry.repeat);
    const key = `${caseId}#${repeat}`;
    if (!caseId) errors.push(`${name} entries[${index}] is missing case_id`);
    if (!commandId) errors.push(`${label} is missing command_id`);
    else if (commandIds.has(commandId)) errors.push(`${name} has duplicate command_id ${commandId}`);
    else commandIds.add(commandId);
    if (!Number.isInteger(repeat) || repeat < 1) errors.push(`${name} entries[${index}] has invalid repeat`);
    if (String(entry.arm || '') !== expectedMode) errors.push(`${label} arm must be ${expectedMode}`);
    if (!String(entry.scenario || '').trim()) errors.push(`${label} is missing scenario`);
    if (!String(entry.command || '').trim()) errors.push(`${label} is missing command`);
    const exitCode = Number(entry.exit_code);
    if (!Number.isInteger(exitCode)) errors.push(`${label} has invalid exit_code`);
    if (keys.has(key)) errors.push(`${name} has duplicate benchmark key ${key}`);
    keys.add(key);
    cases.set(caseId, Number(cases.get(caseId) || 0) + 1);
    if (entry.execution_ok !== true) executionFailures += 1;
    if (typeof entry.task_success !== 'boolean' || typeof entry.oracle_match !== 'boolean') {
      errors.push(`${name} entries[${index}] must expose task_success and oracle_match booleans`);
    }
    if (entry.task_success !== entry.oracle_match) {
      errors.push(`${name} entries[${index}] task_success disagrees with oracle_match`);
    }
    const oracleCase = oracleCases.get(caseId);
    const expectedSha256 = oracleCase?.expectedSha256 || null;
    const observedSha256 = String(entry.observed_sha256 || '').toLowerCase();
    if (!expectedSha256 && caseId) uncoveredOracleCases.add(caseId);
    else if (caseId) usedOracleCases.add(caseId);
    const declaredExpectedSha256 = String(entry.expected_sha256 || '').toLowerCase();
    if (!isSha256(declaredExpectedSha256)) errors.push(`${label} has invalid expected_sha256`);
    else if (expectedSha256 && declaredExpectedSha256 !== expectedSha256) errors.push(`${label} expected_sha256 disagrees with oracle sidecar`);
    if (!isSha256(observedSha256)) errors.push(`${name} entries[${index}] has invalid observed_sha256`);
    const sourceSha256 = String(entry.source_sha256 || '').toLowerCase();
    if (!isSha256(sourceSha256)) errors.push(`${label} has invalid source_sha256`);
    else if (oracleCase?.sourceSha256 && sourceSha256 !== oracleCase.sourceSha256) {
      errors.push(`${label} source_sha256 disagrees with oracle source fingerprint`);
    }
    if (oracleCase?.scenario && String(entry.scenario || '') !== oracleCase.scenario) {
      errors.push(`${label} scenario disagrees with oracle preregistration`);
    }
    const expectedSemanticOutcome = entry.task_success === true ? 'pass' : 'oracle_mismatch';
    if (String(entry.semantic_outcome || '') !== expectedSemanticOutcome) {
      errors.push(`${label} semantic_outcome must be ${expectedSemanticOutcome}`);
    }
    const observationSha256 = canonicalObservationSha256(entry.canonical_observation, label, errors);
    if (observationSha256 && isSha256(observedSha256) && observationSha256 !== observedSha256) {
      errors.push(`${label} observed_sha256 does not match canonical_observation`);
    }
    const observedMatchesOracle = Boolean(expectedSha256 && isSha256(observedSha256) && observedSha256 === expectedSha256);
    if (expectedSha256 && isSha256(observedSha256) && typeof entry.oracle_match === 'boolean' && entry.oracle_match !== observedMatchesOracle) {
      errors.push(`${name} entries[${index}] oracle_match disagrees with observed_sha256`);
    }
    validateSparkCommandTrace(
      path.dirname(filePath),
      entry,
      {
        command_id: commandId,
        case_id: caseId,
        scenario: entry.scenario,
        coverage_area: 'benchmark',
        arm: expectedMode,
        repeat,
        command: entry.command,
        exit_code: exitCode,
        duration_ms: Number(entry.duration_ms),
        semantic_pass: entry.task_success === true,
        semantic_outcome: expectedSemanticOutcome,
        source_sha256: oracleCase?.sourceSha256 || null
      },
      label,
      errors,
      tracePaths
    );
    if (entry.task_success === true) taskSuccesses += 1;
    for (const metric of ['duration_ms', 'files_read', 'context_bytes', 'estimated_context_tokens']) {
      const value = Number(entry[metric]);
      if (!Number.isFinite(value) || value < 0) errors.push(`${name} entries[${index}] has invalid ${metric}`);
    }
    const claims = Number(entry.unverified_claims);
    if (!Number.isInteger(claims) || claims < 0) errors.push(`${name} entries[${index}] has invalid unverified_claims`);
    else unverifiedClaims += claims;
  }
  for (const caseId of uncoveredOracleCases) errors.push(`${name} case_id ${caseId} is not covered by the oracle sidecar`);
  for (const caseId of oracleCases.keys()) {
    if (!usedOracleCases.has(caseId)) errors.push(`${name} oracle sidecar case_id ${caseId} has no benchmark entries`);
  }
  if (cases.size < 6) errors.push(`${name} must contain at least 6 distinct case_id values`);
  for (const [caseId, count] of cases.entries()) {
    if (count < 10) errors.push(`${name} case ${caseId} has ${count} repeats; expected at least 10`);
  }
  if (executionFailures > 0) errors.push(`${name} has ${executionFailures} execution failure(s)`);
  if (unverifiedClaims > 0) errors.push(`${name} has ${unverifiedClaims} unverified claim(s)`);

  const durationValues = entries.map((entry) => Number(entry.duration_ms)).filter(Number.isFinite);
  const metrics = {
    mode: expectedMode,
    runs: entries.length,
    cases: cases.size,
    task_success_count: taskSuccesses,
    task_success_rate: entries.length ? taskSuccesses / entries.length : 0,
    duration_ms_total: durationValues.reduce((sum, value) => sum + value, 0),
    duration_ms_p50: percentile(durationValues, 0.5),
    duration_ms_p95: percentile(durationValues, 0.95),
    files_read_total: entries.reduce((sum, entry) => sum + Number(entry.files_read || 0), 0),
    context_bytes_total: entries.reduce((sum, entry) => sum + Number(entry.context_bytes || 0), 0),
    estimated_context_tokens_total: entries.reduce((sum, entry) => sum + Number(entry.estimated_context_tokens || 0), 0),
    unverified_claims_total: unverifiedClaims
  };
  return {
    benchmark,
    entries,
    keys,
    commandIds,
    metrics,
    oracleEvidence,
    oracleCases,
    tracePaths,
    binding: {
      path: name,
      bytes: benchmarkBody.length,
      sha256: evidenceSha256(benchmarkBody)
    }
  };
}

function validateBenchmarkPair(reportDir, errors) {
  const withPath = path.join(reportDir, 'benchmark-with-knowledge.json');
  const withoutPath = path.join(reportDir, 'benchmark-without-knowledge.json');
  for (const benchmarkPath of [withPath, withoutPath]) {
    if (!fs.existsSync(benchmarkPath)) errors.push(`${path.basename(benchmarkPath)} is missing beside the SPARK battle report`);
  }
  if (!fs.existsSync(withPath) || !fs.existsSync(withoutPath)) return null;
  const assisted = validateBenchmarkFile(withPath, 'with-knowledge', errors);
  const baseline = validateBenchmarkFile(withoutPath, 'without-knowledge', errors);
  if (!assisted || !baseline) return null;
  if (String(assisted.benchmark.oracle_path || '') !== String(baseline.benchmark.oracle_path || '')) {
    errors.push('assisted and baseline benchmarks must use the same oracle_path');
  }
  if (
    !isSha256(assisted.benchmark.oracle_sha256)
    || !isSha256(baseline.benchmark.oracle_sha256)
    || String(assisted.benchmark.oracle_sha256).toLowerCase() !== String(baseline.benchmark.oracle_sha256).toLowerCase()
  ) {
    errors.push('assisted and baseline benchmarks must use the same oracle_sha256');
  }
  const assistedOracleCases = new Set(assisted.oracleCases.keys());
  const baselineOracleCases = new Set(baseline.oracleCases.keys());
  const oracleCaseDifference = [
    ...[...assistedOracleCases].filter((caseId) => !baselineOracleCases.has(caseId)),
    ...[...baselineOracleCases].filter((caseId) => !assistedOracleCases.has(caseId))
  ];
  if (oracleCaseDifference.length) errors.push('assisted and baseline parsed oracle case sets differ');
  const reusedTracePaths = [...assisted.tracePaths].filter((tracePath) => baseline.tracePaths.has(tracePath));
  if (reusedTracePaths.length) {
    errors.push(`assisted and baseline benchmarks reuse ${reusedTracePaths.length} command trace path(s)`);
  }
  const reusedCommandIds = [...assisted.commandIds].filter((commandId) => baseline.commandIds.has(commandId));
  if (reusedCommandIds.length) {
    errors.push(`assisted and baseline benchmarks reuse ${reusedCommandIds.length} command_id value(s)`);
  }
  const missingAssisted = [...baseline.keys].filter((key) => !assisted.keys.has(key));
  const missingBaseline = [...assisted.keys].filter((key) => !baseline.keys.has(key));
  if (missingAssisted.length || missingBaseline.length) {
    errors.push(`benchmark case/repeat sets differ: assisted_missing=${missingAssisted.length}, baseline_missing=${missingBaseline.length}`);
  }
  if (assisted.metrics.task_success_rate < baseline.metrics.task_success_rate) {
    errors.push('assisted benchmark correctness is lower than baseline');
  }
  if (assisted.metrics.task_success_rate < 1) errors.push('assisted benchmark did not reach 100% oracle correctness');
  const correctnessImproved = assisted.metrics.task_success_rate > baseline.metrics.task_success_rate;
  if (!correctnessImproved && assisted.metrics.duration_ms_p50 > baseline.metrics.duration_ms_p50 * 1.1) {
    errors.push('assisted benchmark p50 is more than 10% slower without a correctness improvement');
  }
  if (assisted.metrics.estimated_context_tokens_total >= baseline.metrics.estimated_context_tokens_total) {
    errors.push('assisted benchmark did not reduce estimated context tokens');
  }
  return {
    matched_runs: assisted.keys.size - missingBaseline.length,
    evidence_bindings: {
      assisted: assisted.binding,
      baseline: baseline.binding
    },
    baseline: baseline.metrics,
    assisted: assisted.metrics,
    deltas: {
      duration_ms_p50_pct: baseline.metrics.duration_ms_p50 > 0
        ? ((assisted.metrics.duration_ms_p50 - baseline.metrics.duration_ms_p50) / baseline.metrics.duration_ms_p50) * 100
        : null,
      files_read_pct: baseline.metrics.files_read_total > 0
        ? ((assisted.metrics.files_read_total - baseline.metrics.files_read_total) / baseline.metrics.files_read_total) * 100
        : null,
      estimated_context_tokens_pct: baseline.metrics.estimated_context_tokens_total > 0
        ? ((assisted.metrics.estimated_context_tokens_total - baseline.metrics.estimated_context_tokens_total) / baseline.metrics.estimated_context_tokens_total) * 100
        : null
    }
  };
}

function validateSparkBattleReport(flags = {}) {
  const started = Date.now();
  const reportPath = sparkBattleReportPath(flags);
  const errors = [];
  let parsed = null;
  let benchmarkComparison = null;
  let reportSha256 = null;
  if (!reportPath || !fs.existsSync(reportPath)) {
    errors.push('SPARK battle report does not exist');
  } else {
    try {
      const body = readStableRegularFile(reportPath);
      reportSha256 = evidenceSha256(body);
      parsed = JSON.parse(stripBom(body.toString('utf8')));
    }
    catch (error) { errors.push(`invalid SPARK battle JSON: ${error.message}`); }
  }
  if (parsed) {
    if (parsed.schema_version !== 'knowledge-spark-battle.v2') {
      errors.push('SPARK battle schema_version must be knowledge-spark-battle.v2');
    }
    if (!['pass', 'pass_with_expected_blocks'].includes(String(parsed.status || ''))) {
      errors.push(`SPARK battle status is ${parsed.status || 'missing'}`);
    }
    if (!Array.isArray(parsed.commands) || parsed.commands.length !== Number(parsed.total_commands || -1)) {
      errors.push('SPARK battle command details are missing or total_commands does not match');
    }
    if (Number(parsed.passed || 0) !== Number(parsed.total_commands || -1)) {
      errors.push('SPARK battle passed must equal total_commands after expected outcomes are classified');
    }
    if (Number(parsed.failed || 0) !== 0) errors.push(`SPARK battle failed is ${parsed.failed}`);
    if (Number(parsed.critical_failed || 0) !== 0) errors.push(`SPARK battle critical_failed is ${parsed.critical_failed}`);
    if (Number(parsed.unexpected_semantic_failure_count || 0) !== 0) {
      errors.push(`SPARK battle unexpected_semantic_failure_count is ${parsed.unexpected_semantic_failure_count}`);
    }
    const caseIds = new Set();
    const traceCommandIds = new Set();
    const commandById = new Map();
    const commandTracePaths = new Set();
    for (const [index, command] of (parsed.commands || []).entries()) {
      const label = `SPARK battle commands[${index}]`;
      const commandId = String(command.command_id || '').trim();
      const caseId = String(command.case_id || '').trim();
      if (!caseId) errors.push(`SPARK battle commands[${index}] is missing case_id`);
      else if (caseIds.has(caseId)) errors.push(`SPARK battle has duplicate case_id ${caseId}`);
      else {
        caseIds.add(caseId);
        commandById.set(caseId, command);
      }
      if (!commandId) errors.push(`${label} is missing command_id`);
      else if (traceCommandIds.has(commandId)) errors.push(`SPARK battle has duplicate command_id ${commandId}`);
      else traceCommandIds.add(commandId);
      if (!String(command.scenario || '').trim()) errors.push(`SPARK battle commands[${index}] is missing scenario`);
      if (!String(command.command || '').trim()) errors.push(`SPARK battle commands[${index}] is missing command`);
      if (!SPARK_COVERAGE_AREAS.includes(String(command.coverage_area || ''))) {
        errors.push(`SPARK battle commands[${index}] has invalid coverage_area ${command.coverage_area || 'missing'}`);
      }
      if (!String(command.arm || '').trim()) errors.push(`SPARK battle commands[${index}] is missing arm`);
      const repeat = Number(command.repeat);
      if (!Number.isInteger(repeat) || repeat < 1) errors.push(`SPARK battle commands[${index}] has invalid repeat`);
      if (!Number.isFinite(Number(command.duration_ms)) || Number(command.duration_ms) < 0) {
        errors.push(`SPARK battle commands[${index}] has invalid duration_ms`);
      }
      if (command.semantic_pass !== true) errors.push(`SPARK battle commands[${index}] semantic_pass is not true`);
      validateSparkCommandTrace(
        path.dirname(reportPath),
        command,
        {
          command_id: commandId,
          case_id: caseId,
          scenario: command.scenario,
          coverage_area: command.coverage_area,
          arm: command.arm,
          repeat,
          command: command.command,
          exit_code: Number(command.exit_code),
          duration_ms: Number(command.duration_ms),
          semantic_pass: true,
          semantic_outcome: command.semantic_outcome,
          source_sha256: String(command.source_sha256 || '').toLowerCase()
        },
        label,
        errors,
        commandTracePaths
      );
      if (!isExpectedRow(command) && Number(command.exit_code) !== 0) {
        errors.push(`SPARK battle commands[${index}] has unexpected exit_code ${command.exit_code}`);
      }
    }
    const coverage = parsed.coverage && typeof parsed.coverage === 'object' ? parsed.coverage : {};
    const coverageOwners = new Map();
    for (const area of SPARK_COVERAGE_AREAS) {
      const item = coverage[area];
      const expectedStatuses = area === 'pinecone_live_local' ? ['pass', 'environment_blocked'] : ['pass'];
      if (!expectedStatuses.includes(String(item?.status || ''))) {
        errors.push(`SPARK battle coverage.${area}.status must be ${expectedStatuses.join(' or ')}`);
      }
      const coverageCaseIds = Array.isArray(item?.case_ids) ? item.case_ids : [];
      if (!coverageCaseIds.length) errors.push(`SPARK battle coverage.${area}.case_ids is empty`);
      for (const caseId of coverageCaseIds) {
        const normalizedCaseId = String(caseId);
        if (!caseIds.has(normalizedCaseId)) {
          errors.push(`SPARK battle coverage.${area} references unknown case_id ${caseId}`);
          continue;
        }
        if (coverageOwners.has(normalizedCaseId)) {
          errors.push(`SPARK battle case_id ${caseId} is reused by coverage.${coverageOwners.get(normalizedCaseId)} and coverage.${area}`);
        } else {
          coverageOwners.set(normalizedCaseId, area);
        }
        const command = commandById.get(normalizedCaseId);
        if (String(command?.coverage_area || '') !== area) {
          errors.push(`SPARK battle coverage.${area} case_id ${caseId} is bound to coverage_area ${command?.coverage_area || 'missing'}`);
        }
        const commandPattern = SPARK_COVERAGE_COMMAND_PATTERNS[area];
        if (commandPattern && !commandPattern.test(`${command?.scenario || ''} ${command?.command || ''}`)) {
          errors.push(`SPARK battle coverage.${area} case_id ${caseId} does not execute an area-specific command`);
        }
      }
      if (area === 'pinecone_live_local' && item?.status === 'environment_blocked') {
        if (!String(item.reason || '').trim()) errors.push('SPARK battle coverage.pinecone_live_local environment block is missing a reason');
        for (const caseId of coverageCaseIds) {
          const command = commandById.get(String(caseId));
          if (
            command
            && (
              command.expected_block !== true
              || !['blocked_external_quota', 'blocked_missing_credentials', 'blocked_network'].includes(String(command.semantic_outcome || ''))
            )
          ) {
            errors.push(`SPARK battle coverage.pinecone_live_local case_id ${caseId} is not a classified expected block`);
          }
        }
      }
    }
    for (const caseId of caseIds) {
      if (!coverageOwners.has(caseId)) errors.push(`SPARK battle command case_id ${caseId} is not assigned to exactly one coverage area`);
    }
    const semantic = inspectSemanticJson(parsed, { failOnInvalidEmbeddedJson: true });
    errors.push(...semantic.errors.map((error) => `SPARK battle semantic failure: ${error}`));
    benchmarkComparison = validateBenchmarkPair(path.dirname(reportPath), errors);
  }
  return {
    id: 'spark-battle-report',
    name: 'SPARK semantic battle and benchmark evidence',
    command: '<validate supplied SPARK battle report>',
    status: errors.length ? 'fail' : 'pass',
    exit_code: errors.length ? 2 : 0,
    duration_ms: Date.now() - started,
    report_path: reportPath ? sanitizeText(reportPath) : null,
    report_sha256: reportSha256,
    benchmark_comparison: benchmarkComparison,
    json_contract_errors: errors,
    stdout_tail: parsed ? `commands=${parsed.total_commands}; failed=${parsed.failed}; critical=${parsed.critical_failed}` : '',
    stderr_tail: errors.join('; ')
  };
}

function currentSourceHash(relativePath) {
  const filePath = path.join(root, String(relativePath || '').replace(/^\.knowledge[\\/]/, ''));
  try {
    return evidenceSha256(
      readStableRegularFile(filePath)
    );
  } catch {
    return null;
  }
}

function validateMemoryBattleReport(flags = {}) {
  const started = Date.now();
  const reportPath = memoryBattleReportPath(flags);
  const errors = [];
  let parsed = null;
  let reportSha256 = null;
  if (!reportPath) {
    errors.push('missing --memory-battle-report or KNOWLEDGE_MEMORY_BATTLE_REPORT');
  } else if (!fs.existsSync(reportPath)) {
    errors.push('memory battle report does not exist');
  } else {
    try {
      const body = readStableRegularFile(reportPath);
      reportSha256 = evidenceSha256(body);
      parsed = JSON.parse(stripBom(body.toString('utf8')));
    }
    catch (error) { errors.push(`invalid memory battle JSON: ${error.message}`); }
  }

  if (parsed) {
    if (String(parsed.release_version || '') !== String(version)) {
      errors.push(`memory battle release version is ${parsed.release_version || 'missing'}, expected ${version}`);
    }
    if (!['pass', 'pass_with_expected_blocks'].includes(String(parsed.status || ''))) {
      errors.push(`memory battle status is ${parsed.status || 'missing'}`);
    }
    if (!Array.isArray(parsed.commands) || parsed.commands.length !== Number(parsed.command_count || -1)) {
      errors.push('memory battle command details are missing or command_count does not match');
    }
    const semantic = inspectSemanticJson(parsed);
    errors.push(...semantic.errors.map((error) => `memory battle semantic failure: ${error}`));
    if (Number(parsed.metadata_scope_mismatch_count || 0) !== 0) {
      errors.push(`metadata_scope_mismatch_count is ${parsed.metadata_scope_mismatch_count}`);
    }
    if (parsed.local_memory?.utility_pass !== true) {
      errors.push('local FastEmbed utility proof did not pass');
    }
    for (const operation of ['add', 'search', 'recall', 'list']) {
      if (Number(parsed.local_memory?.[`${operation}_useful_count`] || 0) < 1) {
        errors.push(`local FastEmbed ${operation} has no useful live result`);
      }
    }
    if (parsed.failure_injection?.lock_busy_observed !== true) {
      errors.push('qdrant lock failure injection was not observed');
    }
    if (Number(parsed.encoding?.mojibake_count || 0) !== 0 || parsed.encoding?.unicode_path_roundtrip !== true) {
      errors.push('UTF-8/Unicode path verification did not pass cleanly');
    }
    if (Number(parsed.security?.secret_leak_count || 0) !== 0) {
      errors.push(`memory battle secret_leak_count is ${parsed.security.secret_leak_count}`);
    }
    const generated = Date.parse(parsed.generated_at || '');
    const maxAgeHours = Number(flags.memoryBattleMaxAgeHours || process.env.KNOWLEDGE_MEMORY_BATTLE_MAX_AGE_HOURS || 72);
    if (!Number.isFinite(generated)) errors.push('memory battle generated_at is invalid');
    else if (Date.now() - generated > maxAgeHours * 60 * 60 * 1000) errors.push(`memory battle report is older than ${maxAgeHours} hours`);

    const sourceFiles = parsed.source_files;
    if (!sourceFiles || typeof sourceFiles !== 'object' || Array.isArray(sourceFiles) || Object.keys(sourceFiles).length === 0) {
      errors.push('memory battle source file hashes are missing');
    } else {
      for (const [relativePath, expectedHash] of Object.entries(sourceFiles)) {
        const actualHash = currentSourceHash(relativePath);
        if (!actualHash || actualHash !== expectedHash) errors.push(`memory battle source hash mismatch: ${relativePath}`);
      }
    }
  }

  return {
    id: 'memory-battle-report',
    name: 'Mem0/FastEmbed semantic battle evidence',
    command: '<validate supplied memory battle report>',
    status: errors.length === 0 ? 'pass' : 'fail',
    exit_code: errors.length === 0 ? 0 : 2,
    duration_ms: Date.now() - started,
    expect_json: true,
    json_status: parsed?.status || null,
    json_contract_errors: errors,
    report_file: reportPath ? path.basename(reportPath) : null,
    report_sha256: reportSha256,
    blocked_count: Number(parsed?.blocked_count || 0),
    stdout_tail: parsed ? `commands=${parsed.command_count}; unexpected=${parsed.unexpected_semantic_failure_count}; blocked=${parsed.blocked_count || 0}` : '',
    stderr_tail: errors.join('; ')
  };
}

function sourceBootstrapStep(context, options = {}) {
  const started = Date.now();
  const knowledgeRoot = path.resolve(options.knowledgeRoot || root);
  const projectRoot = path.resolve(options.projectRoot || path.dirname(knowledgeRoot));
  const projectIndexPath = path.join(knowledgeRoot, 'project_index.json');
  const ingestPath = path.resolve(options.ingestPath || path.join(knowledgeRoot, 'tools', 'ingest-existing-project.js'));
  const stdoutPath = path.join(context.logDir, 'source-bootstrap.stdout.txt');
  const stderrPath = path.join(context.logDir, 'source-bootstrap.stderr.txt');
  const errors = [];
  ensureDir(context.logDir);

  function projectIndexEntryExists() {
    try {
      fs.lstatSync(projectIndexPath);
      return true;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return false;
    }
  }

  function projectIndexErrors() {
    let value;
    try {
      const body = readStableRegularFile(
        projectIndexPath,
        { maxBytes: 8 * 1024 * 1024 }
      );
      value = JSON.parse(stripBom(body.toString('utf8')));
    } catch (error) {
      return [
        `is not a valid physical JSON file: ${sanitizeText(error.message)}`
      ];
    }
    const validation = [];
    if (!isRecord(value)) {
      return ['must contain one JSON object'];
    }
    const nonEmptyString = (item) =>
      typeof item === 'string' &&
      item.trim().length > 0;
    if (!nonEmptyString(value.project_name)) {
      validation.push('is missing project_name');
    }
    if (value.repo_root !== '.') {
      validation.push('repo_root must be "."');
    }
    if (!nonEmptyString(value.status)) {
      validation.push('is missing status');
    }
    if (value.primary_source_of_truth !== 'code') {
      validation.push('primary_source_of_truth must be code');
    }
    const modules = Array.isArray(value.modules)
      ? value.modules
      : [];
    const moduleIds = modules.map((item) =>
      nonEmptyString(item?.module_id)
        ? item.module_id.trim()
        : ''
    );
    const moduleIdSet = new Set(moduleIds);
    if (
      modules.length === 0 ||
      !modules.every((item) =>
        isRecord(item) &&
        nonEmptyString(item.module_id) &&
        nonEmptyString(item.card)
      ) ||
      moduleIdSet.size !== moduleIds.length
    ) {
      validation.push(
        'modules must contain unique structured module records'
      );
    }
    const routes = Array.isArray(value.task_routing)
      ? value.task_routing
      : [];
    const routeIds = routes.map((item) =>
      nonEmptyString(item?.route_id)
        ? item.route_id.trim()
        : ''
    );
    const routedModuleIds = new Set(
      routes.flatMap((item) =>
        Array.isArray(item?.target_modules)
          ? item.target_modules.map((moduleId) =>
              nonEmptyString(moduleId)
                ? moduleId.trim()
                : ''
            )
          : []
      )
    );
    if (
      routes.length === 0 ||
      new Set(routeIds).size !== routeIds.length ||
      !routes.every((item) =>
        isRecord(item) &&
        nonEmptyString(item.route_id) &&
        Array.isArray(item.target_modules) &&
        item.target_modules.length > 0 &&
        item.target_modules.every((moduleId) =>
          nonEmptyString(moduleId) &&
          moduleIdSet.has(moduleId.trim())
        ) &&
        Array.isArray(item.start_with) &&
        item.start_with.length > 0 &&
        item.start_with.every(nonEmptyString)
      ) ||
      !moduleIds.every((moduleId) =>
        routedModuleIds.has(moduleId)
      )
    ) {
      validation.push(
        'task_routing must contain structured module-bound routes'
      );
    }
    return validation;
  }

  if (projectIndexEntryExists()) {
    errors.push(
      ...projectIndexErrors().map((error) =>
        `existing project_index.json ${error}`
      )
    );
    const noOpPayload = {
      status: errors.length ? 'fail' : 'pass',
      bootstrap_action: 'noop',
      project_index_path: relPath(projectIndexPath),
      errors
    };
    const stdout = `${JSON.stringify(noOpPayload, null, 2)}\n`;
    const stderr = errors.join('; ');
    const stdoutBody = Buffer.from(stdout, 'utf8');
    const stderrBody = Buffer.from(stderr, 'utf8');
    fs.writeFileSync(stdoutPath, stdoutBody);
    fs.writeFileSync(stderrPath, stderrBody);
    return {
      id: 'source-bootstrap',
      name: 'Bootstrap clean release source project index',
      command: '<noop: project_index.json already exists>',
      status: errors.length ? 'fail' : 'pass',
      exit_code: errors.length ? 2 : 0,
      duration_ms: Date.now() - started,
      bootstrap_action: 'noop',
      project_index_path: relPath(projectIndexPath),
      json_status: noOpPayload.status,
      json_contract_errors: errors,
      stdout_path: relPath(stdoutPath),
      stderr_path: relPath(stderrPath),
      stdout_sha256: evidenceSha256(stdoutBody),
      stderr_sha256: evidenceSha256(stderrBody),
      stdout_tail: sanitizeText(stdout),
      stderr_tail: sanitizeText(stderr)
    };
  }

  const result = spawnSync(process.execPath, [ingestPath, '--merge', '--no-sync'], {
    cwd: projectRoot,
    env: canonicalReleaseEnv(
      {
        KNOWLEDGE_AGENT_ID:
          'release-gate-source-bootstrap'
      },
      process.env,
      {
        knowledgeRoot,
        targetRoot: projectRoot,
        systemRoot: knowledgeRoot
      }
    ),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 300000
  });
  const stdoutBody = Buffer.from(
    String(result.stdout || ''),
    'utf8'
  );
  const stderrBody = Buffer.from(
    String(result.stderr || result.error?.message || ''),
    'utf8'
  );
  // A source-only self-test can legitimately replace or clean the durable
  // evidence subtree while it is running. Recreate the per-run log directory
  // after the child exits so the gate retains stdout/stderr instead of
  // crashing with ENOENT and losing the actual step decision.
  ensureDir(context.logDir);
  fs.writeFileSync(stdoutPath, stdoutBody);
  fs.writeFileSync(stderrPath, stderrBody);
  let parsed = null;
  if (result.status !== 0) errors.push(`source bootstrap exited with ${result.status}`);
  try {
    parsed = parseJson(stdoutBody.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) errors.push('source bootstrap stdout must be a JSON object');
  } catch (error) {
    errors.push(`source bootstrap stdout is invalid JSON: ${error.message}`);
  }
  if (!projectIndexEntryExists()) {
    errors.push(
      'source bootstrap did not create project_index.json'
    );
  } else {
    errors.push(
      ...projectIndexErrors().map((error) =>
        `source bootstrap project_index.json ${error}`
      )
    );
  }
  return {
    id: 'source-bootstrap',
    name: 'Bootstrap clean release source project index',
    command: `node ${sanitizeText(ingestPath)} --merge --no-sync`,
    status: errors.length ? 'fail' : 'pass',
    exit_code: errors.length ? (result.status || 2) : 0,
    duration_ms: Date.now() - started,
    bootstrap_action: 'ingest',
    project_index_path: relPath(projectIndexPath),
    json_status: parsed?.status || null,
    json_contract_errors: errors,
    stdout_path: relPath(stdoutPath),
    stderr_path: relPath(stderrPath),
    stdout_sha256: evidenceSha256(stdoutBody),
    stderr_sha256: evidenceSha256(stderrBody),
    stdout_tail: sanitizeText(stdoutBody.toString('utf8').slice(-3000)),
    stderr_tail: sanitizeText(stderrBody.toString('utf8').slice(-3000))
  };
}

function semanticSelfTest() {
  const cases = [
    {
      name: 'clean report passes',
      expected: true,
      value: { status: 'pass', unexpected_semantic_failure_count: 0, commands: [{ status: 'ok', semantic_pass: true }] }
    },
    {
      name: 'green exit style report with nested error fails',
      expected: false,
      value: { status: 'pass', unexpected_semantic_failure_count: 0, commands: [{ status: 'error', semantic_pass: false, diagnostic_code: 'unexpected' }] }
    },
    {
      name: 'green exit with error JSON in stdout fails',
      expected: false,
      value: { status: 'pass', commands: [{ exit_code: 0, success: true, stdout: JSON.stringify({ status: 'error', diagnostic_code: 'hidden_failure' }) }] }
    },
    {
      name: 'update wrapper cannot hide broken doctor stdout',
      expected: false,
      value: { status: 'ok', post_checks: [{ exit: 0, stdout: JSON.stringify({ status: 'broken', quality_score: 0 }) }] }
    },
    {
      name: 'degraded trust report is not a release pass',
      expected: false,
      value: { status: 'degraded', quality_score: 70 }
    },
    {
      name: 'root ok false fails',
      expected: false,
      value: { status: 'pass', ok: false }
    },
    {
      name: 'command success false fails even without error status',
      expected: false,
      value: { status: 'pass', commands: [{ status: 'ok', success: false, exit_code: 0 }] }
    },
    {
      name: 'nonzero command exit fails even when summary says pass',
      expected: false,
      value: { status: 'pass', commands: [{ status: 'ok', success: true, exit_code: 2 }] }
    },
    {
      name: 'expected negative is accepted',
      expected: true,
      value: { status: 'pass', commands: [{ status: 'error', ok: false, semantic_pass: true, expected_semantic_failure: true, semantic_outcome: 'expected_failure_observed', stdout: JSON.stringify({ status: 'error' }) }] }
    },
    {
      name: 'matched expected nonzero exit is accepted',
      expected: true,
      value: { status: 'pass', steps: [{ status: 'pass', exit_code: 1, expected_failure: true, expected_nonzero_exit: true, expected_failure_code: 'EXPECTED_BLOCK', observed_failure_code: 'EXPECTED_BLOCK' }] }
    },
    {
      name: 'unmatched expected nonzero exit is rejected',
      expected: false,
      value: { status: 'pass', steps: [{ status: 'pass', exit_code: 1, expected_failure: false, expected_nonzero_exit: true, expected_failure_code: 'EXPECTED_BLOCK', observed_failure_code: 'OTHER_BLOCK' }] }
    },
    {
      name: 'missing physical exit cannot satisfy expected nonzero exit',
      expected: false,
      value: { status: 'pass', steps: [{ status: 'pass', exit_code: null, expected_failure: false, expected_nonzero_exit: true, expected_failure_code: 'EXPECTED_BLOCK', observed_failure_code: 'EXPECTED_BLOCK' }] }
    },
    {
      name: 'forged expected marker cannot hide missing physical exit',
      expected: false,
      value: { status: 'pass', steps: [{ status: 'pass', exit_code: null, expected_failure: true, expected_nonzero_exit: true, expected_failure_code: 'EXPECTED_BLOCK', observed_failure_code: 'EXPECTED_BLOCK' }] }
    },
    {
      name: 'quota block is accepted only when explicit',
      expected: true,
      value: { status: 'pass_with_expected_blocks', commands: [{ status: 'error', semantic_pass: true, expected_block: true, semantic_outcome: 'blocked_external_quota' }] }
    }
  ];
  const results = cases.map((item) => {
    const inspected = inspectSemanticJson(item.value);
    return {
      name: item.name,
      status: inspected.ok === item.expected ? 'pass' : 'fail',
      expected_semantic_ok: item.expected,
      actual_semantic_ok: inspected.ok,
      errors: inspected.errors
    };
  });
  const contractRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-spark-contract-'));
  try {
    const hashText = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');
    const hashObservation = (value) => hashText(stableCanonicalStringify(value));
    const logDir = path.join(contractRoot, 'logs');
    ensureDir(logDir);
    const writeTrace = (logPath, row) => {
      const trace = {
        schema_version: SPARK_TRACE_SCHEMA,
        command_id: row.command_id,
        case_id: row.case_id,
        scenario: row.scenario,
        coverage_area: row.coverage_area,
        arm: row.arm,
        repeat: row.repeat,
        command: row.command,
        exit_code: row.exit_code,
        duration_ms: row.duration_ms,
        semantic_pass: row.semantic_pass,
        semantic_outcome: row.semantic_outcome,
        source_sha256: row.source_sha256,
        canonical_observation: row.canonical_observation,
        observed_sha256: row.observed_sha256
      };
      fs.writeFileSync(path.join(contractRoot, logPath), `${JSON.stringify(trace, null, 2)}\n`, 'utf8');
      return sha256IfExists(path.join(contractRoot, logPath));
    };
    const coverageFixtures = [
      ['trust_layer', 'node tools/doctor.js --json', 'pass'],
      ['inspector', 'node tools/build-visual-inspector.js --json', 'pass'],
      ['updater', 'node tools/check-updates.js --status --json', 'pass'],
      ['mem0_local', 'node tools/memory-mem0.js health --json', 'pass'],
      ['pinecone_offline', 'node tools/memory-pinecone.js health --json', 'pass'],
      ['pinecone_live_local', 'node tools/memory-pinecone.js health --adapter live --json', 'blocked_missing_credentials']
    ];
    const commands = coverageFixtures.map(([coverageArea, commandText, semanticOutcome], index) => {
      const expectedBlock = semanticOutcome !== 'pass';
      const row = {
        command_id: `functional-${coverageArea}-r1`,
        case_id: `qa-${coverageArea}`,
        scenario: `${coverageArea}-contract`,
        coverage_area: coverageArea,
        arm: 'functional',
        repeat: 1,
        command: commandText,
        exit_code: expectedBlock ? 2 : 0,
        success: true,
        semantic_pass: true,
        semantic_outcome: semanticOutcome,
        expected_block: expectedBlock,
        duration_ms: 10 + index,
        canonical_observation: {
          case_id: `qa-${coverageArea}`,
          coverage_area: coverageArea,
          outcome: semanticOutcome
        }
      };
      row.source_sha256 = hashText(`functional-source:${row.scenario}:${row.command}`);
      row.observed_sha256 = hashObservation(row.canonical_observation);
      row.log_path = `logs/qa-${coverageArea}.json`;
      row.log_sha256 = writeTrace(row.log_path, row);
      return row;
    });
    const oracleSourceDir = path.join(contractRoot, 'oracle-sources');
    const oracleEvidenceDir = path.join(contractRoot, 'oracle-evidence');
    ensureDir(oracleSourceDir);
    ensureDir(oracleEvidenceDir);
    const expectedByCase = new Map();
    for (let caseIndex = 0; caseIndex < 6; caseIndex += 1) {
      const caseId = `task-${caseIndex + 1}`;
      const scenario = `benchmark-${caseId}`;
      const canonicalObservation = { case_id: caseId, result: `expected:${caseId}` };
      const sourcePath = `oracle-sources/${caseId}.json`;
      writeJsonAtomic(path.join(contractRoot, sourcePath), {
        schema_version: 'knowledge-comparative-source.v1',
        case_id: caseId,
        scenario,
        input: `fixture-input:${caseId}`
      });
      expectedByCase.set(caseId, {
        scenario,
        canonicalObservation,
        expectedSha256: hashObservation(canonicalObservation),
        sourcePath,
        sourceSha256: sha256IfExists(path.join(contractRoot, sourcePath))
      });
    }
    const preregistrationPath = path.join(contractRoot, 'comparative-preregistration.json');
    writeJsonAtomic(preregistrationPath, {
      schema_version: 'knowledge-comparative-preregistration.v1',
      cases: [...expectedByCase].map(([caseId, item]) => ({
        case_id: caseId,
        scenario: item.scenario,
        source_path: item.sourcePath,
        source_sha256: item.sourceSha256,
        expected_sha256: item.expectedSha256
      }))
    });
    const preregistrationSha256 = sha256IfExists(preregistrationPath);
    for (const [caseId, item] of expectedByCase) {
      item.evidencePath = `oracle-evidence/${caseId}.json`;
      writeJsonAtomic(path.join(contractRoot, item.evidencePath), {
        schema_version: 'knowledge-comparative-oracle-evidence.v1',
        case_id: caseId,
        scenario: item.scenario,
        preregistration_sha256: preregistrationSha256,
        source_path: item.sourcePath,
        source_sha256: item.sourceSha256,
        expected_sha256: item.expectedSha256,
        canonical_observation: item.canonicalObservation
      });
      item.evidenceSha256 = sha256IfExists(path.join(contractRoot, item.evidencePath));
    }
    const oraclePath = path.join(contractRoot, 'comparative-oracle.json');
    writeJsonAtomic(oraclePath, {
      schema_version: 'knowledge-comparative-oracle.v1',
      preregistration_path: 'comparative-preregistration.json',
      preregistration_sha256: preregistrationSha256,
      cases: [...expectedByCase].map(([caseId, item]) => ({
        case_id: caseId,
        scenario: item.scenario,
        source_path: item.sourcePath,
        source_sha256: item.sourceSha256,
        evidence_path: item.evidencePath,
        evidence_sha256: item.evidenceSha256,
        expected_sha256: item.expectedSha256,
        canonical_observation: item.canonicalObservation
      }))
    });
    const oracleSha256 = sha256IfExists(oraclePath);
    const benchmarkEntries = (mode) => Array.from({ length: 6 }, (_, caseIndex) => (
      Array.from({ length: 10 }, (_, repeatIndex) => {
        const baseline = mode === 'without-knowledge';
        const taskSuccess = baseline ? repeatIndex < 8 : true;
        const caseId = `task-${caseIndex + 1}`;
        const oracleCase = expectedByCase.get(caseId);
        const canonicalObservation = taskSuccess
          ? oracleCase.canonicalObservation
          : { case_id: caseId, result: `mismatch:${caseId}:${repeatIndex + 1}` };
        const row = {
          command_id: `benchmark-${mode}-${caseId}-r${repeatIndex + 1}`,
          case_id: caseId,
          scenario: oracleCase.scenario,
          arm: mode,
          repeat: repeatIndex + 1,
          command: `node benchmark-task.js ${caseId} --arm ${mode}`,
          exit_code: 0,
          execution_ok: true,
          task_success: taskSuccess,
          oracle_match: taskSuccess,
          semantic_outcome: taskSuccess ? 'pass' : 'oracle_mismatch',
          source_sha256: oracleCase.sourceSha256,
          expected_sha256: oracleCase.expectedSha256,
          canonical_observation: canonicalObservation,
          observed_sha256: hashObservation(canonicalObservation),
          duration_ms: baseline ? 100 : 80,
          files_read: baseline ? 10 : 4,
          context_bytes: baseline ? 4000 : 1600,
          estimated_context_tokens: baseline ? 1000 : 400,
          unverified_claims: 0
        };
        const traceRow = {
          ...row,
          coverage_area: 'benchmark',
          semantic_pass: taskSuccess,
          semantic_outcome: taskSuccess ? 'pass' : 'oracle_mismatch'
        };
        row.log_path = `logs/benchmark-${mode}-${caseId}-r${repeatIndex + 1}.json`;
        row.log_sha256 = writeTrace(row.log_path, traceRow);
        return row;
      })
    )).flat();
    const reportPath = path.join(contractRoot, 'spark-battle-results.json');
    writeJsonAtomic(reportPath, {
      schema_version: 'knowledge-spark-battle.v2',
      status: 'pass',
      total_commands: commands.length,
      passed: commands.length,
      failed: 0,
      critical_failed: 0,
      unexpected_semantic_failure_count: 0,
      coverage: {
        trust_layer: { status: 'pass', case_ids: ['qa-trust_layer'] },
        inspector: { status: 'pass', case_ids: ['qa-inspector'] },
        updater: { status: 'pass', case_ids: ['qa-updater'] },
        mem0_local: { status: 'pass', case_ids: ['qa-mem0_local'] },
        pinecone_offline: { status: 'pass', case_ids: ['qa-pinecone_offline'] },
        pinecone_live_local: {
          status: 'environment_blocked',
          reason: 'credentials unavailable in offline contract fixture',
          case_ids: ['qa-pinecone_live_local']
        }
      },
      commands
    });
    for (const mode of ['with-knowledge', 'without-knowledge']) {
      const entries = benchmarkEntries(mode);
      writeJsonAtomic(path.join(contractRoot, `benchmark-${mode === 'with-knowledge' ? 'with' : 'without'}-knowledge.json`), {
        schema_version: 'knowledge-comparative-benchmark.v2',
        mode,
        oracle_path: 'comparative-oracle.json',
        oracle_sha256: oracleSha256,
        command_count: entries.length,
        entries
      });
    }
    const readContractJson = (filePath) => JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const writeContractJson = (filePath, value) => writeJsonAtomic(filePath, value);
    const assistedPath = path.join(contractRoot, 'benchmark-with-knowledge.json');
    const baselinePath = path.join(contractRoot, 'benchmark-without-knowledge.json');
    const originalReport = readContractJson(reportPath);
    const originalAssisted = readContractJson(assistedPath);
    const originalBaseline = readContractJson(baselinePath);
    const pushValidationResult = (name, validation, expectedPass) => {
      const actualPass = validation.status === 'pass';
      results.push({
        name,
        status: actualPass === expectedPass ? 'pass' : 'fail',
        expected_semantic_ok: expectedPass,
        actual_semantic_ok: actualPass,
        errors: validation.json_contract_errors
      });
    };

    const valid = validateSparkBattleReport({ sparkBattleReport: reportPath });
    pushValidationResult('matched SPARK traces and common-oracle benchmark v2 contract passes', valid, true);

    const weakTraceReport = readContractJson(reportPath);
    delete weakTraceReport.commands[0].log_sha256;
    writeContractJson(reportPath, weakTraceReport);
    pushValidationResult(
      'legacy weak SPARK evidence without trace hash is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const escapingTraceReport = readContractJson(reportPath);
    escapingTraceReport.commands[0].log_path = '../outside.log';
    writeContractJson(reportPath, escapingTraceReport);
    pushValidationResult(
      'SPARK trace path traversal is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const firstTracePath = path.join(contractRoot, originalReport.commands[0].log_path);
    const originalTrace = fs.readFileSync(firstTracePath, 'utf8');
    fs.appendFileSync(firstTracePath, '{"tampered":true}\n', 'utf8');
    pushValidationResult(
      'SPARK trace content tampering is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    fs.writeFileSync(firstTracePath, originalTrace, 'utf8');

    const emptyTracePath = path.join(contractRoot, 'logs', 'empty.log');
    fs.writeFileSync(emptyTracePath, '', 'utf8');
    const emptyTraceReport = readContractJson(reportPath);
    emptyTraceReport.commands[0].log_path = 'logs/empty.log';
    emptyTraceReport.commands[0].log_sha256 = sha256IfExists(emptyTracePath);
    writeContractJson(reportPath, emptyTraceReport);
    pushValidationResult(
      'empty SPARK trace is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const directoryTraceReport = readContractJson(reportPath);
    directoryTraceReport.commands[0].log_path = 'logs';
    directoryTraceReport.commands[0].log_sha256 = '0'.repeat(64);
    writeContractJson(reportPath, directoryTraceReport);
    pushValidationResult(
      'non-regular SPARK trace is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const invalidJsonTracePath = path.join(contractRoot, 'logs', 'not-json.log');
    fs.writeFileSync(invalidJsonTracePath, 'not a JSON command trace\n', 'utf8');
    const invalidJsonTraceReport = readContractJson(reportPath);
    invalidJsonTraceReport.commands[0].log_path = 'logs/not-json.log';
    invalidJsonTraceReport.commands[0].log_sha256 = sha256IfExists(invalidJsonTracePath);
    writeContractJson(reportPath, invalidJsonTraceReport);
    pushValidationResult(
      'non-JSON SPARK command trace is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const reusedTraceReport = readContractJson(reportPath);
    reusedTraceReport.commands[1].log_path = reusedTraceReport.commands[0].log_path;
    reusedTraceReport.commands[1].log_sha256 = reusedTraceReport.commands[0].log_sha256;
    writeContractJson(reportPath, reusedTraceReport);
    pushValidationResult(
      'one generic trace cannot be reused by multiple SPARK commands',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const missingCommandIdReport = readContractJson(reportPath);
    delete missingCommandIdReport.commands[0].command_id;
    writeContractJson(reportPath, missingCommandIdReport);
    pushValidationResult(
      'SPARK functional command_id is required',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const duplicateCommandIdReport = readContractJson(reportPath);
    duplicateCommandIdReport.commands[1].command_id = duplicateCommandIdReport.commands[0].command_id;
    writeContractJson(reportPath, duplicateCommandIdReport);
    pushValidationResult(
      'SPARK functional command_id values must be unique',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const commandIdTracePath = path.join(contractRoot, originalReport.commands[0].log_path);
    const originalCommandIdTrace = readContractJson(commandIdTracePath);
    const mismatchedCommandIdTrace = { ...originalCommandIdTrace, command_id: 'unbound-functional-command' };
    writeContractJson(commandIdTracePath, mismatchedCommandIdTrace);
    const commandIdMismatchReport = readContractJson(reportPath);
    commandIdMismatchReport.commands[0].log_sha256 = sha256IfExists(commandIdTracePath);
    writeContractJson(reportPath, commandIdMismatchReport);
    pushValidationResult(
      'SPARK trace command_id must exactly bind to its functional row',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(commandIdTracePath, originalCommandIdTrace);
    writeContractJson(reportPath, originalReport);

    const reusedCoverageReport = readContractJson(reportPath);
    reusedCoverageReport.coverage.inspector.case_ids = reusedCoverageReport.coverage.trust_layer.case_ids.slice();
    writeContractJson(reportPath, reusedCoverageReport);
    pushValidationResult(
      'one generic command cannot satisfy multiple SPARK coverage areas',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(reportPath, originalReport);

    const weakBenchmark = readContractJson(assistedPath);
    delete weakBenchmark.oracle_path;
    delete weakBenchmark.oracle_sha256;
    delete weakBenchmark.entries[0].observed_sha256;
    writeContractJson(assistedPath, weakBenchmark);
    pushValidationResult(
      'legacy weak benchmark evidence without oracle provenance is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(assistedPath, originalAssisted);

    const duplicateBenchmarkCommandId = readContractJson(assistedPath);
    duplicateBenchmarkCommandId.entries[1].command_id = duplicateBenchmarkCommandId.entries[0].command_id;
    writeContractJson(assistedPath, duplicateBenchmarkCommandId);
    pushValidationResult(
      'benchmark command_id values must be unique',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(assistedPath, originalAssisted);

    const crossArmCommandIdReuse = readContractJson(baselinePath);
    crossArmCommandIdReuse.entries[0].command_id = originalAssisted.entries[0].command_id;
    writeContractJson(baselinePath, crossArmCommandIdReuse);
    pushValidationResult(
      'benchmark command_id values cannot be reused across arms',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(baselinePath, originalBaseline);

    const benchmarkTraceBinding = readContractJson(assistedPath);
    benchmarkTraceBinding.entries[0].command_id = 'unbound-benchmark-command';
    writeContractJson(assistedPath, benchmarkTraceBinding);
    pushValidationResult(
      'benchmark trace command_id must exactly bind to its row',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(assistedPath, originalAssisted);

    const firstOracleCase = expectedByCase.get('task-1');
    const sourceEvidencePath = path.join(contractRoot, firstOracleCase.sourcePath);
    const originalSourceEvidence = fs.readFileSync(sourceEvidencePath);
    fs.appendFileSync(sourceEvidencePath, '\n', 'utf8');
    pushValidationResult(
      'oracle source fingerprint tampering is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    fs.writeFileSync(sourceEvidencePath, originalSourceEvidence);

    const originalPreregistration = fs.readFileSync(preregistrationPath);
    fs.appendFileSync(preregistrationPath, '\n', 'utf8');
    pushValidationResult(
      'oracle preregistration fingerprint tampering is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    fs.writeFileSync(preregistrationPath, originalPreregistration);

    const selfReportedObservation = readContractJson(assistedPath);
    selfReportedObservation.entries[0].canonical_observation = { invented: true };
    writeContractJson(assistedPath, selfReportedObservation);
    pushValidationResult(
      'self-reported benchmark hash without matching canonical observation is rejected',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(assistedPath, originalAssisted);

    const falseOracleMatch = readContractJson(assistedPath);
    falseOracleMatch.entries[0].observed_sha256 = hashText('not-the-oracle-result');
    writeContractJson(assistedPath, falseOracleMatch);
    pushValidationResult(
      'oracle_match cannot disagree with observed_sha256',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(assistedPath, originalAssisted);

    const mismatched = readContractJson(assistedPath);
    mismatched.entries[0].case_id = 'unmatched-task';
    writeContractJson(assistedPath, mismatched);
    const invalid = validateSparkBattleReport({ sparkBattleReport: reportPath });
    pushValidationResult('mismatched benchmark case set and missing oracle coverage fail', invalid, false);
    writeContractJson(assistedPath, originalAssisted);

    const mismatchedOracle = readContractJson(baselinePath);
    mismatchedOracle.oracle_sha256 = '0'.repeat(64);
    writeContractJson(baselinePath, mismatchedOracle);
    pushValidationResult(
      'assisted and baseline must use the same verified oracle sidecar hash',
      validateSparkBattleReport({ sparkBattleReport: reportPath }),
      false
    );
    writeContractJson(baselinePath, originalBaseline);

    const bootstrapProjectRoot = path.join(contractRoot, 'bootstrap-project');
    const bootstrapKnowledgeRoot = path.join(bootstrapProjectRoot, '.knowledge');
    const fakeIngestPath = path.join(bootstrapKnowledgeRoot, 'tools', 'fake-ingest.js');
    const bootstrapLogDir = path.join(contractRoot, 'bootstrap-logs');
    ensureDir(path.dirname(fakeIngestPath));
    fs.writeFileSync(fakeIngestPath, [
      "'use strict';",
      "const fs = require('fs');",
      "const path = require('path');",
      "const target = path.join(process.cwd(), '.knowledge', 'project_index.json');",
      "fs.mkdirSync(path.dirname(target), { recursive: true });",
      "const index = { status: 'heuristic_ingest', project_name: 'bootstrap-fixture', repo_root: '.', generated_by: process.env.KNOWLEDGE_AGENT_ID, primary_source_of_truth: 'code', modules: [{ module_id: 'root', card: '.knowledge/modules/root.json', confidence: 'medium' }], task_routing: [{ route_id: 'root', target_modules: ['root'], start_with: ['.knowledge/modules/root.json'] }] };",
      "fs.writeFileSync(target, JSON.stringify(index) + '\\n', 'utf8');",
      "console.log(JSON.stringify({ generated_at: '2026-01-01T00:00:00.000Z', modules_detected: 1, modules_total: 1, ignored_source_checkouts: [], technologies: [], root_module: true, mode: 'merge', routing_bundle: null, search_documents: null, auto_track: { enabled: false, limit: 25, added: 0, considered: 0, capped: false, tracked_total: 0 } }));"
    ].join('\n'), 'utf8');
    const bootstrap = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      { knowledgeRoot: bootstrapKnowledgeRoot, projectRoot: bootstrapProjectRoot, ingestPath: fakeIngestPath }
    );
    results.push({
      name: 'clean source bootstrap creates a valid project index',
      status: bootstrap.status === 'pass' && bootstrap.bootstrap_action === 'ingest' && fs.existsSync(path.join(bootstrapKnowledgeRoot, 'project_index.json')) ? 'pass' : 'fail',
      expected_semantic_ok: true,
      actual_semantic_ok: bootstrap.status === 'pass',
      errors: bootstrap.json_contract_errors
    });
    const bootstrapNoop = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      { knowledgeRoot: bootstrapKnowledgeRoot, projectRoot: bootstrapProjectRoot, ingestPath: fakeIngestPath }
    );
    const bootstrapNoopStdoutPath = path.join(
      bootstrapLogDir,
      'source-bootstrap.stdout.txt'
    );
    const bootstrapNoopStderrPath = path.join(
      bootstrapLogDir,
      'source-bootstrap.stderr.txt'
    );
    const bootstrapNoopLog = JSON.parse(
      fs.readFileSync(bootstrapNoopStdoutPath, 'utf8')
    );
    results.push({
      name: 'source bootstrap is a valid no-op when project index exists',
      status:
        bootstrapNoop.status === 'pass' &&
        bootstrapNoop.bootstrap_action === 'noop' &&
        bootstrapNoop.json_status === 'pass' &&
        Boolean(bootstrapNoop.stdout_path) &&
        Boolean(bootstrapNoop.stderr_path) &&
        bootstrapNoop.stdout_sha256 ===
          evidenceSha256(
            fs.readFileSync(bootstrapNoopStdoutPath)
          ) &&
        bootstrapNoop.stderr_sha256 ===
          evidenceSha256(
            fs.readFileSync(bootstrapNoopStderrPath)
          ) &&
        bootstrapNoopLog.status === 'pass' &&
        bootstrapNoopLog.bootstrap_action === 'noop' &&
        fs.existsSync(bootstrapNoopStderrPath)
          ? 'pass'
          : 'fail',
      expected_semantic_ok: true,
      actual_semantic_ok: bootstrapNoop.status === 'pass',
      errors: bootstrapNoop.json_contract_errors
    });
    const validBootstrapIndex = fs.readFileSync(
      path.join(
        bootstrapKnowledgeRoot,
        'project_index.json'
      )
    );
    fs.writeFileSync(
      path.join(
        bootstrapKnowledgeRoot,
        'project_index.json'
      ),
      '{}\n',
      'utf8'
    );
    const malformedBootstrapNoop = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      {
        knowledgeRoot: bootstrapKnowledgeRoot,
        projectRoot: bootstrapProjectRoot,
        ingestPath: fakeIngestPath
      }
    );
    const malformedBootstrapLog = JSON.parse(
      fs.readFileSync(bootstrapNoopStdoutPath, 'utf8')
    );
    results.push({
      name:
        'source bootstrap rejects a structurally empty project index with bound logs',
      status:
        malformedBootstrapNoop.status === 'fail' &&
        malformedBootstrapNoop.exit_code === 2 &&
        malformedBootstrapLog.status === 'fail' &&
        malformedBootstrapLog.errors.length > 0 &&
        fs.readFileSync(
          bootstrapNoopStderrPath,
          'utf8'
        ).length > 0
          ? 'pass'
          : 'fail',
      expected_semantic_ok: false,
      actual_semantic_ok:
        malformedBootstrapNoop.status === 'pass',
      errors: malformedBootstrapNoop.json_contract_errors
    });
    const externalBootstrapIndex = path.join(
      bootstrapProjectRoot,
      'external-project-index.json'
    );
    const bootstrapProjectIndex = path.join(
      bootstrapKnowledgeRoot,
      'project_index.json'
    );
    fs.unlinkSync(bootstrapProjectIndex);
    fs.writeFileSync(
      externalBootstrapIndex,
      validBootstrapIndex
    );
    fs.linkSync(
      externalBootstrapIndex,
      bootstrapProjectIndex
    );
    const linkedBootstrapNoop = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      {
        knowledgeRoot: bootstrapKnowledgeRoot,
        projectRoot: bootstrapProjectRoot,
        ingestPath: fakeIngestPath
      }
    );
    results.push({
      name:
        'source bootstrap rejects a multiply-linked project index',
      status:
        linkedBootstrapNoop.status === 'fail' &&
        linkedBootstrapNoop.exit_code === 2 &&
        linkedBootstrapNoop.json_contract_errors.some(
          (error) =>
            /physical JSON file/.test(error)
        )
          ? 'pass'
          : 'fail',
      expected_semantic_ok: false,
      actual_semantic_ok: linkedBootstrapNoop.status === 'pass',
      errors: linkedBootstrapNoop.json_contract_errors
    });
    fs.unlinkSync(bootstrapProjectIndex);
    fs.unlinkSync(externalBootstrapIndex);
    fs.writeFileSync(
      bootstrapProjectIndex,
      JSON.stringify({
        status: 'heuristic_ingest',
        project_name: 'module-only-fixture',
        repo_root: '.',
        primary_source_of_truth: 'code',
        modules: [{
          module_id: 'api',
          card: '.knowledge/modules/api.json',
          confidence: 'medium'
        }],
        task_routing: [{
          route_id: 'api',
          target_modules: ['api'],
          start_with: ['.knowledge/modules/api.json']
        }]
      }) + '\n',
      'utf8'
    );
    const moduleOnlyBootstrapNoop = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      {
        knowledgeRoot: bootstrapKnowledgeRoot,
        projectRoot: bootstrapProjectRoot,
        ingestPath: fakeIngestPath
      }
    );
    results.push({
      name:
        'source bootstrap accepts a structured module-only project index',
      status:
        moduleOnlyBootstrapNoop.status === 'pass' &&
        moduleOnlyBootstrapNoop.exit_code === 0
          ? 'pass'
          : 'fail',
      expected_semantic_ok: true,
      actual_semantic_ok:
        moduleOnlyBootstrapNoop.status === 'pass',
      errors: moduleOnlyBootstrapNoop.json_contract_errors
    });
    fs.writeFileSync(
      bootstrapProjectIndex,
      JSON.stringify({
        status: ['heuristic_ingest'],
        project_name: {},
        repo_root: '.',
        primary_source_of_truth: 'code',
        modules: [{
          module_id: 123,
          card: {},
          confidence: 'medium'
        }],
        task_routing: [{
          route_id: {},
          target_modules: [123],
          start_with: [null]
        }]
      }) + '\n',
      'utf8'
    );
    const mistypedBootstrapNoop = sourceBootstrapStep(
      { logDir: bootstrapLogDir },
      {
        knowledgeRoot: bootstrapKnowledgeRoot,
        projectRoot: bootstrapProjectRoot,
        ingestPath: fakeIngestPath
      }
    );
    results.push({
      name:
        'source bootstrap rejects type-coerced routing fields',
      status:
        mistypedBootstrapNoop.status === 'fail' &&
        mistypedBootstrapNoop.exit_code === 2 &&
        mistypedBootstrapNoop.json_contract_errors.length > 0
          ? 'pass'
          : 'fail',
      expected_semantic_ok: false,
      actual_semantic_ok:
        mistypedBootstrapNoop.status === 'pass',
      errors: mistypedBootstrapNoop.json_contract_errors
    });
    fs.writeFileSync(
      bootstrapProjectIndex,
      validBootstrapIndex
    );
    const syntheticLogDir = path.join(
      contractRoot,
      'synthetic-validator-logs'
    );
    const syntheticValidation =
      bindSyntheticStepStreams({
        id: 'memory-battle-report',
        name: 'synthetic validator fixture',
        command: '<validate supplied report>',
        status: 'pass',
        exit_code: 0,
        duration_ms: 1,
        json_status: 'pass',
        json_contract_errors: [],
        report_file: 'fixture.json',
        report_sha256: 'a'.repeat(64)
      }, { logDir: syntheticLogDir });
    const syntheticStdoutPath = path.join(
      syntheticLogDir,
      'memory-battle-report.stdout.txt'
    );
    const syntheticStderrPath = path.join(
      syntheticLogDir,
      'memory-battle-report.stderr.txt'
    );
    results.push({
      name:
        'optional evidence validators emit bound physical streams',
      status:
        fs.existsSync(syntheticStdoutPath) &&
        fs.existsSync(syntheticStderrPath) &&
        syntheticValidation.stdout_sha256 ===
          evidenceSha256(
            fs.readFileSync(syntheticStdoutPath)
          ) &&
        syntheticValidation.stderr_sha256 ===
          evidenceSha256(
            fs.readFileSync(syntheticStderrPath)
          )
          ? 'pass'
          : 'fail',
      expected_semantic_ok: true,
      actual_semantic_ok:
        Boolean(syntheticValidation.stdout_path) &&
        Boolean(syntheticValidation.stderr_path),
      errors: []
    });

    const previousMemoryReport = process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT;
    const previousSparkReport =
      process.env.KNOWLEDGE_SPARK_BATTLE_REPORT;
    delete process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT;
    delete process.env.KNOWLEDGE_SPARK_BATTLE_REPORT;
    try {
      const quickSteps = modeSteps(
        'quick',
        { ignoreAmbientEvidence: true }
      ).map((item) => item.id);
      const fullWithoutMemory = modeSteps(
        'full',
        { ignoreAmbientEvidence: true }
      ).map((item) => item.id);
      const fullWithMemory = modeSteps('full', { memoryBattleReport: 'sanitized-memory-report.json' }).map((item) => item.id);
      const releaseSteps = modeSteps('release', {}).map((item) => item.id);
      const bootstrapIndex = fullWithoutMemory.indexOf('source-bootstrap');
      const firstSourceTestIndex = fullWithoutMemory.indexOf('self-test-inspector-launcher');
      const privacyIndex = quickSteps.indexOf('self-test-export-privacy');
      const repairIndex = quickSteps.indexOf('self-test-repair-on-touch');
      const dedicatedIndex = quickSteps.indexOf(
        'self-test-dedicated-verification'
      );
      const sessionIsolationIndex = quickSteps.indexOf(
        'self-test-repair-session-isolation'
      );
      const packageIndex = quickSteps.indexOf('package-release');
      const quickSpecs = modeSteps(
        'quick',
        { ignoreAmbientEvidence: true }
      );
      const packageSpec = quickSpecs.find((item) => item.id === 'package-release');
      const modeContractOk = (
        !fullWithoutMemory.includes('memory-battle-report')
        && fullWithMemory.includes('memory-battle-report')
        && releaseSteps.includes('memory-battle-report')
        && quickSteps.includes('public-consistency')
        && quickSteps.includes('self-test-export-privacy')
        && fullWithoutMemory.includes('self-test-export-privacy')
        && releaseSteps.includes('self-test-export-privacy')
        && !quickSteps.includes('self-test-handoff-current-state')
        && fullWithoutMemory.includes('self-test-handoff-current-state')
        && releaseSteps.includes('self-test-handoff-current-state')
        && quickSteps.filter((id) => id === 'self-test-export-privacy').length === 1
        && quickSteps.filter((id) => id === 'self-test-repair-on-touch').length === 1
        && quickSteps.filter((id) =>
          id === 'self-test-dedicated-verification').length === 1
        && quickSteps.filter((id) =>
          id === 'self-test-repair-session-isolation').length === 1
        && fullWithoutMemory.filter((id) =>
          id === 'self-test-dedicated-verification').length === 1
        && fullWithoutMemory.filter((id) =>
          id === 'self-test-repair-session-isolation').length === 1
        && releaseSteps.filter((id) =>
          id === 'self-test-dedicated-verification').length === 1
        && releaseSteps.filter((id) =>
          id === 'self-test-repair-session-isolation').length === 1
        && privacyIndex >= 0
        && privacyIndex < packageIndex
        && repairIndex >= 0
        && repairIndex < packageIndex
        && dedicatedIndex >= 0
        && dedicatedIndex < packageIndex
        && sessionIsolationIndex >= 0
        && sessionIsolationIndex < packageIndex
        && packageSpec?.requires?.includes('self-test-export-privacy')
        && packageSpec?.requires?.includes('self-test-repair-on-touch')
        && packageSpec?.requires?.includes(
          'self-test-dedicated-verification'
        )
        && packageSpec?.requires?.includes(
          'self-test-repair-session-isolation'
        )
        && satisfiedImpactGatesForMode('quick').has('public-consistency')
        && !satisfiedImpactGatesForMode('quick').has('full')
        && satisfiedImpactGatesForMode('full').has('full')
        && satisfiedImpactGatesForMode('full').has('conformance-suite')
        && !satisfiedImpactGatesForMode('quick').has('unknown-gate')
        && bootstrapIndex >= 0
        && bootstrapIndex < firstSourceTestIndex
      );
      results.push({
        name: 'mode capabilities route public consistency/full/conformance and preserve memory/bootstrap contracts',
        status: modeContractOk ? 'pass' : 'fail',
        expected_semantic_ok: true,
        actual_semantic_ok: modeContractOk,
        errors: modeContractOk ? [] : [{ quickSteps, fullWithoutMemory, fullWithMemory, releaseSteps }]
      });
      const fullPlan = canonicalFullEvidencePlan();
      const repeatedPlan = canonicalFullEvidencePlan();
      const producerClosure =
        canonicalReleaseProducerClosure();
      const repeatedProducerClosure =
        canonicalReleaseProducerClosure();
      process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT =
        'ambient-memory-report.json';
      process.env.KNOWLEDGE_SPARK_BATTLE_REPORT =
        'ambient-spark-report.json';
      const ambientPlan = canonicalFullEvidencePlan();
      const ambientProducerClosure =
        canonicalReleaseProducerClosure();
      delete process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT;
      delete process.env.KNOWLEDGE_SPARK_BATTLE_REPORT;
      const requiredProducers = new Set([
        'package.json',
        'release-policy.json',
        'tools/release-gate.js',
        'tools/package-release.js',
        'tools/validate-release-artifact.js',
        'tools/ingest-existing-project.js',
        'tools/recertify.js',
        'tools/lib/repair-on-touch.js',
        'tools/lib/json-transaction.js',
        'docs/release/3.3.0/finalize-evidence-pack.js'
      ]);
      const producerPaths = new Set(
        producerClosure.files.map((item) => item.path)
      );
      const planAndProducerBindingOk = (
        fullPlan.schema_version ===
          'knowledge-release-gate-step-plan.v1' &&
        fullPlan.mode === 'full' &&
        fullPlan.steps.length === fullWithoutMemory.length &&
        fullPlan.steps.map((item) => item.id).join('\0') ===
          fullWithoutMemory.join('\0') &&
        isSha256(fullPlan.sha256) &&
        stableCanonicalStringify(fullPlan) ===
          stableCanonicalStringify(repeatedPlan) &&
        stableCanonicalStringify(fullPlan) ===
          stableCanonicalStringify(ambientPlan) &&
        producerClosure.schema_version ===
          'knowledge-release-gate-producer-closure.v1' &&
        producerClosure.files.length >= 100 &&
        producerClosure.files.every((item) =>
          item.bytes > 0 && isSha256(item.sha256)) &&
        Array.from(requiredProducers).every((item) =>
          producerPaths.has(item)) &&
        isSha256(producerClosure.aggregate_sha256) &&
        stableCanonicalStringify(producerClosure) ===
          stableCanonicalStringify(repeatedProducerClosure) &&
        stableCanonicalStringify(producerClosure) ===
          stableCanonicalStringify(ambientProducerClosure)
      );
      results.push({
        name: 'full step plan and conservative producer closure are deterministic and complete',
        status: planAndProducerBindingOk ? 'pass' : 'fail',
        expected_semantic_ok: true,
        actual_semantic_ok: planAndProducerBindingOk,
        errors: planAndProducerBindingOk
          ? []
          : [{
              fullPlan,
              producer_files:
                producerClosure.files.length,
              missing_producers:
                Array.from(requiredProducers).filter(
                  (item) => !producerPaths.has(item)
                )
            }]
      });

      const failedArtifactPath = path.join(contractRoot, 'failed-candidate.zip');
      fs.writeFileSync(failedArtifactPath, 'failed candidate', 'utf8');
      const failedCleanup = cleanupFailedCandidateArtifact({
        mode: 'full',
        keepFailed: false,
        failures: [{ id: 'self-test-export-privacy' }],
        artifactPath: failedArtifactPath
      });
      const keptArtifactPath = path.join(contractRoot, 'kept-candidate.zip');
      fs.writeFileSync(keptArtifactPath, 'kept candidate', 'utf8');
      const keptCleanup = cleanupFailedCandidateArtifact({
        mode: 'release',
        keepFailed: true,
        failures: [{ id: 'self-test-export-privacy' }],
        artifactPath: keptArtifactPath
      });
      const failedCleanupOk = (
        failedCleanup.attempted === true
        && failedCleanup.removed === true
        && !fs.existsSync(failedArtifactPath)
        && keptCleanup.attempted === false
        && keptCleanup.reason === 'keep_failed'
        && fs.existsSync(keptArtifactPath)
      );
      results.push({
        name: 'failed release candidate is removed unless keep-failed is explicit',
        status: failedCleanupOk ? 'pass' : 'fail',
        expected_semantic_ok: true,
        actual_semantic_ok: failedCleanupOk,
        errors: failedCleanupOk ? [] : [{ failedCleanup, keptCleanup }]
      });

      let injectedConformanceCalls = 0;
      const injectedConformanceReport = {
        schema_version: 'release-gate-report.v2',
        status: 'pass',
        mode: 'quick',
        steps: [],
        failures: [],
        skipped: []
      };
      finalizeConformanceReport(injectedConformanceReport, () => {
        injectedConformanceCalls += 1;
        throw new Error('injected conformance generation failure');
      });
      const conformanceFailure = injectedConformanceReport.failures.find(
        (item) => item.id === 'generate-conformance-report'
      );
      const conformanceFailClosed = (
        injectedConformanceCalls === 1
        && injectedConformanceReport.status === 'fail'
        && injectedConformanceReport.conformance_report?.status === 'failed'
        && injectedConformanceReport.steps.some((item) => item.id === 'generate-conformance-report' && item.status === 'fail')
        && conformanceFailure?.exit_code === 2
      );
      results.push({
        name: 'injected conformance report generation failure fails the final report exactly once',
        status: conformanceFailClosed ? 'pass' : 'fail',
        expected_semantic_ok: true,
        actual_semantic_ok: conformanceFailClosed,
        errors: conformanceFailClosed ? [] : [{
          calls: injectedConformanceCalls,
          report: injectedConformanceReport
        }]
      });
    } finally {
      if (previousMemoryReport === undefined) delete process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT;
      else process.env.KNOWLEDGE_MEMORY_BATTLE_REPORT = previousMemoryReport;
      if (previousSparkReport === undefined) {
        delete process.env.KNOWLEDGE_SPARK_BATTLE_REPORT;
      } else {
        process.env.KNOWLEDGE_SPARK_BATTLE_REPORT =
          previousSparkReport;
      }
    }
  } finally {
    fs.rmSync(contractRoot, { recursive: true, force: true });
  }
  return {
    schema_version: 'release-gate-semantic-self-test.v1',
    status: results.every((item) => item.status === 'pass') ? 'pass' : 'fail',
    results
  };
}

function skippedStep(id, reason) {
  return {
    id,
    name: id,
    command: '<skipped>',
    status: 'skipped',
    exit_code: null,
    duration_ms: 0,
    reason
  };
}

function generateConformanceReportSafe(report, generateOverride = null) {
  try {
    const generateFromReport = generateOverride || require('./generate-conformance-report').generateFromReport;
    const generated = generateFromReport(report);
    if (generated?.status !== 'pass' || !isRecord(generated.outputs)) {
      throw new Error('conformance report generator returned an invalid success contract');
    }
    return generated.outputs;
  } catch (error) {
    return {
      status: 'failed',
      error: sanitizeText(error.message)
    };
  }
}

function finalizeConformanceReport(report, generateOverride = null) {
  const conformance = generateConformanceReportSafe(report, generateOverride);
  report.conformance_report = conformance;
  if (conformance?.status !== 'failed') return report;

  const failure = {
    id: 'generate-conformance-report',
    name: 'generate conformance report',
    command: 'internal generateFromReport(report)',
    status: 'fail',
    exit_code: 2,
    duration_ms: 0,
    json_contract_errors: [`conformance report generation failed: ${conformance.error || 'unknown error'}`],
    stdout_tail: '',
    stderr_tail: conformance.error || 'unknown error'
  };
  report.steps = Array.isArray(report.steps) ? report.steps : [];
  report.failures = Array.isArray(report.failures) ? report.failures : [];
  if (!report.steps.some((item) => item.id === failure.id)) report.steps.push(failure);
  if (!report.failures.some((item) => item.id === failure.id)) report.failures.push(failure);
  report.status = 'fail';
  return report;
}

function npmAuditStep(context) {
  if (!fs.existsSync(path.join(root, 'package-lock.json')) && !fs.existsSync(path.join(root, 'npm-shrinkwrap.json'))) {
    return skippedStep('npm-audit', 'no package-lock.json or npm-shrinkwrap.json; no bundled npm dependency audit input');
  }
  return runCommand({
    id: 'npm-audit',
    name: 'npm audit production dependencies',
    command: process.platform === 'win32' ? 'npm.cmd' : 'npm',
    args: ['audit', '--omit=dev', '--json'],
    timeoutMs: 180000,
    expectJson: true,
    requiredFields: ['metadata']
  }, context);
}

function step(id, args, options = {}) {
  return {
    id,
    name: options.name || id,
    command: process.execPath,
    args,
    timeoutMs: options.timeoutMs,
    expectJson: options.expectJson !== false,
    allowedStatuses: options.allowedStatuses || ['pass', 'ok'],
    requiredFields: options.requiredFields || ['status'],
    semanticChecks: options.semanticChecks !== false,
    allowFailuresArray: Boolean(options.allowFailuresArray),
    flowLogEvidence: Boolean(options.flowLogEvidence),
    requires: options.requires || []
  };
}

function satisfiedImpactGatesForMode(mode) {
  const normalized = String(mode || '').toLowerCase();
  if (normalized === 'quick') return new Set(['quick', 'public-consistency']);
  if (normalized === 'full' || normalized === 'release') {
    return new Set(['quick', 'public-consistency', 'full', 'conformance-suite']);
  }
  return new Set();
}

function modeSteps(mode, flags) {
  const keepFailed = flags.keepFailed || flags.keep;
  const tag = flags.tag || `v${version}`;
  const repo = flags.repo || 'pro2pilot/knowledge';
  const expectedOwner = flags.expectedOwner || 'pro2pilot';
  const quick = [
    step('classify-release-impact', ['tools/classify-release-impact.js', '--json'], { allowedStatuses: ['pass'] }),
    step('public-consistency', ['tools/check-public-consistency.js', '--json'], { allowedStatuses: ['pass'] }),
    step('self-test-export-privacy', ['tools/self-test-export-privacy.js'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('self-test-recertify-lifecycle', ['tools/self-test-recertify-lifecycle.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-repair-on-touch', ['tools/self-test-repair-on-touch.js'], { timeoutMs: 240000, allowedStatuses: ['pass'] }),
    step('self-test-dedicated-verification', ['tools/self-test-dedicated-verification.js'], { timeoutMs: 360000, allowedStatuses: ['pass'] }),
    step('self-test-repair-session-isolation', ['tools/self-test-repair-session-isolation.js'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('wiki-structural-ci-gate', ['tools/lint-wiki.js', '--strict'], { timeoutMs: 180000, allowedStatuses: ['healthy', 'usable_with_warnings'], requiredFields: ['status', 'structural_status', 'quality_score'] }),
    step('self-test-wiki-structural-status', ['tools/self-test-wiki-structural-status.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-adaptive-routing', ['tools/self-test-adaptive-routing.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-task-routing', ['tools/self-test-task-routing.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-field-report', ['tools/self-test-field-report.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('verify-contained-lock-usage', ['tools/verify-contained-lock-usage.js'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('self-test-contained-lock-manager', ['tools/self-test-contained-lock-manager.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-context-lock-safety', ['tools/self-test-context-lock-safety.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-stale-recovery', ['tools/self-test-stale-recovery.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-evidence-report-contract', ['tools/self-test-evidence-report-contract.js'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('self-test-rc40-document-consistency', ['tools/internal/self-test-rc40-document-consistency.js'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('verify-lock-consumer-inventory', ['tools/verify-lock-consumer-inventory.js', '--inventory', 'docs/release/3.3.0/project-lock-inspection-rc40/LOCK-CONSUMER-INVENTORY.json'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('self-test-install-integration-transaction', ['tools/self-test-install-integration-transaction.js'], { timeoutMs: 240000, allowedStatuses: ['pass'] }),
    step('validate-sbom', ['tools/validate-sbom.js', '--json'], { allowedStatuses: ['pass'] }),
    step('validate-third-party-notices', ['tools/validate-third-party-notices.js', '--json'], { allowedStatuses: ['pass'] }),
    step('release-gate-semantic-self-test', ['tools/release-gate.js', '--self-test-semantics', '--json'], { allowedStatuses: ['pass'] }),
    step('schema-version-hygiene', ['tools/self-test-schema-version.js'], { allowedStatuses: ['pass'] }),
    step('mem0-recipe-quality', ['tools/self-test-memory-providers.js', '--recipe-quality-only'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('inspector-next-actions-smoke', ['tools/self-test-inspector-next-actions.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] })
  ];
  if (sparkBattleReportPath(flags)) quick.push({ id: 'spark-battle-report', special: 'spark-battle-report' });
  const packageAndValidate = [
    step('package-release', ['tools/package-release.js', '--json'], { allowedStatuses: ['ok'], requires: ['self-test-export-privacy', 'self-test-recertify-lifecycle', 'self-test-repair-on-touch', 'self-test-dedicated-verification', 'self-test-repair-session-isolation', 'wiki-structural-ci-gate', 'self-test-wiki-structural-status', 'self-test-adaptive-routing', 'self-test-task-routing', 'self-test-field-report', 'self-test-context-lock-safety', 'self-test-stale-recovery', 'self-test-evidence-report-contract', 'self-test-rc40-document-consistency', 'verify-lock-consumer-inventory'] }),
    step('validate-release-artifact', ['tools/validate-release-artifact.js', artifactRel, '--profile', 'public_runtime', '--json'], { allowedStatuses: ['ok'], requiredFields: ['status', 'violations'], requires: ['package-release'] }),
    step('verify-contained-lock-rc39', ['tools/verify-contained-lock-rc39.js', '--zip', artifactRel], { timeoutMs: 240000, allowedStatuses: ['pass'], requires: ['validate-release-artifact'] }),
    step('verify-context-lock-safety-rc40', ['tools/verify-context-lock-safety-rc40.js', '--zip', artifactRel, '--expect', 'pass'], { timeoutMs: 240000, allowedStatuses: ['pass'], semanticChecks: false, requires: ['validate-release-artifact'] }),
    step('verify-project-lock-physical-rc40', ['tools/verify-project-lock-physical-rc40.js', '--zip', artifactRel], { timeoutMs: 300000, allowedStatuses: ['pass'], semanticChecks: false, requires: ['validate-release-artifact'] }),
    step('self-test-audit-replay-bundle', ['tools/self-test-audit-replay-bundle.js', '--zip', artifactRel], { timeoutMs: 300000, allowedStatuses: ['pass'], requires: ['validate-release-artifact'] })
  ];

  const sourceSelfTests = [
    step('self-test-install-check-interface', ['tools/self-test-install-check-interface.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-conformance-upgrade-entrypoint', ['tools/self-test-conformance-upgrade-entrypoint.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-public-integration-allowlist', ['tools/self-test-public-integration-allowlist.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-agent-integration-coexistence', ['tools/self-test-agent-integration-coexistence.js'], { timeoutMs: 240000, allowedStatuses: ['pass'] }),
    step('self-test-handoff-current-state', ['tools/self-test-handoff-current-state.js', '--json'], { timeoutMs: 120000, allowedStatuses: ['pass'] }),
    step('self-test-inspector-launcher', ['tools/self-test-inspector-launcher.js', '--json'], { timeoutMs: 180000 }),
    step('self-test-inspector-actions', ['tools/self-test-inspector-actions.js', '--json'], { timeoutMs: 180000 }),
    step('self-test-agent-activity', ['tools/self-test-agent-activity.js', '--json'], { timeoutMs: 120000 }),
    step('self-test-safe-queue', ['tools/self-test-safe-queue.js', '--json'], { timeoutMs: 180000 }),
    step('self-test-json-store-windows-writes', ['tools/self-test-json-store-windows-writes.js'], { timeoutMs: 120000 }),
    step('self-test-flow-finalization', ['tools/self-test-flow-finalization.js'], { timeoutMs: 120000 }),
    step('self-test-evaluation-metrics', ['tools/self-test-evaluation-metrics.js'], { timeoutMs: 240000 }),
    step('self-test-release-gate-p0', ['tools/self-test-release-gate-p0.js'], { timeoutMs: 300000 }),
    step('self-test-agent-footer', ['tools/self-test-agent-footer.js', '--json'], { timeoutMs: 120000 }),
    step('self-test-restore-trust', ['tools/self-test-restore-trust.js', '--json'], { timeoutMs: 120000 }),
    step('self-test-update-checks', ['tools/self-test-update-checks.js'], { expectJson: false, timeoutMs: 120000 }),
    step('self-test-inspector-update-e2e', ['tools/self-test-inspector-update-e2e.js'], { expectJson: false, timeoutMs: 420000 }),
    step('self-test-install-policy', ['tools/self-test-install-policy.js'], { expectJson: false, timeoutMs: 900000 }),
    step('self-test-memory-providers', ['tools/self-test-memory-providers.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-external-memory', ['tools/self-test-external-memory.js'], { timeoutMs: 180000, allowedStatuses: ['pass'] }),
    step('self-test-free-core-graph', ['tools/self-test-free-core-graph.js'], { expectJson: false, timeoutMs: 120000 }),
    step('self-test-pr-impact', ['tools/self-test-pr-impact.js'], { expectJson: false, timeoutMs: 180000 }),
    step('self-test-team-mode', ['tools/self-test-team-mode.js'], { expectJson: false, timeoutMs: 360000 }),
    step('self-test-team-inspector-json', ['tools/self-test-team-inspector-json.js'], { expectJson: false, timeoutMs: 360000 }),
    step('build-inspector', ['tools/build-visual-inspector.js'], { expectJson: false, timeoutMs: 180000 }),
    step('self-test-inspector-ui', ['tools/self-test-inspector-ui.js'], { expectJson: false, timeoutMs: 180000 }),
    step('evaluation-harness', ['tools/evaluation-harness.js'], { timeoutMs: 360000, allowedStatuses: ['release_candidate'], requiredFields: ['status', 'score', 'results'] }),
    step('flow-release', ['tools/flow.js', 'release', '--no-color', '--json'], {
      timeoutMs: 360000,
      allowedStatuses: ['ok', 'pass'],
      requiredFields: ['status', 'flow_log', 'flow_log_bytes', 'flow_log_sha256', 'flow_log_status', 'started_at', 'target_root', 'state_root'],
      flowLogEvidence: true
    }),
    step('doctor', ['tools/doctor.js', '--json'], { timeoutMs: 180000, allowedStatuses: ['healthy', 'usable_with_warnings', 'ok', 'pass'], requiredFields: ['status', 'structural_status', 'quality_score'] })
  ];

  if (mode === 'quick') return [
    ...quick,
    ...packageAndValidate
  ];
  if (mode === 'full') {
    return [
      ...quick,
      ...(memoryBattleReportPath(flags) ? [{ id: 'memory-battle-report', special: 'memory-battle-report' }] : []),
      { id: 'source-bootstrap', special: 'source-bootstrap' },
      ...sourceSelfTests,
      ...packageAndValidate,
      step('conformance-install-smoke', ['tools/conformance-install-smoke.js', artifactRel, '--json', ...(keepFailed ? ['--keep-failed'] : [])], { timeoutMs: 420000, allowedStatuses: ['pass'], requires: ['package-release', 'validate-release-artifact'] })
    ];
  }
  if (mode === 'release') {
    return [
      ...quick,
      { id: 'memory-battle-report', special: 'memory-battle-report' },
      { id: 'source-bootstrap', special: 'source-bootstrap' },
      ...sourceSelfTests,
      { id: 'npm-audit', special: 'npm-audit' },
      ...packageAndValidate,
      step('validate-source-deliverable', ['tools/validate-source-deliverable.js', '--profile', 'source_release', '--json'], { timeoutMs: 180000, allowedStatuses: ['ok'], requires: ['package-release', 'validate-release-artifact'] }),
      step('conformance-install-smoke', ['tools/conformance-install-smoke.js', artifactRel, '--json', ...(keepFailed ? ['--keep-failed'] : [])], { timeoutMs: 420000, allowedStatuses: ['pass'], requires: ['package-release', 'validate-release-artifact'] })
    ];
  }
  if (mode === 'post-release') {
    return [
      step('post-release-live-asset', ['tools/post-release-live-asset.js', '--tag', tag, '--repo', repo, '--expected-owner', expectedOwner, '--json', ...(keepFailed ? ['--keep-failed'] : [])], { timeoutMs: 900000, allowedStatuses: ['pass'] })
    ];
  }
  throw new Error(`Unsupported release gate mode: ${mode}`);
}

function renderMarkdown(report) {
  const lines = [
    '# Release Gate Report',
    '',
    `Generated: ${report.generated_at}`,
    `Mode: ${report.mode}`,
    `Status: ${report.status}`,
    '',
    '## Artifact',
    '',
    `- Package version: ${report.package_version}`,
    `- Artifact: ${report.artifact}`,
    `- SHA-256: ${report.artifact_sha256 || 'not available'}`,
    '',
    '## Environment',
    '',
    `- Node: ${report.node_version}`,
    `- Platform: ${report.platform}`,
    `- Git head: ${report.git_head || 'not available'}`,
    '',
    '## Steps',
    '',
    '| Step | Status | Duration ms | Logs |',
    '|---|---|---:|---|'
  ];
  for (const item of report.steps) {
    const logs = item.stdout_path ? `${item.stdout_path}<br>${item.stderr_path}` : item.reason || '';
    lines.push(`| ${item.id} | ${item.status} | ${item.duration_ms} | ${logs} |`);
  }
  if (report.failures.length) {
    lines.push('', '## Failures', '');
    for (const failure of report.failures) lines.push(`- ${failure.id}: ${failure.json_contract_errors?.join('; ') || failure.stderr_tail || failure.stdout_tail || failure.reason || 'failed'}`);
  }
  return `${lines.join('\n')}\n`;
}

function updateTelemetry(report) {
  const telemetryPath = path.join(
    durableGateRoot,
    'history.json'
  );
  let history = { schema_version: 'release-gate-history.v1', runs: [] };
  if (fs.existsSync(telemetryPath)) {
    try { history = JSON.parse(fs.readFileSync(telemetryPath, 'utf8')); } catch { history = { schema_version: 'release-gate-history.v1', runs: [] }; }
  }
  history.runs = Array.isArray(history.runs) ? history.runs : [];
  history.runs.push({
    run_id: report.run_id || null,
    generated_at: report.generated_at,
    mode: report.mode,
    status: report.status,
    artifact_sha256: report.artifact_sha256,
    steps: report.steps.map((item) => ({ id: item.id, status: item.status, duration_ms: item.duration_ms }))
  });
  history.runs = history.runs.slice(-30);
  const stepStats = {};
  for (const run of history.runs) {
    for (const item of run.steps || []) {
      stepStats[item.id] = stepStats[item.id] || { runs: 0, failures: 0, durations_ms: [] };
      stepStats[item.id].runs += 1;
      if (item.status === 'fail') stepStats[item.id].failures += 1;
      if (Number.isFinite(item.duration_ms)) stepStats[item.id].durations_ms.push(item.duration_ms);
    }
  }
  const summary = Object.fromEntries(Object.entries(stepStats).map(([id, stats]) => {
    const durations = stats.durations_ms.slice(-10);
    const avg = durations.length ? Math.round(durations.reduce((sum, value) => sum + value, 0) / durations.length) : null;
    return [id, { runs: stats.runs, failures: stats.failures, avg_duration_ms_last_10: avg }];
  }));
  history.summary = summary;
  ensureDir(path.dirname(telemetryPath));
  fs.writeFileSync(telemetryPath, JSON.stringify(history, null, 2) + '\n', 'utf8');
  return {
    path: relPath(telemetryPath),
    runs_tracked: history.runs.length,
    last_failures: history.runs.filter((run) => run.status === 'fail').slice(-5).map((run) => ({ generated_at: run.generated_at, mode: run.mode }))
  };
}

function main(argv = process.argv.slice(2)) {
  const { flags } = parseCliArgs(argv);
  if (flags.selfTestSemantics) {
    const report = semanticSelfTest();
    if (flags.json) console.log(JSON.stringify(report, null, 2));
    else console.log(`release gate semantic self-test ${report.status}`);
    if (report.status !== 'pass') process.exit(2);
    return report;
  }
  const mode = String(flags.mode || 'release').toLowerCase();
  if (['quick', 'full'].includes(mode)) {
    flags.ignoreAmbientEvidence = true;
  }
  const failFast = flags.failFast ? true : flags.noFailFast ? false : !['release', 'post-release'].includes(mode);
  const plannedSpecs = modeSteps(mode, flags);
  const stepPlan = buildReleaseStepPlanFromSpecs(
    mode,
    plannedSpecs
  );
  const producerClosureBefore =
    releaseProducerClosureFromSpecs(plannedSpecs);
  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const logDir = path.join(
    durableGateRoot,
    'runs',
    runId,
    'logs'
  );
  ensureDir(path.join(root, 'maintenance'));
  ensureDir(logDir);

  const staleArtifactCleanup = ['quick', 'full', 'release'].includes(mode) ? deleteCandidateArtifact() : null;
  const context = { logDir };
  const steps = [];
  const stepsById = new Map();
  for (const spec of plannedSpecs) {
    const unmet = (spec.requires || []).filter((id) => stepsById.get(id)?.status !== 'pass');
    let result = unmet.length
      ? skippedStep(spec.id, `required step(s) did not pass: ${unmet.join(', ')}`)
      : spec.special === 'npm-audit'
      ? npmAuditStep(context)
      : spec.special === 'memory-battle-report'
      ? bindSyntheticStepStreams(
          validateMemoryBattleReport(flags),
          context
        )
      : spec.special === 'spark-battle-report'
      ? bindSyntheticStepStreams(
          validateSparkBattleReport(flags),
          context
        )
      : spec.special === 'source-bootstrap'
      ? sourceBootstrapStep(context)
      : runCommand(spec, context);
    if (result.id === 'classify-release-impact' && result.status === 'pass') {
      const satisfiedImpactGates = satisfiedImpactGatesForMode(mode);
      const unmetImpactGates = (result.required_gates || []).filter((gate) => !satisfiedImpactGates.has(String(gate)));
      if (unmetImpactGates.length) {
        result.status = 'fail';
        result.impact_unmet_gates = unmetImpactGates;
        result.json_contract_errors.push(`selected ${mode} mode does not satisfy required gate(s): ${unmetImpactGates.join(', ')}`);
      }
    }
    result = bindStepDecision(result, context);
    steps.push(result);
    stepsById.set(result.id, result);
    if (result.status === 'fail' && failFast) break;
  }

  const failures = steps.filter((item) => item.status === 'fail');
  const skipped = steps.filter((item) => item.status === 'skipped');
  const artifactPath = path.join(root, artifactRel);
  const report = {
    schema_version: 'release-gate-report.v2',
    run_id: runId,
    generated_at: new Date().toISOString(),
    status: failures.length ? 'fail' : 'pass',
    mode,
    fail_fast: failFast,
    package_version: version,
    artifact: artifactRel,
    artifact_sha256: sha256IfExists(artifactPath),
    node_version: process.version,
    platform: `${process.platform}/${process.arch}`,
    os_release: os.release(),
    git_head: gitHead(),
    log_dir: relPath(logDir),
    stale_artifact_cleanup: staleArtifactCleanup,
    step_plan: stepPlan,
    producer_closure: producerClosureBefore,
    producer_source_unchanged: null,
    steps,
    failures,
    skipped
  };
  finalizeConformanceReport(report);
  bindLateInternalReportSteps(report, context);
  const producerClosureAfter =
    releaseProducerClosureFromSpecs(plannedSpecs);
  report.producer_source_unchanged =
    producerClosureBefore.aggregate_sha256 ===
      producerClosureAfter.aggregate_sha256;
  report.producer_closure_after_sha256 =
    producerClosureAfter.aggregate_sha256;
  if (!report.producer_source_unchanged) {
    const failure = bindStepDecision(
      bindSyntheticStepStreams({
      id: 'release-producer-source-drift',
      name: 'release producer source stability',
      command: '<internal producer closure guard>',
      status: 'fail',
      exit_code: 2,
      duration_ms: 0,
      json_contract_errors: [
        'release producer source changed during the gate'
      ],
      stdout_tail: '',
      stderr_tail: ''
      }, context),
      context
    );
    report.steps.push(failure);
    report.failures.push(failure);
    report.status = 'fail';
  }
  report.failed_artifact_cleanup = cleanupFailedCandidateArtifact({
    mode,
    keepFailed: Boolean(flags.keepFailed || flags.keep),
    failures: report.failures,
    artifactPath
  });
  report.artifact_sha256 = sha256IfExists(artifactPath);
  report.flaky_telemetry = updateTelemetry(report);

  writeJsonAtomic(path.join(root, 'maintenance', 'release-gate-report.json'), report);
  fs.writeFileSync(path.join(root, 'maintenance', 'release-gate-report.md'), renderMarkdown(report), 'utf8');
  if (flags.json) console.log(JSON.stringify(report, null, 2));
  else console.log(`release gate ${report.status}`);
  if (report.status !== 'pass') process.exit(2);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const { flags } = parseCliArgs(process.argv.slice(2));
    const mode = flags.mode || 'release';
    const failedArtifactCleanup = cleanupFailedCandidateArtifact({
      mode,
      keepFailed: Boolean(flags.keepFailed || flags.keep),
      failures: [{ id: 'release-gate-exception' }]
    });
    const failed = {
      schema_version: 'release-gate-report.v2',
      run_id: new Date().toISOString().replace(/[:.]/g, '-'),
      generated_at: new Date().toISOString(),
      status: 'fail',
      mode,
      error: sanitizeText(error.message),
      failed_artifact_cleanup: failedArtifactCleanup
    };
    ensureDir(path.join(root, 'maintenance'));
    writeJsonAtomic(path.join(root, 'maintenance', 'release-gate-report.json'), failed);
    fs.writeFileSync(path.join(root, 'maintenance', 'release-gate-report.md'), `# Release Gate Report\n\nStatus: fail\n\n${failed.error}\n`, 'utf8');
    if (flags.json) console.log(JSON.stringify(failed, null, 2));
    else console.error(failed.error);
    process.exit(2);
  }
}

module.exports = {
  bindStepDecision,
  canonicalReleaseEnv,
  main,
  semanticSelfTest,
  validateBenchmarkPair,
  validateJsonContract,
  validateMemoryBattleReport,
  validateSparkBattleReport,
  sourceBootstrapStep,
  validateFlowLogEvidence,
  generateConformanceReportSafe,
  finalizeConformanceReport,
  cleanupFailedCandidateArtifact,
  satisfiedImpactGatesForMode,
  stableCanonicalStringify,
  buildReleaseStepPlan,
  releaseProducerClosure,
  canonicalFullEvidencePlan,
  canonicalReleaseProducerClosure,
  runCommand
};
