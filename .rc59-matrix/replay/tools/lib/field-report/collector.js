'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');
const { canonicalWikiStatus } = require('../wiki-status');
let taskRouting = null;
try { taskRouting = require('../task-routing'); } catch { taskRouting = null; }
let taskRoutingState = null;
try { taskRoutingState = require('../task-routing-state'); } catch { taskRoutingState = null; }
let teamStore = null;
try { teamStore = require('../team-store'); } catch { teamStore = null; }

const SCHEMA_VERSION = 'knowledge-field-report-facts.v2';

function relativeSource(value) {
  const source = String(value || '').replace(/\\/g, '/').replace(/^\.?\//, '');
  if (!source || path.posix.isAbsolute(source) || source.split('/').includes('..')) {
    throw new Error(`Unsafe Field Report source path: ${value}`);
  }
  return source.startsWith('.knowledge/') || source === 'runtime/context'
    ? source
    : `.knowledge/${source}`;
}

function warningMessage(source, error) {
  if (error?.code === 'ENOENT') return `missing artifact: ${source}`;
  return `unavailable or corrupt artifact: ${source}`;
}

function readJsonArtifact(file, source, warnings) {
  const safeSource = relativeSource(source);
  try {
    const value = JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
    return { available: true, value, source: safeSource, warning: null };
  } catch (error) {
    const warning = warningMessage(safeSource, error);
    warnings.push(warning);
    return { available: false, value: null, source: safeSource, warning };
  }
}

function fact(value, kind, source, schemaPath, collectedAt, confidence = 'high', warning = null) {
  const unavailable = kind === 'unavailable' || value === undefined || value === null;
  return {
    value: unavailable ? null : value,
    kind: unavailable ? 'unavailable' : kind,
    source: relativeSource(source),
    schema_path: schemaPath,
    collected_at: collectedAt,
    confidence: unavailable ? 'unavailable' : confidence,
    warning: warning || null
  };
}

function fromArtifact(artifact, value, schemaPath, collectedAt, confidence = 'high', kind = 'observed') {
  if (!artifact.available || value === undefined || value === null) {
    return fact(null, 'unavailable', artifact.source, schemaPath, collectedAt, 'unavailable', artifact.warning);
  }
  return fact(value, kind, artifact.source, schemaPath, collectedAt, confidence);
}

function projectType(root) {
  if (fs.existsSync(path.join(root, 'package.json'))) return 'JavaScript or TypeScript project';
  if (fs.existsSync(path.join(root, 'pyproject.toml')) ||
      fs.existsSync(path.join(root, 'requirements.txt'))) return 'Python project';
  if (fs.existsSync(path.join(root, 'go.mod'))) return 'Go project';
  if (fs.existsSync(path.join(root, 'Cargo.toml'))) return 'Rust project';
  return 'Repository';
}


const REPOSITORY_SOURCE_EXTENSIONS = new Set([
  '.astro', '.c', '.cc', '.cpp', '.cxx', '.cs', '.css', '.go', '.h', '.hpp',
  '.html', '.java', '.js', '.jsx', '.kt', '.kts', '.less', '.mjs', '.cjs',
  '.php', '.py', '.rb', '.rs', '.scss', '.sh', '.svelte', '.swift', '.ts',
  '.tsx', '.vue', '.ps1'
]);
const REPOSITORY_PROFILE_EXCLUDED_SEGMENTS = new Set([
  '.git', '.knowledge', '.astro', '.cache', '.next', '.nuxt', '.tmp',
  'benchmark-runs', 'build', 'coverage', 'dist', 'logs', 'node_modules',
  'qa-results', 'release-work', 'temp', 'tmp'
]);

function normalizeRepositoryPath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function repositoryProfilePathExcluded(value) {
  const relative = normalizeRepositoryPath(value);
  if (!relative || path.posix.isAbsolute(relative) || relative.split('/').includes('..')) {
    return true;
  }
  const segments = relative.split('/').filter(Boolean);
  if (segments.some((segment) => REPOSITORY_PROFILE_EXCLUDED_SEGMENTS.has(segment.toLowerCase()))) {
    return true;
  }
  const basename = segments[segments.length - 1] || '';
  const lower = basename.toLowerCase();
  if (/^\.env(?:\.|$)/.test(lower) && !/^\.env\.(?:example|sample|template)$/.test(lower)) {
    return true;
  }
  return /(?:^|[-_.])(?:secret|secrets|credential|credentials)(?:[-_.]|$)/i.test(basename);
}

function gitResult(root, args, options = {}) {
  return childProcess.spawnSync('git', ['-C', root, ...args], {
    encoding: options.encoding === undefined ? 'utf8' : options.encoding,
    input: options.input,
    maxBuffer: options.maxBuffer || 64 * 1024 * 1024,
    windowsHide: true
  });
}

function gitBlobSizes(root, hashes) {
  const unique = [...new Set(hashes.filter(Boolean))];
  if (!unique.length) return new Map();
  const result = gitResult(root, ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'], {
    input: `${unique.join('\n')}\n`
  });
  if (result.status !== 0 || result.error) return new Map();
  const sizes = new Map();
  for (const line of String(result.stdout || '').split(/\r?\n/)) {
    const match = /^([0-9a-f]{40,64})\s+blob\s+(\d+)$/.exec(line.trim());
    if (match) sizes.set(match[1], Number(match[2]));
  }
  return sizes;
}

function profileFromGit(root) {
  const listed = gitResult(root, ['ls-files', '-s', '-z', '--cached'], { encoding: null });
  if (listed.status !== 0 || listed.error || !Buffer.isBuffer(listed.stdout)) return null;
  const entries = [];
  for (const record of listed.stdout.toString('utf8').split('\0')) {
    if (!record) continue;
    const match = /^(\d{6})\s+([0-9a-f]{40,64})\s+(\d)\t([\s\S]+)$/.exec(record);
    if (!match || match[3] !== '0') continue;
    entries.push({ mode: match[1], hash: match[2], path: normalizeRepositoryPath(match[4]) });
  }
  const blobSizes = gitBlobSizes(root, entries.map((entry) => entry.hash));
  let trackedFiles = 0;
  let trackedBytes = 0;
  let sourceFiles = 0;
  let sourceBytes = 0;
  let excludedFiles = 0;
  for (const entry of entries) {
    if (repositoryProfilePathExcluded(entry.path)) {
      excludedFiles += 1;
      continue;
    }
    const full = path.join(root, ...entry.path.split('/'));
    let bytes = blobSizes.get(entry.hash);
    try {
      const stat = fs.lstatSync(full);
      if (stat.isFile() || stat.isSymbolicLink()) bytes = stat.size;
    } catch {}
    if (!Number.isFinite(bytes) || bytes < 0) continue;
    trackedFiles += 1;
    trackedBytes += bytes;
    if (REPOSITORY_SOURCE_EXTENSIONS.has(path.extname(entry.path).toLowerCase())) {
      sourceFiles += 1;
      sourceBytes += bytes;
    }
  }
  const status = gitResult(root, ['status', '--porcelain=v1', '--untracked-files=normal']);
  let dirty = null;
  let trackedChanges = null;
  let untrackedFiles = null;
  let conflicts = null;
  let snapshotStatus = 'unavailable';
  if (status.status === 0) {
    const rows = String(status.stdout || '').split(/\r?\n/).filter(Boolean);
    const conflictCodes = new Set(['DD', 'AU', 'UD', 'UA', 'DU', 'AA', 'UU']);
    untrackedFiles = rows.filter((row) => row.startsWith('??')).length;
    conflicts = rows.filter((row) => conflictCodes.has(row.slice(0, 2))).length;
    trackedChanges = rows.filter((row) => !row.startsWith('??') && !row.startsWith('!!')).length;
    dirty = rows.length > 0;
    snapshotStatus = !dirty
      ? 'clean'
      : conflicts > 0
        ? 'dirty_conflicted'
        : trackedChanges > 0 && untrackedFiles > 0
          ? 'dirty_mixed'
          : trackedChanges > 0
            ? 'dirty_tracked'
            : 'dirty_untracked';
  }
  return {
    available: true,
    basis: 'git_index_worktree',
    tracked_files: trackedFiles,
    tracked_bytes: trackedBytes,
    source_files: sourceFiles,
    source_bytes: sourceBytes,
    excluded_files: excludedFiles,
    dirty,
    dirty_tracked_changes: trackedChanges,
    dirty_untracked_files: untrackedFiles,
    dirty_conflicts: conflicts,
    snapshot_status: snapshotStatus,
    warning: null
  };
}

function profileFromFilesystem(root) {
  const pending = [{ absolute: root, relative: '' }];
  let trackedFiles = 0;
  let trackedBytes = 0;
  let sourceFiles = 0;
  let sourceBytes = 0;
  let excludedFiles = 0;
  let visited = 0;
  const limit = 100000;
  while (pending.length) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current.absolute, { withFileTypes: true })) {
      const relative = normalizeRepositoryPath(path.posix.join(current.relative, entry.name));
      if (repositoryProfilePathExcluded(relative)) {
        excludedFiles += 1;
        continue;
      }
      const absolute = path.join(current.absolute, entry.name);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) {
        excludedFiles += 1;
        continue;
      }
      if (stat.isDirectory()) {
        pending.push({ absolute, relative });
        continue;
      }
      if (!stat.isFile()) continue;
      visited += 1;
      if (visited > limit) {
        return { available: false, warning: `repository profile exceeded ${limit} files` };
      }
      trackedFiles += 1;
      trackedBytes += stat.size;
      if (REPOSITORY_SOURCE_EXTENSIONS.has(path.extname(relative).toLowerCase())) {
        sourceFiles += 1;
        sourceBytes += stat.size;
      }
    }
  }
  return {
    available: true,
    basis: 'filtered_worktree_fallback',
    tracked_files: trackedFiles,
    tracked_bytes: trackedBytes,
    source_files: sourceFiles,
    source_bytes: sourceBytes,
    excluded_files: excludedFiles,
    dirty: null,
    dirty_tracked_changes: null,
    dirty_untracked_files: null,
    dirty_conflicts: null,
    snapshot_status: 'non_git',
    warning: 'Git tracked-file inventory was unavailable; a filtered filesystem fallback was used.'
  };
}

function collectRepositoryProfile(root, warnings = []) {
  try {
    const gitProfile = profileFromGit(root);
    if (gitProfile) return gitProfile;
    const fallback = profileFromFilesystem(root);
    if (fallback.warning) warnings.push(fallback.warning);
    return fallback;
  } catch (error) {
    const warning = `repository profile unavailable: ${error?.code || 'collection_failed'}`;
    warnings.push(warning);
    return { available: false, warning };
  }
}

function doctorFindings(report) {
  if (Array.isArray(report?.issues)) return report.issues;
  if (Array.isArray(report?.findings)) return report.findings;
  return null;
}

function doctorFindingCounts(report) {
  const findings = doctorFindings(report);
  if (!findings) return { active: null, critical: null };
  const active = findings.filter((item) =>
    !['closed', 'resolved'].includes(String(item?.status || 'open').trim().toLowerCase()));
  return {
    active: active.length,
    critical: active.filter((item) =>
      String(item?.severity || '').trim().toLowerCase() === 'critical').length
  };
}

function wikiBrokenEdgeCount(graph) {
  if (Number.isInteger(graph?.broken_edge_count) && graph.broken_edge_count >= 0) {
    return graph.broken_edge_count;
  }
  if (Array.isArray(graph?.broken_edges)) return graph.broken_edges.length;
  if (Number.isInteger(graph?.broken_edges) && graph.broken_edges >= 0) return graph.broken_edges;
  if (Array.isArray(graph?.edges)) {
    return graph.edges.filter((edge) => edge?.broken === true ||
      String(edge?.status || '').trim().toLowerCase() === 'broken').length;
  }
  return null;
}

function validateModuleRegistryArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const modules = artifact.value?.modules;
  const valid = plainObject(artifact.value) && Array.isArray(modules) &&
    modules.every((item) => plainObject(item) &&
      typeof item.module_id === 'string' && Boolean(item.module_id.trim()));
  return valid ? artifact : semanticInvalid(artifact, warnings);
}


function workspaceScope(context, warnings = []) {
  const mode = String(context?.mode || '').trim().toLowerCase();
  if (mode === 'repo') {
    return {
      kind: 'standalone_repository',
      repositories_total: 1,
      confidence: 'high',
      warning: null
    };
  }
  if (mode !== 'team') {
    return {
      kind: 'workspace_scope_unknown',
      repositories_total: null,
      confidence: 'unavailable',
      warning: 'repository scope is unavailable for the current mode'
    };
  }
  if (!context?.teamRoot || !teamStore?.listTeamStatus) {
    const warning = 'team workspace repository count is unavailable';
    warnings.push(warning);
    return {
      kind: 'team_workspace_unknown',
      repositories_total: null,
      confidence: 'unavailable',
      warning
    };
  }
  try {
    const status = teamStore.listTeamStatus(context.teamRoot);
    const repoIds = [...new Set((Array.isArray(status?.repos) ? status.repos : [])
      .filter((repo) => String(repo?.status || 'active').trim().toLowerCase() !== 'archived')
      .map((repo) => String(repo?.repoId || '').trim())
      .filter(Boolean))];
    if (repoIds.length > 1) {
      return {
        kind: 'multi_repository_workspace',
        repositories_total: repoIds.length,
        confidence: 'high',
        warning: null
      };
    }
    if (repoIds.length === 1) {
      return {
        kind: 'single_repository_team_workspace',
        repositories_total: 1,
        confidence: 'high',
        warning: null
      };
    }
    const warning = 'team workspace repository count is unavailable';
    warnings.push(warning);
    return {
      kind: 'team_workspace_unknown',
      repositories_total: null,
      confidence: 'unavailable',
      warning
    };
  } catch (error) {
    const warning = `team workspace repository count is unavailable: ${error?.code || 'inspection_failed'}`;
    warnings.push(warning);
    return {
      kind: 'team_workspace_unknown',
      repositories_total: null,
      confidence: 'unavailable',
      warning
    };
  }
}

function listFiles(dir) {
  if (!fs.existsSync(dir)) return null;
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile()) files.push(full);
    }
  };
  visit(dir);
  return files;
}

function countReleaseFlows(stateRoot) {
  const dir = path.join(stateRoot, 'maintenance', 'flow-logs');
  const files = listFiles(dir);
  if (files === null) {
    return {
      available: false,
      value: null,
      warning: 'missing artifact: .knowledge/maintenance/flow-logs'
    };
  }
  let count = 0;
  for (const file of files.filter((item) => /\.(?:json|ndjson)$/i.test(item))) {
    const name = path.basename(file).toLowerCase();
    let body = '';
    try { body = fs.readFileSync(file, 'utf8').slice(0, 65536).toLowerCase(); } catch {}
    if (name.includes('release') ||
        /"(?:flow|flow_type|command)"\s*:\s*"[^"]*release/.test(body)) count += 1;
  }
  return { available: true, value: count, warning: null };
}

function countPrSummaries(stateRoot) {
  const dir = path.join(stateRoot, 'maintenance', 'pr-summaries');
  const files = listFiles(dir);
  let count = files === null ? 0 : files.filter((file) => /\.(?:md|json)$/i.test(file)).length;
  const canonical = path.join(stateRoot, 'maintenance', 'pr_summary.md');
  if (fs.existsSync(canonical)) count += 1;
  if (files === null && !fs.existsSync(canonical)) {
    return {
      available: false,
      value: null,
      warning: 'missing artifact: .knowledge/maintenance/pr-summaries'
    };
  }
  return { available: true, value: count, warning: null };
}

function sessionArray(registry) {
  if (Array.isArray(registry)) return registry;
  if (Array.isArray(registry?.sessions)) return registry.sessions;
  if (Array.isArray(registry?.agents)) return registry.agents;
  return null;
}

function repairArray(queue) {
  if (Array.isArray(queue)) return queue;
  if (Array.isArray(queue?.queue)) return queue.queue;
  if (Array.isArray(queue?.items)) return queue.items;
  return null;
}

function plainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (plainObject(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function taskScopeHash(scope) {
  const canonical = JSON.parse(JSON.stringify(scope || {}));
  delete canonical.scope_hash;
  return crypto.createHash('sha256').update(canonicalJson(canonical)).digest('hex');
}

function semanticInvalid(artifact, warnings) {
  if (!artifact.available) return artifact;
  const warning = `semantically invalid artifact: ${artifact.source}`;
  warnings.push(warning);
  return {
    ...artifact,
    available: false,
    value: null,
    warning
  };
}

function validateRegistryArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const sessions = sessionArray(artifact.value);
  const statuses = new Set([
    'running',
    'waiting',
    'done',
    'completed',
    'failed',
    'cancelled',
    'blocked',
    'idle'
  ]);
  if (!sessions || sessions.some((session) =>
    !plainObject(session) ||
    typeof session.status !== 'string' ||
    !statuses.has(session.status.trim().toLowerCase())
  )) {
    return semanticInvalid(artifact, warnings);
  }
  return artifact;
}

function validateRepairQueueArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const records = repairArray(artifact.value);
  const allowed = new Set([
    'open',
    'queued',
    'pending',
    'in_progress',
    'closed',
    'resolved',
    'reopened',
    'unmanaged'
  ]);
  if (!records || records.some((record) => {
    if (!plainObject(record)) return true;
    if (record.status === undefined || record.status === null || record.status === '') return false;
    return typeof record.status !== 'string' ||
      !allowed.has(record.status.trim().toLowerCase());
  })) {
    return semanticInvalid(artifact, warnings);
  }
  return artifact;
}

function validNullableNumber(value, options = {}) {
  if (value === null || value === undefined) return true;
  if (!Number.isFinite(value)) return false;
  if (options.integer && !Number.isInteger(value)) return false;
  if (options.minimum !== undefined && value < options.minimum) return false;
  if (options.maximum !== undefined && value > options.maximum) return false;
  return true;
}

function repairTelemetryAssessment(artifact, status, reason, warnings, options = {}) {
  const warning = status === 'current'
    ? null
    : status === 'unavailable'
      ? artifact.warning || `unavailable artifact: ${artifact.source}`
      : `${status} artifact: ${artifact.source} (${reason})`;
  if (warning && !warnings.includes(warning)) warnings.push(warning);
  return {
    ...artifact,
    available: status === 'current',
    value: status === 'current' || options.keepValue === true ? artifact.value : null,
    warning,
    telemetry_status: status,
    telemetry_reason: reason || null
  };
}

function validateRepairTelemetryArtifact(artifact, warnings, opportunitiesArtifact = null) {
  if (!artifact.available) {
    const reason = artifact.warning?.startsWith('missing artifact:')
      ? 'No Repair-on-touch telemetry artifact was present for this snapshot.'
      : 'Repair-on-touch telemetry could not be read for this snapshot.';
    return repairTelemetryAssessment(artifact, 'unavailable', reason, warnings);
  }
  const value = artifact.value;
  const modes = new Set(['off', 'safe-only', 'dedicated', 'scoped', 'aggressive']);
  const countKeys = [
    'repair_findings_considered',
    'repair_findings_selected',
    'repair_findings_closed',
    'repair_findings_deferred'
  ];
  const actualKeys = [
    'repair_extra_wall_time_ms',
    'repair_extra_input_tokens',
    'repair_extra_output_tokens'
  ];
  const scoreKeys = [
    'doctor_before',
    'doctor_after',
    'task_readiness_before',
    'task_readiness_after'
  ];
  const lifecycleIds = (input) => Array.isArray(input) &&
    input.every((id) => /^LC-[a-f0-9]{16}$/.test(String(id))) &&
    new Set(input.map(String)).size === input.length;

  let structuralReason = null;
  if (!plainObject(value) ||
      value.schema_version !== 'knowledge-repair-on-touch-telemetry.v1' ||
      typeof value.generated_at !== 'string' ||
      !Number.isFinite(Date.parse(value.generated_at)) ||
      typeof value.task_id !== 'string' || !value.task_id ||
      typeof value.session_id !== 'string' || !value.session_id ||
      !/^[a-f0-9]{64}$/.test(String(value.task_scope_sha256 || '')) ||
      typeof value.repair_on_touch_enabled !== 'boolean' ||
      !modes.has(value.repair_mode) ||
      value.token_values !== 'actual_only') {
    structuralReason = 'schema_or_identity_invalid';
  }
  if (!structuralReason && countKeys.some((key) =>
    !validNullableNumber(value[key], { integer: true, minimum: 0 }) ||
    value[key] === null || value[key] === undefined)) {
    structuralReason = 'count_fields_invalid';
  }
  if (!structuralReason) {
    const considered = value.repair_findings_considered;
    const selected = value.repair_findings_selected;
    const closed = value.repair_findings_closed;
    const deferred = value.repair_findings_deferred;
    const workCount = considered + selected + closed + deferred;
    const actualWork = actualKeys.some((key) =>
      value[key] !== null && value[key] !== undefined && Number(value[key]) > 0);
    if (value.repair_on_touch_enabled !== (value.repair_mode !== 'off')) {
      structuralReason = 'enabled_mode_mismatch';
    } else if (!value.repair_on_touch_enabled && (workCount !== 0 || actualWork)) {
      structuralReason = 'disabled_telemetry_contains_work';
    } else if (closed > selected || selected > considered || deferred > considered || selected + deferred > considered) {
      structuralReason = 'count_relationship_invalid';
    }
  }
  if (!structuralReason && (actualKeys.some((key) =>
    !validNullableNumber(value[key], {
      integer: key !== 'repair_extra_wall_time_ms',
      minimum: 0
    })) || scoreKeys.some((key) =>
    !validNullableNumber(value[key], { minimum: 0, maximum: 100 })))) {
    structuralReason = 'measurement_fields_invalid';
  }
  if (!structuralReason) {
    const consideredIds = value.repair_lifecycle_ids_considered;
    const closedIds = value.repair_lifecycle_ids_closed;
    if (!lifecycleIds(consideredIds) ||
        !lifecycleIds(closedIds) ||
        consideredIds.length !== value.repair_findings_considered ||
        closedIds.length !== value.repair_findings_closed ||
        closedIds.some((id) => !consideredIds.includes(id))) {
      structuralReason = 'lifecycle_ids_invalid';
    }
  }
  if (structuralReason) {
    return repairTelemetryAssessment(
      artifact,
      'invalid',
      `The telemetry artifact failed semantic validation (${structuralReason}); no Repair-on-touch effect is claimed.`,
      warnings
    );
  }

  if (!opportunitiesArtifact?.available || !plainObject(opportunitiesArtifact.value)) {
    return repairTelemetryAssessment(
      artifact,
      'stale',
      'The telemetry is structurally valid, but the current repair-opportunities snapshot is unavailable, so its task binding cannot be confirmed.',
      warnings
    );
  }
  const snapshot = opportunitiesArtifact.value;
  const taskScope = snapshot.task_scope;
  const scopeHash = plainObject(taskScope) ? taskScopeHash(taskScope) : null;
  if (!plainObject(taskScope) ||
      value.task_id !== taskScope.task_id ||
      value.session_id !== taskScope.session_id ||
      value.task_scope_sha256 !== scopeHash ||
      (taskScope.scope_hash !== undefined && taskScope.scope_hash !== scopeHash)) {
    return repairTelemetryAssessment(
      artifact,
      'stale',
      'The telemetry is structurally valid, but it is bound to a different task scope or session.',
      warnings
    );
  }
  if (Number.isFinite(Date.parse(snapshot.generated_at)) &&
      Date.parse(value.generated_at) < Date.parse(snapshot.generated_at)) {
    return repairTelemetryAssessment(
      artifact,
      'stale',
      'The telemetry predates the current repair-opportunities snapshot.',
      warnings
    );
  }
  const opportunities = Array.isArray(snapshot.opportunities) ? snapshot.opportunities : [];
  const consideredIds = opportunities.map((item) => String(item.lifecycle_id)).sort();
  const selected = opportunities.filter((item) =>
    ['selected', 'repaired'].includes(String(item.status))).length;
  const closedIds = opportunities
    .filter((item) => item.status === 'repaired')
    .map((item) => String(item.lifecycle_id))
    .sort();
  const deferred = opportunities.filter((item) => item.status === 'deferred').length;
  const current = snapshot.repair_on_touch?.effective_mode === value.repair_mode &&
    value.repair_findings_considered === opportunities.length &&
    value.repair_findings_selected === selected &&
    value.repair_findings_closed === closedIds.length &&
    value.repair_findings_deferred === deferred &&
    JSON.stringify([...value.repair_lifecycle_ids_considered].sort()) === JSON.stringify(consideredIds) &&
    JSON.stringify([...value.repair_lifecycle_ids_closed].sort()) === JSON.stringify(closedIds);
  if (!current) {
    return repairTelemetryAssessment(
      artifact,
      'stale',
      'The telemetry is structurally valid, but its repair counts or lifecycle IDs do not match the current repair-opportunities snapshot.',
      warnings
    );
  }
  return repairTelemetryAssessment(artifact, 'current', null, warnings);
}

function validateRepairOpportunitiesArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const value = artifact.value;
  const scope = value?.task_scope;
  const repair = value?.repair_on_touch;
  const global = value?.global;
  const readiness = value?.task_readiness;
  const summary = value?.summary;
  const budget = value?.budget;
  const statuses = new Set(['selected', 'repaired', 'deferred', 'rejected']);
  const relations = new Set(['direct_overlap', 'dependency_overlap', 'no_overlap']);
  const modes = new Set(['off', 'safe-only', 'dedicated', 'scoped', 'aggressive']);
  const opportunities = Array.isArray(value?.opportunities) ? value.opportunities : null;
  const lifecycleIds = opportunities?.map((item) => String(item?.lifecycle_id || '')) || [];
  const selectedCount = opportunities?.filter((item) =>
    ['selected', 'repaired'].includes(String(item?.status || ''))).length;
  const deferredCount = opportunities?.filter((item) =>
    item?.status === 'deferred').length;
  const valid = plainObject(value) &&
    value.schema_version === 'knowledge-repair-opportunities.v1' &&
    typeof value.generated_at === 'string' &&
    Number.isFinite(Date.parse(value.generated_at)) &&
    opportunities !== null &&
    plainObject(scope) &&
    scope.schema_version === 'knowledge-task-scope.v1' &&
    typeof scope.task_id === 'string' &&
    Boolean(scope.task_id) &&
    typeof scope.session_id === 'string' &&
    Boolean(scope.session_id) &&
    /^[a-f0-9]{64}$/.test(String(scope.scope_hash || '')) &&
    scope.scope_hash === taskScopeHash(scope) &&
    plainObject(repair) &&
    modes.has(String(repair.configured_mode || '')) &&
    modes.has(String(repair.effective_mode || '')) &&
    typeof repair.effective_mode_source === 'string' &&
    Boolean(repair.effective_mode_source) &&
    plainObject(repair.hard_safety) &&
    repair.hard_safety.edit_source_for_health === false &&
    plainObject(global) &&
    validNullableNumber(global.score, { minimum: 0, maximum: 100 }) &&
    typeof global.status === 'string' &&
    Boolean(global.status) &&
    plainObject(readiness) &&
    validNullableNumber(readiness.score, { minimum: 0, maximum: 100 }) &&
    typeof readiness.status === 'string' &&
    Number.isInteger(readiness.relevant_findings_open) &&
    readiness.relevant_findings_open >= 0 &&
    Number.isInteger(readiness.relevant_findings_closed) &&
    readiness.relevant_findings_closed >= 0 &&
    plainObject(summary) &&
    summary.findings_considered === opportunities.length &&
    summary.findings_selected === selectedCount &&
    summary.findings_deferred === deferredCount &&
    plainObject(budget) &&
    plainObject(budget.limits) &&
    plainObject(budget.selected) &&
    typeof budget.exhausted === 'boolean' &&
    opportunities.every((item) =>
      plainObject(item) &&
      /^LC-[a-f0-9]{16}$/.test(String(item.lifecycle_id || '')) &&
      typeof item.code === 'string' &&
      Boolean(item.code) &&
      typeof item.module_id === 'string' &&
      Boolean(item.module_id) &&
      Array.isArray(item.affected_artifacts) &&
      item.affected_artifacts.length > 0 &&
      item.affected_artifacts.every((artifactPath) =>
        typeof artifactPath === 'string' && Boolean(artifactPath)) &&
      Number.isFinite(item.score_cost) &&
      item.score_cost >= 0 &&
      typeof item.repair_class === 'string' &&
      Boolean(item.repair_class) &&
      Array.isArray(item.required_checks) &&
      item.required_checks.every((check) => typeof check === 'string' && Boolean(check)) &&
      typeof item.resolution_predicate === 'string' &&
      Boolean(item.resolution_predicate) &&
      relations.has(String(item.relation_to_current_task || '')) &&
      typeof item.safe_during_current_task === 'boolean' &&
      typeof item.requires_confirmation === 'boolean' &&
      typeof item.decision_reason === 'string' &&
      Boolean(item.decision_reason) &&
      statuses.has(String(item.status || ''))) &&
    new Set(lifecycleIds).size === lifecycleIds.length;
  return valid ? artifact : semanticInvalid(artifact, warnings);
}

function validatePackageArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const value = artifact.value;
  const release = value?.knowledge_release;
  const releaseValid = release === undefined || (
    plainObject(release) &&
    ['stable', 'release_candidate', 'development'].includes(String(release.channel || '')) &&
    (release.candidate_label === null || release.candidate_label === undefined ||
      /^RC[1-9][0-9]*$/.test(String(release.candidate_label))) &&
    (release.candidate_name === null || release.candidate_name === undefined ||
      /^knowledge-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.zip$/.test(String(release.candidate_name)))
  );
  return plainObject(value) &&
    typeof value.version === 'string' &&
    /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(value.version) &&
    releaseValid
    ? artifact
    : semanticInvalid(artifact, warnings);
}

function validateScoreArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  return plainObject(artifact.value) &&
    Number.isFinite(artifact.value.quality_score) &&
    artifact.value.quality_score >= 0 &&
    artifact.value.quality_score <= 100
    ? artifact
    : semanticInvalid(artifact, warnings);
}

function validateTrustArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  if (!plainObject(artifact.value)) return semanticInvalid(artifact, warnings);
  const stale = staleCount(artifact.value);
  const counts = moduleTrustCounts(artifact.value);
  const validCount = (value) => value === null ||
    (Number.isInteger(value) && value >= 0);
  const staleCandidates = [
    Number.isFinite(artifact.value.stale_artifacts_total)
      ? artifact.value.stale_artifacts_total
      : null,
    Array.isArray(artifact.value.stale_items) ? artifact.value.stale_items.length : null,
    Number.isFinite(artifact.value.stale_total) ? artifact.value.stale_total : null
  ].filter((value) => value !== null);
  const countCandidates = (status, scalarName) => [
    counts[status],
    Array.isArray(artifact.value[status]) ? uniqueModuleIds(artifact.value[status]).length : null,
    Number.isFinite(artifact.value[scalarName]) ? artifact.value[scalarName] : null
  ].filter((value) => value !== null);
  const coherent = (values) => values.every((value) => value === values[0]);
  return validCount(stale) &&
    Object.values(counts).every(validCount) &&
    (stale !== null || Object.values(counts).some((value) => value !== null)) &&
    coherent(staleCandidates) &&
    coherent(countCandidates('suspect', 'modules_suspect')) &&
    coherent(countCandidates('low_confidence', 'modules_low_confidence')) &&
    coherent(countCandidates('needs_recheck', 'modules_needing_recheck'))
    ? artifact
    : semanticInvalid(artifact, warnings);
}

function validateGraphArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const value = artifact.value;
  const valid = plainObject(value) &&
    Array.isArray(value.nodes) &&
    Array.isArray(value.edges) &&
    value.nodes.every(plainObject) &&
    value.edges.every(plainObject);
  return valid ? artifact : semanticInvalid(artifact, warnings);
}

function validateSearchArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const value = artifact.value;
  return plainObject(value) &&
    Array.isArray(value.documents) &&
    value.documents.every(plainObject)
    ? artifact
    : semanticInvalid(artifact, warnings);
}

function validateReceiptIndexArtifact(artifact, warnings) {
  if (!artifact.available) return artifact;
  const value = artifact.value;
  const valid = plainObject(value) &&
    value.schema_version === 'knowledge-verification-receipt-index.v1' &&
    Array.isArray(value.receipts) &&
    value.receipts.every((receipt) =>
      plainObject(receipt) &&
      typeof receipt.receipt_id === 'string' &&
      /^KVR-[a-f0-9]{64}$/.test(receipt.receipt_id) &&
      /^[a-f0-9]{64}$/.test(String(receipt.content_sha256 || '')) &&
      typeof receipt.path === 'string' &&
      !path.posix.isAbsolute(receipt.path.replace(/\\/g, '/')) &&
      !receipt.path.replace(/\\/g, '/').split('/').includes('..')
    );
  return valid ? artifact : semanticInvalid(artifact, warnings);
}

function repairCounts(records) {
  const result = { open: 0, closed: 0, reopened: 0, unmanaged: 0 };
  for (const record of records) {
    const status = String(record?.status || '').trim().toLowerCase();
    if (status === 'reopened') result.reopened += 1;
    else if (['open', 'queued', 'pending', 'in_progress'].includes(status)) result.open += 1;
    else if (['closed', 'resolved'].includes(status)) result.closed += 1;
    else if (!status && record?.closed_at) result.closed += 1;
    else result.unmanaged += 1;
  }
  return result;
}

function uniqueModuleIds(values) {
  if (!Array.isArray(values)) return [];
  return [...new Set(values
    .filter((value) => typeof value === 'string' && value.trim())
    .map((value) => value.trim()))].sort();
}

function moduleIdsForStatus(trust, status) {
  const ids = new Set();
  let available = false;
  const moduleBucket = trust?.modules?.[status];
  if (Array.isArray(moduleBucket)) {
    available = true;
    for (const id of uniqueModuleIds(moduleBucket)) ids.add(id);
  }
  if (Array.isArray(trust?.[status])) {
    available = true;
    for (const id of uniqueModuleIds(trust[status])) ids.add(id);
  }
  if (Array.isArray(trust?.module_statuses)) {
    available = true;
    for (const item of trust.module_statuses) {
      const itemStatus = String(item?.trust_status || item?.status || '').trim().toLowerCase();
      const moduleId = String(item?.module_id || item?.id || '').trim();
      if (itemStatus === status && moduleId) ids.add(moduleId);
    }
  }
  return available ? [...ids].sort() : null;
}

function moduleTrustCounts(trust) {
  const suspect = moduleIdsForStatus(trust, 'suspect');
  const lowConfidence = moduleIdsForStatus(trust, 'low_confidence');
  const explicitRecheck = moduleIdsForStatus(trust, 'needs_recheck');
  const recheckAvailable = suspect !== null || lowConfidence !== null || explicitRecheck !== null;
  return {
    suspect: suspect === null ? null : suspect.length,
    low_confidence: lowConfidence === null ? null : lowConfidence.length,
    needs_recheck: recheckAvailable
      ? new Set([...(suspect || []), ...(lowConfidence || []), ...(explicitRecheck || [])]).size
      : null
  };
}

function moduleSuspectCount(trust) {
  return moduleTrustCounts(trust).suspect;
}

function moduleLowConfidenceCount(trust) {
  return moduleTrustCounts(trust).low_confidence;
}

function moduleNeedingRecheckCount(trust) {
  return moduleTrustCounts(trust).needs_recheck;
}

function staleCount(trust) {
  if (Number.isFinite(trust?.stale_artifacts_total)) return trust.stale_artifacts_total;
  if (Array.isArray(trust?.stale_items)) return trust.stale_items.length;
  if (Number.isFinite(trust?.stale_total)) return trust.stale_total;
  return null;
}

function runtimeNames(sessions) {
  const values = new Set();
  for (const session of sessions) {
    for (const candidate of [
      session?.runtime,
      session?.agent_runtime,
      session?.model,
      session?.agent,
      session?.provider
    ]) {
      if (typeof candidate === 'string' && candidate.trim()) values.add(candidate.trim());
    }
  }
  return [...values].sort();
}

function collect(context, options = {}) {
  const collectedAt = new Date().toISOString();
  const warnings = [];
  const stateRoot = context.stateRoot;
  const systemRoot = context.systemRoot;
  const get = (relative, source = relative) =>
    readJsonArtifact(path.join(stateRoot, relative), source, warnings);

  const packageArtifact = validatePackageArtifact(
    readJsonArtifact(
      path.join(systemRoot, 'package.json'),
      '.knowledge/package.json',
      warnings
    ),
    warnings
  );
  const quality = validateScoreArtifact(
    get(path.join('maintenance', 'quality_report.json')),
    warnings
  );
  const lint = validateScoreArtifact(
    get(path.join('maintenance', 'wiki_lint_report.json')),
    warnings
  );
  const trust = validateTrustArtifact(
    get(path.join('maintenance', 'trust_report.json')),
    warnings
  );
  const graph = validateGraphArtifact(
    get(path.join('maps', 'wiki_graph.json')),
    warnings
  );
  const wikiStatusAvailable = lint.available || graph.available;
  const wikiStatus = wikiStatusAvailable
    ? canonicalWikiStatus(lint.value || {}, graph.value || {})
    : null;
  const wikiStatusWarning = [
    lint.available ? null : lint.warning,
    graph.available ? null : graph.warning
  ].filter(Boolean).join('; ') || null;
  const search = validateSearchArtifact(get(path.join('search', 'index.json')), warnings);
  const moduleRegistry = validateModuleRegistryArtifact(
    get(path.join('modules', 'module_registry.json')),
    warnings
  );
  const repositoryProfile = collectRepositoryProfile(context.targetRoot, warnings);
  const registry = validateRegistryArtifact(
    get(path.join('sessions', 'agent-registry.json')),
    warnings
  );
  const repair = validateRepairQueueArtifact(
    get(path.join('maintenance', 'repair_queue.json')),
    warnings
  );
  const repairOpportunities = validateRepairOpportunitiesArtifact(
    get(path.join('maintenance', 'repair_opportunities.json')),
    warnings
  );
  const verificationReceipts = validateReceiptIndexArtifact(
    get(path.join('maintenance', 'verification_receipts', 'index.json')),
    warnings
  );
  const rawRepairTelemetry = get(path.join('maintenance', 'repair_on_touch_telemetry.json'));
  const repairTelemetry = validateRepairTelemetryArtifact(
    rawRepairTelemetry,
    warnings,
    repairOpportunities
  );
  const repairTelemetryStatus = repairTelemetry.telemetry_status ||
    (repairTelemetry.available ? 'current' : 'unavailable');
  const repairTelemetryReason = repairTelemetry.telemetry_reason || null;
  const requestedTaskId = options.routingTaskId ? String(options.routingTaskId) : null;
  const routingIndex = get(path.join('routing', 'index.json'));
  const fallbackTasks = Array.isArray(routingIndex.value?.tasks) ? routingIndex.value.tasks : [];
  const routingManifests = taskRouting ? taskRouting.listTasks(context) : fallbackTasks;
  const selectedManifest = requestedTaskId
    ? routingManifests.find((item) => item.task_scope_hash === requestedTaskId) || null
    : (routingManifests.length === 1 ? routingManifests[0] : null);
  const routingResolution = taskRouting && selectedManifest ? taskRouting.inspectTask(context, selectedManifest.task_scope_hash) : null;
  const effectiveRoutingState = taskRoutingState && selectedManifest
    ? taskRoutingState.resolveEffectiveTaskRoutingState({ context, taskScopeHash: selectedManifest.task_scope_hash, verifyLiveInputs: true })
    : null;
  const currentTask = routingResolution?.status === 'ok' && routingResolution.current
    ? routingResolution.current
    : selectedManifest;
  if (requestedTaskId && !currentTask) {
    warnings.push(`requested routing task snapshot is unavailable: ${requestedTaskId}`);
  }
  const taskSnapshotHash = currentTask?.routing_snapshot_hash || currentTask?.snapshot_hash || currentTask?.current_routing_snapshot_hash || currentTask?.current_snapshot_hash || null;
  const taskBundle = currentTask?.task_scope_hash && taskSnapshotHash
    ? get(path.join('routing', 'tasks', currentTask.task_scope_hash, 'snapshots', taskSnapshotHash, 'bundle.json'))
    : { available: false, value: null, source: '.knowledge/routing/tasks', warning: requestedTaskId ? 'requested task routing snapshot is unavailable' : 'no unambiguous task routing snapshot' };
  const taskMetrics = effectiveRoutingState?.metrics || currentTask?.metrics || {};
  const taskMetricsArtifact = {
    available: Boolean(effectiveRoutingState && Object.keys(taskMetrics).length),
    value: taskMetrics,
    source: currentTask?.task_scope_hash && effectiveRoutingState?.metrics_comparison_hash
      ? `routing/tasks/${currentTask.task_scope_hash}/comparisons/${effectiveRoutingState.metrics_comparison_hash}/metrics.json`
      : '.knowledge/routing/tasks',
    warning: effectiveRoutingState ? null : 'task routing comparison is unavailable'
  };

  const scope = workspaceScope(context, warnings);
  const doctorCounts = quality.available ? doctorFindingCounts(quality.value) : { active: null, critical: null };
  const sessions = registry.available ? sessionArray(registry.value) : null;
  const repairs = repair.available ? repairArray(repair.value) : null;
  const repairSummary = repairs ? repairCounts(repairs) : null;
  const flowSummary = countReleaseFlows(stateRoot);
  const prSummary = countPrSummaries(stateRoot);
  if (flowSummary.warning) warnings.push(flowSummary.warning);
  if (prSummary.warning) warnings.push(prSummary.warning);

  const values = {
    knowledge_version: fromArtifact(
      packageArtifact,
      packageArtifact.value?.version,
      '$.version',
      collectedAt
    ),
    knowledge_release_channel: fromArtifact(
      packageArtifact,
      packageArtifact.value?.knowledge_release?.channel,
      '$.knowledge_release.channel',
      collectedAt
    ),
    knowledge_candidate_label: fromArtifact(
      packageArtifact,
      packageArtifact.value?.knowledge_release?.candidate_label,
      '$.knowledge_release.candidate_label',
      collectedAt
    ),
    knowledge_candidate_name: fromArtifact(
      packageArtifact,
      packageArtifact.value?.knowledge_release?.candidate_name,
      '$.knowledge_release.candidate_name',
      collectedAt
    ),
    mode: fact(context.mode, 'observed', 'runtime/context', '$.mode', collectedAt),
    workspace_scope_kind: fact(
      scope.kind,
      scope.kind === 'workspace_scope_unknown' || scope.kind === 'team_workspace_unknown'
        ? 'unavailable'
        : 'derived',
      'runtime/context',
      '$.workspace_scope_kind',
      collectedAt,
      scope.confidence,
      scope.warning
    ),
    workspace_repositories_total: fact(
      scope.repositories_total,
      Number.isInteger(scope.repositories_total) ? 'derived' : 'unavailable',
      'runtime/context',
      '$.workspace_repositories_total',
      collectedAt,
      scope.confidence,
      scope.warning
    ),
    branch: fact(
      context.branch,
      context.branch ? 'observed' : 'unavailable',
      'runtime/context',
      '$.branch',
      collectedAt
    ),
    head_sha: fact(
      context.headSha,
      context.headSha ? 'observed' : 'unavailable',
      'runtime/context',
      '$.headSha',
      collectedAt
    ),
    project_type: fact(
      projectType(context.targetRoot),
      'derived',
      'runtime/context',
      '$.targetRoot',
      collectedAt,
      'medium'
    ),
    functional_modules_total: fromArtifact(
      moduleRegistry,
      Array.isArray(moduleRegistry.value?.modules) ? moduleRegistry.value.modules.length : null,
      '$.modules.length',
      collectedAt
    ),
    repository_tracked_files: fact(
      repositoryProfile.tracked_files,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.tracked_files',
      collectedAt,
      repositoryProfile.basis === 'git_index_worktree' ? 'high' : 'medium',
      repositoryProfile.warning || null
    ),
    repository_tracked_bytes: fact(
      repositoryProfile.tracked_bytes,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.tracked_bytes',
      collectedAt,
      repositoryProfile.basis === 'git_index_worktree' ? 'high' : 'medium',
      repositoryProfile.warning || null
    ),
    repository_source_files: fact(
      repositoryProfile.source_files,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.source_files',
      collectedAt,
      repositoryProfile.basis === 'git_index_worktree' ? 'high' : 'medium',
      repositoryProfile.warning || null
    ),
    repository_source_bytes: fact(
      repositoryProfile.source_bytes,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.source_bytes',
      collectedAt,
      repositoryProfile.basis === 'git_index_worktree' ? 'high' : 'medium',
      repositoryProfile.warning || null
    ),
    repository_profile_excluded_files: fact(
      repositoryProfile.excluded_files,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.excluded_files',
      collectedAt,
      'medium',
      repositoryProfile.warning || null
    ),
    repository_profile_basis: fact(
      repositoryProfile.basis,
      repositoryProfile.available ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.basis',
      collectedAt,
      repositoryProfile.basis === 'git_index_worktree' ? 'high' : 'medium',
      repositoryProfile.warning || null
    ),
    repository_profile_dirty: fact(
      repositoryProfile.dirty,
      repositoryProfile.available && repositoryProfile.dirty !== null ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.dirty',
      collectedAt,
      'medium',
      repositoryProfile.dirty === null ? 'working-tree change status is unavailable' : null
    ),
    repository_snapshot_status: fact(
      repositoryProfile.snapshot_status || null,
      repositoryProfile.available && repositoryProfile.snapshot_status ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.snapshot_status',
      collectedAt,
      repositoryProfile.snapshot_status ? 'high' : 'unavailable',
      repositoryProfile.snapshot_status ? null : 'final snapshot status is unavailable'
    ),
    repository_dirty_tracked_changes: fact(
      repositoryProfile.dirty_tracked_changes,
      repositoryProfile.available && repositoryProfile.dirty_tracked_changes !== null ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.dirty_tracked_changes',
      collectedAt
    ),
    repository_dirty_untracked_files: fact(
      repositoryProfile.dirty_untracked_files,
      repositoryProfile.available && repositoryProfile.dirty_untracked_files !== null ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.dirty_untracked_files',
      collectedAt
    ),
    repository_dirty_conflicts: fact(
      repositoryProfile.dirty_conflicts,
      repositoryProfile.available && repositoryProfile.dirty_conflicts !== null ? 'derived' : 'unavailable',
      'runtime/context',
      '$.repository_profile.dirty_conflicts',
      collectedAt
    ),
    agent_sessions: fromArtifact(registry, sessions?.length, '$.sessions.length', collectedAt),
    completed_sessions: fromArtifact(
      registry,
      sessions?.filter((session) =>
        ['done', 'completed'].includes(String(session?.status).trim().toLowerCase())
      ).length,
      '$.sessions[status=done|completed]',
      collectedAt
    ),
    running_sessions: fromArtifact(
      registry,
      sessions?.filter((session) =>
        String(session?.status).trim().toLowerCase() === 'running').length,
      '$.sessions[status=running]',
      collectedAt
    ),
    waiting_sessions: fromArtifact(
      registry,
      sessions?.filter((session) =>
        String(session?.status).trim().toLowerCase() === 'waiting').length,
      '$.sessions[status=waiting]',
      collectedAt
    ),
    agent_runtimes: fromArtifact(
      registry,
      sessions ? runtimeNames(sessions) : null,
      '$.sessions[*].runtime|agent_runtime|model',
      collectedAt,
      'medium',
      'derived'
    ),
    release_flow_count: fact(
      flowSummary.value,
      flowSummary.available ? 'observed' : 'unavailable',
      '.knowledge/maintenance/flow-logs',
      '$.release_flow_count',
      collectedAt,
      'high',
      flowSummary.warning
    ),
    pr_summary_count: fact(
      prSummary.value,
      prSummary.available ? 'observed' : 'unavailable',
      '.knowledge/maintenance/pr-summaries',
      '$.pr_summary_count',
      collectedAt,
      'high',
      prSummary.warning
    ),
    doctor_score: fromArtifact(
      quality,
      quality.value?.quality_score,
      '$.quality_score',
      collectedAt,
      'medium'
    ),
    doctor_status: fromArtifact(
      quality,
      quality.value?.status,
      '$.status',
      collectedAt,
      'high'
    ),
    doctor_structural_status: fromArtifact(
      quality,
      quality.value?.structural_status,
      '$.structural_status',
      collectedAt,
      'high'
    ),
    doctor_active_findings: fromArtifact(
      quality,
      doctorCounts.active,
      '$.issues[status!=closed|resolved]',
      collectedAt,
      'high'
    ),
    doctor_critical_findings: fromArtifact(
      quality,
      doctorCounts.critical,
      '$.issues[severity=critical,status!=closed|resolved]',
      collectedAt,
      'high'
    ),
    wiki_lint_score: fromArtifact(
      lint,
      lint.value?.quality_score,
      '$.quality_score',
      collectedAt,
      'medium'
    ),
    wiki_structural_status: fact(
      wikiStatus,
      wikiStatusAvailable ? 'derived' : 'unavailable',
      lint.available ? lint.source : graph.source,
      '$.status|$.structural_status + .knowledge/maps/wiki_graph.json::$.structural_status',
      collectedAt,
      'high',
      wikiStatusWarning
    ),
    search_documents: fromArtifact(
      search,
      Array.isArray(search.value?.documents) ? search.value.documents.length : null,
      '$.documents.length',
      collectedAt
    ),
    wiki_nodes: fromArtifact(
      graph,
      Array.isArray(graph.value?.nodes) ? graph.value.nodes.length : graph.value?.nodes,
      '$.nodes',
      collectedAt
    ),
    wiki_edges: fromArtifact(
      graph,
      Array.isArray(graph.value?.edges) ? graph.value.edges.length : graph.value?.edges,
      '$.edges',
      collectedAt
    ),
    wiki_broken_edges: fromArtifact(
      graph,
      wikiBrokenEdgeCount(graph.value),
      '$.broken_edge_count|$.broken_edges',
      collectedAt
    ),
    stale_artifacts_total: fromArtifact(
      trust,
      staleCount(trust.value),
      '$.stale_artifacts_total',
      collectedAt
    ),
    modules_suspect: fromArtifact(
      trust,
      moduleSuspectCount(trust.value),
      '$.modules.suspect',
      collectedAt
    ),
    modules_low_confidence: fromArtifact(
      trust,
      moduleLowConfidenceCount(trust.value),
      '$.modules.low_confidence',
      collectedAt
    ),
    modules_needing_recheck: fromArtifact(
      trust,
      moduleNeedingRecheckCount(trust.value),
      '$.modules.suspect + $.modules.low_confidence + $.module_statuses[trust_status=needs_recheck]',
      collectedAt
    ),
    routing_scope: fromArtifact(taskBundle, taskBundle.value?.task_scope_hash, '$.task_scope_hash', collectedAt, 'high'),
    routing_task_bound_to_report: fact(
      Boolean(requestedTaskId && currentTask),
      requestedTaskId ? (currentTask ? 'observed' : 'unavailable') : 'unavailable',
      currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks',
      '$.snapshot_hash',
      collectedAt,
      'high',
      requestedTaskId ? null : 'no explicit routing task was bound to this Field Report'
    ),
    routing_scope_source: fromArtifact(taskBundle, taskBundle.value?.scope_source, '$.scope_source', collectedAt, 'high'),
    modules_total: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_narrowing?.modules_total, '$.workspace_narrowing.modules_total', collectedAt),
    modules_selected: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_narrowing?.modules_selected, '$.workspace_narrowing.modules_selected', collectedAt),
    paths_total: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_narrowing?.paths_total, '$.workspace_narrowing.paths_total', collectedAt),
    paths_selected: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_narrowing?.paths_selected, '$.workspace_narrowing.paths_selected', collectedAt),
    unrelated_paths_excluded: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_narrowing?.unrelated_paths_excluded, '$.workspace_narrowing.unrelated_paths_excluded', collectedAt),
    routing_scope_comparable: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.scope_comparable ?? taskMetrics.scope_comparable, '$.scope_comparable', collectedAt),
    routing_claim_eligible: fact(Boolean(effectiveRoutingState?.effective_claim_eligible), effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.effective_claim_eligible', collectedAt, 'high', effectiveRoutingState?.claim_ineligible_reasons?.join(', ') || null),
    routing_claim_ineligible_reason: fact(taskMetrics.claim_ineligible_reason || effectiveRoutingState?.claim_ineligible_reasons?.[0] || null, effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.claim_ineligible_reasons', collectedAt),
    routing_pointer_consistent: fact(Boolean(effectiveRoutingState?.pointer_consistent), effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.pointer_consistent', collectedAt),
    routing_live_inputs_match: fact(Boolean(effectiveRoutingState?.live_inputs_match), effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.live_inputs_match', collectedAt),
    routing_current_status: fact(effectiveRoutingState?.current_status || null, effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.current_status', collectedAt),
    routing_snapshot_hash: fact(effectiveRoutingState?.routing_snapshot_hash || null, effectiveRoutingState ? 'observed' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.routing_snapshot_hash', collectedAt, 'high'),
    routing_baseline_hash: fact(effectiveRoutingState?.baseline_hash || null, effectiveRoutingState ? 'observed' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.baseline_hash', collectedAt, 'high'),
    routing_metrics_comparison_hash: fact(effectiveRoutingState?.metrics_comparison_hash || null, effectiveRoutingState ? 'observed' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.metrics_comparison_hash', collectedAt, 'high'),
    routing_live_input_digest: fact(effectiveRoutingState?.live_input_digest || null, effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.live_input_digest', collectedAt, 'high'),
    routing_task_readiness: fact(effectiveRoutingState?.task_readiness || null, effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.task_readiness', collectedAt, 'high'),
    routing_continuation_digest: fact(effectiveRoutingState?.continuation_digest || null, effectiveRoutingState ? 'derived' : 'unavailable', currentTask ? `routing/tasks/${currentTask.task_scope_hash}/current.json` : 'routing/tasks', '$.continuation_digest', collectedAt, 'high'),
    routing_continuation_required: fromArtifact(taskBundle, taskBundle.value?.high_risk_continuation?.required, '$.high_risk_continuation.required', collectedAt),
    routing_measurement_kind: fromArtifact(taskMetricsArtifact, taskMetrics.measurement_kind, '$.measurement_kind', collectedAt),
    routing_comparison_kind: fromArtifact(taskMetricsArtifact, taskMetrics.comparison_kind, '$.comparison_kind', collectedAt),
    routing_workspace_baseline_recipe_id: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_baseline?.recipe_id, '$.workspace_baseline.recipe_id', collectedAt),
    routing_workspace_baseline_recipe_version: fromArtifact(taskMetricsArtifact, taskMetrics.workspace_baseline?.recipe_version, '$.workspace_baseline.recipe_version', collectedAt),
    routing_workspace_baseline_estimated_tokens: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.workspace_baseline?.estimated_tokens : null, '$.workspace_baseline.estimated_tokens', collectedAt),
    routing_task_estimated_tokens: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.task_context?.estimated_tokens : null, '$.task_context.estimated_tokens', collectedAt),
    routing_signed_delta_tokens: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.signed_delta_tokens : null, '$.signed_delta_tokens', collectedAt),
    routing_signed_delta_percent: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.signed_delta_percent : null, '$.signed_delta_percent', collectedAt),
    routing_estimated_tokens_saved: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.estimated_tokens_saved : null, '$.estimated_tokens_saved', collectedAt),
    routing_estimated_percent_saved: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.estimated_percent_saved : null, '$.estimated_percent_saved', collectedAt),
    routing_estimated_tokens_overhead: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.estimated_tokens_overhead : null, '$.estimated_tokens_overhead', collectedAt),
    routing_estimated_percent_overhead: fromArtifact(taskMetricsArtifact, effectiveRoutingState?.effective_claim_eligible ? taskMetrics.estimated_percent_overhead : null, '$.estimated_percent_overhead', collectedAt),
    routing_estimator_assessment: fromArtifact(taskMetricsArtifact, taskMetrics.assessment, '$.assessment', collectedAt),
    repair_open: fromArtifact(repair, repairSummary?.open, '$.queue[status=open]', collectedAt),
    repair_closed: fromArtifact(repair, repairSummary?.closed, '$.queue[status=closed]', collectedAt),
    repair_reopened: fromArtifact(
      repair,
      repairSummary?.reopened,
      '$.queue[status=reopened]',
      collectedAt
    ),
    repair_unmanaged: fromArtifact(
      repair,
      repairSummary?.unmanaged,
      '$.queue[status=unmanaged]',
      collectedAt
    ),
    repair_task_readiness_status: fromArtifact(
      repairOpportunities,
      repairOpportunities.value?.task_readiness?.status,
      '$.task_readiness.status',
      collectedAt,
      'high'
    ),
    repair_task_readiness_score: fromArtifact(
      repairOpportunities,
      repairOpportunities.value?.task_readiness?.score,
      '$.task_readiness.score',
      collectedAt,
      'high'
    ),
    repair_task_relevant_findings_open: fromArtifact(
      repairOpportunities,
      repairOpportunities.value?.task_readiness?.relevant_findings_open,
      '$.task_readiness.relevant_findings_open',
      collectedAt,
      'high'
    ),
    repair_telemetry_status: fact(
      repairTelemetryStatus,
      'derived',
      repairTelemetry.source || '.knowledge/maintenance/repair_on_touch_telemetry.json',
      '$.repair_telemetry_status',
      collectedAt,
      repairTelemetry.available ? 'high' : 'medium',
      repairTelemetry.warning || null
    ),
    repair_telemetry_reason: fact(
      repairTelemetryReason,
      repairTelemetryReason ? 'derived' : 'unavailable',
      repairTelemetry.source || '.knowledge/maintenance/repair_on_touch_telemetry.json',
      '$.repair_telemetry_reason',
      collectedAt,
      repairTelemetryReason ? 'high' : 'unavailable',
      repairTelemetry.warning || null
    ),
    repair_on_touch_enabled: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_on_touch_enabled,
      '$.repair_on_touch_enabled',
      collectedAt
    ),
    repair_mode: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_mode ??
        repairOpportunities.value?.repair_on_touch?.effective_mode,
      '$.repair_mode',
      collectedAt
    ),
    repair_findings_considered: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_findings_considered,
      '$.repair_findings_considered',
      collectedAt
    ),
    repair_findings_selected: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_findings_selected,
      '$.repair_findings_selected',
      collectedAt
    ),
    repair_findings_closed: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_findings_closed,
      '$.repair_findings_closed',
      collectedAt
    ),
    repair_findings_deferred: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_findings_deferred,
      '$.repair_findings_deferred',
      collectedAt
    ),
    repair_extra_wall_time_ms: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_extra_wall_time_ms,
      '$.repair_extra_wall_time_ms',
      collectedAt
    ),
    repair_extra_input_tokens: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_extra_input_tokens,
      '$.repair_extra_input_tokens',
      collectedAt
    ),
    repair_extra_output_tokens: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.repair_extra_output_tokens,
      '$.repair_extra_output_tokens',
      collectedAt
    ),
    repair_doctor_before: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.doctor_before,
      '$.doctor_before',
      collectedAt
    ),
    repair_doctor_after: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.doctor_after,
      '$.doctor_after',
      collectedAt
    ),
    repair_task_readiness_before: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.task_readiness_before,
      '$.task_readiness_before',
      collectedAt
    ),
    repair_task_readiness_after: fromArtifact(
      repairTelemetry,
      repairTelemetry.value?.task_readiness_after,
      '$.task_readiness_after',
      collectedAt
    ),
    verification_receipts: fromArtifact(
      verificationReceipts,
      Array.isArray(verificationReceipts.value?.receipts)
        ? verificationReceipts.value.receipts.length
        : null,
      '$.receipts.length',
      collectedAt
    )
  };

  const facts = Object.values(values);
  return {
    schema_version: SCHEMA_VERSION,
    collected_at: collectedAt,
    mode: context.mode,
    warnings: [...new Set(warnings)],
    facts_observed: facts.filter((item) => item.kind === 'observed').length,
    facts_derived: facts.filter((item) => item.kind === 'derived').length,
    facts_unavailable: facts.filter((item) => item.kind === 'unavailable').length,
    facts_with_warnings: facts.filter((item) => Boolean(item.warning)).length,
    values
  };
}

module.exports = {
  SCHEMA_VERSION,
  collect,
  fact,
  relativeSource,
  repairCounts,
  sessionArray,
  validateRegistryArtifact,
  validateGraphArtifact,
  validatePackageArtifact,
  validateRepairQueueArtifact,
  validateRepairOpportunitiesArtifact,
  validateRepairTelemetryArtifact,
  validateReceiptIndexArtifact,
  validateScoreArtifact,
  validateSearchArtifact,
  validateTrustArtifact,
  moduleSuspectCount,
  moduleLowConfidenceCount,
  moduleNeedingRecheckCount,
  moduleTrustCounts,
  collectRepositoryProfile,
  doctorFindingCounts,
  repositoryProfilePathExcluded,
  validateModuleRegistryArtifact,
  wikiBrokenEdgeCount,
  workspaceScope
};
