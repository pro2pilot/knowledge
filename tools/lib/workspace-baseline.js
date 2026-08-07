'use strict';

const crypto = require('crypto');
const path = require('path');
const { readContainedJson } = require('./contained-artifact');

const BASELINE_SCHEMA = 'knowledge-workspace-first-read-baseline.v1';
const RECIPE_SCHEMA = 'knowledge-workspace-first-read-recipe.v1';
const RECIPE_ID = 'knowledge-workspace-first-read-recipe';
const RECIPE_VERSION = 'v1';
const GENERATOR = 'pro2pilot.workspace-baseline.canonical-generator';

const LIMITS = Object.freeze({
  id: 128,
  name: 256,
  path: 1024,
  role: 1024,
  purpose: 4096,
  summary: 16384,
  modules: 2048,
  runtimeSurfaces: 2048,
  sourceRefsPerModule: 512,
  dependenciesPerModule: 256,
  trustBucketMembers: 2048,
  repairItems: 10000,
  criticalPaths: 4096,
  moduleList: 2048,
  firstReads: 256,
  roleBytes: 512 * 1024,
  roleSourceBytes: 2 * 1024 * 1024,
  schemaVersion: 128
});

const CONFIDENCE_VALUES = new Set(['high', 'medium', 'low', 'unknown']);
const MODULE_STATUS_VALUES = new Set([
  'partial', 'active', 'stable', 'verified', 'deprecated', 'disabled',
  'template_seed', 'trusted', 'near_trusted', 'routing_trusted',
  'advisory_only', 'suspect', 'low_confidence', 'needs_recheck', 'unknown'
]);
const TRUST_BUCKETS = Object.freeze([
  'trusted', 'near_trusted', 'routing_trusted', 'advisory_only',
  'suspect', 'low_confidence'
]);
const TRUST_STATUS_VALUES = new Set([...TRUST_BUCKETS, 'needs_recheck']);
const FRESHNESS_VALUES = new Set([
  'fresh', 'stale', 'suspect', 'needs_recheck', 'missing_card', 'missing',
  'partial', 'clean', 'unknown'
]);
const REPAIR_STATUS_VALUES = new Set(['open', 'closed', 'reopened', 'unmanaged', 'resolved']);
const CRITICAL_SEVERITY_VALUES = new Set(['critical', 'high', 'medium', 'low', 'unknown']);
const CONCURRENCY_MODE_VALUES = new Set([
  'concurrent_safe', 'locked_atomic_writes', 'event-driven', 'manual',
  'disabled', 'safe_queue', 'unknown'
]);
const SOURCE_OF_TRUTH_VALUES = new Set(['code', 'tests', 'evidence', 'mixed', 'unknown']);

const ROLE_RECIPE = Object.freeze([
  { role: 'workspace_project_index', path: '.knowledge/project_index.json', required: true, projector: 'workspace_project_index.v2', source_policy: 'curated', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'workspace_module_registry', path: '.knowledge/modules/module_registry.json', required: true, projector: 'workspace_module_registry.v2', source_policy: 'curated', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'workspace_trust_summary', path: '.knowledge/maintenance/trust_report.json', required: true, projector: 'workspace_trust_summary.v2', source_policy: 'runtime', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'workspace_repair_summary', path: '.knowledge/maintenance/repair_queue.json', required: false, projector: 'workspace_repair_summary.v2', source_policy: 'runtime', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'workspace_handoff_summary', path: '.knowledge/maintenance/handoff_summary.json', required: false, projector: 'workspace_handoff_summary.v2', source_policy: 'runtime', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'workspace_critical_paths_summary', path: '.knowledge/maps/critical_paths.json', required: false, projector: 'workspace_critical_paths_summary.v2', source_policy: 'runtime', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'source_of_truth_policy_summary', path: '.knowledge/project_index.json', required: true, projector: 'source_of_truth_policy_summary.v2', source_policy: 'curated', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes },
  { role: 'concurrency_policy_summary', path: '.knowledge/maintenance/concurrency_policy.json', required: false, projector: 'concurrency_policy_summary.v2', source_policy: 'curated', allow_fallback: false, max_bytes: LIMITS.roleSourceBytes }
]);


function sha(value) {
  return crypto.createHash('sha256').update(
    typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)
  ).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function stableBody(value) {
  return JSON.stringify(canonical(value));
}

function relPath(value) {
  return String(value || '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+/g, '/').replace(/\/$/, '');
}

function safePath(value, options = {}) {
  const normalized = relPath(value);
  if (options.allowDot && normalized === '.') return '.';
  if (!normalized || normalized.length > (options.limit || LIMITS.path)) return null;
  return !path.posix.isAbsolute(normalized) && !normalized.split('/').includes('..') ? normalized : null;
}

function pushOnce(errors, value) {
  if (value && !errors.includes(value)) errors.push(value);
}

function boundedArray(value, field, errors, max, options = {}) {
  if (!Array.isArray(value)) {
    if (options.optional && value === undefined) return [];
    pushOnce(errors, `${field}_invalid`);
    return [];
  }
  if (value.length > max) pushOnce(errors, `${field}_count_anomaly`);
  return value.slice(0, max + 1);
}

function boundedString(value, field, errors, limit = LIMITS.purpose, options = {}) {
  if (typeof value !== 'string' || (!options.allowEmpty && !value.trim())) {
    pushOnce(errors, `${field}_invalid`);
    return null;
  }
  const normalized = value.replace(/\r\n/g, '\n').trim();
  if (normalized.length > limit || /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(normalized)) {
    pushOnce(errors, `${field}_size_anomaly`);
    return null;
  }
  return normalized;
}

function boundedId(value, field, errors) {
  const result = boundedString(value, field, errors, LIMITS.id);
  if (result !== null && !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(result)) {
    pushOnce(errors, `${field}_invalid`);
    return null;
  }
  return result;
}

function boundedEnum(value, field, errors, allowed, fallback = null) {
  const raw = value === undefined || value === null || value === '' ? fallback : value;
  const normalized = boundedString(String(raw ?? ''), field, errors, 64);
  if (normalized === null) return null;
  const lowered = normalized.toLowerCase();
  if (!allowed.has(lowered)) {
    pushOnce(errors, `${field}_unsupported`);
    return null;
  }
  return lowered;
}

function boundedInteger(value, field, errors, options = {}) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < (options.min ?? 0) || number > (options.max ?? Number.MAX_SAFE_INTEGER)) {
    pushOnce(errors, `${field}_invalid`);
    return null;
  }
  return number;
}

function boundedStringList(value, field, errors, options = {}) {
  const source = boundedArray(value, field, errors, options.max || LIMITS.moduleList, { optional: options.optional });
  const rows = [];
  const seen = new Set();
  for (let index = 0; index < source.length; index += 1) {
    const item = options.ids
      ? boundedId(source[index], `${field}_${index}`, errors)
      : boundedString(source[index], `${field}_${index}`, errors, options.limit || LIMITS.purpose);
    if (item === null) continue;
    if (seen.has(item)) {
      pushOnce(errors, `${field}_duplicate`);
      continue;
    }
    seen.add(item);
    if (options.membership && options.membership.size && !options.membership.has(item)) {
      pushOnce(errors, `${field}_foreign_${item}`);
    }
    rows.push(item);
  }
  return rows.sort();
}

function schemaAllowed(value, allowed, errors) {
  if (value === undefined || value === null || value === '') return 'legacy';
  const normalized = boundedString(String(value), 'schema_version', errors, LIMITS.schemaVersion);
  if (normalized === null) return null;
  if (!allowed.includes(normalized)) pushOnce(errors, 'schema_version_unsupported');
  return normalized;
}

function boundedSchemaVersion(value, errors) {
  if (value === undefined || value === null || value === '') return 'legacy';
  return boundedString(String(value), 'schema_version', errors, LIMITS.schemaVersion);
}

function sameSet(left, right) {
  if (left.size !== right.size) return false;
  for (const item of left) if (!right.has(item)) return false;
  return true;
}

function projectIndexProjection(value, context, registryInput) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['project_index_object_required'], projection: null };
  const registryModules = registryInput instanceof Map
    ? registryInput
    : new Map([...(registryInput || new Set())].map((id) => [id, { module_id: id }]));
  const registryIds = new Set(registryModules.keys());
  const sourceSchema = schemaAllowed(value.schema_version, ['knowledge-project-index.v1'], errors);
  const projectName = boundedString(value.project_name, 'project_name', errors, LIMITS.name);
  const repoRoot = safePath(value.repo_root, { allowDot: true });
  if (!repoRoot) pushOnce(errors, 'repo_root_invalid');
  const primary = boundedEnum(value.primary_source_of_truth || 'code', 'primary_source_of_truth', errors, SOURCE_OF_TRUTH_VALUES, 'code');
  const moduleRows = boundedArray(value.modules, 'modules', errors, LIMITS.modules);
  if (!moduleRows.length) pushOnce(errors, 'modules_required');
  const seen = new Set();
  const modules = moduleRows.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      pushOnce(errors, `module_${index}_invalid`);
      return null;
    }
    const moduleId = boundedId(row.module_id, `module_${index}_id`, errors);
    const card = safePath(row.card);
    if (!card) pushOnce(errors, `module_${index}_card_invalid`);
    const confidence = boundedEnum(row.confidence || 'unknown', `module_${index}_confidence`, errors, CONFIDENCE_VALUES, 'unknown');
    if (moduleId && seen.has(moduleId)) pushOnce(errors, 'duplicate_module_id');
    if (moduleId) seen.add(moduleId);
    if (moduleId && registryIds.size && !registryIds.has(moduleId)) pushOnce(errors, `module_reference_missing_${moduleId}`);
    const registryModule = moduleId ? registryModules.get(moduleId) : null;
    if (registryModule?.card && card && relPath(registryModule.card) !== card) pushOnce(errors, `module_card_mismatch_${moduleId}`);
    return moduleId && card && confidence ? { module_id: moduleId, card, confidence } : null;
  }).filter(Boolean).sort((left, right) => left.module_id.localeCompare(right.module_id));
  if (registryIds.size && !sameSet(new Set(modules.map((item) => item.module_id)), registryIds)) pushOnce(errors, 'project_modules_registry_incoherent');

  const surfacesRows = boundedArray(value.runtime_surfaces, 'runtime_surfaces', errors, LIMITS.runtimeSurfaces, { optional: true });
  const surfaceIds = new Set();
  const runtimeSurfaces = surfacesRows.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      pushOnce(errors, `runtime_surface_${index}_invalid`);
      return null;
    }
    const id = boundedId(row.id, `runtime_surface_${index}_id`, errors);
    const surfacePath = safePath(row.path);
    const role = boundedString(row.role, `runtime_surface_${index}_role`, errors, LIMITS.role);
    if (!surfacePath) pushOnce(errors, `runtime_surface_${index}_path_invalid`);
    if (id && surfaceIds.has(id)) pushOnce(errors, 'duplicate_runtime_surface_id');
    if (id) surfaceIds.add(id);
    if (id && registryIds.size && !registryIds.has(id)) pushOnce(errors, `runtime_surface_foreign_module_${id}`);
    const registryModule = id ? registryModules.get(id) : null;
    if (registryModule?.path && surfacePath && relPath(registryModule.path) !== surfacePath) pushOnce(errors, `runtime_surface_path_mismatch_${id}`);
    return id && surfacePath && role !== null ? { id, path: surfacePath, role } : null;
  }).filter(Boolean).sort((left, right) => left.id.localeCompare(right.id));
  if (runtimeSurfaces.length > registryIds.size && registryIds.size) pushOnce(errors, 'runtime_surfaces_count_incoherent');

  if (value.workspace_id && String(value.workspace_id) !== String(context.workspaceId)) pushOnce(errors, 'foreign_workspace_id');
  if (value.repository_id && String(value.repository_id) !== String(context.repoId)) pushOnce(errors, 'foreign_repository_id');
  return {
    errors,
    source_schema: sourceSchema,
    projection: {
      project_name: projectName,
      repo_root: repoRoot,
      primary_source_of_truth: primary,
      modules,
      runtime_surfaces: runtimeSurfaces
    }
  };
}

function normalizeSourceReference(value, field, errors) {
  const row = typeof value === 'string' ? { path: value } : value;
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    pushOnce(errors, `${field}_invalid`);
    return null;
  }
  const sourcePath = safePath(row.path);
  if (!sourcePath) pushOnce(errors, `${field}_path_invalid`);
  return sourcePath ? { path: sourcePath, required: row.required !== false } : null;
}

function sourceReferenceList(value, field, errors, options = {}) {
  const source = boundedArray(value, field, errors, options.max || LIMITS.sourceRefsPerModule, { optional: options.optional });
  const seen = new Set();
  return source.map((item, index) => normalizeSourceReference(item, `${field}_${index}`, errors))
    .filter(Boolean)
    .filter((item) => {
      if (seen.has(item.path)) {
        pushOnce(errors, `${field}_duplicate`);
        return false;
      }
      seen.add(item.path);
      return true;
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

function moduleRegistryProjection(value) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['module_registry_object_required'], projection: null, module_ids: new Set(), module_map: new Map() };
  const sourceSchema = schemaAllowed(value.schema_version, ['knowledge-module-registry.v1'], errors);
  const rows = boundedArray(value.modules, 'modules', errors, LIMITS.modules);
  if (!rows.length) pushOnce(errors, 'modules_required');
  const seen = new Set();
  const modules = rows.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      pushOnce(errors, `module_${index}_invalid`);
      return null;
    }
    const moduleId = boundedId(row.module_id, `module_${index}_id`, errors);
    if (moduleId && seen.has(moduleId)) pushOnce(errors, 'duplicate_module_id');
    if (moduleId) seen.add(moduleId);
    const modulePath = safePath(row.path, { allowDot: true });
    const card = safePath(row.card);
    if (!modulePath) pushOnce(errors, `module_${index}_path_invalid`);
    if (!card) pushOnce(errors, `module_${index}_card_invalid`);
    const purpose = boundedString(row.purpose || row.summary || '', `module_${index}_purpose`, errors, LIMITS.purpose);
    const name = boundedString(row.name || moduleId || '', `module_${index}_name`, errors, LIMITS.name);
    const status = boundedEnum(row.status || row.current_trust_level || 'unknown', `module_${index}_status`, errors, MODULE_STATUS_VALUES, 'unknown');
    const confidence = boundedEnum(row.confidence || 'unknown', `module_${index}_confidence`, errors, CONFIDENCE_VALUES, 'unknown');
    const keyFiles = sourceReferenceList(row.key_files, `module_${index}_key_files`, errors, { optional: true });
    const evidenceInput = boundedArray(row.evidence_files, `module_${index}_evidence_files`, errors, LIMITS.sourceRefsPerModule, { optional: true })
      .map((item) => typeof item === 'string' ? { path: item, required: false } : { ...item, required: item?.required === true });
    const evidenceFiles = sourceReferenceList(evidenceInput, `module_${index}_evidence_files_normalized`, errors, { optional: true });
    const dependencyRows = boundedArray([...(row.dependencies || []), ...(row.depends_on || [])], `module_${index}_dependencies`, errors, LIMITS.dependenciesPerModule, { optional: true });
    const dependencies = [];
    const dependencySeen = new Set();
    dependencyRows.forEach((item, itemIndex) => {
      const raw = typeof item === 'string' ? item : item?.module_id || item?.id;
      const dependency = boundedId(raw, `module_${index}_dependency_${itemIndex}`, errors);
      if (!dependency) return;
      if (dependencySeen.has(dependency)) pushOnce(errors, `module_${index}_dependencies_duplicate`);
      else {
        dependencySeen.add(dependency);
        dependencies.push(dependency);
      }
    });
    dependencies.sort();
    return moduleId && modulePath && card && purpose !== null && name !== null && status && confidence ? {
      module_id: moduleId,
      name,
      path: modulePath,
      card,
      purpose,
      key_files: keyFiles,
      evidence_files: evidenceFiles,
      dependencies,
      status,
      confidence
    } : null;
  }).filter(Boolean).sort((left, right) => left.module_id.localeCompare(right.module_id));
  for (const moduleInfo of modules) {
    for (const dependency of moduleInfo.dependencies) {
      if (!seen.has(dependency)) pushOnce(errors, `dependency_reference_missing_${dependency}`);
    }
  }
  const moduleMap = new Map(modules.map((item) => [item.module_id, item]));
  return { errors, source_schema: sourceSchema, projection: { modules }, module_ids: seen, module_map: moduleMap };
}

function trustProjection(value, registryIds) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['trust_report_object_required'], projection: null };
  const sourceSchema = schemaAllowed(value.schema_version, ['knowledge-trust-report.v1'], errors);
  if (!value.modules || typeof value.modules !== 'object' || Array.isArray(value.modules)) pushOnce(errors, 'trust_buckets_required');
  const statusRows = boundedArray(value.module_statuses, 'module_statuses', errors, LIMITS.modules);
  if (!statusRows.length && registryIds.size) pushOnce(errors, 'module_statuses_required');
  const buckets = {};
  const bucketByModule = new Map();
  for (const bucket of TRUST_BUCKETS) {
    const list = boundedStringList(value.modules?.[bucket], `modules_${bucket}`, errors, {
      optional: true,
      ids: true,
      max: Math.min(LIMITS.trustBucketMembers, Math.max(registryIds.size, 1)),
      membership: registryIds
    });
    buckets[bucket] = list;
    for (const moduleId of list) {
      if (bucketByModule.has(moduleId)) pushOnce(errors, `trust_bucket_overlap_${moduleId}`);
      else bucketByModule.set(moduleId, bucket);
    }
  }
  if (registryIds.size && !sameSet(new Set(bucketByModule.keys()), registryIds)) pushOnce(errors, 'trust_bucket_registry_coverage_incoherent');

  const statusSeen = new Set();
  const statuses = statusRows.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      pushOnce(errors, `status_${index}_invalid`);
      return null;
    }
    const moduleId = boundedId(row.module_id, `status_${index}_module_id`, errors);
    if (moduleId && statusSeen.has(moduleId)) pushOnce(errors, 'duplicate_trust_module_id');
    if (moduleId) statusSeen.add(moduleId);
    if (moduleId && registryIds.size && !registryIds.has(moduleId)) pushOnce(errors, `foreign_trust_module_${moduleId}`);
    const confidence = boundedEnum(row.confidence || 'unknown', `status_${index}_confidence`, errors, CONFIDENCE_VALUES, 'unknown');
    const freshnessStatus = boundedEnum(row.freshness_status || 'unknown', `status_${index}_freshness`, errors, FRESHNESS_VALUES, 'unknown');
    const trustStatus = boundedEnum(row.trust_status, `status_${index}_trust`, errors, TRUST_STATUS_VALUES);
    if (moduleId && trustStatus) {
      const bucket = bucketByModule.get(moduleId);
      if (trustStatus === 'needs_recheck') {
        if (!['suspect', 'low_confidence'].includes(bucket)) pushOnce(errors, `trust_status_bucket_mismatch_${moduleId}`);
      } else if (bucket !== trustStatus) {
        pushOnce(errors, `trust_status_bucket_mismatch_${moduleId}`);
      }
    }
    return moduleId && confidence && freshnessStatus && trustStatus ? {
      module_id: moduleId,
      confidence,
      freshness_status: freshnessStatus,
      trust_status: trustStatus
    } : null;
  }).filter(Boolean).sort((left, right) => left.module_id.localeCompare(right.module_id));
  if (registryIds.size && !sameSet(statusSeen, registryIds)) pushOnce(errors, 'module_statuses_registry_coverage_incoherent');

  const modulesTotal = boundedInteger(value.modules_total, 'modules_total', errors, { max: LIMITS.modules });
  const modulesLowConfidence = boundedInteger(value.modules_low_confidence, 'modules_low_confidence', errors, { max: LIMITS.modules });
  const staleTotal = boundedInteger(value.stale_artifacts_total, 'stale_artifacts_total', errors, { max: 10000000 });
  const contradictions = boundedInteger(value.open_contradictions_total ?? 0, 'open_contradictions_total', errors, { max: 10000000 });
  const highContradictions = boundedInteger(value.high_severity_contradictions_total ?? 0, 'high_severity_contradictions_total', errors, { max: 10000000 });
  if (modulesTotal !== null && modulesTotal !== registryIds.size) pushOnce(errors, 'modules_total_incoherent');
  if (modulesLowConfidence !== null && modulesLowConfidence !== buckets.low_confidence.length) pushOnce(errors, 'modules_low_confidence_incoherent');
  if (statuses.length !== registryIds.size) pushOnce(errors, 'module_statuses_incoherent');
  if (highContradictions !== null && contradictions !== null && highContradictions > contradictions) pushOnce(errors, 'contradictions_total_incoherent');

  return {
    errors,
    source_schema: sourceSchema,
    projection: {
      modules_total: modulesTotal,
      stale_artifacts_total: staleTotal,
      modules_low_confidence: modulesLowConfidence,
      open_contradictions_total: contradictions,
      high_severity_contradictions_total: highContradictions,
      modules: buckets,
      module_statuses: statuses
    }
  };
}

function repairProjection(value, registryIds) {
  const errors = [];
  const queueSource = value?.queue || value?.items;
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Array.isArray(queueSource)) {
    return { errors: ['repair_queue_invalid'], projection: null };
  }
  const queue = boundedArray(queueSource, 'repair_queue', errors, LIMITS.repairItems);
  const seen = new Set();
  const items = queue.map((row, index) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      pushOnce(errors, `repair_${index}_invalid`);
      return null;
    }
    const id = boundedString(row.lifecycle_id || row.id, `repair_${index}_id`, errors, 256);
    if (id && seen.has(id)) pushOnce(errors, 'duplicate_repair_id');
    if (id) seen.add(id);
    const moduleId = row.module_id ? boundedId(row.module_id, `repair_${index}_module_id`, errors) : null;
    if (moduleId && registryIds.size && !registryIds.has(moduleId)) pushOnce(errors, `repair_foreign_module_${moduleId}`);
    const code = boundedString(String(row.code || 'unspecified'), `repair_${index}_code`, errors, 128);
    if (code && !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(code)) pushOnce(errors, `repair_${index}_code_unsupported`);
    const status = boundedEnum(row.status || 'open', `repair_${index}_status`, errors, REPAIR_STATUS_VALUES, 'open');
    return id && code && status ? { id, code, status, module_id: moduleId } : null;
  }).filter(Boolean).sort((left, right) => left.id.localeCompare(right.id));
  const count = (status) => items.filter((item) => item.status === status || (status === 'closed' && item.status === 'resolved')).length;
  return { errors, source_schema: boundedSchemaVersion(value.schema_version, errors), projection: { open: count('open'), closed: count('closed'), reopened: count('reopened'), unmanaged: count('unmanaged'), items } };
}

function validateModuleList(value, field, errors, registryIds) {
  return boundedStringList(value, field, errors, { optional: true, ids: true, max: LIMITS.moduleList, membership: registryIds });
}

function handoffProjection(value, registryIds) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['handoff_summary_invalid'], projection: null };
  const summary = boundedString(value.project_operational_summary || value.summary || '', 'handoff_summary', errors, LIMITS.summary);
  const reads = boundedStringList(value.next_agent_first_reads ?? value.new_chat_first_files, 'next_agent_first_reads', errors, { optional: true, max: LIMITS.firstReads, limit: LIMITS.path });
  for (const read of reads) if (!safePath(read)) pushOnce(errors, 'next_agent_first_reads_path_invalid');
  return {
    errors,
    source_schema: boundedSchemaVersion(value.schema_version, errors),
    projection: {
      project_operational_summary: summary,
      trusted_modules: validateModuleList(value.trusted_modules, 'trusted_modules', errors, registryIds),
      near_trusted_modules: validateModuleList(value.near_trusted_modules, 'near_trusted_modules', errors, registryIds),
      routing_only_modules: validateModuleList(value.routing_only_modules, 'routing_only_modules', errors, registryIds),
      highest_risk_modules: validateModuleList(value.highest_risk_modules, 'highest_risk_modules', errors, registryIds),
      next_agent_first_reads: reads
    }
  };
}

function criticalPathsProjection(value, registryIds) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Array.isArray(value.paths)) return { errors: ['critical_paths_invalid'], projection: null };
  const rows = boundedArray(value.paths, 'critical_paths', errors, LIMITS.criticalPaths);
  const seen = new Set();
  const paths = rows.map((row, index) => {
    const itemPath = safePath(typeof row === 'string' ? row : row?.path);
    if (!itemPath) pushOnce(errors, `critical_path_${index}_invalid`);
    if (itemPath && seen.has(itemPath)) pushOnce(errors, 'duplicate_critical_path');
    if (itemPath) seen.add(itemPath);
    const modules = boundedStringList(Array.isArray(row?.modules) ? row.modules : [], `critical_path_${index}_modules`, errors, { optional: true, ids: true, max: LIMITS.dependenciesPerModule, membership: registryIds });
    const severity = boundedEnum(row?.severity || row?.risk || 'high', `critical_path_${index}_severity`, errors, CRITICAL_SEVERITY_VALUES, 'high');
    return itemPath && severity ? { path: itemPath, modules, severity } : null;
  }).filter(Boolean).sort((left, right) => left.path.localeCompare(right.path));
  return { errors, source_schema: boundedSchemaVersion(value.schema_version, errors), projection: { paths } };
}

function sourcePolicyProjection(value) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['source_policy_invalid'], projection: null };
  const primary = boundedEnum(value.primary_source_of_truth || 'code', 'primary_source_of_truth', errors, SOURCE_OF_TRUTH_VALUES, 'code');
  return { errors, source_schema: boundedSchemaVersion(value.schema_version, errors), projection: { primary_source_of_truth: primary, code_is_source_of_truth: primary === 'code', tests_beat_prose: true } };
}

function concurrencyProjection(value) {
  const errors = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { errors: ['concurrency_policy_invalid'], projection: null };
  const mode = boundedEnum(value.mode || 'unknown', 'concurrency_mode', errors, CONCURRENCY_MODE_VALUES, 'unknown');
  const lockPath = safePath(value.write_policy?.lock_path || '.knowledge/locks/v1/sync.lock');
  if (!lockPath) pushOnce(errors, 'concurrency_lock_path_invalid');
  return {
    errors,
    source_schema: boundedSchemaVersion(value.schema_version, errors),
    projection: {
      mode,
      atomic_writes: value.write_policy?.atomic_writes === true,
      lock_path: lockPath,
      code_is_source_of_truth: value.merge_policy?.code_is_source_of_truth !== false,
      tests_beat_prose: value.merge_policy?.tests_beat_prose !== false,
      suspect_requires_code_recheck: value.merge_policy?.suspect_or_low_confidence_requires_code_recheck !== false
    }
  };
}

function readRole(context, recipe) {
  return readContainedJson(context, recipe.path, recipe.source_policy, {
    allowFallback: recipe.allow_fallback === true,
    maxBytes: recipe.max_bytes || LIMITS.roleSourceBytes
  });
}

function buildWorkspaceBaseline(context) {
  const loaded = new Map(ROLE_RECIPE.map((recipe) => [recipe.role, readRole(context, recipe)]));
  const registrySource = loaded.get('workspace_module_registry');
  const registryResult = registrySource?.value
    ? moduleRegistryProjection(registrySource.value)
    : { errors: [registrySource?.error || 'role_source_missing'], projection: null, module_ids: new Set(), module_map: new Map() };
  const registryIds = registryResult.module_ids || new Set();
  const registryMap = registryResult.module_map || new Map();
  const validators = {
    workspace_module_registry: () => registryResult,
    workspace_project_index: (value) => projectIndexProjection(value, context, registryMap),
    workspace_trust_summary: (value) => trustProjection(value, registryIds),
    workspace_repair_summary: (value) => repairProjection(value, registryIds),
    workspace_handoff_summary: (value) => handoffProjection(value, registryIds),
    workspace_critical_paths_summary: (value) => criticalPathsProjection(value, registryIds),
    source_of_truth_policy_summary: sourcePolicyProjection,
    concurrency_policy_summary: concurrencyProjection
  };
  const roles = ROLE_RECIPE.map((recipe) => {
    const source = loaded.get(recipe.role);
    let result = { errors: [source?.error || 'role_source_missing'], projection: null, source_schema: null };
    if (source?.available && !source.error) result = validators[recipe.role](source.value);
    const projectionBody = result.projection ? stableBody(result.projection) : '';
    if (projectionBody && Buffer.byteLength(projectionBody, 'utf8') > LIMITS.roleBytes) pushOnce(result.errors, 'role_projection_size_anomaly');
    const errors = [...new Set(result.errors || [])];
    const valid = Boolean(source?.available && errors.length === 0);
    return {
      role: recipe.role,
      required: recipe.required,
      source_artifact: recipe.path,
      source_policy: recipe.source_policy,
      source_fallback_allowed: recipe.allow_fallback === true,
      resolved_source: source?.file ? {
        physical_path: source.file,
        physical_root: source.root,
        relative_path: source.relative,
        raw_sha256: source.raw_sha256 || null,
        bytes: source.bytes || 0
      } : null,
      source_schema: result.source_schema || null,
      projector_version: recipe.projector,
      canonical_serializer: 'canonical-json.v2',
      available: Boolean(source?.available),
      valid,
      validation_result: { status: valid ? 'valid' : source?.available ? 'invalid' : 'missing', errors },
      projection: valid ? result.projection : null,
      projection_hash: valid ? sha(projectionBody) : null,
      bytes: valid ? Buffer.byteLength(projectionBody, 'utf8') : 0,
      estimated_tokens: valid ? Math.ceil(Buffer.byteLength(projectionBody, 'utf8') / 4) : 0
    };
  });
  const sizeAnomaly = roles.some((role) => role.validation_result.errors.some((error) => /size_anomaly|count_anomaly/.test(error)));
  const unsafeSource = roles.some((role) => role.validation_result.errors.some((error) => /role_source_unsafe/.test(error)));
  const invalidRequired = roles.filter((role) => role.required && !role.valid);
  const invalidPresent = roles.filter((role) => role.available && !role.valid);
  const reasons = [];
  if (unsafeSource) reasons.push('workspace_baseline_role_source_unsafe');
  if (sizeAnomaly) reasons.push('workspace_baseline_role_size_anomaly');
  if (invalidRequired.length) reasons.push('workspace_baseline_required_role_invalid');
  else if (invalidPresent.length) reasons.push('workspace_baseline_optional_role_invalid');
  const complete = reasons.length === 0;
  const semanticIdentity = {
    recipe_id: RECIPE_ID,
    recipe_version: RECIPE_VERSION,
    workspace_id: String(context.workspaceId),
    repository_id: String(context.repoId),
    roles: roles.map((role) => ({
      role: role.role,
      required: role.required,
      source_policy: role.source_policy,
      source_fallback_allowed: role.source_fallback_allowed === true,
      projector_version: role.projector_version,
      projection_hash: role.projection_hash,
      valid: role.valid
    }))
  };
  const baselineHash = sha(stableBody(semanticIdentity));
  const estimatedTokens = roles.reduce((sum, role) => sum + role.estimated_tokens, 0);
  const payload = {
    schema_version: BASELINE_SCHEMA,
    recipe_schema_version: RECIPE_SCHEMA,
    generator: GENERATOR,
    canonical: true,
    recipe_id: RECIPE_ID,
    recipe_version: RECIPE_VERSION,
    workspace_id: String(context.workspaceId),
    repository_id: String(context.repoId),
    baseline_hash: baselineHash,
    complete,
    comparison_contract_valid: complete,
    claim_eligible: complete,
    claim_ineligible_reason: reasons[0] || null,
    claim_ineligible_reasons: reasons,
    roles,
    totals: {
      roles_total: roles.length,
      roles_available: roles.filter((role) => role.available).length,
      roles_valid: roles.filter((role) => role.valid).length,
      bytes: roles.reduce((sum, role) => sum + role.bytes, 0),
      estimated_tokens: estimatedTokens
    },
    identity: semanticIdentity,
    provenance: {
      source: 'built_in_versioned_workspace_recipe',
      arbitrary_file_lists_accepted: false,
      unknown_fields_included: false,
      actual_source_tree_included: false,
      role_source_precedence: Object.fromEntries(ROLE_RECIPE.map((item) => [item.role, { policy: item.source_policy, fallback_allowed: item.allow_fallback === true }]))
    }
  };
  return {
    complete,
    comparison_contract_valid: complete,
    reason: reasons[0] || null,
    reasons,
    baseline_hash: baselineHash,
    parsed: payload,
    measurement: {
      files: roles.filter((role) => role.valid).map((role) => ({
        role: role.role,
        path: role.source_artifact,
        sha256: role.projection_hash,
        bytes: role.bytes,
        estimated_tokens: role.estimated_tokens
      })),
      payload_hash: sha(stableBody(semanticIdentity)),
      schema_version: BASELINE_SCHEMA,
      estimated_tokens: estimatedTokens
    }
  };
}

module.exports = {
  BASELINE_SCHEMA,
  RECIPE_SCHEMA,
  RECIPE_ID,
  RECIPE_VERSION,
  GENERATOR,
  ROLE_RECIPE,
  LIMITS,
  buildWorkspaceBaseline,
  __test: {
    canonical,
    stableBody,
    projectIndexProjection,
    moduleRegistryProjection,
    trustProjection,
    repairProjection,
    handoffProjection,
    criticalPathsProjection,
    sourcePolicyProjection,
    concurrencyProjection,
    readRole
  }
};
