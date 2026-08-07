'use strict';

const path = require('path');
const { canonicalWikiStatus } = require('./wiki-status');

const ROUTING_MODES = new Set(['minimal', 'compact', 'full']);
const HIGH_RISK_TASKS = new Set(['security_review', 'migration', 'architecture_audit', 'incident_analysis']);
const RISK_STATUSES = new Set(['changed', 'missing', 'suspect', 'stale', 'needs_recheck', 'low_confidence']);
const DEFAULT_BUDGETS = Object.freeze({
  minimal: { bytes: 12 * 1024, estimated_tokens: 3072, module_cap: 5 },
  compact: { bytes: 64 * 1024, estimated_tokens: 16384, module_cap: 20 },
  full: { bytes: null, estimated_tokens: null, module_cap: null }
});

const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'in', 'into',
  'is', 'it', 'of', 'on', 'or', 'our', 'the', 'this', 'to', 'with', 'без', 'в',
  'для', 'и', 'из', 'на', 'по', 'при', 'с'
]);

function unique(values) {
  return Array.from(new Set((values || []).filter((value) => value !== null && value !== undefined && value !== '')));
}

function displayPath(value) {
  return String(value || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/\/+/g, '/');
}

function normalizePath(value) {
  return displayPath(value).toLowerCase();
}

function textValues(value, out = []) {
  if (value === null || value === undefined) return out;
  if (Array.isArray(value)) {
    for (const item of value) textValues(item, out);
    return out;
  }
  if (typeof value === 'object') {
    for (const item of Object.values(value)) textValues(item, out);
    return out;
  }
  out.push(String(value));
  return out;
}

function tokens(value) {
  return unique(
    String(value || '')
      .toLowerCase()
      .replace(/[^a-z0-9а-яё._/-]+/giu, ' ')
      .split(/\s+/)
      .map((token) => token.replace(/^[./_-]+|[./_-]+$/g, ''))
      .filter((token) => token.length >= 2 && !STOP_WORDS.has(token))
  );
}

function phraseMatch(haystack, needle) {
  const wanted = String(needle || '').trim().toLowerCase();
  if (!wanted) return false;
  return String(haystack || '').toLowerCase().includes(wanted);
}

function countMatches(wantedTokens, corpus) {
  const corpusTokens = new Set(tokens(corpus));
  return wantedTokens.filter((token) => corpusTokens.has(token) || String(corpus || '').toLowerCase().includes(token)).length;
}

function normalizeWikiStatus(wikiLint = {}, wikiGraph = {}) {
  return canonicalWikiStatus(wikiLint, wikiGraph);
}

function repoClass(size = {}) {
  const files = Number(size.files || 0);
  const bytes = Number(size.bytes || 0);
  if (files <= 100 && bytes <= 2 * 1024 * 1024) return 'XS';
  if (files <= 500 && bytes <= 15 * 1024 * 1024) return 'S';
  if (files <= 3000 && bytes <= 80 * 1024 * 1024) return 'M';
  if (files <= 15000 && bytes <= 400 * 1024 * 1024) return 'L';
  return 'XL';
}

function hasStem(taskTokens, stems) {
  return taskTokens.some((token) => stems.some((stem) => token === stem || token.startsWith(stem)));
}

function hasPhrase(value, phrases) {
  return phrases.some((phrase) => phraseMatch(value, phrase));
}

function securityIntent(value, taskTokens = tokens(value)) {
  return /\b(security|secure|vulnerabilit(?:y|ies)|cve|auth(?:entication|orization)?|credential|secret|threat|permission|access control|cryptograph(?:y|ic)|encrypt(?:ion|ed)?|xss|csrf|injection)\b/i.test(value) ||
    hasStem(taskTokens, [
      'безопасн', 'уязвим', 'аутентифик', 'авторизац', 'секрет',
      'угроз', 'инъекц', 'криптограф', 'шифрован', 'учетн', 'парол'
    ]);
}

function classifyTask(task) {
  const value = String(task || '').toLowerCase();
  const taskTokens = tokens(value);
  const auditLike = /\b(audit|review|analyse|analyze|assessment)\b/i.test(value) ||
    hasStem(taskTokens, ['аудит', 'ревью', 'обзор', 'анализ', 'оценк', 'проверк']);
  const repoWide = /\b(repo(?:sitory)?[- ]?wide|entire (?:repo|repository|codebase)|all modules)\b/i.test(value) ||
    hasPhrase(value, [
      'весь репозиторий',
      'всего репозитория',
      'по всему репозиторию',
      'вся кодовая база',
      'всей кодовой базы',
      'все модули',
      'всех модулей'
    ]);
  const crossModule = /\b(cross[- ]?(?:module|cutting)|repo[- ]?wide|repository[- ]?wide|entire (?:repo|repository|codebase)|all modules)\b/i.test(value) ||
    repoWide ||
    hasStem(taskTokens, ['межмодуль', 'сквозн']) ||
    hasPhrase(value, ['между модулями', 'несколько модулей', 'нескольких модулей']);
  const flags = {
    security: securityIntent(value, taskTokens),
    migration: /\b(migrat(?:e|ed|es|ing|ion|ions)|upgrad(?:e|ed|es|ing)|schema changes?|version transition)\b/i.test(value) ||
      hasStem(taskTokens, ['миграц', 'мигрир']) ||
      hasPhrase(value, ['обновление версии', 'переход на версию', 'изменение схемы']),
    architecture: (/\b(architecture|architectural)\b/i.test(value) ||
      hasStem(taskTokens, ['архитект'])) && auditLike,
    incident: /\b(incident|outage|postmortem|root cause|production failure|diagnostic)\b/i.test(value) ||
      hasStem(taskTokens, ['инцидент', 'авари', 'постморт', 'первопричин', 'диагност']) ||
      hasPhrase(value, ['сбой в продакшене', 'производственный сбой']),
    crossModule,
    refactor: /\brefactor\b/i.test(value) || hasStem(taskTokens, ['рефактор']),
    prReview: /\b(pull request|pr review|review (?:this )?pr|merge request)\b/i.test(value) ||
      ((taskTokens.includes('pr') || hasPhrase(value, ['pull request'])) &&
        hasStem(taskTokens, ['ревью', 'проверк', 'обзор'])),
    explicitFull: /\b(full context|unbounded context|load all modules|diagnostic flow)\b/i.test(value) ||
      hasPhrase(value, [
        'полный контекст',
        'без ограничений контекста',
        'загрузить все модули',
        'диагностический режим'
      ]),
    repoWideAudit: repoWide && auditLike
  };
  let type = 'simple_edit';
  if (flags.security) type = 'security_review';
  else if (flags.migration) type = 'migration';
  else if (flags.architecture) type = 'architecture_audit';
  else if (flags.incident) type = 'incident_analysis';
  else if (flags.crossModule && flags.refactor) type = 'cross_module_refactor';
  else if (flags.prReview) type = 'pr_review';
  return { type, flags, tokens: taskTokens, raw: String(task || '') };
}

function valuesArray(value) {
  return Array.isArray(value) ? value : [];
}

function moduleDependencies(moduleInfo) {
  return unique([
    ...valuesArray(moduleInfo.dependencies),
    ...valuesArray(moduleInfo.depends_on),
    ...valuesArray(moduleInfo.related_modules)
  ].map((item) => typeof item === 'string' ? item : (item?.module_id || item?.id)));
}

function moduleFiles(moduleInfo) {
  return unique([
    moduleInfo.path,
    moduleInfo.card,
    ...valuesArray(moduleInfo.key_files),
    ...valuesArray(moduleInfo.evidence_files),
    ...valuesArray(moduleInfo.start_with)
  ].map(normalizePath));
}

function pathTouchesModule(changedPath, moduleInfo) {
  const changed = normalizePath(changedPath);
  if (!changed) return false;
  const files = moduleFiles(moduleInfo);
  if (files.some((file) => file && (changed === file || changed.startsWith(`${file}/`) || file.startsWith(`${changed}/`)))) return true;
  const modulePath = normalizePath(moduleInfo.path);
  return Boolean(modulePath && modulePath !== '.' && changed.startsWith(modulePath));
}

function statusForModule(statusByModule, moduleInfo) {
  if (statusByModule instanceof Map) return statusByModule.get(moduleInfo.module_id) || {};
  return valuesArray(statusByModule).find((item) => item.module_id === moduleInfo.module_id) || {};
}

function trustBucketStatus(trustReport, moduleId) {
  for (const name of ['suspect', 'low_confidence', 'advisory_only', 'routing_trusted', 'near_trusted', 'trusted']) {
    if (valuesArray(trustReport?.modules?.[name]).includes(moduleId)) return name;
  }
  return null;
}

function criticalModuleIds(criticalPaths) {
  return new Set(valuesArray(criticalPaths?.paths).flatMap((item) => valuesArray(item.modules)));
}

function matchedCriticalPaths(criticalPaths, moduleId) {
  return valuesArray(criticalPaths?.paths)
    .filter((item) => valuesArray(item.modules).includes(moduleId))
    .map((item) => item.id || item.name || 'unnamed');
}

function currentChangedFiles(input) {
  const rows = [];
  for (const item of valuesArray(input.changedFiles)) {
    if (typeof item === 'string') rows.push({ path: item, status: 'changed', source: 'current_diff' });
    else if (item?.path) rows.push({ path: item.path, status: item.status || 'changed', source: item.source || 'current_diff' });
  }
  for (const item of valuesArray(input.freshness?.tracked_files)) {
    if (RISK_STATUSES.has(String(item.status || '').toLowerCase())) rows.push({ path: item.path, status: item.status, source: 'freshness' });
  }
  const statusPriority = new Map([
    ['changed', 1],
    ['stale', 2],
    ['low_confidence', 3],
    ['needs_recheck', 4],
    ['suspect', 5],
    ['missing', 6]
  ]);
  const sourcePriority = new Map([
    ['freshness', 1],
    ['current_diff', 2],
    ['explicit_scope', 3]
  ]);
  const byPath = new Map();
  for (const row of rows.filter((item) => item.path)) {
    const key = displayPath(row.path);
    if (!key) continue;
    const status = String(row.status || 'changed').toLowerCase();
    const source = String(row.source || 'current_diff');
    const current = byPath.get(key) || {
      path: key,
      status,
      source,
      statuses: [],
      sources: []
    };
    current.statuses = unique([...current.statuses, status]).sort();
    current.sources = unique([...current.sources, source]).sort();
    if ((statusPriority.get(status) || 0) > (statusPriority.get(current.status) || 0)) current.status = status;
    if ((sourcePriority.get(source) || 0) > (sourcePriority.get(current.source) || 0)) {
      current.source = source;
      current.path = key;
    }
    byPath.set(key, current);
  }
  return Array.from(byPath.values()).sort((a, b) =>
    normalizePath(a.path).localeCompare(normalizePath(b.path)) ||
    displayPath(a.path).localeCompare(displayPath(b.path))
  );
}

function routeMatches(taskInfo, taskRouting) {
  const matches = new Map();
  for (const route of valuesArray(taskRouting)) {
    const routeCorpus = textValues([route.route_id, route.keywords, route.description]).join(' ').toLowerCase();
    const matched = countMatches(taskInfo.tokens, routeCorpus);
    if (!matched && !phraseMatch(taskInfo.raw, route.route_id)) continue;
    for (const moduleId of valuesArray(route.target_modules)) {
      const reasons = matches.get(moduleId) || [];
      reasons.push(`task_route:${route.route_id || 'unnamed'}`);
      matches.set(moduleId, unique(reasons));
    }
  }
  return matches;
}

function openQueueRows(repairQueue) {
  return valuesArray(repairQueue?.queue || repairQueue?.items)
    .filter((item) => !['done', 'closed', 'resolved', 'superseded'].includes(String(item.status || item.state || 'open').toLowerCase()));
}

function matchingFailureRows(moduleInfo, quality, repairQueue) {
  const all = [...valuesArray(quality?.issues), ...openQueueRows(repairQueue)];
  return all.filter((item) => {
    if (item.module_id && item.module_id === moduleInfo.module_id) return true;
    const artifact = item.artifact || item.path;
    return artifact && pathTouchesModule(artifact, moduleInfo);
  });
}

function moduleCorpus(moduleInfo) {
  return textValues([
    moduleInfo.module_id,
    moduleInfo.name,
    moduleInfo.path,
    moduleInfo.card,
    moduleInfo.purpose,
    moduleInfo.summary,
    moduleInfo.description,
    moduleInfo.keywords,
    moduleInfo.tags,
    moduleInfo.key_files,
    moduleInfo.evidence_files
  ]).join(' ').toLowerCase();
}

function baseCandidates(input, taskInfo) {
  const changed = Array.isArray(input.resolvedChangedFiles)
    ? input.resolvedChangedFiles
    : currentChangedFiles(input);
  const criticalIds = criticalModuleIds(input.criticalPaths);
  const routed = routeMatches(taskInfo, input.taskRouting);
  return valuesArray(input.registry?.modules).map((moduleInfo) => {
    const status = statusForModule(input.statusByModule || input.trustReport?.module_statuses, moduleInfo);
    const trustStatus = status.trust_status || trustBucketStatus(input.trustReport, moduleInfo.module_id) || moduleInfo.current_trust_level || 'unknown';
    const freshnessStatus = String(status.freshness_status || moduleInfo.freshness_status || 'unknown').toLowerCase();
    const confidence = String(status.confidence || moduleInfo.confidence || 'unknown').toLowerCase();
    const corpus = moduleCorpus(moduleInfo);
    const reasons = [];
    let score = 1;

    const explicitScope = phraseMatch(taskInfo.raw, moduleInfo.module_id) ||
      (normalizePath(moduleInfo.path).length > 2 && phraseMatch(taskInfo.raw, normalizePath(moduleInfo.path)));
    if (explicitScope) { score += 80; reasons.push('explicit_scope'); }

    const taskMatches = countMatches(taskInfo.tokens, corpus);
    if (taskMatches > 0) {
      score += Math.min(42, taskMatches * 7);
      reasons.push(`task_text:${taskMatches}`);
    }

    for (const reason of routed.get(moduleInfo.module_id) || []) {
      score += 55;
      reasons.push(reason);
    }

    const changedRows = changed.filter((item) => pathTouchesModule(item.path, moduleInfo));
    if (changedRows.length) {
      score += 45 + Math.min(20, (changedRows.length - 1) * 4);
      reasons.push(`changed_files:${changedRows.length}`);
    }

    const suspect = trustStatus === 'suspect' || valuesArray(input.trustReport?.modules?.suspect).includes(moduleInfo.module_id);
    const lowConfidence = trustStatus === 'low_confidence' || confidence === 'low' ||
      valuesArray(input.trustReport?.modules?.low_confidence).includes(moduleInfo.module_id);
    const stale = ['stale', 'needs_recheck', 'missing', 'suspect'].includes(freshnessStatus);
    if (suspect) { score += 60; reasons.push('suspect'); }
    if (lowConfidence) { score += 50; reasons.push('low_confidence'); }
    if (stale) { score += 40; reasons.push(`freshness:${freshnessStatus}`); }

    const criticalPaths = matchedCriticalPaths(input.criticalPaths, moduleInfo.module_id);
    const critical = criticalIds.has(moduleInfo.module_id) || moduleInfo.critical === true ||
      moduleInfo.critical_path === true ||
      String(moduleInfo.criticality || '').toLowerCase() === 'critical' ||
      String(moduleInfo.zone_importance || '').toLowerCase() === 'critical';
    if (critical) {
      score += 38;
      reasons.push(`critical_path:${criticalPaths.join(',') || 'declared'}`);
    }

    const securitySensitive = moduleInfo.security_sensitive === true ||
      /\b(security|auth|credential|secret|permission|policy|crypto|token)\b/i.test(corpus) ||
      securityIntent(corpus);
    if (securitySensitive && taskInfo.flags.security) {
      score += 65;
      reasons.push('security_sensitive');
    } else if (securitySensitive) {
      score += 8;
      reasons.push('security_surface');
    }

    const contradictions = valuesArray(status.reasons?.open_contradictions).length +
      Number(status.open_contradictions_total || 0) +
      Number(moduleInfo.open_contradictions_total || 0);
    if (contradictions > 0) {
      score += 70;
      reasons.push(`open_contradictions:${contradictions}`);
    }

    const failures = matchingFailureRows(moduleInfo, input.quality, input.repairQueue);
    if (failures.length) {
      score += 32 + Math.min(18, (failures.length - 1) * 3);
      reasons.push(`recent_failure_evidence:${failures.length}`);
    }

    if (taskInfo.flags.prReview && changedRows.length) {
      score += 25;
      reasons.push('pr_impact');
    }

    const relevant = explicitScope || taskMatches > 0 || routed.has(moduleInfo.module_id) ||
      changedRows.length > 0 || failures.length > 0 || contradictions > 0 ||
      (taskInfo.flags.security && securitySensitive);
    const highRisk = changedRows.length > 0 || suspect || lowConfidence || stale || critical ||
      contradictions > 0 || failures.length > 0 || (taskInfo.flags.security && securitySensitive);
    const required = contradictions > 0 || (suspect && critical) ||
      (taskInfo.flags.security && securitySensitive) || (relevant && highRisk);
    const publicRow = {
      module_id: moduleInfo.module_id,
      path: moduleInfo.path,
      card: moduleInfo.card,
      confidence: status.confidence || moduleInfo.confidence || 'unknown',
      trust_status: trustStatus,
      freshness_status: status.freshness_status || moduleInfo.freshness_status || 'unknown',
      start_with: unique([moduleInfo.card, ...valuesArray(moduleInfo.key_files), ...valuesArray(moduleInfo.evidence_files)]).slice(0, 8),
      reasons: status.reasons || {},
      routing_score: score,
      selection_reasons: unique(reasons)
    };
    return {
      module_id: moduleInfo.module_id,
      moduleInfo,
      publicRow,
      score,
      reasons: unique(reasons),
      relevant,
      high_risk: highRisk,
      required,
      dependencies: moduleDependencies(moduleInfo),
      flags: {
        changed: changedRows.length > 0,
        suspect,
        stale,
        low_confidence: lowConfidence,
        critical_path: critical,
        security_sensitive: securitySensitive,
        contradiction: contradictions > 0,
        recent_failure: failures.length > 0
      },
      changed_files: changedRows.map((item) => ({
        path: item.path,
        status: item.status,
        source: item.source,
        statuses: item.statuses || [item.status],
        sources: item.sources || [item.source]
      })),
      estimated_bytes: Buffer.byteLength(JSON.stringify(publicRow), 'utf8')
    };
  });
}

function addDependencyDistance(candidates) {
  const byId = new Map(candidates.map((item) => [item.module_id, item]));
  const adjacency = new Map(candidates.map((item) => [item.module_id, new Set()]));
  for (const candidate of candidates) {
    for (const dependency of candidate.dependencies) {
      if (!byId.has(dependency)) continue;
      adjacency.get(candidate.module_id).add(dependency);
      adjacency.get(dependency).add(candidate.module_id);
    }
  }
  const seeds = candidates.filter((item) => item.relevant || item.flags.changed).map((item) => item.module_id);
  const distances = new Map(seeds.map((id) => [id, 0]));
  const queue = [...seeds];
  while (queue.length) {
    const current = queue.shift();
    const distance = distances.get(current);
    for (const next of adjacency.get(current) || []) {
      if (distances.has(next)) continue;
      distances.set(next, distance + 1);
      queue.push(next);
    }
  }
  for (const candidate of candidates) {
    const distance = distances.get(candidate.module_id);
    if (!Number.isInteger(distance) || distance === 0 || distance > 3) continue;
    const boost = 18 - ((distance - 1) * 5);
    candidate.score += boost;
    candidate.publicRow.routing_score = candidate.score;
    candidate.reasons.push(`dependency_distance:${distance}`);
    candidate.publicRow.selection_reasons = unique(candidate.reasons);
    candidate.relevant = true;
    if (candidate.high_risk) candidate.required = true;
  }
  return candidates;
}

function rankCandidates(candidates) {
  return [...candidates].sort((a, b) => (
    Number(b.required) - Number(a.required) ||
    Number(b.high_risk) - Number(a.high_risk) ||
    b.score - a.score ||
    String(a.module_id).localeCompare(String(b.module_id))
  ));
}

function modeDecision(input, candidates, taskInfo, wikiStatus) {
  const requested = input.override ? String(input.override).toLowerCase() : null;
  if (requested && !ROUTING_MODES.has(requested)) {
    throw new Error(`Invalid routing mode '${requested}'. Expected minimal, compact, or full.`);
  }
  const safetyOverrides = [];
  const risk = {
    high_risk_task: HIGH_RISK_TASKS.has(taskInfo.type),
    suspect_critical: candidates.some((item) => item.flags.suspect && item.flags.critical_path),
    unresolved_contradiction: candidates.some((item) => item.flags.contradiction),
    touched_critical_path: candidates.some((item) => item.flags.changed && item.flags.critical_path),
    warning_graph: wikiStatus === 'usable_with_warnings'
  };

  if (wikiStatus === 'structurally_broken') {
    safetyOverrides.push('structurally_broken_graph');
    return { mode: 'full', reason: 'safety_structurally_broken_graph', requested, selection: 'safety_override', safetyOverrides, risk };
  }
  if (requested === 'full') {
    return { mode: 'full', reason: 'manual_full_override', requested, selection: 'manual', safetyOverrides, risk };
  }
  const fullReason =
    taskInfo.flags.explicitFull ? 'explicit_task_full_context' :
    (taskInfo.flags.repoWideAudit || taskInfo.type === 'architecture_audit') ? 'repo_wide_audit' :
    (taskInfo.flags.migration && taskInfo.flags.crossModule) ? 'cross_cutting_migration' :
    taskInfo.type === 'incident_analysis' ? 'diagnostic_flow' :
    null;
  if (fullReason) {
    return { mode: 'full', reason: `safety_${fullReason}`, requested, selection: 'safety_override', safetyOverrides: [fullReason], risk };
  }

  const requiresCompact = risk.high_risk_task || risk.suspect_critical || risk.unresolved_contradiction ||
    risk.touched_critical_path || risk.warning_graph;
  if (requested === 'compact') {
    return { mode: 'compact', reason: 'manual_compact_override', requested, selection: 'manual', safetyOverrides, risk };
  }
  if (requested === 'minimal' && requiresCompact) {
    for (const [key, value] of Object.entries(risk)) if (value) safetyOverrides.push(key);
    return { mode: 'compact', reason: 'safety_escalated_manual_minimal', requested, selection: 'safety_override', safetyOverrides, risk };
  }
  if (requested === 'minimal') {
    return { mode: 'minimal', reason: 'manual_minimal_override', requested, selection: 'manual', safetyOverrides, risk };
  }
  if (requiresCompact) {
    for (const [key, value] of Object.entries(risk)) if (value) safetyOverrides.push(key);
    return { mode: 'compact', reason: 'auto_safety_compact', requested, selection: 'safety_override', safetyOverrides, risk };
  }
  const sizeClass = repoClass(input.size);
  if (sizeClass === 'XS' || sizeClass === 'S') {
    return { mode: 'minimal', reason: `auto_${sizeClass.toLowerCase()}_low_risk_minimal`, requested, selection: 'auto', safetyOverrides, risk };
  }
  return { mode: 'compact', reason: `auto_${sizeClass.toLowerCase()}_bounded_compact`, requested, selection: 'auto', safetyOverrides, risk };
}

function budgetFor(mode, value) {
  const defaults = DEFAULT_BUDGETS[mode];
  if (mode === 'full') return { ...defaults };
  const numeric = Number(value);
  const bytes = Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : defaults.bytes;
  return {
    bytes,
    estimated_tokens: Math.ceil(bytes / 4),
    module_cap: defaults.module_cap
  };
}

function selectCandidates(candidates, mode, budget) {
  const ranked = rankCandidates(candidates);
  if (mode === 'full') {
    return {
      selected: ranked.map((item) => ({
        ...item,
        publicRow: {
          ...item.publicRow,
          selection_reasons: unique([...item.reasons, 'full_mode'])
        }
      })),
      excluded: [],
      selectedBytes: ranked.reduce((total, item) => total + item.estimated_bytes, 0),
      fallback: ranked.some((item) => item.relevant) ? 'not_needed' : 'full_mode_all_modules',
      truncationReason: 'not_truncated'
    };
  }

  const hasRelevant = ranked.some((item) => item.relevant);
  const selected = [];
  const selectedIds = new Set();
  let selectedBytes = 0;
  let overrun = false;
  const add = (item, reason) => {
    if (selectedIds.has(item.module_id)) return;
    const next = {
      ...item,
      publicRow: {
        ...item.publicRow,
        selection_reasons: unique([...item.reasons, reason].filter(Boolean))
      }
    };
    selected.push(next);
    selectedIds.add(item.module_id);
    selectedBytes += item.estimated_bytes;
  };

  for (const item of ranked.filter((candidate) => candidate.required)) {
    if (selected.length >= budget.module_cap || selectedBytes + item.estimated_bytes > budget.bytes) overrun = true;
    add(item, 'safety_required');
  }

  const pool = hasRelevant
    ? ranked
    : rankCandidates(ranked.map((item) => ({
      ...item,
      score: item.score + (item.high_risk ? 25 : 0)
    })));
  for (const item of pool) {
    if (selectedIds.has(item.module_id)) continue;
    if (selected.length >= budget.module_cap) continue;
    if (selectedBytes + item.estimated_bytes > budget.bytes) continue;
    add(item, hasRelevant ? null : 'fallback:no_relevant_module');
  }

  if (selected.length === 0 && ranked.length > 0) {
    overrun = ranked[0].estimated_bytes > budget.bytes;
    add(ranked[0], hasRelevant ? 'single_candidate_fallback' : 'fallback:no_relevant_module');
  }

  // Fail closed if future scoring changes would otherwise omit a relevant
  // high-risk module. Budget is advisory for safety-required context.
  for (const item of ranked.filter((candidate) => candidate.relevant && candidate.high_risk)) {
    if (selectedIds.has(item.module_id)) continue;
    overrun = true;
    add(item, 'acceptance_invariant:relevant_high_risk');
  }

  const excluded = ranked.filter((item) => !selectedIds.has(item.module_id));
  const budgetExcluded = excluded.some((item) => selectedBytes + item.estimated_bytes > budget.bytes);
  const capExcluded = excluded.length > 0 && selected.length >= budget.module_cap;
  const truncation = [];
  if (overrun) truncation.push('safety_budget_overrun');
  if (budgetExcluded) truncation.push('context_budget_exhausted');
  if (capExcluded) truncation.push('module_cap_reached');
  if (!excluded.length) truncation.push('not_truncated');
  return {
    selected,
    excluded,
    selectedBytes,
    fallback: hasRelevant ? 'not_needed' : 'ranked_high_risk_then_stable_tiebreak',
    truncationReason: truncation.join('+') || 'ranked_truncation'
  };
}

function buildRoutingDecision(input) {
  const task = classifyTask(input.task);
  const wikiStatus = normalizeWikiStatus(input.wikiLint, input.wikiGraph);
  const changedFiles = currentChangedFiles(input);
  const candidates = addDependencyDistance(baseCandidates({ ...input, resolvedChangedFiles: changedFiles }, task));
  const mode = modeDecision(input, candidates, task, wikiStatus);
  const budget = budgetFor(mode.mode, input.contextBudgetBytes);
  const selection = selectCandidates(candidates, mode.mode, budget);
  const selectedIds = new Set(selection.selected.map((item) => item.module_id));
  const excludedHighRisk = selection.excluded
    .filter((item) => item.high_risk)
    .map((item) => ({
      module_id: item.module_id,
      score: item.score,
      relevant: item.relevant,
      reason: item.relevant
        ? 'invariant_violation_relevant_high_risk'
        : 'not_relevant_to_task_after_safety_ranking'
    }));
  const omittedRelevantHighRisk = candidates.filter((item) => item.relevant && item.high_risk && !selectedIds.has(item.module_id));
  if (omittedRelevantHighRisk.length) {
    throw new Error(`Routing safety invariant failed: omitted relevant high-risk modules: ${omittedRelevantHighRisk.map((item) => item.module_id).join(', ')}`);
  }

  const candidateRows = rankCandidates(candidates).map((item) => ({
    module_id: item.module_id,
    score: item.score,
    relevant: item.relevant,
    high_risk: item.high_risk,
    safety_required: item.required,
    selected: selectedIds.has(item.module_id),
    estimated_bytes: item.estimated_bytes,
    reasons: item.reasons,
    flags: item.flags,
    changed_files: item.changed_files
  }));
  return {
    schema_version: 'adaptive-routing-decision.v2',
    mode: mode.mode,
    selection: mode.selection,
    reason: mode.reason,
    requested_mode: mode.requested,
    task: { type: task.type, input: task.raw || null, flags: task.flags },
    wiki_status: wikiStatus,
    safety_overrides: mode.safetyOverrides,
    risk: mode.risk,
    changed_files: changedFiles,
    context_budget: {
      ...budget,
      selected_bytes: selection.selectedBytes,
      selected_estimated_tokens: Math.ceil(selection.selectedBytes / 4),
      safety_overrun: selection.selectedBytes > (budget.bytes ?? Number.POSITIVE_INFINITY)
    },
    candidate_modules: candidateRows,
    selected_modules: selection.selected.map((item) => item.module_id),
    excluded_high_risk_modules: excludedHighRisk,
    omitted_relevant_high_risk_modules: omittedRelevantHighRisk.map((item) => item.module_id),
    truncation_reason: selection.truncationReason,
    fallback_behavior: selection.fallback,
    selected: selection.selected,
    excluded: selection.excluded
  };
}

function filterCriticalPaths(paths, selectedIds, mode) {
  const rows = valuesArray(paths);
  if (mode === 'full') return rows;
  return rows.filter((item) => valuesArray(item.modules).some((moduleId) => selectedIds.has(moduleId)));
}

function filterTaskRoutes(routes, selectedIds, mode, task) {
  const rows = valuesArray(routes);
  if (mode === 'full') return rows;
  const taskTokens = tokens(task);
  return rows.filter((item) => (
    valuesArray(item.target_modules).some((moduleId) => selectedIds.has(moduleId)) ||
    countMatches(taskTokens, textValues([item.route_id, item.keywords, item.description]).join(' ')) > 0
  ));
}

module.exports = {
  ROUTING_MODES,
  DEFAULT_BUDGETS,
  displayPath,
  normalizePath,
  normalizeWikiStatus,
  repoClass,
  classifyTask,
  buildRoutingDecision,
  filterCriticalPaths,
  filterTaskRoutes,
  __test: {
    tokens,
    securityIntent,
    currentChangedFiles,
    pathTouchesModule,
    baseCandidates,
    addDependencyDistance,
    modeDecision,
    selectCandidates,
    budgetFor,
    rankCandidates
  }
};
