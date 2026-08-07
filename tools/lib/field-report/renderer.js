'use strict';

const { formatTaskRoutingEstimate } = require('../routing-estimate-formatter');

const {
  DEFAULT_SCHEMA,
  humanValue,
  translationRequired,
  unwrap
} = require('./contract');
const {
  redactAnswers,
  scanEnglishLanguage,
  scanPublication
} = require('./redactor');

const SECTION_ORDER = Object.freeze([
  'Setup and workflow fit',
  'Real test scenario',
  'Accuracy and response speed',
  'Observed results and limitations',
  'What did not work',
  'Comparison with the previous workflow',
  'Final assessment',
  'Supporting material',
  'Publication permission'
]);

const REPORT_RELATIONSHIPS = Object.freeze({
  first_party_maintainer: {
    title: 'First-party maintainer dogfooding',
    disclosure:
      'This is a first-party maintainer dogfooding report. It documents a real ' +
      'repository workflow, but it is not an independent customer testimonial or a ' +
      'controlled model-performance study.'
  },
  independent_user: {
    title: 'Independent user report',
    disclosure:
      'The tester identified this as an independent user report. The workflow records ' +
      'the tester\'s observations; `.knowledge` does not independently verify affiliation ' +
      'or every claimed outcome.'
  },
  internal_qa: {
    title: 'Internal QA report',
    disclosure:
      'This is an internal QA report. It documents a real validation workflow, not an ' +
      'independent customer testimonial.'
  },
  controlled_comparison: {
    title: 'Controlled comparison',
    disclosure:
      'This report is part of a controlled comparison. Only outcomes backed by the ' +
      'stated method and attached evidence should be treated as comparative claims.'
  }
});

function empty(value) {
  const unwrapped = unwrap(value);
  return unwrapped === undefined || unwrapped === null ||
    (typeof unwrapped === 'string' && unwrapped.trim() === '');
}

function displayValue(value) {
  if (Array.isArray(value)) return value.join(', ');
  if (value && typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function answerLine(label, value) {
  if (empty(value)) return '';
  const text = displayValue(value);
  return text.includes('\n')
    ? `**${label}:**\n\n${text.trim()}\n\n`
    : `**${label}:** ${text.trim()}\n\n`;
}

function speedMetric(answers) {
  const basis = unwrap(answers['response-speed-basis']);
  const baseline = Number(unwrap(answers['baseline-duration-ms']));
  const knowledge = Number(unwrap(answers['knowledge-duration-ms']));
  if (basis === 'measured' && baseline > 0 && knowledge >= 0) {
    return {
      value: ((baseline - knowledge) / baseline) * 100,
      unit: 'percent',
      kind: 'derived',
      method: 'paired_duration_change_v2',
      inputs: {
        baseline_duration_ms: baseline,
        knowledge_duration_ms: knowledge
      }
    };
  }
  const percent = unwrap(answers['response-speed-percent']);
  if (!empty(percent) && Number.isFinite(Number(percent))) {
    return {
      value: Number(percent),
      unit: 'percent',
      kind: basis === 'estimated_from_comparable_tasks'
        ? 'tester_estimate'
        : 'tester_observation',
      method: 'tester_supplied_signed_percent_v2'
    };
  }
  return null;
}

function factItem(facts, id) {
  return facts?.values?.[id] || null;
}

function factValue(facts, id) {
  const item = factItem(facts, id);
  return item && item.kind !== 'unavailable' ? item.value : null;
}

function firstAvailableFact(facts, ids) {
  for (const id of ids) {
    const value = factValue(facts, id);
    if (value !== null && value !== undefined && value !== '') return { id, value };
  }
  return { id: null, value: null };
}

function normalizeCount(value) {
  if (value === null || value === undefined || value === '') return null;
  const count = Number(value);
  return Number.isInteger(count) && count >= 0 ? count : null;
}

function normalizeNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function countLabel(value, singular, plural = `${singular}s`) {
  const count = normalizeCount(value);
  if (count === null) return `an unavailable number of ${plural}`;
  return `${count} ${count === 1 ? singular : plural}`;
}

function humanStatus(value) {
  const text = String(value || '').trim();
  if (!text) return '';
  const normalized = text.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function formatBytes(value) {
  const bytes = normalizeNumber(value);
  if (bytes === null || bytes < 0) return 'Unavailable';
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let current = bytes / 1024;
  let index = 0;
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024;
    index += 1;
  }
  const precision = current >= 100 ? 0 : current >= 10 ? 1 : 2;
  return `${Number(current.toFixed(precision))} ${units[index]}`;
}

function taskScopeText(facts) {
  const routingBound = factValue(facts, 'routing_task_bound_to_report') === true;
  if (!routingBound) return 'No explicit task-routing snapshot was bound to this report.';
  const modulesSelected = normalizeCount(factValue(facts, 'modules_selected'));
  const pathsSelected = normalizeCount(factValue(facts, 'paths_selected'));
  const parts = [];
  if (modulesSelected !== null) parts.push(countLabel(modulesSelected, 'selected module'));
  if (pathsSelected !== null) parts.push(countLabel(pathsSelected, 'selected path'));
  return parts.length
    ? `The task was explicitly scoped to ${parts.join(' and ')}.`
    : 'An explicit task-routing snapshot was bound, but selection counts were unavailable.';
}

function scopeDisclosure(facts) {
  const mode = String(factValue(facts, 'mode') || '').trim().toLowerCase();
  const explicitKind = factValue(facts, 'workspace_scope_kind');
  const scopeKind = explicitKind || (mode === 'repo'
    ? 'standalone_repository'
    : mode === 'team' ? 'team_workspace_unknown' : 'workspace_scope_unknown');
  const repositoriesTotal = normalizeCount(
    factValue(facts, 'workspace_repositories_total') ??
      factValue(facts, 'workspace_projects_total')
  );
  const modulesTotal = normalizeCount(
    factValue(facts, 'functional_modules_total') ?? factValue(facts, 'modules_total')
  );
  const moduleDescription = modulesTotal !== null
    ? countLabel(modulesTotal, 'functional module')
    : null;
  const scoped = taskScopeText(facts);

  if (scopeKind === 'standalone_repository') {
    return `This standalone repository${moduleDescription ? ` contained ${moduleDescription}` : ''}. ${scoped}`;
  }
  if (scopeKind === 'multi_repository_workspace') {
    const repositories = repositoriesTotal !== null
      ? countLabel(repositoriesTotal, 'repository', 'repositories')
      : 'multiple repositories';
    return `This team workspace registered ${repositories}. ` +
      `${moduleDescription ? `The current repository contained ${moduleDescription}. ` : ''}${scoped}`;
  }
  if (scopeKind === 'single_repository_team_workspace') {
    return 'This team workspace registered one repository. ' +
      `${moduleDescription ? `The current repository contained ${moduleDescription}. ` : ''}${scoped}`;
  }
  if (scopeKind === 'team_workspace_unknown') {
    return 'Repository count for this team workspace was unavailable. ' +
      `${moduleDescription ? `The current repository contained ${moduleDescription}. ` : ''}${scoped}`;
  }
  return 'Repository scope was unavailable. ' +
    `${moduleDescription ? `The current repository contained ${moduleDescription}. ` : ''}${scoped}`;
}

function truncateDiscussionTitle(value, maximum = 96) {
  const normalized = String(value || '').replace(/\s+/g, ' ').trim();
  if (!Number.isInteger(maximum) || maximum < 2) {
    throw new Error('Discussion title maximum must be an integer of at least 2.');
  }
  const characters = Array.from(normalized);
  if (characters.length <= maximum) return normalized;
  const room = maximum - 1;
  const candidate = characters.slice(0, room).join('');
  const boundary = candidate.lastIndexOf(' ');
  const body = (boundary > 0 ? candidate.slice(0, boundary) : candidate).trimEnd();
  return `${body || candidate}…`;
}

function markdownTableValue(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function relationshipDefinition(answers) {
  const id = String(unwrap(answers['report-relationship']) || '').trim();
  return REPORT_RELATIONSHIPS[id] || {
    title: 'Field report',
    disclosure:
      'The tester relationship was unavailable. Publication should remain blocked until ' +
      'the report type is explicitly selected.'
  };
}

function relationshipDisclosure(answers) {
  return relationshipDefinition(answers).disclosure;
}

function releaseIdentity(facts) {
  const version = factValue(facts, 'knowledge_version');
  const channel = factValue(facts, 'knowledge_release_channel');
  const candidateLabel = factValue(facts, 'knowledge_candidate_label');
  const candidateName = factValue(facts, 'knowledge_candidate_name');
  const parts = [];
  if (version !== null) parts.push(String(version));
  if (candidateLabel !== null) parts.push(String(candidateLabel));
  const display = parts.length ? parts.join(' ') : 'Unavailable';
  return { version, channel, candidateLabel, candidateName, display };
}

const CLAIM_TEXT_FIELDS = Object.freeze([
  'project-context', 'quick-summary', 'workflow-notes', 'main-scenario',
  'accuracy-example', 'response-speed-notes', 'useful-parts', 'observed-results',
  'what-did-not-work', 'previous-workflow-comparison', 'final-assessment'
]);

function claimTextEntries(answers) {
  return CLAIM_TEXT_FIELDS
    .map((field) => [field, unwrap(answers[field])])
    .filter(([, value]) => typeof value === 'string' && value.trim());
}

function negatedClaim(text, index) {
  const prefix = text.slice(Math.max(0, index - 64), index).toLowerCase();
  return /(?:\bno\b|\bnot\b|without|unconfirmed|unavailable|not enough|did not|does not|cannot|can't|wasn't|isn't|never)\s*$/.test(prefix) ||
    /(?:no|not|without|unconfirmed|unavailable|not enough|did not|does not|cannot|can't|wasn't|isn't|never)[^.!?]{0,42}$/.test(prefix);
}

function findPositiveClaims(field, text, patterns, rule, reason) {
  const findings = [];
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(text)) !== null) {
      if (!negatedClaim(text, match.index)) {
        findings.push({
          field,
          rule,
          severity: 'high',
          reason,
          excerpt: match[0].slice(0, 180)
        });
      }
      if (!pattern.global) break;
    }
  }
  return findings;
}

function claimSafetyFindings(facts, answers) {
  const findings = [];
  const taskRows = factValue(facts, 'task_verification_results');
  const taskEntries = Array.isArray(taskRows)
    ? taskRows.flatMap((row) => [
      [`task-results:${row.id || 'row'}:summary`, row.public_summary],
      [`task-results:${row.id || 'row'}:interpretation`, row.interpretation]
    ]).filter(([, value]) => typeof value === 'string' && value.trim())
    : [];
  const taskTitle = factValue(facts, 'task_result_title');
  const taskSummary = factValue(facts, 'task_result_summary');
  if (typeof taskTitle === 'string' && taskTitle.trim()) taskEntries.push(['task-results:task:title', taskTitle]);
  if (typeof taskSummary === 'string' && taskSummary.trim()) taskEntries.push(['task-results:task:summary', taskSummary]);
  const entries = [...claimTextEntries(answers), ...taskEntries];
  const routingBound = factValue(facts, 'routing_task_bound_to_report') === true;
  const routingClaimEligible = factValue(facts, 'routing_claim_eligible') === true;
  const accuracyChange = String(unwrap(answers['accuracy-change']) || '');
  const speedChange = String(unwrap(answers['response-speed-change']) || '');
  const identity = releaseIdentity(facts);

  const routingEffectPatterns = [
    /(?:\.knowledge|\bthe system\b|\bthe workflow\b)\s+(?:limited|constrained|reduced|narrowed|restricted)\s+(?:the\s+)?(?:scope|context|files?|paths?)\b/gi,
    /\brouting\s+(?:limited|constrained|reduced|narrowed|selected|excluded)\b/gi
  ];
  const routingUsagePatterns = [
    /(?:\.knowledge|\bthe system\b|\bthe workflow\b)\s+(?:added|provided|used)\s+routing\b/gi
  ];
  if (!routingBound) {
    for (const [field, text] of entries) {
      findings.push(...findPositiveClaims(
        field,
        text,
        [...routingEffectPatterns, ...routingUsagePatterns],
        'unsupported_routing_claim',
        'No explicit task-routing snapshot was bound to this report.'
      ));
    }
  } else if (!routingClaimEligible) {
    for (const [field, text] of entries) {
      findings.push(...findPositiveClaims(
        field,
        text,
        routingEffectPatterns,
        'ineligible_routing_effect_claim',
        'A task-routing snapshot was bound, but its workspace comparison was not claim-eligible.'
      ));
    }
  }

  const tokenPatterns = [
    /\b(?:saved|reduced|cut|lowered)\s+(?:about\s+|approximately\s+)?(?:\d+(?:\.\d+)?%?\s+)?(?:of\s+)?(?:input\s+|model\s+)?tokens?\b/gi,
    /\btoken\s+savings?\b/gi,
    /\b(?:reduced|lower|lowered|cut)\s+(?:api\s+)?costs?\b/gi,
    /\bcost\s+savings?\b/gi
  ];
  for (const [field, text] of entries) {
    findings.push(...findPositiveClaims(
      field,
      text,
      tokenPatterns,
      'unsupported_provider_usage_claim',
      'No provider-reported usage receipt is bound to the Field Report.'
    ));
  }

  if (['not_enough_evidence', 'no_clear_change', 'became_worse'].includes(accuracyChange)) {
    const patterns = [
      /\b(?:improved|increased|raised)\s+(?:model\s+|task\s+)?(?:accuracy|precision|correctness)\b/gi,
      /\b(?:made|was|became|is)\s+[^.!?]{0,36}\b(?:more accurate|more precise|more correct)\b/gi,
      /\b(?:reduced|lowered|prevented)\s+(?:agent\s+)?(?:errors?|mistakes?|hallucinations?)\b/gi
    ];
    for (const [field, text] of entries) {
      findings.push(...findPositiveClaims(
        field,
        text,
        patterns,
        'unsupported_accuracy_claim',
        `The selected accuracy result is ${accuracyChange || 'unavailable'}.`
      ));
    }
  }

  if (['not_enough_data', 'no_clear_change', 'slightly_slower', 'much_slower'].includes(speedChange)) {
    const patterns = [
      /\b(?:made|was|became|is)\s+[^.!?]{0,36}\b(?:faster|quicker)\b/gi,
      /\b(?:improved|increased)\s+(?:agent\s+|task\s+)?speed\b/gi,
      /\b(?:reduced|lowered|cut)\s+(?:completion\s+time|latency|response\s+time)\b/gi
    ];
    for (const [field, text] of entries) {
      findings.push(...findPositiveClaims(
        field,
        text,
        patterns,
        'unsupported_speed_claim',
        `The selected speed result is ${speedChange || 'unavailable'}.`
      ));
    }
  }

  const publicationPermission = String(unwrap(answers['github-publication-permission']) || '');
  const structuredTaskRows = factValue(facts, 'task_verification_results');
  if (publicationPermission === 'github_publication_allowed' &&
      (!Array.isArray(structuredTaskRows) || structuredTaskRows.filter((row) => row?.public !== false).length === 0)) {
    findings.push({
      field: 'github-publication-permission',
      rule: 'structured_task_results_required',
      severity: 'high',
      reason: 'GitHub publication approval requires a structured task-result summary with content-addressed evidence.',
      excerpt: 'task-results.json missing or empty'
    });
  }
  const snapshotStatus = String(factValue(facts, 'repository_snapshot_status') || '');
  if (publicationPermission === 'github_publication_allowed' && snapshotStatus.startsWith('dirty_')) {
    findings.push({
      field: 'github-publication-permission',
      rule: 'dirty_final_snapshot_publication',
      severity: 'high',
      reason: 'GitHub publication approval requires facts collected from a clean final Git working tree.',
      excerpt: snapshotStatus
    });
  }

  const repairTelemetryStatus = String(factValue(facts, 'repair_telemetry_status') || '');
  if (repairTelemetryStatus && repairTelemetryStatus !== 'current') {
    const patterns = [
      /(?:repair-on-touch|\.knowledge)\s+(?:fixed|repaired|closed|resolved)\b/gi,
      /\b(?:repair-on-touch)\s+(?:improved|reduced|eliminated)\b/gi
    ];
    for (const [field, text] of entries) {
      findings.push(...findPositiveClaims(
        field,
        text,
        patterns,
        'unsupported_repair_effect_claim',
        `Repair-on-touch telemetry status is ${repairTelemetryStatus}; no repair effect is verified.`
      ));
    }
  }

  if (identity.candidateLabel) {
    for (const [field, text] of entries) {
      const pattern = /\bRC\s*([1-9][0-9]*)\b/gi;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const mentioned = `RC${match[1]}`;
        if (mentioned === identity.candidateLabel) continue;
        const prefix = text.slice(Math.max(0, match.index - 36), match.index).toLowerCase();
        if (/(?:from|previous|prior|baseline|historical|before|upgraded\s+from)\s*$/.test(prefix)) continue;
        findings.push({
          field,
          rule: 'candidate_identity_mismatch',
          severity: 'high',
          reason: `Installed build metadata identifies ${identity.candidateLabel}, not ${mentioned}.`,
          excerpt: match[0]
        });
      }
    }
  }

  const seen = new Set();
  return findings.filter((finding) => {
    const key = `${finding.field}|${finding.rule}|${finding.excerpt}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function repositoryProfileRows(facts) {
  const basis = factValue(facts, 'repository_profile_basis');
  const trackedFiles = normalizeCount(factValue(facts, 'repository_tracked_files'));
  const trackedBytes = normalizeNumber(factValue(facts, 'repository_tracked_bytes'));
  const sourceFiles = normalizeCount(factValue(facts, 'repository_source_files'));
  const sourceBytes = normalizeNumber(factValue(facts, 'repository_source_bytes'));
  const dirty = factValue(facts, 'repository_profile_dirty');
  const gitBasis = basis === 'git_index_worktree';
  const fallbackBasis = basis === 'filtered_worktree_fallback';
  const evidence = gitBasis
    ? 'Git tracked snapshot'
    : fallbackBasis
      ? 'Filtered repository snapshot'
      : 'Repository profile collector';
  const basisExplanation = gitBasis
    ? 'Tracked paths were measured from the Git index using current working-tree file sizes when available.'
    : fallbackBasis
      ? 'Git inventory was unavailable, so a filtered working-tree snapshot was used; these are repository files, not Git-tracked files.'
      : 'A repository-size profile could not be collected; no size claim is made.';
  if (trackedFiles === null && trackedBytes === null && sourceFiles === null && sourceBytes === null) {
    return [{
      metric: 'Repository profile',
      value: 'Unavailable',
      interpretation: basisExplanation,
      evidence
    }];
  }
  const exclusionText =
    'System state, dependencies, build output, caches, generated evidence, and secret-like paths are excluded.';
  const rows = [
    {
      metric: gitBasis ? 'Tracked repository files' : 'Filtered repository files',
      value: trackedFiles === null ? 'Unavailable' : String(trackedFiles),
      interpretation: `${basisExplanation} ${exclusionText}`,
      evidence
    },
    {
      metric: gitBasis ? 'Tracked repository content' : 'Filtered repository content',
      value: trackedBytes === null ? 'Unavailable' : formatBytes(trackedBytes),
      interpretation: 'Approximate content size for the same filtered snapshot; this is not full disk usage.',
      evidence
    },
    {
      metric: 'Source files',
      value: sourceFiles === null ? 'Unavailable' : String(sourceFiles),
      interpretation: 'Files with recognized programming, markup, stylesheet, shell, or build-script extensions.',
      evidence
    },
    {
      metric: 'Source content',
      value: sourceBytes === null ? 'Unavailable' : formatBytes(sourceBytes),
      interpretation: 'Approximate size of the recognized source-file subset.',
      evidence
    }
  ];
  if (gitBasis) {
    const snapshotStatus = factValue(facts, 'repository_snapshot_status');
    const trackedChanges = normalizeCount(factValue(facts, 'repository_dirty_tracked_changes'));
    const untrackedFiles = normalizeCount(factValue(facts, 'repository_dirty_untracked_files'));
    const conflicts = normalizeCount(factValue(facts, 'repository_dirty_conflicts'));
    const details = [];
    if (trackedChanges !== null) details.push(countLabel(trackedChanges, 'tracked change'));
    if (untrackedFiles !== null) details.push(countLabel(untrackedFiles, 'untracked file'));
    if (conflicts !== null && conflicts > 0) details.push(countLabel(conflicts, 'merge conflict'));
    rows.push({
      metric: 'Snapshot state',
      value: snapshotStatus === 'clean'
        ? 'Clean working tree'
        : snapshotStatus && snapshotStatus.startsWith('dirty_')
          ? `${humanStatus(snapshotStatus)}${details.length ? ` — ${details.join(', ')}` : ''}`
          : dirty === true ? 'Dirty working tree' : dirty === false ? 'Clean working tree' : 'Unavailable',
      interpretation: snapshotStatus && snapshotStatus.startsWith('dirty_')
        ? 'The repository profile was collected before the final Git snapshot was clean. Untracked files are not included in the size totals.'
        : snapshotStatus === 'clean' || dirty === false
          ? 'The Git working tree was clean when the repository profile was collected.'
          : 'Working-tree cleanliness could not be determined.',
      evidence
    });
  }
  return rows;
}

function routingEstimateRow(facts) {
  const routingBound = factValue(facts, 'routing_task_bound_to_report') === true;
  if (!routingBound) return null;
  const eligible = factValue(facts, 'routing_claim_eligible') === true;
  const limitation = factValue(facts, 'routing_claim_ineligible_reason');
  const metrics = {
    assessment: factValue(facts, 'routing_estimator_assessment'),
    comparison_kind: factValue(facts, 'routing_comparison_kind'),
    signed_delta_tokens: factValue(facts, 'routing_signed_delta_tokens'),
    signed_delta_percent: factValue(facts, 'routing_signed_delta_percent'),
    workspace_baseline: {
      estimated_tokens: factValue(facts, 'routing_workspace_baseline_estimated_tokens')
    },
    task_context: {
      estimated_tokens: factValue(facts, 'routing_task_estimated_tokens')
    },
    workspace_narrowing: {
      modules_total: factValue(facts, 'modules_total'),
      modules_selected: factValue(facts, 'modules_selected'),
      unrelated_paths_excluded: factValue(facts, 'unrelated_paths_excluded')
    },
    baseline_incomplete_reason: limitation
  };
  return {
    check: 'Workspace-to-task first-read estimate',
    result: formatTaskRoutingEstimate(metrics, {
      effective_claim_eligible: eligible,
      claim_ineligible_reasons: eligible ? [] : [limitation || 'task_routing_ineligible']
    }),
    interpretation:
      'A deterministic local first-read context estimate. It is not provider-reported model-token usage, cost, or measured agent speed.',
    evidence: 'Task routing snapshot'
  };
}

function taskResultStatusLabel(status) {
  return ({
    pass: 'Passed',
    warning: 'Passed with warnings',
    fail: 'Failed',
    not_run: 'Not performed',
    unavailable: 'Unavailable'
  })[status] || humanStatus(status);
}

function formatTaskResultMetrics(metrics) {
  if (!metrics || typeof metrics !== 'object') return '';
  const parts = [];
  const total = normalizeCount(metrics.total);
  const passed = normalizeCount(metrics.passed);
  const failed = normalizeCount(metrics.failed);
  const warnings = normalizeCount(metrics.warnings);
  if (total !== null) {
    if (passed !== null) parts.push(`${passed}/${total} passed`);
    else parts.push(`${total} total`);
    if (failed !== null && failed > 0) parts.push(`${failed} failed`);
    if (warnings !== null && warnings > 0) parts.push(`${warnings} with warnings`);
  } else {
    if (passed !== null) parts.push(`${passed} passed`);
    if (failed !== null) parts.push(`${failed} failed`);
    if (warnings !== null) parts.push(`${warnings} with warnings`);
  }
  const value = normalizeNumber(metrics.value);
  if (value !== null) {
    const unit = String(metrics.unit || '').trim();
    parts.push(`${value}${unit ? ` ${unit}` : ''}`);
  }
  return parts.join(', ');
}

function verifiedOutcomeRows(facts, answers) {
  const rows = [];
  const title = factValue(facts, 'task_result_title');
  const outcome = factValue(facts, 'task_result_outcome');
  const summary = factValue(facts, 'task_result_summary');
  const taskResults = factValue(facts, 'task_verification_results');
  if (title) {
    rows.push({
      check: 'Engineering task',
      result: title,
      interpretation:
        'The report-specific task title supplied through the structured task-results contract.',
      evidence: 'Task-results manifest'
    });
  }
  if (outcome || summary) {
    rows.push({
      check: 'Overall outcome',
      result: `${taskResultStatusLabel(outcome || 'unavailable')}${summary ? ` — ${summary}` : ''}`,
      interpretation:
        'Derived from the evidence-backed task checks below. It is separate from Doctor, Task Readiness, and other .knowledge system-state metrics.',
      evidence: 'Task-results manifest'
    });
  }
  if (Array.isArray(taskResults)) {
    for (const row of taskResults.filter((item) => item && item.public !== false)) {
      const result = `${taskResultStatusLabel(row.status)}${row.public_summary ? ` — ${row.public_summary}` : ''}`;
      rows.push({
        check: row.label || row.id || 'Task check',
        result,
        interpretation: row.interpretation || 'Evidence-bound engineering check.',
        evidence: row.evidence?.label || 'Task-results evidence'
      });
    }
  }
  if (!rows.length) {
    const observed = unwrap(answers['observed-results']) || unwrap(answers['quick-summary']);
    if (!empty(observed)) {
      rows.push({
        check: 'Tester-observed task outcome',
        result: displayValue(observed),
        interpretation:
          'Tester-supplied observation. No structured task-results manifest was attached, so this is not presented as an automated pass/fail result.',
        evidence: 'Tester observation'
      });
    }
    rows.push({
      check: 'Structured task verification',
      result: 'Not attached',
      interpretation:
        'Attach a report-specific task-results manifest with content-addressed evidence to publish a verified engineering outcome table.',
      evidence: 'Field Report task-results contract'
    });
  }
  return rows;
}

function systemStateRows(facts) {
  const rows = [];
  rows.push({
    check: 'Repository scope',
    result: scopeDisclosure(facts),
    interpretation:
      'Functional modules and repositories are counted separately; multiple modules do not imply a multi-project workspace.',
    evidence: 'Repository context'
  });

  const snapshotStatus = factValue(facts, 'repository_snapshot_status');
  const trackedChanges = normalizeCount(factValue(facts, 'repository_dirty_tracked_changes'));
  const untrackedFiles = normalizeCount(factValue(facts, 'repository_dirty_untracked_files'));
  const conflicts = normalizeCount(factValue(facts, 'repository_dirty_conflicts'));
  const snapshotParts = [];
  if (trackedChanges !== null) snapshotParts.push(countLabel(trackedChanges, 'tracked change'));
  if (untrackedFiles !== null) snapshotParts.push(countLabel(untrackedFiles, 'untracked file'));
  if (conflicts !== null && conflicts > 0) snapshotParts.push(countLabel(conflicts, 'merge conflict'));
  rows.push({
    check: 'Final repository snapshot',
    result: snapshotStatus === 'clean'
      ? 'Clean Git working tree'
      : snapshotStatus === 'non_git'
        ? 'Non-Git filtered snapshot'
        : snapshotStatus && snapshotStatus.startsWith('dirty_')
          ? `${humanStatus(snapshotStatus)}${snapshotParts.length ? ` — ${snapshotParts.join(', ')}` : ''}`
          : 'Unavailable',
    interpretation: snapshotStatus === 'clean'
      ? 'The public facts were collected from a clean Git working tree.'
      : snapshotStatus === 'non_git'
        ? 'Git cleanliness is not applicable; repository size used the filtered filesystem fallback.'
        : snapshotStatus && snapshotStatus.startsWith('dirty_')
          ? 'The facts were collected before the final Git snapshot was clean. Public approval is blocked when GitHub publication permission is requested.'
          : 'Final snapshot cleanliness could not be determined.',
    evidence: 'Repository profile collector'
  });

  const build = releaseIdentity(facts);
  rows.push({
    check: '.knowledge build',
    result: build.display,
    interpretation: build.channel === 'release_candidate'
      ? 'Embedded package metadata identifies this release-candidate build. It is not the ZIP artifact SHA.'
      : build.channel === 'stable'
        ? 'Embedded package metadata identifies a stable build. It is not the ZIP artifact SHA.'
        : 'Embedded package metadata identifies the installed product version; release-channel detail was unavailable.',
    evidence: 'Installed package metadata'
  });

  const readiness = firstAvailableFact(facts, [
    'routing_task_readiness',
    'repair_task_readiness_status'
  ]);
  const readinessScore = normalizeNumber(factValue(facts, 'repair_task_readiness_score'));
  const relevantOpen = normalizeCount(factValue(facts, 'repair_task_relevant_findings_open'));
  {
    const details = [];
    if (readinessScore !== null) details.push(`${readinessScore}/100`);
    if (relevantOpen !== null) details.push(`${countLabel(relevantOpen, 'task-relevant finding')} open`);
    rows.push({
      check: 'Task readiness',
      result: readiness.value === null
        ? 'Unavailable'
        : `${humanStatus(readiness.value)}${details.length ? ` — ${details.join(', ')}` : ''}`,
      interpretation: readiness.value === null
        ? 'No current task-readiness record was available, so no task-readiness claim is made.'
        : 'Task-scoped readiness for the current evidence snapshot; it is separate from repository-wide Doctor health.',
      evidence: 'Task readiness record'
    });
  }

  const doctorScore = normalizeNumber(factValue(facts, 'doctor_score'));
  const doctorStatus = firstAvailableFact(facts, ['doctor_status', 'doctor_structural_status']).value;
  const active = normalizeCount(factValue(facts, 'doctor_active_findings'));
  const critical = normalizeCount(factValue(facts, 'doctor_critical_findings'));
  {
    const resultParts = [];
    if (doctorScore !== null) resultParts.push(`${doctorScore}/100`);
    if (doctorStatus !== null) resultParts.push(humanStatus(doctorStatus));
    const findingParts = [];
    if (active !== null) findingParts.push(`${countLabel(active, 'current finding')}`);
    if (critical !== null) findingParts.push(`${countLabel(critical, 'critical finding')}`);
    const available = resultParts.length > 0 || findingParts.length > 0;
    rows.push({
      check: 'Repository Doctor',
      result: available
        ? `${resultParts.join(' — ')}${findingParts.length ? `; ${findingParts.join(', ')}` : ''}`
        : 'Unavailable',
      interpretation: available
        ? 'Repository-health evidence. The Doctor score is not model accuracy, task success, or a performance percentage.'
        : 'No current Doctor report was available, so no repository-health claim is made.',
      evidence: 'Doctor report'
    });
  }

  const wikiStatus = factValue(facts, 'wiki_structural_status');
  const wikiScore = normalizeNumber(factValue(facts, 'wiki_lint_score'));
  const brokenEdges = normalizeCount(factValue(facts, 'wiki_broken_edges'));
  {
    const resultParts = [];
    if (wikiStatus !== null) resultParts.push(humanStatus(wikiStatus));
    if (wikiScore !== null) resultParts.push(`${wikiScore}/100`);
    if (brokenEdges !== null) resultParts.push(countLabel(brokenEdges, 'broken edge'));
    rows.push({
      check: 'Wiki integrity',
      result: resultParts.length ? resultParts.join(' — ') : 'Unavailable',
      interpretation: resultParts.length
        ? 'Structural and quality status of the repository-local knowledge graph at collection time.'
        : 'No current wiki lint or graph result was available, so no wiki-integrity claim is made.',
      evidence: 'Wiki lint and graph'
    });
  }

  const receipts = normalizeCount(factValue(facts, 'verification_receipts'));
  rows.push({
    check: 'Stored verification evidence',
    result: receipts === null ? 'Unavailable' : countLabel(receipts, 'verification receipt'),
    interpretation: receipts === null
      ? 'No current verification-receipt index was available. Tester observations remain separate from automated evidence.'
      : 'Stored verification records available to the workflow. This is evidence volume, not a task count or success rate.',
    evidence: 'Verification receipt index'
  });

  const telemetryStatus = factValue(facts, 'repair_telemetry_status');
  const telemetryReason = factValue(facts, 'repair_telemetry_reason');
  const repairEnabled = factValue(facts, 'repair_on_touch_enabled');
  const repairMode = factValue(facts, 'repair_mode');
  const repairSelected = normalizeCount(factValue(facts, 'repair_findings_selected'));
  const repairClosed = normalizeCount(factValue(facts, 'repair_findings_closed'));
  const repairDeferred = normalizeCount(factValue(facts, 'repair_findings_deferred'));
  const resultParts = [];
  if (telemetryStatus === 'current') {
    resultParts.push('Current — validated');
    if (repairEnabled !== null) resultParts.push(repairEnabled ? 'enabled' : 'disabled');
    if (repairMode !== null) resultParts.push(`mode: ${humanStatus(repairMode)}`);
    if (repairSelected !== null) resultParts.push(`${repairSelected} selected`);
    if (repairClosed !== null) resultParts.push(`${repairClosed} closed`);
    if (repairDeferred !== null) resultParts.push(`${repairDeferred} deferred`);
  } else if (telemetryStatus === 'stale') {
    resultParts.push('Stale — metrics withheld');
  } else if (telemetryStatus === 'invalid') {
    resultParts.push('Invalid — metrics withheld');
  } else {
    resultParts.push('Unavailable');
  }
  rows.push({
    check: 'Repair-on-touch telemetry',
    result: resultParts.join('; '),
    interpretation: telemetryStatus === 'current'
      ? 'Current, semantically validated task-scoped repair lifecycle activity. Closed findings are lifecycle outcomes, not model-quality, speed, or accuracy measurements.'
      : telemetryReason || 'Repair-on-touch telemetry was unavailable; no repair effect is claimed.',
    evidence: telemetryStatus === 'current' ? 'Current validated Repair-on-touch telemetry' : 'Telemetry freshness and validity check'
  });


  const routing = routingEstimateRow(facts);
  if (routing) rows.push(routing);
  return rows;
}

function systemObservations(facts) {
  const observations = [];
  const doctorScore = normalizeNumber(factValue(facts, 'doctor_score'));
  const active = normalizeCount(factValue(facts, 'doctor_active_findings'));
  const critical = normalizeCount(factValue(facts, 'doctor_critical_findings'));
  if (doctorScore !== null) {
    const current = active === null
      ? 'The current finding count was unavailable.'
      : `${countLabel(active, 'current Doctor finding')} remained at collection time.`;
    const criticalText = critical === null
      ? ''
      : critical === 0
        ? ' No critical findings were active.'
        : ` ${countLabel(critical, 'critical finding')} ${critical === 1 ? 'was' : 'were'} active.`;
    observations.push(
      `Doctor finished at ${doctorScore}/100. ${current}${criticalText} ` +
      'This is a repository-health score, not model accuracy.'
    );
  }

  const repairOpen = normalizeCount(factValue(facts, 'repair_open'));
  if (repairOpen !== null) {
    const comparison = active !== null
      ? ` The Doctor separately counted ${countLabel(active, 'current finding')}.`
      : '';
    observations.push(
      `The lifecycle queue contained ${countLabel(repairOpen, 'open row')}. ` +
      `Queue rows can include historical or inactive recheck records and are not the number of current blockers.${comparison}`
    );
  }

  const stale = normalizeCount(factValue(facts, 'stale_artifacts_total'));
  if (stale !== null) {
    observations.push(
      `${countLabel(stale, 'artifact')} ${stale === 1 ? 'was' : 'were'} marked for freshness recheck. ` +
      'This is a maintenance signal, not a count of failed tasks.'
    );
  }

  const receipts = normalizeCount(factValue(facts, 'verification_receipts'));
  if (receipts !== null) {
    observations.push(
      `${countLabel(receipts, 'verification receipt')} ${receipts === 1 ? 'was' : 'were'} available. ` +
      'This measures stored evidence volume, not task success or quality.'
    );
  }

  const modules = normalizeCount(
    factValue(facts, 'functional_modules_total') ?? factValue(facts, 'modules_total')
  );
  if (modules !== null && modules > 1 && factValue(facts, 'workspace_scope_kind') === 'standalone_repository') {
    observations.push(
      `The standalone repository contained ${countLabel(modules, 'functional module')}. ` +
      'Functional modules are not separate repositories or projects.'
    );
  }

  const profileBasis = factValue(facts, 'repository_profile_basis');
  if (profileBasis) {
    observations.push(
      `Repository size used the ${profileBasis === 'git_index_worktree' ? 'Git tracked snapshot' : 'filtered working-tree fallback'}. ` +
      'System state, dependencies, build output, caches, generated evidence, and secret-like paths are not counted.'
    );
  }

  const profileDirty = factValue(facts, 'repository_profile_dirty');
  if (profileBasis === 'git_index_worktree' && profileDirty === true) {
    observations.push(
      'The repository profile was collected from a dirty working tree. Tracked-path sizes reflect the current working tree, while untracked files are not included in the size totals.'
    );
  }

  if (factValue(facts, 'routing_task_bound_to_report') === true) {
    observations.push(
      'Any workspace-to-task context number is a deterministic local first-read estimate, ' +
      'not provider-reported model-token usage, cost, accuracy, or speed.'
    );
  }
  return observations;
}

function renderRows(title, headers, rows, keys) {
  if (!rows.length) return '';
  const lines = [
    `## ${title}`,
    '',
    `| ${headers.join(' | ')} |`,
    `|${headers.map(() => '---').join('|')}|`
  ];
  for (const row of rows) {
    lines.push(`| ${keys.map((key) => markdownTableValue(row[key])).join(' | ')} |`);
  }
  return `${lines.join('\n')}\n\n`;
}

function renderRepositoryProfile(facts) {
  return renderRows(
    'Repository profile',
    ['Metric', 'Value', 'What it means', 'Evidence'],
    repositoryProfileRows(facts),
    ['metric', 'value', 'interpretation', 'evidence']
  );
}

function renderVerifiedOutcome(facts, answers) {
  return renderRows(
    'Verified engineering outcome',
    ['Check', 'Result', 'What it means', 'Evidence'],
    verifiedOutcomeRows(facts, answers),
    ['check', 'result', 'interpretation', 'evidence']
  );
}

function renderSystemState(facts) {
  return renderRows(
    'System state at collection',
    ['Check', 'Result', 'What it means', 'Evidence'],
    systemStateRows(facts),
    ['check', 'result', 'interpretation', 'evidence']
  );
}

function renderSystemObservations(facts) {
  const observations = systemObservations(facts);
  if (!observations.length) return '';
  return `## System observations\n\n${observations.map((item) => `- ${item}`).join('\n')}\n\n`;
}

// Kept as a compatibility export. The public contract now exposes explained outcomes,
// not an unlabelled dump of internal counters.
function evidenceRows(facts, answers = {}) {
  return [...verifiedOutcomeRows(facts, answers), ...systemStateRows(facts)].map((row) => ({
    label: row.check,
    value: row.result,
    source: row.evidence,
    interpretation: row.interpretation
  }));
}

function renderEvidence(facts, answers = {}) {
  return renderVerifiedOutcome(facts, answers);
}

function publicationPermissionDisplay(facts, answers, schema = DEFAULT_SCHEMA) {
  const selected = String(unwrap(answers['github-publication-permission']) || '');
  if (selected !== 'github_publication_allowed') {
    return humanValue('github-publication-permission', selected, schema);
  }
  const taskRows = factValue(facts, 'task_verification_results');
  if (!Array.isArray(taskRows) || taskRows.filter((row) => row?.public !== false).length === 0) {
    return 'Requested by the tester, but blocked until structured, content-addressed task results are attached.';
  }
  const snapshotStatus = String(factValue(facts, 'repository_snapshot_status') || '');
  if (snapshotStatus.startsWith('dirty_')) {
    return 'Requested by the tester, but blocked until the final Git working tree is clean and the report facts are recollected.';
  }
  return humanValue('github-publication-permission', selected, schema);
}

function publicSections(answers, schema = DEFAULT_SCHEMA, facts = null) {
  const sections = new Map();
  const skipped = new Set([
    'knowledge-version',
    'report-relationship',
    'observed-results',
    'response-speed-percent',
    'baseline-duration-ms',
    'knowledge-duration-ms'
  ]);
  for (const field of schema.fields) {
    if (skipped.has(field.id)) continue;
    const value = unwrap(answers[field.id]);
    if (empty(value) && field.omission_policy !== 'never') continue;
    const section = field.public_section;
    if (!sections.has(section)) sections.set(section, []);
    const renderedValue = field.id === 'github-publication-permission'
      ? publicationPermissionDisplay(facts, answers, schema)
      : humanValue(field.id, value, schema);
    sections.get(section).push({
      order: field.renderer.order,
      text: answerLine(field.renderer.label, renderedValue)
    });
  }
  const metric = speedMetric(answers);
  if (metric) {
    const basis = humanValue(
      'response-speed-basis',
      unwrap(answers['response-speed-basis']),
      schema
    );
    const sampleCount = unwrap(answers['response-speed-sample-count']);
    const signed = `${metric.value >= 0 ? '+' : ''}${Math.round(metric.value * 10) / 10}%`;
    const suffix = `${basis}${empty(sampleCount) ? '' : `, n=${sampleCount}`}`;
    if (!sections.has('Accuracy and response speed')) {
      sections.set('Accuracy and response speed', []);
    }
    sections.get('Accuracy and response speed').push({
      order: 75,
      text: answerLine('Signed speed change', `${signed} (${suffix})`)
    });
  }
  return sections;
}

function renderPublicBody(manifest, facts, answers, schema = DEFAULT_SCHEMA) {
  const sections = publicSections(answers, schema, facts);
  const relationship = relationshipDefinition(answers);
  const build = releaseIdentity(facts);
  let body = '# Field Report\n\n';
  body += `> **Disclosure:** ${relationship.disclosure}\n\n`;

  body += '## Quick summary\n\n';
  body += answerLine('Main result', humanValue('quick-summary', unwrap(answers['quick-summary']), schema));

  body += '## Project context\n\n';
  if (build.display !== 'Unavailable') body += answerLine('.knowledge build', build.display);
  body += answerLine('Project context', unwrap(answers['project-context']));
  body += answerLine('Repository scope', scopeDisclosure(facts));

  body += renderRepositoryProfile(facts);
  body += renderVerifiedOutcome(facts, answers);
  body += renderSystemState(facts);
  body += renderSystemObservations(facts);

  for (const section of SECTION_ORDER) {
    const entries = (sections.get(section) || [])
      .filter((item) => item.text)
      .sort((left, right) => left.order - right.order);
    if (entries.length) {
      body += `## ${section}\n\n${entries.map((item) => item.text).join('')}`;
    }
  }

  if (translationRequired(manifest.language, manifest.public_language) &&
      manifest.translation?.status === 'translation_approved' &&
      manifest.translation?.approved_by_tester) {
    body += '> The tester answered in another language. The English publication version ' +
      'was agent-assisted and approved by the tester.\n\n';
  }
  const testerApproved = manifest.approval?.approved_by_tester === true;
  body += testerApproved
    ? '> This report was prepared semi-automatically with the `.knowledge field-report` ' +
      'workflow and explicitly approved by the tester for this exact public draft.\n'
    : '> This report was prepared semi-automatically with the `.knowledge field-report` ' +
      'workflow. Publication requires explicit tester review and approval.\n';
  return body;
}

function renderDraft(manifest, facts, answers, publicBody) {
  const lines = [
    '# Internal Field Report draft',
    '',
    '> This file contains provenance and diagnostics. Publish `public.md`, not this file.',
    '',
    '## Workflow state',
    '',
    `- Report ID: \`${manifest.report_id}\``,
    `- Status before render: \`${manifest.status}\``,
    `- Source language: \`${manifest.language}\``,
    `- Public language: \`${manifest.public_language}\``,
    `- Translation state: \`${manifest.translation?.status || 'unknown'}\``,
    `- Anonymization: \`${manifest.anonymized ? 'enabled' : 'disabled'}\``,
    '',
    '## Collected fact provenance',
    '',
    '| Fact ID | Value | Kind | Source | Schema path | Confidence | Warning |',
    '|---|---|---|---|---|---|---|'
  ];
  for (const [id, item] of Object.entries(facts?.values || {})) {
    lines.push(
      `| \`${markdownTableValue(id)}\` | ${markdownTableValue(displayValue(item.value))} | ` +
      `${markdownTableValue(item.kind)} | \`${markdownTableValue(item.source)}\` | ` +
      `\`${markdownTableValue(item.schema_path)}\` | ${markdownTableValue(item.confidence)} | ` +
      `${markdownTableValue(item.warning || '')} |`
    );
  }
  lines.push('', '## Collector warnings', '');
  if (facts?.warnings?.length) {
    for (const warning of facts.warnings) lines.push(`- ${warning}`);
  } else {
    lines.push('- None.');
  }
  lines.push('', '## Answer provenance', '');
  for (const [id, raw] of Object.entries(answers)) {
    const value = unwrap(raw);
    const kind = raw?.kind || 'tester';
    const source = raw?.source || 'tester_answer';
    lines.push(
      `### \`${id}\``,
      '',
      `- Kind: \`${kind}\``,
      `- Source: \`${source}\``,
      '',
      displayValue(value),
      ''
    );
  }
  lines.push('## Redacted public preview', '', publicBody.trim(), '');
  return `${lines.join('\n')}\n`;
}


function titleSubject(value, fallback) {
  const source = empty(value) ? fallback : value;
  const plain = String(source || '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*_#~>|]/g, ' ')
    .replace(/https?:\/\/\S+/gi, ' ')
    .replace(/\s+/g, ' ')
    .replace(/[.!?;:,]+$/g, '')
    .trim();
  return plain || String(fallback || 'Repository');
}

function discussionRelationshipLabel(value, fallback) {
  return ({
    first_party_maintainer: 'maintainer dogfooding',
    independent_user: 'independent user',
    internal_qa: 'internal QA',
    controlled_comparison: 'controlled comparison'
  })[value] || String(fallback || 'field report').toLowerCase();
}

function discussionSubject(value, fallback) {
  let subject = titleSubject(value, fallback)
    .replace(/^(?:the\s+)?(?:real\s+)?(?:engineering\s+)?task\s+(?:was\s+)?(?:to\s+)?/i, '')
    .replace(/^real\s+task\s*:\s*/i, '')
    .replace(/^task\s*:\s*/i, '')
    .replace(/^to\s+/i, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!subject || /^(?:engineering task|repository update|project work|task|work)$/i.test(subject)) {
    subject = titleSubject(fallback, 'Repository engineering work');
  }
  return subject;
}

function buildDiscussionTitle(subject, relationship, maximum = 96) {
  const prefix = '[Field report] ';
  const suffix = ` — ${relationship}`;
  const subjectBudget = maximum - Array.from(prefix).length - Array.from(suffix).length;
  if (subjectBudget < 8) throw new Error('Discussion title relationship leaves no useful subject space.');
  const concise = truncateDiscussionTitle(
    discussionSubject(subject, 'Repository engineering work'),
    subjectBudget
  );
  return `${prefix}${concise}${suffix}`;
}

function publicAnswerLanguageFindings(answers, schema = DEFAULT_SCHEMA) {
  const fieldTypes = new Map(schema.fields.map((field) => [field.id, field.type]));
  const findings = [];
  for (const [id, raw] of Object.entries(answers || {})) {
    if (fieldTypes.get(id) !== 'string') continue;
    const value = unwrap(raw);
    if (empty(value)) continue;
    const result = scanEnglishLanguage(String(value));
    for (const finding of result.findings || []) {
      findings.push({
        field: id,
        ...finding
      });
    }
  }
  return findings;
}

function render(manifest, facts, answers, schema = DEFAULT_SCHEMA) {
  const answerScan = redactAnswers(answers, manifest.anonymized);
  const publicAnswers = answerScan.answers;
  const project = factValue(facts, 'project_type') || 'Repository';
  const relationship = relationshipDefinition(publicAnswers);
  const structuredTitle = factValue(facts, 'task_result_title');
  const subject = discussionSubject(
    structuredTitle || unwrap(publicAnswers['main-scenario']),
    project
  );
  const shortRelationship = discussionRelationshipLabel(
    unwrap(publicAnswers['report-relationship']),
    relationship.title
  );
  const rawTitle = buildDiscussionTitle(subject, shortRelationship, 96);
  const rawBody = renderPublicBody(manifest, facts, publicAnswers, schema);
  const supporting = unwrap(publicAnswers['supporting-material']) || '';
  const finalScan = scanPublication({
    title: rawTitle,
    body: rawBody,
    supporting_material: supporting,
    generated_links: []
  }, manifest.anonymized, { requireEnglish: true });
  const answerLanguageFindings = publicAnswerLanguageFindings(publicAnswers, schema);
  const claimFindings = claimSafetyFindings(facts, publicAnswers);
  const blocked = answerScan.report.status === 'blocked' ||
    finalScan.report.status === 'blocked' || answerLanguageFindings.length > 0 ||
    claimFindings.length > 0;
  const warned = answerScan.report.status === 'warning' ||
    finalScan.report.status === 'warning';
  const redaction = {
    schema_version: 'knowledge-field-report-redaction.v2',
    status: blocked ? 'blocked' : warned ? 'warning' : 'pass',
    answer_scan: answerScan.report,
    final_publication_scan: finalScan.report,
    unresolved_findings: [
      ...(answerScan.report.unresolved_findings || []),
      ...(finalScan.report.unresolved_findings || []),
      ...answerLanguageFindings,
      ...claimFindings
    ],
    claim_safety_scan: {
      status: claimFindings.length ? 'blocked' : 'pass',
      findings: claimFindings,
      policy: 'knowledge-field-report-claim-safety.v1'
    },
    answer_language_scan: {
      status: answerLanguageFindings.length ? 'blocked' : 'pass',
      findings: answerLanguageFindings,
      heuristic: 'knowledge-field-report-english-publication.v1'
    }
  };
  const publicBody = finalScan.body;
  return {
    public: publicBody,
    draft: renderDraft(manifest, facts, publicAnswers, publicBody),
    title: finalScan.title,
    answers: publicAnswers,
    redaction,
    speed_metric: speedMetric(publicAnswers),
    report_relationship: unwrap(publicAnswers['report-relationship']) || null
  };
}

module.exports = {
  buildDiscussionTitle,
  SECTION_ORDER,
  REPORT_RELATIONSHIPS,
  claimSafetyFindings,
  discussionSubject,
  evidenceRows,
  formatTaskResultMetrics,
  formatBytes,
  publicAnswerLanguageFindings,
  relationshipDisclosure,
  releaseIdentity,
  render,
  renderDraft,
  renderEvidence,
  renderRepositoryProfile,
  renderSystemObservations,
  renderSystemState,
  renderVerifiedOutcome,
  repositoryProfileRows,
  scopeDisclosure,
  speedMetric,
  systemObservations,
  systemStateRows,
  titleSubject,
  truncateDiscussionTitle,
  verifiedOutcomeRows
};
