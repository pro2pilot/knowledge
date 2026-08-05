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
  scanPublication
} = require('./redactor');

const SECTION_ORDER = Object.freeze([
  'Quick summary',
  'Project context',
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

function factValue(facts, id) {
  const item = facts?.values?.[id];
  return item && item.kind !== 'unavailable' ? item.value : null;
}

function evidenceRows(facts) {
  const definitions = [
    ['.knowledge version', 'knowledge_version'],
    ['Completed sessions', 'completed_sessions'],
    ['Open repair items', 'repair_open'],
    ['Stale artifacts', 'stale_artifacts_total'],
    ['Suspect modules', 'modules_suspect'],
    ['Low-confidence modules', 'modules_low_confidence'],
    ['Modules needing recheck', 'modules_needing_recheck'],
    ['Doctor score', 'doctor_score'],
    ['Repair-on-touch mode', 'repair_mode'],
    ['Task readiness before', 'repair_task_readiness_before'],
    ['Task readiness after', 'repair_task_readiness_after'],
    ['Verification receipts', 'verification_receipts'],
    ['Routing scope', 'routing_scope'],
    ['Field Report bound to routing task', 'routing_task_bound_to_report'],
    ['Routing scope source', 'routing_scope_source'],
    ['Workspace modules total', 'modules_total'],
    ['Workspace candidate paths total', 'paths_total'],
    ['Task modules selected', 'modules_selected'],
    ['Task paths selected', 'paths_selected'],
    ['Task readiness', 'routing_task_readiness'],
    ['Unrelated paths excluded', 'unrelated_paths_excluded']
  ];
  const rows = definitions.flatMap(([label, id]) => {
    const item = facts?.values?.[id];
    if (!item || item.kind === 'unavailable' || item.value === null) return [];
    return [{
      label,
      value: displayValue(item.value),
      source: item.source
    }];
  });
  const routingBound = factValue(facts, 'routing_task_bound_to_report') === true;
  if (routingBound) {
    const eligible = factValue(facts, 'routing_claim_eligible') === true;
    const limitation = factValue(facts, 'routing_claim_ineligible_reason');
    const metrics = {
      assessment: factValue(facts, 'routing_estimator_assessment'),
      comparison_kind: factValue(facts, 'routing_comparison_kind'),
      signed_delta_tokens: factValue(facts, 'routing_signed_delta_tokens'),
      signed_delta_percent: factValue(facts, 'routing_signed_delta_percent'),
      workspace_baseline: { estimated_tokens: factValue(facts, 'routing_workspace_baseline_estimated_tokens') },
      task_context: { estimated_tokens: factValue(facts, 'routing_task_estimated_tokens') },
      workspace_narrowing: {
        modules_total: factValue(facts, 'modules_total'),
        modules_selected: factValue(facts, 'modules_selected'),
        unrelated_paths_excluded: factValue(facts, 'unrelated_paths_excluded')
      },
      baseline_incomplete_reason: limitation
    };
    rows.push({
      label: 'Workspace-to-task first-read narrowing',
      value: formatTaskRoutingEstimate(metrics, {
        effective_claim_eligible: eligible,
        claim_ineligible_reasons: eligible ? [] : [limitation || 'task_routing_ineligible']
      }),
      source: facts.values.routing_claim_eligible?.source || '.knowledge/routing/tasks'
    });
    const modulesTotal = Number(factValue(facts, 'modules_total') || 0);
    rows.push({
      label: 'Workspace scope disclosure',
      value: modulesTotal > 1
        ? 'This `.knowledge` installation covered a multi-project workspace. The task itself was explicitly scoped to the selected module(s).'
        : 'The workspace contained a single project, so workspace narrowing was limited.',
      source: facts.values.modules_total?.source || '.knowledge/routing/tasks'
    });
  }
  return rows;
}

function markdownTableValue(value) {
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function renderEvidence(facts) {
  const rows = evidenceRows(facts);
  if (!rows.length) return '';
  const lines = [
    '## Automatically collected evidence',
    '',
    '| Metric | Value | Source |',
    '|---|---:|---|'
  ];
  for (const row of rows) {
    lines.push(
      `| ${markdownTableValue(row.label)} | ${markdownTableValue(row.value)} | ` +
      `\`${markdownTableValue(row.source)}\` |`
    );
  }
  return `${lines.join('\n')}\n\n`;
}

function publicSections(answers, schema = DEFAULT_SCHEMA) {
  const sections = new Map();
  const specialSpeedIds = new Set([
    'response-speed-percent',
    'baseline-duration-ms',
    'knowledge-duration-ms'
  ]);
  for (const field of schema.fields) {
    if (field.id === 'knowledge-version' || specialSpeedIds.has(field.id)) continue;
    const value = unwrap(answers[field.id]);
    if (empty(value) && field.omission_policy !== 'never') continue;
    const section = field.public_section;
    if (!sections.has(section)) sections.set(section, []);
    sections.get(section).push({
      order: field.renderer.order,
      text: answerLine(field.renderer.label, humanValue(field.id, value, schema))
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
  const sections = publicSections(answers, schema);
  let body = '# Field Report\n\n';
  for (const section of SECTION_ORDER) {
    const entries = (sections.get(section) || [])
      .filter((item) => item.text)
      .sort((left, right) => left.order - right.order);
    if (entries.length) {
      body += `## ${section}\n\n${entries.map((item) => item.text).join('')}`;
    }
    if (section === 'Project context') body += renderEvidence(facts);
  }
  if (!body.includes('## Automatically collected evidence')) body += renderEvidence(facts);
  if (translationRequired(manifest.language, manifest.public_language) &&
      manifest.translation?.status === 'translation_approved' &&
      manifest.translation?.approved_by_tester) {
    body += '> The tester answered in another language. The public-language version was ' +
      'agent-assisted and approved by the tester.\n\n';
  }
  body += '> This report was prepared semi-automatically with the `.knowledge field-report` ' +
    'workflow and reviewed by the tester before publication.\n';
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

function render(manifest, facts, answers, schema = DEFAULT_SCHEMA) {
  const answerScan = redactAnswers(answers, manifest.anonymized);
  const publicAnswers = answerScan.answers;
  const project = manifest.anonymized
    ? 'Private project'
    : factValue(facts, 'project_type') || 'Repository';
  const runtimes = factValue(facts, 'agent_runtimes');
  const agent = Array.isArray(runtimes) && runtimes.length ? runtimes[0] : 'coding agent';
  const summary = unwrap(publicAnswers['quick-summary']) || 'tester observations';
  const rawTitle = `[Field report] ${project} + ${agent} — ` +
    String(summary).replace(/[\r\n]+/g, ' ').slice(0, 96);
  const rawBody = renderPublicBody(manifest, facts, publicAnswers, schema);
  const supporting = unwrap(publicAnswers['supporting-material']) || '';
  const finalScan = scanPublication({
    title: rawTitle,
    body: rawBody,
    supporting_material: supporting,
    generated_links: []
  }, manifest.anonymized);
  const blocked = answerScan.report.status === 'blocked' ||
    finalScan.report.status === 'blocked';
  const warned = answerScan.report.status === 'warning' ||
    finalScan.report.status === 'warning';
  const redaction = {
    schema_version: 'knowledge-field-report-redaction.v2',
    status: blocked ? 'blocked' : warned ? 'warning' : 'pass',
    answer_scan: answerScan.report,
    final_publication_scan: finalScan.report,
    unresolved_findings: [
      ...(answerScan.report.unresolved_findings || []),
      ...(finalScan.report.unresolved_findings || [])
    ]
  };
  const publicBody = finalScan.body;
  return {
    public: publicBody,
    draft: renderDraft(manifest, facts, publicAnswers, publicBody),
    title: finalScan.title,
    answers: publicAnswers,
    redaction,
    speed_metric: speedMetric(publicAnswers)
  };
}

module.exports = {
  SECTION_ORDER,
  evidenceRows,
  render,
  renderDraft,
  renderEvidence,
  speedMetric
};
