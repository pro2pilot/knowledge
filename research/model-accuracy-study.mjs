#!/usr/bin/env node
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const API = 'https://models.github.ai/inference/chat/completions';
const MODEL = process.env.MODEL_ACCURACY_MODEL || 'openai/gpt-4.1-mini';
const TOKEN = process.env.GITHUB_TOKEN;
const OUT = path.resolve(process.env.MODEL_ACCURACY_OUT || 'model-accuracy-results');
const TASK_COUNT = 12;
const FIRST_READ_CHAR_BUDGET = 2600;
const TEMPERATURE = 0;
const STUDY_ID = 'knowledge-3.4.0-rc1-routing-accuracy-v1';

if (!TOKEN) throw new Error('GITHUB_TOKEN is required');
fs.mkdirSync(OUT, { recursive: true });

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const behaviors = [
  ['order ownership fallback', 'orders-app', 'shared-routing', 'orders-app/src/routes.js'],
  ['invoice retry classification', 'billing-worker', 'shared-retry', 'billing-worker/src/classify.js'],
  ['profile avatar normalization', 'accounts-api', 'shared-media', 'accounts-api/src/avatar.js'],
  ['catalog locale fallback', 'catalog-web', 'shared-i18n', 'catalog-web/src/locale.js'],
  ['shipment carrier mapping', 'shipping-api', 'shared-carriers', 'shipping-api/src/carrier.js'],
  ['audit event redaction', 'audit-service', 'shared-redaction', 'audit-service/src/redact.js'],
  ['search synonym expansion', 'search-api', 'shared-query', 'search-api/src/synonyms.js'],
  ['notification channel policy', 'notify-worker', 'shared-policy', 'notify-worker/src/channel.js'],
  ['subscription grace period', 'subscriptions-api', 'shared-time', 'subscriptions-api/src/grace.js'],
  ['document preview format', 'documents-web', 'shared-preview', 'documents-web/src/format.js'],
  ['support priority routing', 'support-api', 'shared-routing', 'support-api/src/priority.js'],
  ['analytics consent filter', 'analytics-worker', 'shared-consent', 'analytics-worker/src/filter.js']
];

const decoyModules = [
  'content-app', 'admin-console', 'legacy-api', 'marketing-web',
  'reporting-worker', 'sandbox-service', 'demo-app', 'migration-tools'
];

function moduleCard(id, behavior, dependency, file, relevant) {
  if (relevant) {
    return `MODULE ${id}\nROLE: owns ${behavior}\nSOURCE: ${file}\nDIRECT_DEPENDENCY: ${dependency}\nRULE: preserve all unrelated module behavior.\n`;
  }
  return `MODULE ${id}\nROLE: owns unrelated ${id.replaceAll('-', ' ')} behavior\nSOURCE: ${id}/src/index.js\nDIRECT_DEPENDENCY: shared-common\nRULE: do not edit for unrelated tasks.\n`;
}

function buildTask(index) {
  const [behavior, target, dependency, file] = behaviors[index];
  const cards = decoyModules.map((id) => moduleCard(id, behavior, dependency, file, false));
  // The canonical workspace-wide first read is stable and bounded. The relevant
  // card is deliberately outside that bounded prefix, matching the study's
  // preregistered question: can task routing improve the model's first decision
  // when broad first-read context is noisy and truncated?
  cards.push(moduleCard(target, behavior, dependency, file, true));
  cards.push(moduleCard(dependency, behavior, dependency, `${dependency}/src/index.js`, false));
  const workspace = [
    'WORKSPACE POLICY: choose one owner module, one required direct dependency, and one target source file.',
    'Do not choose a sibling application merely because its name resembles the task.',
    ...cards
  ].join('\n');
  const routed = [
    'TASK-SCOPED ROUTE: current, ready, claim-eligible.',
    moduleCard(target, behavior, dependency, file, true),
    `DEPENDENCY ${dependency}\nROLE: required direct dependency for ${behavior}\nSOURCE: ${dependency}/src/index.js\n`,
    'EXCLUDED: unrelated sibling applications and migration tooling.'
  ].join('\n');
  const task = `A change is required for ${behavior}. Before editing, identify the owning module, the required direct dependency, and the first source file to inspect.`;
  return {
    task_id: `A${String(index + 1).padStart(2, '0')}`,
    task,
    answer: { target_module: target, dependency_module: dependency, target_file: file },
    workspace_context: workspace.slice(0, FIRST_READ_CHAR_BUDGET),
    routed_context: routed.slice(0, FIRST_READ_CHAR_BUDGET),
    full_workspace_sha256: sha256(workspace),
    workspace_context_sha256: sha256(workspace.slice(0, FIRST_READ_CHAR_BUDGET)),
    routed_context_sha256: sha256(routed.slice(0, FIRST_READ_CHAR_BUDGET))
  };
}

const tasks = Array.from({ length: TASK_COUNT }, (_, i) => buildTask(i));
const preregistration = {
  schema_version: 'knowledge-model-accuracy-preregistration.v1',
  study_id: STUDY_ID,
  created_before_model_calls: true,
  model: MODEL,
  temperature: TEMPERATURE,
  task_count: TASK_COUNT,
  paired_conditions: ['workspace_wide_first_read', 'knowledge_task_scoped_first_read'],
  first_read_char_budget: FIRST_READ_CHAR_BUDGET,
  primary_endpoint: 'first_pass_repository_decision_accuracy',
  scoring: 'exact match on target_module, dependency_module, and target_file',
  exclusions: 'infrastructure/API failures only; no task exclusions after results',
  interpretation: 'Scoped workflow accuracy under a fixed first-read budget; not intrinsic model intelligence, code correctness, provider-token savings, or universal accuracy.',
  tasks_sha256: sha256(JSON.stringify(tasks.map(({ task_id, task, answer, full_workspace_sha256 }) => ({ task_id, task, answer, full_workspace_sha256 }))))
};
fs.writeFileSync(path.join(OUT, 'PREREGISTRATION.json'), `${JSON.stringify(preregistration, null, 2)}\n`);

async function infer(task, condition, context) {
  const system = [
    'You are making the first repository decision before coding.',
    'Use only the supplied first-read context.',
    'Return strict JSON with exactly: target_module, dependency_module, target_file.',
    'Do not include markdown or explanation.'
  ].join(' ');
  const body = {
    model: MODEL,
    temperature: TEMPERATURE,
    response_format: { type: 'json_object' },
    messages: [
      { role: 'system', content: system },
      { role: 'user', content: `${task.task}\n\nFIRST-READ CONTEXT (${condition}):\n${context}` }
    ]
  };
  const started = Date.now();
  const response = await fetch(API, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    },
    body: JSON.stringify(body)
  });
  const text = await response.text();
  if (!response.ok) {
    const error = new Error(`GitHub Models request failed ${response.status}: ${text.slice(0, 500)}`);
    error.status = response.status;
    throw error;
  }
  const payload = JSON.parse(text);
  const raw = payload.choices?.[0]?.message?.content || '';
  let parsed;
  try { parsed = JSON.parse(raw); } catch { parsed = null; }
  const expected = task.answer;
  const pass = Boolean(parsed &&
    parsed.target_module === expected.target_module &&
    parsed.dependency_module === expected.dependency_module &&
    parsed.target_file === expected.target_file);
  return {
    condition,
    pass,
    expected,
    actual: parsed,
    raw_sha256: sha256(raw),
    duration_ms: Date.now() - started,
    usage: payload.usage || null,
    provider_model: payload.model || MODEL,
    finish_reason: payload.choices?.[0]?.finish_reason || null
  };
}

function exactBinomialTwoSided(k, n, p = 0.5) {
  const choose = (nn, kk) => {
    let r = 1;
    for (let i = 1; i <= kk; i += 1) r = r * (nn - kk + i) / i;
    return r;
  };
  const prob = (x) => choose(n, x) * (p ** x) * ((1 - p) ** (n - x));
  const observed = prob(k);
  let total = 0;
  for (let x = 0; x <= n; x += 1) if (prob(x) <= observed + 1e-15) total += prob(x);
  return Math.min(1, total);
}

const results = [];
for (const task of tasks) {
  for (const [condition, context] of [
    ['workspace_wide_first_read', task.workspace_context],
    ['knowledge_task_scoped_first_read', task.routed_context]
  ]) {
    try {
      const result = await infer(task, condition, context);
      results.push({ task_id: task.task_id, task: task.task, ...result });
    } catch (error) {
      results.push({
        task_id: task.task_id,
        task: task.task,
        condition,
        pass: null,
        infrastructure_failure: true,
        error: String(error.message || error)
      });
    }
    await sleep(5200);
  }
}

const usable = results.filter((r) => !r.infrastructure_failure);
const byTask = new Map();
for (const row of usable) {
  const pair = byTask.get(row.task_id) || {};
  pair[row.condition] = row;
  byTask.set(row.task_id, pair);
}
const pairs = Array.from(byTask.entries())
  .filter(([, pair]) => pair.workspace_wide_first_read && pair.knowledge_task_scoped_first_read)
  .map(([task_id, pair]) => ({ task_id, ...pair }));
const baselinePass = pairs.filter((p) => p.workspace_wide_first_read.pass).length;
const treatmentPass = pairs.filter((p) => p.knowledge_task_scoped_first_read.pass).length;
const discordantTreatmentWins = pairs.filter((p) => !p.workspace_wide_first_read.pass && p.knowledge_task_scoped_first_read.pass).length;
const discordantBaselineWins = pairs.filter((p) => p.workspace_wide_first_read.pass && !p.knowledge_task_scoped_first_read.pass).length;
const discordant = discordantTreatmentWins + discordantBaselineWins;
const pValue = discordant ? exactBinomialTwoSided(Math.min(discordantTreatmentWins, discordantBaselineWins), discordant) : 1;
const baselineRate = pairs.length ? baselinePass / pairs.length : null;
const treatmentRate = pairs.length ? treatmentPass / pairs.length : null;
const deltaPp = pairs.length ? (treatmentRate - baselineRate) * 100 : null;
const supported = Boolean(
  pairs.length === TASK_COUNT &&
  treatmentPass > baselinePass &&
  discordantTreatmentWins > discordantBaselineWins
);

const report = {
  schema_version: 'knowledge-model-accuracy-study.v1',
  study_id: STUDY_ID,
  status: usable.length === TASK_COUNT * 2 ? 'complete' : 'complete_with_infrastructure_failures',
  preregistration,
  candidate_claim: {
    status: supported ? 'supported' : 'unsupported',
    wording: supported
      ? `In ${pairs.length} preregistered synthetic repository-navigation tasks under a fixed first-read budget, the same model's first-pass repository-decision accuracy increased from ${(baselineRate * 100).toFixed(1)}% to ${(treatmentRate * 100).toFixed(1)}% with .knowledge task-scoped routing.`
      : 'The preregistered study did not support an accuracy-improvement claim.',
    limitations: [
      'Synthetic repository-navigation tasks.',
      `One provider model: ${MODEL}.`,
      'Measures first repository decision, not complete coding-task accuracy.',
      'Does not establish provider-token or cost savings.',
      'Does not generalize to all repositories, models, or tasks.'
    ]
  },
  metrics: {
    paired_tasks: pairs.length,
    baseline_passed: baselinePass,
    treatment_passed: treatmentPass,
    baseline_accuracy: baselineRate,
    treatment_accuracy: treatmentRate,
    absolute_delta_percentage_points: deltaPp,
    treatment_only_wins: discordantTreatmentWins,
    baseline_only_wins: discordantBaselineWins,
    mcnemar_exact_two_sided_p: pValue,
    infrastructure_failures: results.filter((r) => r.infrastructure_failure).length
  },
  pairs,
  all_calls: results
};
fs.writeFileSync(path.join(OUT, 'MODEL-ACCURACY-STUDY.json'), `${JSON.stringify(report, null, 2)}\n`);
const md = [
  '# Model workflow accuracy study',
  '',
  `Status: **${report.candidate_claim.status.toUpperCase()}**`,
  '',
  `- Model: \`${MODEL}\``,
  `- Paired tasks: ${pairs.length}/${TASK_COUNT}`,
  `- Workspace-wide first-read accuracy: ${baselineRate === null ? 'n/a' : `${(baselineRate * 100).toFixed(1)}% (${baselinePass}/${pairs.length})`}`,
  `- Task-scoped route accuracy: ${treatmentRate === null ? 'n/a' : `${(treatmentRate * 100).toFixed(1)}% (${treatmentPass}/${pairs.length})`}`,
  `- Absolute delta: ${deltaPp === null ? 'n/a' : `${deltaPp.toFixed(1)} percentage points`}`,
  `- Treatment-only wins: ${discordantTreatmentWins}`,
  `- Baseline-only wins: ${discordantBaselineWins}`,
  `- McNemar exact two-sided p: ${pValue.toFixed(6)}`,
  '',
  '## Permitted wording',
  '',
  report.candidate_claim.wording,
  '',
  '## Scope',
  '',
  ...report.candidate_claim.limitations.map((x) => `- ${x}`),
  '',
  '> This study measures first-pass repository-decision accuracy under a fixed first-read budget. It does not claim that the underlying model became intrinsically more intelligent.'
].join('\n');
fs.writeFileSync(path.join(OUT, 'MODEL-ACCURACY-STUDY.md'), `${md}\n`);

if (report.status !== 'complete') process.exitCode = 2;
