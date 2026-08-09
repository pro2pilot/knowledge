import fs from 'node:fs';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { performance } from 'node:perf_hooks';

const packed = fs.readFileSync(new URL('./dataset.json.gz.b64', import.meta.url), 'utf8').trim();
const dataset = JSON.parse(zlib.gunzipSync(Buffer.from(packed, 'base64')).toString('utf8'));
const endpoint = 'https://models.github.ai/inference/chat/completions';
const token = process.env.GITHUB_TOKEN;
if (!token) throw new Error('GITHUB_TOKEN is required');

const SYSTEM = `You are evaluating repository navigation. Use only the supplied repository context. Return exactly one JSON object with these keys: primary_module (string), files_to_edit (array of repository-relative strings), dependencies_to_read (array of repository-relative strings), modules_to_avoid (array of module IDs), confidence (number 0 to 1). Do not include Markdown, explanations, or extra keys. Select the active authoritative implementation, its required shared dependency, and avoid deprecated or unrelated modules.`;
const sha = (v) => crypto.createHash('sha256').update(typeof v === 'string' ? v : JSON.stringify(v)).digest('hex');
const norm = (a) => [...new Set((Array.isArray(a) ? a : []).map(String))].sort();
const same = (a,b) => JSON.stringify(norm(a)) === JSON.stringify(norm(b));
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function extractJson(text) {
  const s = String(text || '').trim();
  try { return JSON.parse(s); } catch {}
  const start = s.indexOf('{'); const end = s.lastIndexOf('}');
  if (start >= 0 && end > start) return JSON.parse(s.slice(start, end + 1));
  throw new Error('model output is not parseable JSON');
}
function score(task, answer) {
  const expected = task.expected;
  const primary = String(answer.primary_module || '') === expected.primary_module;
  const edits = same(answer.files_to_edit, expected.files_to_edit);
  const deps = same(answer.dependencies_to_read, expected.dependencies_to_read);
  const avoid = same(answer.modules_to_avoid, expected.modules_to_avoid);
  const forbidden = new Set(expected.modules_to_avoid);
  const forbiddenSelected = [String(answer.primary_module || ''), ...norm(answer.modules_to_avoid === undefined ? [] : []), ...norm(answer.selected_modules || [])].filter(x => forbidden.has(x));
  const predictedFiles = norm([...(answer.files_to_edit || []), ...(answer.dependencies_to_read || [])]);
  const expectedFiles = norm([...expected.files_to_edit, ...expected.dependencies_to_read]);
  const tp = predictedFiles.filter(x => expectedFiles.includes(x)).length;
  const precision = predictedFiles.length ? tp / predictedFiles.length : 0;
  const recall = expectedFiles.length ? tp / expectedFiles.length : 0;
  const f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  return {
    strict_success: primary && edits && deps && avoid,
    components: { primary_module: primary, files_to_edit: edits, dependencies_to_read: deps, modules_to_avoid: avoid },
    file_precision: precision, file_recall: recall, file_f1: f1,
    forbidden_selection: forbiddenSelected.length > 0,
  };
}
async function callModel(body) {
  let last;
  for (let attempt = 1; attempt <= 5; attempt++) {
    const started = performance.now();
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Accept':'application/vnd.github+json','Authorization':`Bearer ${token}`,'Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28' },
      body: JSON.stringify(body)
    });
    const text = await res.text();
    const latency_ms = performance.now() - started;
    if (res.ok) return { json: JSON.parse(text), latency_ms, attempts: attempt };
    last = { status: res.status, text: text.slice(0,2000), latency_ms };
    if (![408,409,429,500,502,503,504].includes(res.status) || attempt === 5) break;
    const retryAfter = Number(res.headers.get('retry-after') || 0);
    await sleep(Math.max(retryAfter * 1000, 1500 * 2 ** (attempt - 1)));
  }
  throw new Error(`model request failed: ${JSON.stringify(last)}`);
}

const jobs = [];
for (const task of dataset.tasks) {
  for (let repetition = 1; repetition <= dataset.repetitions_per_condition; repetition++) {
    for (const condition of dataset.conditions) {
      jobs.push({ task, repetition, condition, order_key: sha(`${dataset.dataset_sha256}:${task.id}:${repetition}:${condition}`) });
    }
  }
}
jobs.sort((a,b) => a.order_key.localeCompare(b.order_key));

const results = [];
for (let i=0; i<jobs.length; i++) {
  const { task, repetition, condition } = jobs[i];
  const context = condition === 'baseline_workspace_wide' ? dataset.baseline_context : task.treatment_context;
  const user = `TASK:\n${task.task}\n\nREPOSITORY CONTEXT:\n${context}\n\nReturn the required JSON navigation decision.`;
  const request = {
    model: dataset.model,
    messages: [{role:'system',content:SYSTEM},{role:'user',content:user}],
    temperature: 0.1,
    max_tokens: 400,
    response_format: { type: 'json_object' }
  };
  const request_sha256 = sha(request);
  let record;
  try {
    const reply = await callModel(request);
    const content = reply.json?.choices?.[0]?.message?.content ?? '';
    const answer = extractJson(content);
    record = {
      id: `${task.id}:${condition}:r${repetition}`,
      task_id: task.id, condition, repetition,
      model: dataset.model, request_sha256,
      response_id: reply.json?.id || null,
      finish_reason: reply.json?.choices?.[0]?.finish_reason || null,
      answer, score: score(task,answer),
      provider_usage: reply.json?.usage || null,
      latency_ms: Number(reply.latency_ms.toFixed(3)),
      infrastructure_attempts: reply.attempts,
      status: 'completed'
    };
  } catch (error) {
    record = { id:`${task.id}:${condition}:r${repetition}`, task_id:task.id, condition, repetition, model:dataset.model, request_sha256, status:'infrastructure_failure', error:String(error.message || error) };
  }
  results.push(record);
  console.log(`${i+1}/${jobs.length} ${record.id} ${record.status}${record.score ? ` strict=${record.score.strict_success}` : ''}`);
}

function aggregate(condition) {
  const rows = results.filter(r => r.condition === condition && r.status === 'completed');
  const strict = rows.filter(r => r.score.strict_success).length;
  const avg = (f) => rows.length ? rows.reduce((s,r)=>s+f(r),0)/rows.length : null;
  const usageRows = rows.filter(r => r.provider_usage && Number.isFinite(r.provider_usage.prompt_tokens));
  return {
    condition,
    runs_planned: dataset.tasks.length * dataset.repetitions_per_condition,
    runs_completed: rows.length,
    strict_successes: strict,
    strict_accuracy: rows.length ? strict/rows.length : null,
    component_accuracy: {
      primary_module: avg(r=>Number(r.score.components.primary_module)),
      files_to_edit: avg(r=>Number(r.score.components.files_to_edit)),
      dependencies_to_read: avg(r=>Number(r.score.components.dependencies_to_read)),
      modules_to_avoid: avg(r=>Number(r.score.components.modules_to_avoid)),
    },
    mean_file_f1: avg(r=>r.score.file_f1),
    forbidden_selection_rate: avg(r=>Number(r.score.forbidden_selection)),
    mean_latency_ms: avg(r=>r.latency_ms),
    provider_usage_available: usageRows.length === rows.length && rows.length > 0,
    prompt_tokens_total: usageRows.length ? usageRows.reduce((s,r)=>s+r.provider_usage.prompt_tokens,0) : null,
    completion_tokens_total: usageRows.length ? usageRows.reduce((s,r)=>s+r.provider_usage.completion_tokens,0) : null,
  };
}
const baseline = aggregate('baseline_workspace_wide');
const treatment = aggregate('knowledge_task_scoped');
const paired = dataset.tasks.map(task => {
  const b = results.filter(r=>r.task_id===task.id && r.condition==='baseline_workspace_wide' && r.status==='completed');
  const t = results.filter(r=>r.task_id===task.id && r.condition==='knowledge_task_scoped' && r.status==='completed');
  return { task_id:task.id, baseline_strict:b.filter(r=>r.score.strict_success).length, treatment_strict:t.filter(r=>r.score.strict_success).length, repetitions:dataset.repetitions_per_condition };
});
const promptReduction = baseline.prompt_tokens_total && treatment.prompt_tokens_total !== null ? (baseline.prompt_tokens_total-treatment.prompt_tokens_total)/baseline.prompt_tokens_total : null;
const report = {
  schema_version:'pro2pilot-model-navigation-accuracy-report.v1',
  generated_at:new Date().toISOString(),
  status: results.some(r=>r.status!=='completed') ? 'completed_with_infrastructure_failures' : 'completed',
  pre_registration_sha256: sha(fs.readFileSync(new URL('./PRE-REGISTRATION.md',import.meta.url))),
  candidate:dataset.candidate,
  dataset_sha256:dataset.dataset_sha256,
  model:dataset.model,
  calls_planned:jobs.length,
  calls_completed:results.filter(r=>r.status==='completed').length,
  baseline, treatment,
  effect:{
    strict_accuracy_absolute_delta: treatment.strict_accuracy!==null && baseline.strict_accuracy!==null ? treatment.strict_accuracy-baseline.strict_accuracy : null,
    strict_accuracy_relative_lift: baseline.strict_accuracy ? (treatment.strict_accuracy-baseline.strict_accuracy)/baseline.strict_accuracy : null,
    provider_prompt_token_reduction: promptReduction,
  },
  paired,
  results,
  claim_boundary:'Controlled synthetic repository-navigation accuracy for one model; not general coding accuracy, production error rate, or universal model improvement.'
};
fs.mkdirSync('model-study-output',{recursive:true});
fs.writeFileSync('model-study-output/report.json',JSON.stringify(report,null,2)+'\n');
fs.writeFileSync('model-study-output/results.ndjson',results.map(r=>JSON.stringify(r)).join('\n')+'\n');
fs.writeFileSync('model-study-output/summary.md',`# Model navigation accuracy study\n\n- Candidate: ${dataset.candidate.name} (${dataset.candidate.sha256})\n- Model: ${dataset.model}\n- Baseline strict accuracy: ${baseline.strict_successes}/${baseline.runs_completed} (${baseline.strict_accuracy===null?'n/a':(baseline.strict_accuracy*100).toFixed(1)+'%'})\n- Task-scoped strict accuracy: ${treatment.strict_successes}/${treatment.runs_completed} (${treatment.strict_accuracy===null?'n/a':(treatment.strict_accuracy*100).toFixed(1)+'%'})\n- Absolute delta: ${report.effect.strict_accuracy_absolute_delta===null?'n/a':(report.effect.strict_accuracy_absolute_delta*100).toFixed(1)+' percentage points'}\n- Provider prompt-token reduction: ${promptReduction===null?'unavailable':(promptReduction*100).toFixed(1)+'%'}\n\nThis is a controlled repository-navigation benchmark, not a claim of general coding accuracy.\n`);
if (report.status !== 'completed') process.exitCode = 2;
