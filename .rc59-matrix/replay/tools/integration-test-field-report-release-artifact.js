#!/usr/bin/env node
'use strict';

// Physical, producer-to-consumer Field Report check. It intentionally executes
// only the bytes in a release ZIP; no Field Report source files are imported
// from this checkout into the fixture.

const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { readZipEntries, validate } = require('./validate-release-artifact');

const root = path.resolve(__dirname, '..');

function parseArgs(argv = process.argv.slice(2)) {
  const args = { artifact: null, outDir: null, mode: 'after', keepFixture: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--artifact') args.artifact = argv[++index];
    else if (arg.startsWith('--artifact=')) args.artifact = arg.slice('--artifact='.length);
    else if (arg === '--out-dir') args.outDir = argv[++index];
    else if (arg.startsWith('--out-dir=')) args.outDir = arg.slice('--out-dir='.length);
    else if (arg === '--mode') args.mode = argv[++index] || args.mode;
    else if (arg.startsWith('--mode=')) args.mode = arg.slice('--mode='.length);
    else if (arg === '--keep-fixture') args.keepFixture = true;
  }
  if (!args.artifact) throw new Error('--artifact is required');
  if (!['before', 'after'].includes(args.mode)) throw new Error('--mode must be before or after');
  return args;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeText(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, String(value), 'utf8');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function safeName(value) {
  return String(value).replace(/[^A-Za-z0-9._-]+/g, '-');
}

function command(record, rawDir, id, commandName, commandArgs, options = {}) {
  const started = new Date().toISOString();
  const result = childProcess.spawnSync(commandName, commandArgs, {
    cwd: options.cwd,
    env: { ...process.env, KNOWLEDGE_FLOW_NO_OPEN: '1', ...(options.env || {}) },
    encoding: 'utf8',
    windowsHide: true,
    timeout: options.timeout || 180000
  });
  const stdout = result.stdout || '';
  const stderr = result.stderr || '';
  const item = {
    id,
    command: [commandName, ...commandArgs].join(' '),
    started_at: started,
    finished_at: new Date().toISOString(),
    exit_code: Number.isInteger(result.status) ? result.status : 1,
    stdout_path: `raw/${safeName(id)}.stdout.txt`,
    stderr_path: `raw/${safeName(id)}.stderr.txt`,
    result_path: `raw/${safeName(id)}.result.json`
  };
  writeText(path.join(rawDir, `${safeName(id)}.stdout.txt`), stdout);
  writeText(path.join(rawDir, `${safeName(id)}.stderr.txt`), stderr);
  writeJson(path.join(rawDir, `${safeName(id)}.result.json`), {
    ...item,
    error: result.error ? String(result.error.message || result.error) : null,
    signal: result.signal || null
  });
  record.push(item);
  if (item.exit_code !== 0 || result.error) {
    throw new Error(`${id} failed (exit ${item.exit_code}): ${stderr.trim() || result.error?.message || 'no stderr'}`);
  }
  try { item.json = JSON.parse(stdout.trim()); } catch { item.json = null; }
  return item;
}

function assertion(record, rawDir, id, pass, details) {
  const item = {
    id,
    command: '<internal assertion>',
    exit_code: pass ? 0 : 1,
    stdout_path: `raw/${safeName(id)}.stdout.txt`,
    stderr_path: `raw/${safeName(id)}.stderr.txt`,
    result_path: `raw/${safeName(id)}.result.json`
  };
  writeText(path.join(rawDir, `${safeName(id)}.stdout.txt`), `${JSON.stringify(details, null, 2)}\n`);
  writeText(path.join(rawDir, `${safeName(id)}.stderr.txt`), pass ? '' : 'assertion failed\n');
  writeJson(path.join(rawDir, `${safeName(id)}.result.json`), { ...item, details });
  record.push(item);
  if (!pass) throw new Error(`${id} failed: ${JSON.stringify(details)}`);
}

function extractArtifact(artifact, fixtureRoot) {
  const zip = readZipEntries(artifact);
  if (zip.violations.length) throw new Error(`artifact parse failed: ${JSON.stringify(zip.violations)}`);
  for (const entry of zip.entries) {
    if (!entry.name.startsWith('.knowledge/')) throw new Error(`unsafe artifact entry: ${entry.name}`);
    const target = path.resolve(fixtureRoot, entry.name);
    if (!target.startsWith(`${path.resolve(fixtureRoot)}${path.sep}`)) throw new Error(`artifact traversal: ${entry.name}`);
    ensureDir(path.dirname(target));
    fs.writeFileSync(target, entry.body);
  }
  return zip.entries.map((entry) => entry.name).sort();
}

function fixtureModules(knowledgeRoot) {
  const modulesRoot = path.join(knowledgeRoot, 'modules');
  ensureDir(modulesRoot);
  const cards = [
    {
      module_id: 'physical-suspect',
      name: 'Physical suspect fixture module',
      path: 'src/physical-suspect.js',
      confidence: 'medium',
      verification_status: 'routing_verified',
      purpose: 'Creates an evidence coverage gap so flow release produces suspect trust.',
      key_files: ['src/physical-suspect.js'],
      evidence_files: []
    },
    {
      module_id: 'physical-low',
      name: 'Physical low-confidence fixture module',
      path: 'src/physical-low.js',
      confidence: 'low',
      verification_status: 'docs_only',
      purpose: 'Exercises the independently collected low-confidence trust bucket.',
      key_files: ['src/physical-low.js'],
      evidence_files: []
    }
  ];
  for (const card of cards) writeJson(path.join(modulesRoot, `${card.module_id}.json`), card);
  writeJson(path.join(modulesRoot, 'module_registry.json'), {
    generated_at: new Date().toISOString(),
    generated_by: 'physical-field-report-fixture',
    merge_mode: 'replace',
    modules: cards.map((card) => ({
      module_id: card.module_id,
      name: card.name,
      path: card.path,
      card: `.knowledge/modules/${card.module_id}.json`,
      confidence: card.confidence,
      current_trust_level: 'routing_trusted',
      key_files: card.key_files,
      evidence_files: card.evidence_files,
      purpose: card.purpose,
      target_trust_level: 'routing_trusted'
    }))
  });
  ensureDir(path.join(path.dirname(knowledgeRoot), 'src'));
  writeText(path.join(path.dirname(knowledgeRoot), 'src', 'physical-suspect.js'), 'export const suspect = true;\n');
  writeText(path.join(path.dirname(knowledgeRoot), 'src', 'physical-low.js'), 'export const low = true;\n');
}

function answers() {
  const prose = [
    'no comparable baseline',
    'there was no performance conclusion',
    'turned off manually',
    'yes, but only after review',
    'the issue remains open',
    'the old workflow was closed manually',
    'the result was not clearly improved',
    'we used the off mode once',
    '`no_clear_change`',
    '```text\nclearly_improved\n```',
    '[workflow](https://example.invalid/no_clear_change)',
    '| Status | Note |\n|---|---|\n| no_clear_change | unchanged prose |'
  ].join('\n');
  return {
    'project-context': 'An anonymized JavaScript fixture repository.',
    'keep-using': 'yes',
    'quick-summary': prose,
    'installation-method': 'Physical release asset',
    'workflow-fit': 'few_extra_steps',
    'agent-intervention': 'once_or_twice',
    'workflow-notes': prose,
    'main-scenario': 'A controlled Field Report producer-to-consumer integration task.',
    'accuracy-change': 'slightly_improved',
    'accuracy-example': 'The collector retained the real flow-release trust facts.',
    'accuracy-basis': 'objective_test_result',
    'accuracy-sample-count': 2,
    'speed-scope': 'first_useful_response',
    'response-speed-change': 'slightly_faster',
    'response-speed-percent': 12,
    'response-speed-basis': 'estimated_from_comparable_tasks',
    'response-speed-sample-count': 2,
    'response-speed-notes': 'there was no performance conclusion',
    'useful-parts': 'Trust routing and evidence provenance.',
    'observed-results': prose,
    'what-did-not-work': prose,
    'previous-workflow-comparison': prose,
    'final-assessment': prose,
    'github-publication-permission': 'github_publication_allowed',
    'publication-permission': 'github_only'
  };
}

function factSummary(facts) {
  const fact = (id) => facts.values?.[id] || null;
  return {
    stale_artifacts_total: fact('stale_artifacts_total'),
    modules_suspect: fact('modules_suspect'),
    modules_low_confidence: fact('modules_low_confidence'),
    modules_needing_recheck: fact('modules_needing_recheck'),
    repair_open: fact('repair_open'),
    repair_closed: fact('repair_closed'),
    repair_reopened: fact('repair_reopened'),
    repair_unmanaged: fact('repair_unmanaged'),
    facts_observed: facts.facts_observed,
    facts_derived: facts.facts_derived,
    facts_unavailable: facts.facts_unavailable,
    facts_with_warnings: facts.facts_with_warnings
  };
}

function writeMarkdown(report, destination) {
  const commands = report.commands.map((item) =>
    `| ${item.id} | ${item.exit_code} | \`${item.command}\` |`
  ).join('\n');
  const facts = report.facts?.actual || {};
  const factRows = Object.entries(facts).map(([id, value]) =>
    `| ${id} | ${value?.value ?? value ?? 'unavailable'} | ${value?.kind || ''} |`
  ).join('\n');
  writeText(destination, [
    '# Physical Field Report integration',
    '',
    `Status: **${report.status}**`,
    '',
    `- Candidate: \`${report.candidate.zip_path}\``,
    `- Candidate SHA-256: \`${report.candidate.sha256}\``,
    `- Mode: \`${report.mode}\``,
    `- Started: ${report.started_at}`,
    `- Finished: ${report.finished_at}`,
    '',
    '## Commands',
    '',
    '| Step | Exit | Command |',
    '|---|---:|---|',
    commands,
    '',
    '## Collected facts',
    '',
    '| Fact | Value | Kind |',
    '|---|---:|---|',
    factRows,
    '',
    '## Assertions',
    '',
    `- Prose preservation: ${report.assertions.prose_preservation.status}`,
    `- Typed enum rendering: ${report.assertions.typed_enum.status}`,
    `- Redaction: ${report.assertions.redaction.status}`,
    `- Approval: ${report.assertions.approval.status}`,
    `- Offline dry-run publication preview: ${report.assertions.dry_run_publication.status}`,
    `- Re-render idempotence: ${report.assertions.idempotence.status}`,
    ''
  ].join('\n'));
}

function main() {
  const args = parseArgs();
  const artifact = path.resolve(args.artifact);
  const startedAt = new Date().toISOString();
  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.resolve(args.outDir || path.join(root, 'docs', 'release', '3.3.0', 'test-evidence', 'physical-integration', runId));
  const rawDir = path.join(outDir, 'raw');
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-physical-field-report-'));
  const commands = [];
  const report = {
    schema_version: 'knowledge-physical-field-report-integration.v1',
    mode: args.mode,
    source_commit_sha: null,
    candidate: { zip_path: artifact, sha256: sha256(fs.readFileSync(artifact)), inventory_path: 'inventory.json' },
    environment: { os: `${process.platform}/${process.arch}`, node_version: process.version },
    started_at: startedAt,
    finished_at: null,
    commands,
    trust: { expected: { suspect: 1, low_confidence: 1, needing_recheck: 2 }, actual: null },
    repair: { expected: 'flow-generated queue', actual: null },
    facts: { expected: null, actual: null },
    assertions: {},
    artifact_paths: {},
    fixture_cleanup: null,
    status: 'failed',
    error: null
  };

  try {
    ensureDir(rawDir);
    const validation = validate(artifact, { profile: 'public_runtime' });
    assertion(commands, rawDir, 'validate-artifact', validation.status === 'ok', validation);
    const entries = extractArtifact(artifact, fixtureRoot);
    writeJson(path.join(outDir, 'inventory.json'), { entries, entries_total: entries.length });
    const forbidden = [
      '.knowledge/release-policy.json',
      '.knowledge/tools/package-release.js',
      '.knowledge/tools/release-gate.js',
      '.knowledge/internal/release-gates.md'
    ];
    assertion(commands, rawDir, 'artifact-boundary', forbidden.every((entry) => !entries.includes(entry)), { forbidden, entries_total: entries.length });
    writeJson(path.join(fixtureRoot, 'package.json'), { name: 'physical-field-report-fixture', private: true, version: '1.0.0' });
    writeText(path.join(fixtureRoot, 'README.md'), '# physical fixture\n');
    command(commands, rawDir, 'git-init', 'git', ['init'], { cwd: fixtureRoot });
    command(commands, rawDir, 'git-config-email', 'git', ['config', 'user.email', 'field-report@example.invalid'], { cwd: fixtureRoot });
    command(commands, rawDir, 'git-config-name', 'git', ['config', 'user.name', 'Field Report Fixture'], { cwd: fixtureRoot });
    const node = process.execPath;
    const tool = (name, argsList) => command(commands, rawDir, name, node, [path.join('.knowledge', 'tools', name.includes('field-report') ? 'field-report.js' : 'flow.js'), ...argsList], { cwd: fixtureRoot });
    command(commands, rawDir, 'install-check', node, ['.knowledge/tools/install-check.js', '--json'], { cwd: fixtureRoot });
    command(commands, rawDir, 'flow-import', node, ['.knowledge/tools/flow.js', 'import', '--json'], { cwd: fixtureRoot, timeout: 300000 });
    fixtureModules(path.join(fixtureRoot, '.knowledge'));
    assertion(commands, rawDir, 'configure-real-trust-input', true, { module_registry: '.knowledge/modules/module_registry.json', cards: ['physical-suspect', 'physical-low'] });
    command(commands, rawDir, 'flow-release', node, ['.knowledge/tools/flow.js', 'release', '--json'], { cwd: fixtureRoot, timeout: 300000 });
    const trustPath = path.join(fixtureRoot, '.knowledge', 'maintenance', 'trust_report.json');
    const queuePath = path.join(fixtureRoot, '.knowledge', 'maintenance', 'repair_queue.json');
    const requiredArtifacts = [trustPath, queuePath, path.join(fixtureRoot, '.knowledge', 'maintenance', 'quality_report.json'), path.join(fixtureRoot, '.knowledge', 'maintenance', 'routing_bundle.json')];
    assertion(commands, rawDir, 'flow-artifacts', requiredArtifacts.every(fs.existsSync), { artifacts: requiredArtifacts });
    const trust = JSON.parse(fs.readFileSync(trustPath, 'utf8'));
    report.trust.actual = {
      suspect: (trust.modules?.suspect || []).length,
      low_confidence: (trust.modules?.low_confidence || []).length,
      stale_artifacts_total: trust.stale_artifacts_total
    };
    assertion(commands, rawDir, 'real-flow-trust', report.trust.actual.suspect === 1 && report.trust.actual.low_confidence === 1, report.trust);
    const started = command(commands, rawDir, 'field-report-start', node, ['.knowledge/tools/field-report.js', 'start', '--new', '--anonymize', '--json'], { cwd: fixtureRoot });
    const reportId = started.json?.report_id;
    if (!reportId) throw new Error('field-report start did not return report_id');
    const statusBefore = command(commands, rawDir, 'field-report-status-before', node, ['.knowledge/tools/field-report.js', 'status', `--report-id=${reportId}`, '--json'], { cwd: fixtureRoot });
    const factsPath = statusBefore.json?.paths?.facts;
    if (!factsPath) throw new Error('field-report status did not return facts path');
    const facts = JSON.parse(fs.readFileSync(factsPath, 'utf8'));
    report.facts.actual = factSummary(facts);
    report.repair.actual = ['repair_open', 'repair_closed', 'repair_reopened', 'repair_unmanaged'].reduce((result, id) => ({ ...result, [id]: facts.values[id] }), {});
    const observed = (id) => facts.values?.[id]?.kind === 'observed';
    const expectedObserved = ['stale_artifacts_total', 'modules_suspect', 'modules_low_confidence', 'modules_needing_recheck'];
    const factContract = expectedObserved.every(observed) &&
      facts.values.modules_suspect.value === 1 &&
      facts.values.modules_low_confidence.value === 1 &&
      facts.values.modules_needing_recheck.value === 2;
    if (args.mode === 'before') {
      assertion(commands, rawDir, 'before-fix-trust-defect', !factContract, { actual: report.facts.actual });
    } else {
      assertion(commands, rawDir, 'after-fix-trust-contract', factContract, { actual: report.facts.actual });
    }
    const answersPath = path.join(outDir, 'controlled-answers.json');
    const suppliedAnswers = answers();
    writeJson(answersPath, suppliedAnswers);
    command(commands, rawDir, 'field-report-ingest', node, ['.knowledge/tools/field-report.js', 'ingest', `--report-id=${reportId}`, `--answers=${answersPath}`, '--json'], { cwd: fixtureRoot });
    const rendered = command(commands, rawDir, 'field-report-render', node, ['.knowledge/tools/field-report.js', 'render', `--report-id=${reportId}`, '--json'], { cwd: fixtureRoot });
    const publicPath = rendered.json?.public_path;
    const draftPath = rendered.json?.draft_path;
    if (!publicPath || !draftPath) throw new Error('render did not return public and draft paths');
    const publicBody = fs.readFileSync(publicPath, 'utf8');
    const prose = suppliedAnswers['quick-summary'];
    const prosePreserved = publicBody.includes(prose);
    const typedEnums = publicBody.includes('**Accuracy assessment:** Slightly improved') && !publicBody.includes('**Accuracy assessment:** slightly_improved');
    if (args.mode === 'before') {
      assertion(commands, rawDir, 'before-fix-prose-defect', !prosePreserved, { prose_preserved: prosePreserved });
    } else {
      assertion(commands, rawDir, 'after-fix-prose-preservation', prosePreserved, { prose_preserved: prosePreserved });
      assertion(commands, rawDir, 'typed-enum-rendering', typedEnums, { typed_enum_humanized: typedEnums });
    }
    if (args.mode === 'before') {
      report.assertions = {
        prose_preservation: { status: prosePreserved ? 'unexpected-pass' : 'defect-reproduced', expected: false, actual: prosePreserved },
        typed_enum: { status: 'not-applicable', expected: 'post-fix only', actual: null },
        redaction: { status: 'not-run', expected: 'post-fix only', actual: null },
        approval: { status: 'not-run', expected: 'post-fix only', actual: null },
        dry_run_publication: { status: 'not-run', expected: 'post-fix only', actual: null },
        idempotence: { status: 'not-run', expected: 'post-fix only', actual: null }
      };
      report.artifact_paths = { fixture_report_id: reportId, facts: factsPath, answers: answersPath, public: publicPath, draft: draftPath };
      report.status = 'pass';
      return;
    }
    const firstBodyHash = sha256(publicBody);
    const approval = command(commands, rawDir, 'field-report-approve', node, ['.knowledge/tools/field-report.js', 'approve', `--report-id=${reportId}`, '--yes', '--tester-actor=field-report-tester', '--json'], { cwd: fixtureRoot });
    const preview = command(commands, rawDir, 'field-report-publish-dry-run', node, ['.knowledge/tools/field-report.js', 'publish', `--report-id=${reportId}`, '--dry-run', '--yes', '--tester-actor=field-report-tester', '--json'], { cwd: fixtureRoot });
    const rerendered = command(commands, rawDir, 'field-report-render-repeat', node, ['.knowledge/tools/field-report.js', 'render', `--report-id=${reportId}`, '--json'], { cwd: fixtureRoot });
    const secondBodyHash = sha256(fs.readFileSync(rerendered.json?.public_path, 'utf8'));
    const statusAfter = command(commands, rawDir, 'field-report-status-after', node, ['.knowledge/tools/field-report.js', 'status', `--report-id=${reportId}`, '--json'], { cwd: fixtureRoot });
    const redaction = JSON.parse(fs.readFileSync(statusAfter.json.paths.redaction_report, 'utf8'));
    const previewFile = JSON.parse(fs.readFileSync(statusAfter.json.paths.publication_preview, 'utf8'));
    const title = fs.readFileSync(statusAfter.json.paths.discussion_title, 'utf8');
    const body = fs.readFileSync(statusAfter.json.paths.discussion_body, 'utf8');
    report.assertions = {
      prose_preservation: { status: prosePreserved ? 'pass' : 'fail', expected: true, actual: prosePreserved },
      typed_enum: { status: typedEnums ? 'pass' : 'fail', expected: true, actual: typedEnums },
      redaction: { status: redaction.status === 'pass' ? 'pass' : 'fail', expected: 'pass', actual: redaction.status },
      approval: { status: approval.json?.status === 'approved' ? 'pass' : 'fail', expected: 'approved', actual: approval.json?.status || null },
      dry_run_publication: { status: preview.json?.dry_run === true ? 'pass' : 'fail', expected: true, actual: preview.json?.dry_run, network: 'not invoked by default dry-run' },
      idempotence: { status: firstBodyHash === secondBodyHash ? 'pass' : 'fail', expected: firstBodyHash, actual: secondBodyHash }
    };
    assertion(commands, rawDir, 'publication-and-idempotence', Object.values(report.assertions).every((item) => item.status === 'pass'), report.assertions);
    report.artifact_paths = {
      fixture_report_id: reportId,
      facts: factsPath,
      answers: answersPath,
      public: publicPath,
      draft: draftPath,
      title: statusAfter.json.paths.discussion_title,
      body: statusAfter.json.paths.discussion_body,
      publication_preview: statusAfter.json.paths.publication_preview,
      publication: statusAfter.json.paths.publication,
      preview_hash: previewFile.preview_hash,
      body_sha256: sha256(body),
      title_sha256: sha256(title)
    };
    report.status = 'pass';
  } catch (error) {
    report.error = error.message;
  } finally {
    report.finished_at = new Date().toISOString();
    if (args.keepFixture) report.fixture_cleanup = { status: 'kept', path: fixtureRoot };
    else {
      try {
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
        report.fixture_cleanup = { status: 'removed_after_reports', path: '<temporary fixture>' };
      } catch (error) {
        report.fixture_cleanup = { status: 'failed', error: error.message };
      }
    }
    writeJson(path.join(outDir, 'physical-integration-report.json'), report);
    writeMarkdown(report, path.join(outDir, 'physical-integration-report.md'));
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status !== 'pass') process.exitCode = 2;
}

if (require.main === module) main();

module.exports = { answers, extractArtifact, fixtureModules, main };
