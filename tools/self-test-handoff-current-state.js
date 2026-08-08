#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const { systemVersion } = require('./lib/system-version');

const sourceKnowledgeRoot = path.resolve(__dirname, '..');
const keepTemp = process.argv.includes('--keep-temp');
let fixtureRoot = null;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function copyKnowledgeRuntime(repoRoot) {
  fs.cpSync(sourceKnowledgeRoot, path.join(repoRoot, '.knowledge'), {
    recursive: true,
    force: true,
    filter: (source) => {
      const rel = path.relative(sourceKnowledgeRoot, source).replace(/\\/g, '/');
      return !rel || (!rel.startsWith('dist/') && !rel.startsWith('.lock/'));
    }
  });
}

function fixtureSyncEnv(repoRoot, phase) {
  const env = { ...process.env };
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
    'KNOWLEDGE_REPO_ID'
  ]);
  for (const key of Object.keys(env)) {
    if (controlledKeys.has(key.toUpperCase())) delete env[key];
  }
  return {
    ...env,
    KNOWLEDGE_MODE: 'repo',
    KNOWLEDGE_SYSTEM_ROOT: path.join(repoRoot, '.knowledge'),
    KNOWLEDGE_TARGET_ROOT: repoRoot,
    KNOWLEDGE_AGENT_ID: `handoff-current-state-${phase}`,
    KNOWLEDGE_DISABLE_GIT_DISCOVERY: '0',
    KNOWLEDGE_FLOW_NO_OPEN: '1',
    KNOWLEDGE_INSPECTOR_NO_OPEN: '1'
  };
}

function runSync(repoRoot, phase) {
  const result = spawnSync(process.execPath, [path.join(repoRoot, '.knowledge', 'tools', 'sync-tracked.js'), '--scan'], {
    cwd: repoRoot,
    env: fixtureSyncEnv(repoRoot, phase),
    encoding: 'utf8',
    windowsHide: true,
    timeout: 120000
  });
  assert(result.status === 0, `sync failed in ${phase}: ${result.stderr || result.stdout}`);
  return JSON.parse(result.stdout);
}

function writeContradictions(repoRoot, items) {
  writeJson(path.join(repoRoot, '.knowledge', 'contradictions.json'), {
    schema_version: systemVersion(),
    generated_at: new Date().toISOString(),
    items
  });
}

function validateCurrentHandoff(repoRoot, expectedRisk, phase) {
  const knowledgeRoot = path.join(repoRoot, '.knowledge');
  const handoff = readJson(path.join(knowledgeRoot, 'maintenance', 'handoff_summary.json'));
  const trust = readJson(path.join(knowledgeRoot, 'maintenance', 'trust_report.json'));
  const registry = readJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'));
  const criticalPaths = readJson(path.join(knowledgeRoot, 'maps', 'critical_paths.json'));
  const moduleIds = new Set((registry.modules || []).map((item) => item.module_id));
  const currentRisk = Array.from(new Set([
    ...(trust.modules?.suspect || []),
    ...(trust.modules?.low_confidence || [])
  ]));

  assert(JSON.stringify(handoff.highest_risk_modules) === JSON.stringify(currentRisk), `${phase}: highest_risk_modules is not current trust risk`);
  assert(JSON.stringify(handoff.highest_risk_modules) === JSON.stringify(expectedRisk), `${phase}: unexpected risk modules`);
  assert(JSON.stringify(handoff.current_risk_tiers?.suspect || []) === JSON.stringify(trust.modules?.suspect || []), `${phase}: suspect tier mismatch`);
  assert(JSON.stringify(handoff.current_risk_tiers?.low_confidence || []) === JSON.stringify(trust.modules?.low_confidence || []), `${phase}: low-confidence tier mismatch`);

  for (const moduleId of [
    ...(handoff.trusted_modules || []),
    ...(handoff.near_trusted_modules || []),
    ...(handoff.routing_only_modules || []),
    ...(handoff.non_authoritative_modules || []),
    ...(handoff.highest_risk_modules || [])
  ]) {
    assert(moduleIds.has(moduleId), `${phase}: handoff references unknown module ${moduleId}`);
  }

  for (const rel of handoff.new_chat_first_files || []) {
    const normalized = String(rel).replace(/^\.knowledge[\\/]/, '');
    assert(fs.existsSync(path.join(knowledgeRoot, normalized)), `${phase}: missing first-read path ${rel}`);
  }

  assert(handoff.critical_paths_total === (criticalPaths.paths || []).length, `${phase}: critical path total mismatch`);
  assert(Array.isArray(handoff.critical_path_summary), `${phase}: critical_path_summary missing`);
  assert(handoff.critical_path_summary.length === (criticalPaths.paths || []).length, `${phase}: critical path summary size mismatch`);
  assert(handoff.critical_path_summary_truncated === false, `${phase}: fixture summary must not be truncated`);
  for (const item of handoff.critical_path_summary) {
    const source = (criticalPaths.paths || []).find((candidate) => candidate.id === item.id);
    assert(source, `${phase}: summary references unknown critical path ${item.id}`);
    assert(item.status === (source.test_linkage?.status || 'unknown'), `${phase}: critical path status mismatch for ${item.id}`);
    assert(JSON.stringify(item.gaps) === JSON.stringify(source.test_linkage?.gaps || []), `${phase}: critical path gaps mismatch for ${item.id}`);
    for (const moduleId of item.modules || []) assert(moduleIds.has(moduleId), `${phase}: critical path references unknown module ${moduleId}`);
    for (const rel of item.linked_tests || []) assert(fs.existsSync(path.join(repoRoot, rel)), `${phase}: missing linked test ${rel}`);
  }

  return {
    phase,
    highest_risk_modules: handoff.highest_risk_modules,
    current_risk_tiers: handoff.current_risk_tiers,
    critical_path_ids: handoff.critical_path_summary.map((item) => item.id)
  };
}

function createFixture() {
  fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-handoff-current-state-'));
  const repoRoot = path.join(fixtureRoot, 'repo with spaces');
  fs.mkdirSync(repoRoot, { recursive: true });
  copyKnowledgeRuntime(repoRoot);

  const files = {
    'alpha/package.json': '{"name":"alpha","version":"1.0.0"}\n',
    'alpha/src/index.js': 'module.exports = () => "alpha";\n',
    'alpha/test/index.test.js': 'require("../src")();\n',
    'beta/package.json': '{"name":"beta","version":"1.0.0"}\n',
    'beta/src/index.js': 'module.exports = () => "beta";\n',
    'beta/test/index.test.js': 'require("../src")();\n',
    'README.md': '# Handoff fixture\n'
  };
  for (const [rel, content] of Object.entries(files)) {
    const target = path.join(repoRoot, rel);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, content, 'utf8');
  }

  const knowledgeRoot = path.join(repoRoot, '.knowledge');
  const generatedAt = new Date().toISOString();
  const moduleRows = ['alpha', 'beta'].map((moduleId) => ({
    module_id: moduleId,
    name: moduleId,
    path: `${moduleId}/`,
    card: `.knowledge/modules/${moduleId}.json`,
    confidence: 'high',
    key_files: [`${moduleId}/package.json`, `${moduleId}/src/index.js`, `${moduleId}/test/index.test.js`],
    evidence_files: [`${moduleId}/src/index.js`]
  }));
  writeJson(path.join(knowledgeRoot, 'project_index.json'), {
    schema_version: systemVersion(),
    project_name: 'handoff-current-state-fixture',
    summary: 'Deterministic handoff current-state regression fixture.',
    status: 'verified_fixture',
    modules: moduleRows
  });
  writeJson(path.join(knowledgeRoot, 'modules', 'module_registry.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    generated_by: 'handoff-current-state-fixture',
    modules: moduleRows
  });
  for (const moduleInfo of moduleRows) {
    writeJson(path.join(knowledgeRoot, 'modules', `${moduleInfo.module_id}.json`), {
      schema_version: systemVersion(),
      module_id: moduleInfo.module_id,
      name: moduleInfo.name,
      path: moduleInfo.path,
      confidence: 'high',
      verification_status: 'verified_by_fixture',
      purpose: `${moduleInfo.module_id} fixture module`,
      key_files: moduleInfo.key_files,
      evidence_files: moduleInfo.evidence_files,
      source_of_truth: ['current_code', 'current_tests', '.knowledge/evidence/*.json']
    });
  }

  const trackedFiles = Object.keys(files)
    .filter((rel) => rel !== 'README.md')
    .map((rel) => ({ path: rel, sha256: sha256(path.join(repoRoot, rel)), last_scanned_at: generatedAt, status: 'clean' }));
  writeJson(path.join(knowledgeRoot, 'freshness.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    hash_algorithm: 'sha256',
    tracked_files: trackedFiles,
    artifact_dependencies: {},
    artifact_statuses: {}
  });
  writeJson(path.join(knowledgeRoot, 'maps', 'file_criticality.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    files: Object.keys(files).filter((rel) => rel !== 'README.md').map((rel) => ({
      path: rel,
      classification: rel.includes('/test/') ? 'contextual' : 'important',
      modules: [rel.split('/')[0]],
      source: 'handoff_fixture'
    })),
    coverage_by_module: {}
  });
  writeJson(path.join(knowledgeRoot, 'evidence', 'file_facts.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    facts: ['alpha/package.json', 'alpha/src/index.js', 'beta/package.json', 'beta/src/index.js'].map((file) => ({
      id: `FACT-${file.replace(/[^a-z0-9]+/gi, '-').toUpperCase()}`,
      file,
      sha256: sha256(path.join(repoRoot, file)),
      claim: `Fixture fact for ${file}`,
      evidence_type: 'source_hash'
    }))
  });
  writeContradictions(repoRoot, []);
  writeJson(path.join(knowledgeRoot, 'maps', 'critical_paths.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    paths: [{
      id: 'alpha-to-beta',
      name: 'Alpha to beta verified fixture path',
      modules: ['alpha', 'beta'],
      start_with: ['alpha/src/index.js', 'beta/src/index.js'],
      test_linkage: {
        status: 'verified',
        linked_tests: ['alpha/test/index.test.js', 'beta/test/index.test.js'],
        gaps: [],
        summary: 'Both fixture modules have linked tests.'
      }
    }]
  });
  writeJson(path.join(knowledgeRoot, 'maintenance', 'handoff_summary.json'), {
    schema_version: systemVersion(),
    generated_at: generatedAt,
    generated_by: 'stale-fixture-history',
    project_operational_summary: 'Regression fixture.',
    trusted_modules: [],
    near_trusted_modules: [],
    routing_only_modules: [],
    non_authoritative_modules: [],
    highest_risk_modules: ['historic-module-that-must-be-cleared'],
    new_chat_first_files: [
      '.knowledge/maintenance/routing_bundle.json',
      '.knowledge/project_index.json',
      '.knowledge/maintenance/trust_report.json',
      '.knowledge/maintenance/handoff_summary.json',
      '.knowledge/maps/critical_paths.json'
    ]
  });
  return repoRoot;
}

function main() {
  const repoRoot = createFixture();
  const transitions = [];

  runSync(repoRoot, 'baseline');
  transitions.push(validateCurrentHandoff(repoRoot, [], 'baseline-clears-history'));

  writeContradictions(repoRoot, [{
    id: 'CON-HANDOFF-ALPHA',
    type: 'behavior_contract',
    relation: 'contradicts',
    severity: 'high',
    status: 'open',
    sources: [{ file: 'alpha/src/index.js' }]
  }]);
  runSync(repoRoot, 'alpha-suspect');
  transitions.push(validateCurrentHandoff(repoRoot, ['alpha'], 'alpha-suspect'));

  writeContradictions(repoRoot, [{
    id: 'CON-HANDOFF-ALPHA',
    type: 'behavior_contract',
    relation: 'contradicts',
    severity: 'high',
    status: 'resolved',
    sources: [{ file: 'alpha/src/index.js' }]
  }]);
  runSync(repoRoot, 'alpha-repaired');
  transitions.push(validateCurrentHandoff(repoRoot, [], 'alpha-repaired'));

  writeContradictions(repoRoot, [{
    id: 'CON-HANDOFF-BETA',
    type: 'behavior_contract',
    relation: 'contradicts',
    severity: 'high',
    status: 'open',
    sources: [{ file: 'beta/src/index.js' }]
  }]);
  runSync(repoRoot, 'beta-suspect');
  transitions.push(validateCurrentHandoff(repoRoot, ['beta'], 'beta-suspect'));

  writeContradictions(repoRoot, [{
    id: 'CON-HANDOFF-BETA',
    type: 'behavior_contract',
    relation: 'contradicts',
    severity: 'high',
    status: 'resolved',
    sources: [{ file: 'beta/src/index.js' }]
  }]);
  runSync(repoRoot, 'beta-repaired');
  transitions.push(validateCurrentHandoff(repoRoot, [], 'beta-repaired'));

  const finalHandoff = readJson(path.join(repoRoot, '.knowledge', 'maintenance', 'handoff_summary.json'));
  const output = {
    schema_version: systemVersion(),
    status: 'pass',
    checks: {
      stale_history_cleared: true,
      current_risk_tiers_match_trust_report: true,
      repaired_modules_leave_current_risk: true,
      referenced_modules_and_paths_exist: true,
      critical_path_projection_matches_source: true
    },
    transitions,
    final: {
      highest_risk_modules: finalHandoff.highest_risk_modules,
      current_risk_tiers: finalHandoff.current_risk_tiers,
      critical_path_summary: finalHandoff.critical_path_summary
    },
    fixture_retained: keepTemp,
    fixture_root: keepTemp ? fixtureRoot : null
  };
  console.log(JSON.stringify(output, null, 2));
}

try {
  main();
} catch (error) {
  console.error(error.stack || error.message);
  process.exitCode = 1;
} finally {
  if (fixtureRoot && !keepTemp) fs.rmSync(fixtureRoot, { recursive: true, force: true });
}
