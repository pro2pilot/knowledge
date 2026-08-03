#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const installAgentIntegrations = require('./install-agent-integrations');
const { buildPackageEntries } = require('./package-release');
const { listActions } = require('./lib/action-registry');
const { withTempFixture } = require('./lib/strict-temp-cleanup');

const sourceRoot = path.resolve(__dirname, '..');

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function readText(filePath) {
  return fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, '');
}

function addCheck(checks, id, ok, details = {}) {
  checks.push({ id, status: ok ? 'pass' : 'fail', ...details });
}

function relativeFiles(directory, base = directory, out = []) {
  if (!fs.existsSync(directory)) return out;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) relativeFiles(absolute, base, out);
    else if (entry.isFile()) out.push({ absolute, relative: path.relative(base, absolute).replace(/\\/g, '/') });
  }
  return out;
}

function nodeTargets(text, prefix = '') {
  const targets = [];
  const pattern = /(?:^|[\s`"'=])node\s+(\.knowledge\/)?([A-Za-z0-9_.\-/]+\.js)(?=[\s`"'<]|$)/g;
  for (const match of String(text || '').matchAll(pattern)) {
    targets.push(`${match[1] || prefix}${match[2]}`.replace(/^\.knowledge\//, ''));
  }
  return targets;
}

function readablePublicEntries(root) {
  return buildPackageEntries(root).entries
    .filter((entry) => /\.(?:md|txt|js|json|ya?ml|html|rules)$/i.test(entry.rel))
    .map((entry) => ({ relative: entry.rel, text: readText(entry.abs) }));
}

function addInstalledInterfaceChecks(root, checks, errors, pkg, manifest) {
  const fail = (id, ok, details, message) => {
    addCheck(checks, id, ok, details);
    if (!ok) errors.push(message);
  };
  const publicEntries = readablePublicEntries(root);
  const oldImperative = /estimated\s+tokens\s+saved\s+(?:and|plus)\s+(?:estimated\s+)?percent\s+saved/i;
  const legacyHits = publicEntries.filter((entry) => oldImperative.test(entry.text)).map((entry) => entry.relative);
  fail('installed-interface:no-legacy-metrics-imperative', legacyHits.length === 0, { hits: legacyHits }, `legacy metrics wording remains in public entries: ${legacyHits.join(', ')}`);

  const packageMissing = [];
  for (const [name, command] of Object.entries(pkg?.scripts || {})) {
    for (const target of nodeTargets(command)) {
      if (!fs.existsSync(path.join(root, target))) packageMissing.push({ script: name, target });
    }
  }
  fail('installed-interface:package-script-targets', packageMissing.length === 0, { missing: packageMissing }, `installed package scripts reference missing targets: ${JSON.stringify(packageMissing)}`);

  const docMissing = [];
  for (const entry of publicEntries.filter((item) => item.relative.endsWith('.md'))) {
    for (const target of nodeTargets(entry.text)) {
      if (!fs.existsSync(path.join(root, target))) docMissing.push({ document: entry.relative, target });
    }
  }
  fail('installed-interface:documented-command-targets', docMissing.length === 0, { missing: docMissing }, `public documents reference missing targets: ${JSON.stringify(docMissing)}`);

  const forbidden = ['benchmarks', 'tools/run-benchmarks.js', 'agent-integrations/codex/skills/release-preparation-workflow.md'];
  const publicPaths = new Set(publicEntries.map((entry) => entry.relative));
  const leaked = forbidden.filter((item) => publicPaths.has(item) || Array.from(publicPaths).some((entry) => entry.startsWith(`${item}/`)));
  fail('installed-interface:source-only-paths-absent', leaked.length === 0, { leaked }, `source-only paths leaked into public inventory: ${leaked.join(', ')}`);
  const badScripts = ['kb:benchmarks', 'kb:self-test-team-inspector-json', 'kb:self-test-free-core-graph'].filter((name) => pkg?.scripts?.[name]);
  fail('installed-interface:source-only-scripts-absent', badScripts.length === 0, { scripts: badScripts }, `source-only scripts leaked into installed package.json: ${badScripts.join(', ')}`);

  const contractPath = path.join(root, 'agent-integrations', '_shared', 'metrics-reporting.md');
  const contract = fs.existsSync(contractPath) ? readText(contractPath) : '';
  const meanings = ['workspace-to-task narrowing', 'estimated overhead', 'neutral', 'unavailable / not comparable'];
  const missingMeanings = meanings.filter((term) => !contract.toLowerCase().includes(term));
  fail('installed-interface:four-state-contract', missingMeanings.length === 0 && /not provider-reported model-token usage/i.test(contract), { missing_meanings: missingMeanings }, `shared metrics contract is incomplete: ${missingMeanings.join(', ')}`);

  const expectedTests = [...(manifest?.release_contract?.public_self_test_paths || [])].sort();
  const actualTests = publicEntries.map((entry) => entry.relative).filter((item) => /^tools\/self-test-.*\.js$/i.test(item)).sort();
  fail('installed-interface:public-self-test-allowlist-equality', JSON.stringify(expectedTests) === JSON.stringify(actualTests), { expected: expectedTests, actual: actualTests }, 'public self-test allowlist differs from the packaged self-test inventory');
  const expectedIntegrations = [...(manifest?.release_contract?.public_agent_integration_paths || [])].sort();
  const actualIntegrations = publicEntries.map((entry) => entry.relative).filter((item) => item.startsWith('agent-integrations/')).sort();
  fail('installed-interface:public-integration-allowlist-equality', JSON.stringify(expectedIntegrations) === JSON.stringify(actualIntegrations), { expected_count: expectedIntegrations.length, actual_count: actualIntegrations.length }, 'public integration allowlist differs from the packaged integration inventory');

  const actionMissing = [];
  for (const action of listActions()) {
    for (const target of nodeTargets(action.command || '')) {
      if (!fs.existsSync(path.join(root, target))) actionMissing.push({ action: action.id, target });
    }
  }
  fail('installed-interface:action-registry-targets', actionMissing.length === 0, { missing: actionMissing, actions: listActions().length }, `action registry references missing targets: ${JSON.stringify(actionMissing)}`);

  const inspectorSource = readText(path.join(root, 'tools', 'build-visual-inspector.js'));
  const inspectorTargets = Array.from(new Set(nodeTargets(inspectorSource))).sort();
  const inspectorMissing = inspectorTargets.filter((target) => !fs.existsSync(path.join(root, target)));
  const inspectorLegacy = /benchmarks?\/|run-benchmarks|Benchmark Smoke/i.test(inspectorSource);
  fail('installed-interface:inspector-command-boxes', inspectorMissing.length === 0 && !inspectorLegacy, { targets: inspectorTargets, missing: inspectorMissing, benchmark_reference: inspectorLegacy }, 'Inspector exposes a missing or source-only benchmark command');

  const rcNotes = relativeFiles(path.join(root, '.release-notes'), root)
    .map((item) => item.relative)
    .filter((item) => /(?:step\d+|rc\d+)/i.test(path.basename(item)) && publicPaths.has(item));
  fail('installed-interface:release-note-inventory', rcNotes.length === 0, { internal_rc_notes: rcNotes }, `internal RC notes leaked into public inventory: ${rcNotes.join(', ')}`);

  withTempFixture({ prefix: 'knowledge-public-consistency-' }, (fixture) => {
    const integrationResults = [];
    for (const runtime of ['codex', 'claude', 'opencode', 'openclaw', 'hermes', 'gemini', 'copilot', 'devin', 'windsurf', 'continue', 'roo', 'aider']) {
      const target = path.join(fixture, runtime);
      fs.mkdirSync(target, { recursive: true });
      fs.writeFileSync(path.join(target, 'package.json'), `${JSON.stringify({ name: `fixture-${runtime}`, version: '1.0.0', scripts: {} }, null, 2)}\n`);
      const result = installAgentIntegrations({ __skipCli: true, runtime, systemRoot: root, projectKnowledgeRoot: root, stateRoot: path.join(target, '.state'), targetRoot: target, runInstallCheck: false });
      const generated = relativeFiles(target, target).filter((item) => !item.relative.startsWith('.state/'));
      const combined = generated.filter((item) => /\.(?:md|json|ya?ml)$/i.test(item.relative)).map((item) => readText(item.absolute)).join('\n');
      const missing = [];
      for (const item of generated) {
        if (!/\.(?:md|json|ya?ml)$/i.test(item.relative)) continue;
        for (const commandTarget of nodeTargets(readText(item.absolute))) {
          if (!fs.existsSync(path.join(root, commandTarget))) missing.push({ file: item.relative, target: commandTarget });
        }
      }
      const maintainerLeak = generated.some((item) => /release-preparation-workflow/i.test(item.relative)) || /tools\/package-release\.js/i.test(combined);
      integrationResults.push({ runtime, status: !oldImperative.test(combined) && missing.length === 0 && !maintainerLeak ? 'pass' : 'fail', missing, maintainer_leak: maintainerLeak, installed: result.installed[runtime] });
    }
    const failed = integrationResults.filter((item) => item.status !== 'pass');
    fail('installed-interface:all-generated-integrations', failed.length === 0, { runtimes: integrationResults }, `generated integration failures: ${failed.map((item) => item.runtime).join(', ')}`);
    const codex = integrationResults.find((item) => item.runtime === 'codex');
    const rejected = codex?.installed?.codex_skills_source_only_rejections || [];
    fail('installed-interface:source-only-copy-defense', rejected.includes('agent-integrations/codex/skills/release-preparation-workflow.md'), { rejected }, 'installer did not explicitly reject the source-only release workflow');
  });
}

function currentVersionSection(text, version) {
  const heading = new RegExp(`^##\\s+v?${escapeRegex(version)}(?:\\s|\\b).*?$`, 'mi').exec(text);
  if (!heading) return '';
  const bodyStart = text.indexOf('\n', heading.index + heading[0].length);
  if (bodyStart < 0) return text.slice(heading.index);
  const remainder = text.slice(bodyStart + 1);
  const nextHeading = /^##\s+/m.exec(remainder);
  return text.slice(heading.index, nextHeading ? bodyStart + 1 + nextHeading.index : text.length);
}

function evaluatePublicConsistency(root = sourceRoot) {
  const checks = [];
  const errors = [];
  const requiredFiles = [
    'README.md',
    'INSTALL.md',
    'Quick-Start.md',
    'CHANGELOG.md',
    'RELEASE_NOTES.md',
    'package.json',
    'install-manifest.json'
  ];

  for (const relativePath of requiredFiles) {
    const exists = fs.existsSync(path.join(root, relativePath));
    addCheck(checks, `required:${relativePath}`, exists, { path: relativePath });
    if (!exists) errors.push(`required public/source file is missing: ${relativePath}`);
  }

  let pkg = null;
  try {
    pkg = JSON.parse(readText(path.join(root, 'package.json')));
  } catch (error) {
    errors.push(`package.json is invalid JSON: ${error.message}`);
  }
  const version = String(pkg?.version || '').trim();
  const validVersion = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version);
  addCheck(checks, 'package-version', validVersion, { version: version || null });
  if (!validVersion) errors.push(`package.json version is missing or invalid: ${version || 'missing'}`);

  const releaseNoteRelative = version ? `.release-notes/v${version}.md` : '.release-notes/<unknown>.md';
  const releaseNotePath = path.join(root, releaseNoteRelative);
  const releaseNoteExists = validVersion && fs.existsSync(releaseNotePath);
  addCheck(checks, 'scoped-release-note', releaseNoteExists, { path: releaseNoteRelative });
  if (validVersion && !releaseNoteExists) errors.push(`current release note is missing: ${releaseNoteRelative}`);

  const versionPattern = escapeRegex(version);
  const headingChecks = [
    ['CHANGELOG.md', new RegExp(`^##\\s+v?${versionPattern}(?:\\s|\\b)`, 'mi')],
    ['RELEASE_NOTES.md', new RegExp(`^##\\s+v?${versionPattern}(?:\\s|\\b)`, 'mi')],
    [releaseNoteRelative, new RegExp(`^#\\s+v?${versionPattern}(?:\\s|\\b)`, 'mi')]
  ];
  for (const [relativePath, pattern] of headingChecks) {
    if (!validVersion || !fs.existsSync(path.join(root, relativePath))) continue;
    const matches = pattern.test(readText(path.join(root, relativePath)));
    addCheck(checks, `current-heading:${relativePath}`, matches, { path: relativePath, version });
    if (!matches) errors.push(`${relativePath} has no current ${version} release heading`);
  }

  if (releaseNoteExists) {
    const note = readText(releaseNotePath);
    const provisionalMarkers = [
      /\bpreparation only\b/i,
      /\bplanned verification\b/i,
      /\bnot yet performed\b/i,
      /\bdoes not claim a shipped fix\b/i,
      new RegExp(`\\bno\\s+(?:v)?${versionPattern}\\s+artifact has been packaged\\b`, 'i')
    ];
    const matches = provisionalMarkers
      .map((pattern) => note.match(pattern)?.[0] || null)
      .filter(Boolean);
    addCheck(checks, 'release-note-not-provisional', matches.length === 0, { path: releaseNoteRelative, markers: matches });
    if (matches.length) errors.push(`${releaseNoteRelative} still contains provisional release markers: ${matches.join(', ')}`);
  }

  if (validVersion) {
    const artifactPattern = /\bknowledge-v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\.zip\b/g;
    for (const relativePath of ['README.md', 'INSTALL.md', 'Quick-Start.md', 'RELEASE_NOTES.md', releaseNoteRelative]) {
      const filePath = path.join(root, relativePath);
      if (!fs.existsSync(filePath)) continue;
      const fullText = readText(filePath);
      const inspectedText = relativePath === 'RELEASE_NOTES.md'
        ? currentVersionSection(fullText, version)
        : fullText;
      const versions = [];
      for (const match of inspectedText.matchAll(artifactPattern)) versions.push(match[1]);
      const mismatches = Array.from(new Set(versions.filter((value) => value !== version)));
      addCheck(checks, `artifact-version:${relativePath}`, mismatches.length === 0, {
        path: relativePath,
        referenced_versions: Array.from(new Set(versions)),
        mismatches
      });
      if (mismatches.length) errors.push(`${relativePath} references stale release artifact version(s): ${mismatches.join(', ')}`);
    }
  }

  let manifest = null;
  if (fs.existsSync(path.join(root, 'install-manifest.json'))) {
    try {
      manifest = JSON.parse(readText(path.join(root, 'install-manifest.json')));
      const matches = validVersion && String(manifest.schema_version || '') === version;
      addCheck(checks, 'install-manifest-version', matches, {
        package_version: version || null,
        manifest_version: manifest.schema_version || null
      });
      if (!matches) errors.push(`install-manifest schema_version ${manifest.schema_version || 'missing'} does not match package version ${version || 'missing'}`);
    } catch (error) {
      errors.push(`install-manifest.json is invalid JSON: ${error.message}`);
    }
  }

  const quickStartPath = path.join(root, 'Quick-Start.md');
  if (fs.existsSync(quickStartPath)) {
    const quickStart = readText(quickStartPath);
    const oldMandatoryClaim = /estimated tokens saved and percent saved/i.test(quickStart);
    addCheck(checks, 'routing-estimate:no-obsolete-savings-requirement', !oldMandatoryClaim, { path: 'Quick-Start.md' });
    if (oldMandatoryClaim) errors.push('Quick-Start.md retains the obsolete mandatory saved-token wording');
    const requiredStates = ['narrowing', 'overhead', 'neutral', 'unavailable/not comparable'];
    for (const state of requiredStates) {
      const present = quickStart.toLowerCase().includes(state);
      addCheck(checks, `routing-estimate:${state}`, present, { path: 'Quick-Start.md' });
      if (!present) errors.push(`Quick-Start.md is missing routing estimate state: ${state}`);
    }
    const disclaimer = /deterministic local context estimate, not provider-reported model-token usage/i.test(quickStart);
    addCheck(checks, 'routing-estimate:deterministic-local-disclaimer', disclaimer, { path: 'Quick-Start.md' });
    if (!disclaimer) errors.push('Quick-Start.md is missing the deterministic local estimate disclaimer');
  }

  if (releaseNoteExists && fs.existsSync(path.join(root, 'RELEASE_NOTES.md'))) {
    const publicNotes = [
      [releaseNoteRelative, readText(releaseNotePath)],
      ['RELEASE_NOTES.md', readText(path.join(root, 'RELEASE_NOTES.md'))]
    ];
    const prohibited = [
      ['internal-rc-history', /\bRC\d+-R\d+\b|step\d+-rc\d+/i],
      ['unpublished-public-upgrade', /v3\.2\.12/i],
      ['manual-test-count', /Field Report[^\n]{0,80}\b(?:passed|checks?)\s+\d+/i],
      ['unsupported-model-claim', /(?:faster agents|higher accuracy|fewer model errors|actual token savings)/i]
    ];
    for (const [relativePath, text] of publicNotes) {
      for (const [id, pattern] of prohibited) {
        const match = text.match(pattern)?.[0] || null;
        const ok = !match;
        addCheck(checks, `public-notes:${id}:${relativePath}`, ok, { path: relativePath, match });
        if (!ok) errors.push(`${relativePath} contains prohibited ${id}: ${match}`);
      }
    }
    const directUpgrade = /3\.2\.11[\s\S]{0,80}3\.3\.0/i.test(`${publicNotes[0][1]}\n${publicNotes[1][1]}`);
    addCheck(checks, 'public-notes:direct-3.2.11-to-3.3.0-upgrade', directUpgrade);
    if (!directUpgrade) errors.push('public release notes do not state the 3.2.11 to 3.3.0 upgrade path');
  }

  if (pkg && manifest) {
    try { addInstalledInterfaceChecks(root, checks, errors, pkg, manifest); }
    catch (error) {
      addCheck(checks, 'installed-interface:execution', false, { error: error.message });
      errors.push(`installed-interface consistency failed to execute: ${error.message}`);
    }
  }

  return {
    schema_version: 'knowledge-public-consistency.v2',
    generated_at: new Date().toISOString(),
    status: errors.length ? 'fail' : 'pass',
    scope: 'repository_public_copy',
    network_used: false,
    external_channels_status: 'not_evaluated',
    version: version || null,
    checks_total: checks.length,
    checks_failed: checks.filter((item) => item.status === 'fail').length,
    checks,
    errors
  };
}

function main(argv = process.argv.slice(2)) {
  const report = evaluatePublicConsistency(sourceRoot);
  if (argv.includes('--json')) console.log(JSON.stringify(report, null, 2));
  else console.log(`public consistency ${report.status}: ${report.checks_total - report.checks_failed}/${report.checks_total} checks`);
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) main();

module.exports = {
  evaluatePublicConsistency,
  main
};
