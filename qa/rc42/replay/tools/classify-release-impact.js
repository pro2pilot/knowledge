#!/usr/bin/env node
'use strict';

const fs = require('fs');
const { spawnSync } = require('child_process');

function parseArgs(argv = process.argv.slice(2)) {
  const args = { base: 'origin/main', head: 'HEAD', json: false, githubOutput: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--json') args.json = true;
    else if (arg === '--github-output') args.githubOutput = true;
    else if (arg === '--base') args.base = argv[++i];
    else if (arg.startsWith('--base=')) args.base = arg.slice('--base='.length);
    else if (arg === '--head') args.head = argv[++i];
    else if (arg.startsWith('--head=')) args.head = arg.slice('--head='.length);
  }
  return args;
}

function runGit(args) {
  const result = spawnSync('git', args, { encoding: 'utf8', windowsHide: true, timeout: 60000 });
  return { status: result.status, stdout: result.stdout || '', stderr: result.stderr || '', error: result.error?.message || null };
}

function gitLines(result) {
  return String(result.stdout || '').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function listChangedFiles(base, head) {
  const diff = runGit(['diff', '--name-only', `${base}...${head}`]);
  const unstaged = runGit(['diff', '--name-only']);
  const staged = runGit(['diff', '--cached', '--name-only']);
  const untracked = runGit(['ls-files', '--others', '--exclude-standard']);
  const files = new Set();
  const sources = [];
  for (const [name, result] of [
    ['base_diff', diff],
    ['unstaged', unstaged],
    ['staged', staged],
    ['untracked', untracked]
  ]) {
    if (result.status !== 0) continue;
    sources.push(name);
    for (const file of gitLines(result)) files.add(file);
  }
  const complete = diff.status === 0;
  return {
    files: Array.from(files).sort(),
    complete,
    sources,
    warning: complete ? null : `base diff failed; impact is conservatively unclassified: ${diff.stderr || diff.error || 'unknown error'}`
  };
}

function pushUnique(target, value) {
  if (!target.includes(value)) target.push(value);
}

function classify(files, options = {}) {
  const compatibilityImpact = [];
  const publicSurfaceImpact = [];
  const releaseInfrastructureImpact = [];
  const supplyChainImpact = [];
  const reason = [];

  for (const file of files) {
    const f = file.replace(/\\/g, '/').replace(/^\.knowledge\//, '');
    if (/^(README|INSTALL|SECURITY|CHANGELOG|RELEASE_NOTES)\.md$/.test(f) || /^docs\//.test(f) || /^\.release-notes\//.test(f) || /^WEB\//.test(f)) {
      pushUnique(publicSurfaceImpact, 'public-copy');
      reason.push(`${f}: public docs/site/release copy changed`);
    }
    if (/^(tools\/(install-agent-integrations|install-check|update-system-files|flow|doctor|repair-on-touch|recertify|memory-|memory-provider|agent-|restore-trust|build-visual-inspector|serve-inspector|sync-tracked|export-(?:debug-bundle|pro-snapshot)|self-test-(?:export-privacy|handoff-current-state|repair-on-touch|dedicated-verification|repair-session-isolation|recertify-lifecycle)|lib\/(?:export-sanitizer|repair-on-touch|dedicated-verification|queue-lifecycle|json-transaction))|agent-integrations\/|templates\/|schemas\/(?:repair-opportunities|verification-execution|verification-receipt|dedicated-verification-receipt)\.schema\.json|settings\/|config\.yaml|install-manifest\.json|install-policy\.json|package\.json)/.test(f)) {
      pushUnique(compatibilityImpact, 'install-or-runtime-contract');
      reason.push(`${f}: install/runtime compatibility surface changed`);
    }
    if (/^(tools\/(release-gate|package-release|validate-release-artifact|validate-source-deliverable|classify-release-impact|check-public-consistency|post-release-live-asset|conformance-install-smoke)|release-policy\.json|\.github\/workflows\/)/.test(f)) {
      pushUnique(releaseInfrastructureImpact, 'release-infrastructure');
      reason.push(`${f}: release infrastructure changed`);
    }
    if (/^(SBOM|THIRD_PARTY_NOTICES|package-lock\.json|package\.json|tools\/validate-(sbom|third-party-notices)|tools\/scan-secrets)/.test(f)) {
      pushUnique(supplyChainImpact, 'supply-chain');
      reason.push(`${f}: supply-chain or secret scanning surface changed`);
    }
  }

  const requiredGates = ['quick'];
  if (publicSurfaceImpact.length) pushUnique(requiredGates, 'public-consistency');
  if (compatibilityImpact.length || releaseInfrastructureImpact.length || supplyChainImpact.length) pushUnique(requiredGates, 'full');
  if (compatibilityImpact.length || releaseInfrastructureImpact.length) pushUnique(requiredGates, 'conformance-suite');
  if (options.classificationComplete === false) {
    pushUnique(releaseInfrastructureImpact, 'impact-baseline-unavailable');
    pushUnique(requiredGates, 'full');
    pushUnique(requiredGates, 'conformance-suite');
    reason.push('Git base diff is unavailable; quick-only impact classification is not trustworthy.');
  }
  const mode = requiredGates.includes('conformance-suite') ? 'full'
    : requiredGates.includes('public-consistency') ? 'quick'
      : 'quick';

  return {
    compatibility_impact: compatibilityImpact,
    public_surface_impact: publicSurfaceImpact,
    release_infrastructure_impact: releaseInfrastructureImpact,
    supply_chain_impact: supplyChainImpact,
    required_gates: requiredGates,
    mode,
    reason
  };
}

function writeGithubOutput(result) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `mode=${result.mode}\n`, 'utf8');
  fs.appendFileSync(outputPath, `required_gates=${result.required_gates.join(',')}\n`, 'utf8');
}

function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const changed = listChangedFiles(args.base, args.head);
  const classified = classify(changed.files, { classificationComplete: changed.complete });
  const result = {
    schema_version: 'release-impact-classification.v1',
    status: 'pass',
    base: args.base,
    head: args.head,
    changed_files: changed.files,
    classification_complete: changed.complete,
    change_sources: changed.sources,
    warning: changed.warning,
    ...classified
  };
  if (args.githubOutput) writeGithubOutput(result);
  if (args.json || args.githubOutput) console.log(JSON.stringify(result, null, 2));
  else console.log(result.mode);
}

if (require.main === module) {
  try { main(); }
  catch (error) {
    const args = parseArgs(process.argv.slice(2));
    const result = { schema_version: 'release-impact-classification.v1', status: 'blocked', error: error.message };
    if (args.json || args.githubOutput) console.log(JSON.stringify(result, null, 2));
    else console.error(error.message);
    process.exit(2);
  }
}

module.exports = { classify, listChangedFiles };
