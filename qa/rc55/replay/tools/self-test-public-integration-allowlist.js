#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const installAgentIntegrations = require('./install-agent-integrations');
const { withTempFixture } = require('./lib/strict-temp-cleanup');

const root = path.resolve(__dirname, '..');
const SOURCE_ONLY = 'agent-integrations/codex/skills/release-preparation-workflow.md';

function readManifest(kitRoot = root) {
  return JSON.parse(fs.readFileSync(path.join(kitRoot, 'install-manifest.json'), 'utf8'));
}

function filesUnder(directory, base = directory, out = []) {
  if (!fs.existsSync(directory)) return out;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) filesUnder(absolute, base, out);
    else if (entry.isFile()) out.push(path.relative(base, absolute).replace(/\\/g, '/'));
  }
  return out.sort();
}

function install(runtime, targetRoot, kitRoot = root) {
  return installAgentIntegrations({
    __skipCli: true,
    runtime,
    systemRoot: kitRoot,
    projectKnowledgeRoot: kitRoot,
    stateRoot: path.join(targetRoot, '.knowledge-test-state'),
    targetRoot,
    updatePackageScripts: false,
    runInstallCheck: false
  });
}

function run() {
  const checks = [];
  const check = (id, pass, detail = null) => checks.push({ id, pass: Boolean(pass), detail });
  const manifest = readManifest();
  const allowlist = manifest.release_contract.public_agent_integration_paths;
  const physical = filesUnder(path.join(root, 'agent-integrations'), root);
  const unallowlisted = physical.filter((item) => !allowlist.includes(item));
  check('manifest-has-exact-public-integration-allowlist', Array.isArray(allowlist) && allowlist.length === 73, { count: allowlist?.length });
  check('source-only-template-is-the-only-unallowlisted-template', unallowlisted.length === 1 && unallowlisted[0] === SOURCE_ONLY, unallowlisted);

  withTempFixture({ prefix: 'knowledge-public-integrations-' }, (fixture) => {
    const mappings = [
      ['codex', 'agent-integrations/codex/skills/', '.agents/skills/', 'codex_skills_source_only_rejections'],
      ['openclaw', 'agent-integrations/codex/skills/', '.agents/skills/', 'openclaw_skills_source_only_rejections'],
      ['claude', 'agent-integrations/claude/skills/', '.claude/skills/', 'claude_skills_source_only_rejections'],
      ['opencode', 'agent-integrations/opencode/commands/', '.opencode/commands/', 'opencode_commands_source_only_rejections']
    ];
    for (const [runtime, sourcePrefix, targetPrefix, rejectionKey] of mappings) {
      const target = path.join(fixture, runtime);
      fs.mkdirSync(target, { recursive: true });
      const report = install(runtime, target);
      const expected = allowlist
        .filter((item) => item.startsWith(sourcePrefix))
        .map((item) => `${targetPrefix}${item.slice(sourcePrefix.length)}`)
        .sort();
      const actual = filesUnder(target, target)
        .filter((item) => item.startsWith(targetPrefix))
        .sort();
      const rejected = report.installed[runtime][rejectionKey] || [];
      check(`${runtime}-copies-exact-allowlist`, JSON.stringify(actual) === JSON.stringify(expected), { expected_count: expected.length, actual_count: actual.length });
      check(`${runtime}-does-not-copy-source-only-workflow`, !fs.existsSync(path.join(target, '.agents', 'skills', 'release-preparation-workflow.md')));
      check(
        `${runtime}-reports-source-only-rejection`,
        ['codex', 'openclaw'].includes(runtime)
          ? rejected.length === 1 && rejected[0] === SOURCE_ONLY
          : rejected.length === 0,
        rejected
      );
    }

    const deprecatedTarget = path.join(fixture, 'deprecated');
    const deprecatedPath = path.join(deprecatedTarget, '.agents', 'skills', 'release-preparation-workflow.md');
    fs.mkdirSync(path.dirname(deprecatedPath), { recursive: true });
    fs.writeFileSync(deprecatedPath, '# Codex Skill: Release Preparation Workflow\nnode tools/package-release.js\n');
    const deprecated = install('codex', deprecatedTarget);
    check('recognized-deprecated-copy-is-removed', !fs.existsSync(deprecatedPath), deprecated.installed.codex.codex_release_preparation_cleanup);

    const customTarget = path.join(fixture, 'custom');
    const customPath = path.join(customTarget, '.agents', 'skills', 'release-preparation-workflow.md');
    fs.mkdirSync(path.dirname(customPath), { recursive: true });
    fs.writeFileSync(customPath, '# User-owned workflow\nNever overwrite this file.\n');
    const custom = install('codex', customTarget);
    check('unrecognized-user-file-is-preserved', fs.readFileSync(customPath, 'utf8').includes('User-owned workflow'), custom.installed.codex.codex_release_preparation_cleanup);

    const invalidKit = path.join(fixture, 'invalid-kit');
    fs.mkdirSync(path.join(invalidKit, 'agent-integrations', 'codex', 'skills'), { recursive: true });
    fs.writeFileSync(path.join(invalidKit, 'agent-integrations', 'codex', 'skills', 'kb-test.md'), 'test\n');
    fs.writeFileSync(path.join(invalidKit, 'install-manifest.json'), JSON.stringify({ release_contract: {} }));
    let invalidError = null;
    try { install('codex', path.join(fixture, 'invalid-target'), invalidKit); } catch (error) { invalidError = error; }
    check('missing-allowlist-fails-closed', invalidError?.message.includes('public_agent_integration_paths'), invalidError?.message || null);
  });

  const report = {
    schema_version: 'public-integration-allowlist-self-test.v1',
    generated_at: new Date().toISOString(),
    checks_total: checks.length,
    checks_passed: checks.filter((item) => item.pass).length,
    checks,
    status: checks.every((item) => item.pass) ? 'pass' : 'fail'
  };
  console.log(JSON.stringify(report, null, 2));
  if (report.status !== 'pass') process.exitCode = 2;
  return report;
}

if (require.main === module) run();
module.exports = { run };
