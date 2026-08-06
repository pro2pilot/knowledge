#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const install = require('./install-agent-integrations');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const systemRoot = path.resolve(__dirname, '..');
const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-integration-tx-'));
const results = [];

function assert(condition, message) { if (!condition) throw new Error(message); }
function run(id, fn) {
  try { fn(); results.push({ id, pass: true }); }
  catch (error) { results.push({ id, pass: false, error: error.message, code: error.code || null }); }
}
function makeFixture(name, packageBody = '{"name":"fixture","scripts":{"test":"node test.js"}}\n') {
  const base = path.join(fixtureRoot, name);
  const repo = path.join(base, 'repo');
  const state = path.join(base, 'state');
  fs.mkdirSync(repo, { recursive: true });
  fs.mkdirSync(state, { recursive: true });
  if (packageBody !== null) fs.writeFileSync(path.join(repo, 'package.json'), packageBody, 'utf8');
  return { base, repo, state };
}
function options(fixture, extra = {}) {
  return {
    __skipCli: true,
    systemRoot,
    targetRoot: fixture.repo,
    projectKnowledgeRoot: systemRoot,
    stateRoot: fixture.state,
    runtime: 'codex',
    updatePackageScripts: true,
    runInstallCheck: false,
    ...extra,
  };
}
function expectCode(fn, code) {
  let caught = null;
  try { fn(); } catch (error) { caught = error; }
  assert(caught, `expected ${code}, but no error was thrown`);
  assert(caught.code === code, `expected ${code}, got ${caught.code || caught.message}`);
  return caught;
}
function inventory(root) {
  const entries = [];
  const walk = (current, rel = '') => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const childRel = path.posix.join(rel, entry.name);
      const abs = path.join(current, entry.name);
      const stat = fs.lstatSync(abs);
      if (stat.isSymbolicLink()) entries.push(`${childRel}\0link\0${fs.readlinkSync(abs)}`);
      else if (stat.isDirectory()) { entries.push(`${childRel}/\0dir`); walk(abs, childRel); }
      else entries.push(`${childRel}\0file\0${crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex')}\0${stat.nlink}`);
    }
  };
  walk(root);
  return crypto.createHash('sha256').update(entries.join('\n')).digest('hex');
}
function stagingIsEmpty(stateRoot) {
  const staging = path.join(stateRoot, 'maintenance', 'integration-transactions', '.staging');
  return !fs.existsSync(staging) || fs.readdirSync(staging).length === 0;
}
function transactionReports(stateRoot) {
  const txRoot = path.join(stateRoot, 'maintenance', 'integration-transactions');
  if (!fs.existsSync(txRoot)) return [];
  return fs.readdirSync(txRoot).filter((name) => name.endsWith('.json')).map((name) =>
    JSON.parse(fs.readFileSync(path.join(txRoot, name), 'utf8')));
}

try {
  run('successful_transaction_commits', () => {
    const fixture = makeFixture('success');
    const result = install(options(fixture));
    assert(result.transaction.status === 'committed', 'transaction did not commit');
    assert(fs.existsSync(path.join(fixture.repo, 'AGENTS.md')), 'AGENTS.md missing');
    assert(result.transaction.changes_total > 0, 'no changes recorded');
    assert(stagingIsEmpty(fixture.state), 'staging directory not empty');
  });

  run('repeat_install_is_idempotent', () => {
    const fixture = makeFixture('repeat');
    install(options(fixture));
    const first = inventory(fixture.repo);
    const result = install(options(fixture));
    assert(inventory(fixture.repo) === first, 'repeat install changed repository');
    assert(result.transaction.status === 'committed', 'repeat transaction not committed');
    assert(result.transaction.changes_total === 0, `repeat changes=${result.transaction.changes_total}`);
  });

  run('malformed_package_is_zero_write', () => {
    const fixture = makeFixture('malformed-package', '{malformed');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_package_invalid'), 'package violation missing');
    assert(inventory(fixture.repo) === before, 'malformed package caused a write');
    assert(transactionReports(fixture.state).length === 0, 'transaction began after malformed preflight');
  });

  run('invalid_package_schema_is_zero_write', () => {
    const fixture = makeFixture('invalid-package-schema', '{"name":"fixture","scripts":[]}\n');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_package_invalid'), 'schema violation missing');
    assert(inventory(fixture.repo) === before, 'invalid package schema caused a write');
  });

  run('unbalanced_managed_block_is_zero_write', () => {
    const fixture = makeFixture('unbalanced');
    fs.writeFileSync(path.join(fixture.repo, 'AGENTS.md'), '<!-- BEGIN DOT-KNOWLEDGE MANAGED BLOCK -->\nprivate\n', 'utf8');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_managed_block_invalid'), 'managed-block violation missing');
    assert(inventory(fixture.repo) === before, 'unbalanced managed block caused a write');
  });

  run('hardlinked_target_rejected_before_read_write', () => {
    const fixture = makeFixture('hardlink-target');
    const secretSource = path.join(fixture.repo, 'private-source.txt');
    fs.writeFileSync(secretSource, 'PRIVATE-HARDLINK-PAYLOAD', 'utf8');
    fs.linkSync(secretSource, path.join(fixture.repo, 'AGENTS.md'));
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_hardlinked'), 'hardlink violation missing');
    assert(!JSON.stringify(error).includes('PRIVATE-HARDLINK-PAYLOAD'), 'hardlink payload leaked');
    assert(inventory(fixture.repo) === before, 'hardlink preflight caused a write');
  });

  run('hardlinked_package_rejected_before_read_write', () => {
    const fixture = makeFixture('hardlink-package', null);
    const secretSource = path.join(fixture.repo, 'private-package-source.json');
    fs.writeFileSync(secretSource, '{"name":"fixture","scripts":{},"private":"PRIVATE-HARDLINK-PAYLOAD"}\n', 'utf8');
    fs.linkSync(secretSource, path.join(fixture.repo, 'package.json'));
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_hardlinked'), 'hardlinked package violation missing');
    assert(!JSON.stringify(error).includes('PRIVATE-HARDLINK-PAYLOAD'), 'hardlinked package payload leaked');
    assert(inventory(fixture.repo) === before, 'hardlinked package preflight caused a write');
  });

  run('symlink_target_rejected_before_write', () => {
    const fixture = makeFixture('symlink-target');
    const outside = path.join(fixture.base, 'outside-agents.md');
    fs.writeFileSync(outside, 'outside', 'utf8');
    fs.symlinkSync(outside, path.join(fixture.repo, 'AGENTS.md'), 'file');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_symlink'), 'symlink violation missing');
    assert(inventory(fixture.repo) === before, 'symlink preflight caused a write');
    assert(fs.readFileSync(outside, 'utf8') === 'outside', 'outside target changed');
  });

  run('unsafe_gitattributes_is_zero_write', () => {
    const fixture = makeFixture('unsafe-gitattributes');
    const outside = path.join(fixture.base, 'outside-gitattributes');
    fs.writeFileSync(outside, 'outside', 'utf8');
    fs.symlinkSync(outside, path.join(fixture.repo, '.gitattributes'), 'file');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture)), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_symlink'), 'unsafe .gitattributes violation missing');
    assert(inventory(fixture.repo) === before, 'unsafe .gitattributes caused a write');
    assert(fs.readFileSync(outside, 'utf8') === 'outside', 'outside .gitattributes changed');
  });

  run('unsafe_windsurf_target_is_zero_write', () => {
    const fixture = makeFixture('unsafe-windsurf');
    const target = path.join(fixture.repo, '.windsurf', 'rules', 'knowledge.md');
    const outside = path.join(fixture.base, 'outside-windsurf.md');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(outside, 'outside', 'utf8');
    fs.symlinkSync(outside, target, 'file');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture, { runtime: 'windsurf' })), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_symlink'), 'unsafe Windsurf violation missing');
    assert(inventory(fixture.repo) === before, 'unsafe Windsurf target caused a write');
    assert(fs.readFileSync(outside, 'utf8') === 'outside', 'outside Windsurf target changed');
  });

  run('unsafe_devin_target_is_zero_write', () => {
    const fixture = makeFixture('unsafe-devin');
    const target = path.join(fixture.repo, '.devin', 'rules', 'knowledge.rules');
    const outside = path.join(fixture.base, 'outside-devin.rules');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(outside, 'outside', 'utf8');
    fs.symlinkSync(outside, target, 'file');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture, { runtime: 'devin' })), 'INTEGRATION_PREFLIGHT_FAILED');
    assert(error.violations.some((item) => item.code === 'integration_target_symlink'), 'unsafe Devin violation missing');
    assert(inventory(fixture.repo) === before, 'unsafe Devin target caused a write');
    assert(fs.readFileSync(outside, 'utf8') === 'outside', 'outside Devin target changed');
  });

  run('staging_failure_is_zero_write', () => {
    const fixture = makeFixture('staging-fault');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture, { transactionFault: 'staging' })), 'integration_staging_failed');
    assert(error.transaction.status === 'staging_failed', 'staging failure status missing');
    assert(inventory(fixture.repo) === before, 'staging failure changed repository');
    assert(stagingIsEmpty(fixture.state), 'staging fault leftovers remain');
  });

  run('first_commit_failure_rolls_back', () => {
    const fixture = makeFixture('commit-first');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture, { transactionFault: 'commit:first' })), 'INTEGRATION_COMMIT_ROLLED_BACK');
    assert(error.transaction.rollback.status === 'rolled_back', 'first-commit rollback status missing');
    assert(error.transaction.rollback.restored.length === 0, 'first commit should not restore files');
    assert(inventory(fixture.repo) === before, 'first commit failure changed repository');
    assert(stagingIsEmpty(fixture.state), 'first commit staging leftovers remain');
  });

  run('middle_commit_failure_rolls_back_exactly', () => {
    const fixture = makeFixture('commit-middle');
    const before = inventory(fixture.repo);
    const error = expectCode(() => install(options(fixture, { transactionFault: 'commit:middle' })), 'INTEGRATION_COMMIT_ROLLED_BACK');
    assert(error.transaction.rollback.status === 'rolled_back', 'middle rollback status missing');
    assert(error.transaction.rollback.restored.length > 0, 'middle rollback restored nothing');
    assert(inventory(fixture.repo) === before, 'middle commit rollback was not exact');
    assert(stagingIsEmpty(fixture.state), 'middle commit staging leftovers remain');
  });

  run('persistent_rollback_failure_is_clear', () => {
    const fixture = makeFixture('rollback-failure');
    const error = expectCode(() => install(options(fixture, { transactionFault: 'commit:middle+rollback' })), 'INTEGRATION_ROLLBACK_FAILED');
    assert(error.transaction.status === 'rollback_failed', 'rollback-failed status missing');
    assert(error.transaction.rollback.failed.length === 1, 'rollback failure evidence missing');
    assert(stagingIsEmpty(fixture.state), 'rollback-failure staging leftovers remain');
  });

  run('windsurf_contract_is_specialized', () => {
    const fixture = makeFixture('windsurf');
    const result = install(options(fixture, { runtime: 'windsurf' }));
    const body = fs.readFileSync(path.join(fixture.repo, '.windsurf', 'rules', 'knowledge.md'), 'utf8');
    assert(/^---\r?\n[\s\S]*?trigger:\s*always_on/m.test(body), 'Windsurf always_on frontmatter missing');
    assert(result.transaction.status === 'committed', 'Windsurf transaction did not commit');
  });

  run('devin_contract_is_specialized', () => {
    const fixture = makeFixture('devin');
    const result = install(options(fixture, { runtime: 'devin' }));
    assert(fs.existsSync(path.join(fixture.repo, '.devin', 'rules', 'knowledge.rules')), 'Devin rules bridge missing');
    assert(!fs.existsSync(path.join(fixture.repo, '.devin', 'rules', 'knowledge.md')), 'legacy Devin/Windsurf collision remains');
    assert(result.transaction.status === 'committed', 'Devin transaction did not commit');
  });

  run('all_twelve_runtimes_commit', () => {
    const fixture = makeFixture('all-runtimes');
    const result = install(options(fixture, { runtime: null, all: true, confirmAll: true }));
    assert(result.runtimes.length === 12, `runtimes=${result.runtimes.length}`);
    assert(Object.keys(result.installed).length === 12, `installed=${Object.keys(result.installed).length}`);
    assert(result.transaction.status === 'committed', 'all-runtime transaction did not commit');
    assert(stagingIsEmpty(fixture.state), 'all-runtime staging leftovers remain');
  });

  run('parallel_all_install_attempts_serialize', () => {
    const fixture = makeFixture('parallel-all');
    const installPath = path.join(__dirname, 'install-agent-integrations.js');
    const childOptions = options(fixture, { runtime: null, all: true, confirmAll: true });
    const worker = [
      "const install=require(process.argv[1]);",
      "const options=JSON.parse(process.argv[2]);",
      "try{const result=install(options);process.stdout.write(result.transaction.status);}",
      "catch(error){process.stderr.write(String(error.code||error.message));process.exitCode=1;}",
    ].join('');
    const orchestrator = [
      "const {spawn}=require('child_process');",
      "const worker=process.argv[1],installPath=process.argv[2],options=process.argv[3];",
      "const one=()=>new Promise((resolve)=>{const child=spawn(process.execPath,['-e',worker,installPath,options],{windowsHide:true});let out='',err='';child.stdout.on('data',(v)=>out+=v);child.stderr.on('data',(v)=>err+=v);child.on('close',(code)=>resolve({code,out,err}));});",
      "Promise.all([one(),one()]).then((values)=>{process.stdout.write(JSON.stringify(values));if(values.some((v)=>v.code!==0))process.exitCode=1;});",
    ].join('');
    const raw = execFileSync(process.execPath, ['-e', orchestrator, worker, installPath, JSON.stringify(childOptions)], {
      encoding: 'utf8', timeout: 120000, windowsHide: true,
    });
    const children = JSON.parse(raw);
    assert(children.length === 2 && children.every((item) => item.code === 0 && item.out === 'committed'), `parallel results=${raw}`);
    const result = install(childOptions);
    assert(result.transaction.status === 'committed' && result.transaction.changes_total === 0, 'parallel result is not idempotent');
    assert(stagingIsEmpty(fixture.state), 'parallel install left staging entries');
  });

  run('transaction_reports_are_persisted', () => {
    const fixture = makeFixture('persisted-report');
    const result = install(options(fixture));
    const reports = transactionReports(fixture.state);
    assert(reports.length === 1, `reports=${reports.length}`);
    assert(reports[0].transaction_id === result.transaction.transaction_id, 'persisted transaction id mismatch');
    assert(reports[0].status === 'committed', 'persisted status mismatch');
  });
} finally {
  try { removeTempDirStrict(fixtureRoot); }
  catch (error) { results.push({ id: 'zero_fixture_leftovers', pass: false, error: error.message, code: error.code || null }); }
}

if (!results.some((item) => item.id === 'zero_fixture_leftovers')) {
  results.push({ id: 'zero_fixture_leftovers', pass: !fs.existsSync(fixtureRoot) });
}

const report = {
  schema_version: 'knowledge-integration-transaction-self-test.v1',
  generated_at: new Date().toISOString(),
  platform: process.platform,
  node: process.version,
  checks_total: results.length,
  passed_total: results.filter((item) => item.pass).length,
  failed_total: results.filter((item) => !item.pass).length,
  status: results.every((item) => item.pass) ? 'pass' : 'fail',
  results,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (report.status !== 'pass') process.exitCode = 1;
