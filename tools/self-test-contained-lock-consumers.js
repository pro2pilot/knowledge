#!/usr/bin/env node
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { validate, readZipEntries } = require('./validate-release-artifact');
const { removeTempDirStrict } = require('./lib/strict-temp-cleanup');

const SECRET = 'RC39_CONSUMER_MATRIX_SECRET_MUST_NOT_LEAK';
function parse(argv) { const out = { zip: null, out: null }; for (let i = 0; i < argv.length; i += 1) { const a = argv[i]; if (a === '--zip') out.zip = argv[++i]; else if (a.startsWith('--zip=')) out.zip = a.slice(6); else if (a === '--out') out.out = argv[++i]; else if (a.startsWith('--out=')) out.out = a.slice(6); } if (!out.zip) throw new Error('--zip is required'); return out; }
function sha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function extract(zipPath, root) { const checked = validate(zipPath); if (checked.status !== 'ok') throw new Error('candidate invalid'); const zip = readZipEntries(zipPath); for (const entry of zip.entries) { if (entry.name.endsWith('/')) continue; const rel = entry.name.replace(/\\/g, '/'); if (!rel || rel.startsWith('/') || rel.split('/').includes('..')) throw new Error('unsafe ZIP entry'); const target = path.resolve(root, ...rel.split('/')); if (!target.startsWith(`${path.resolve(root)}${path.sep}`)) throw new Error('escaping ZIP entry'); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, entry.body); } return checked; }

function main() {
  const parsed = parse(process.argv.slice(2)); const zipPath = path.resolve(parsed.zip);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-rc39-consumers-')); const base = path.join(temp, 'base');
  const results = []; let validation;
  try {
    validation = extract(zipPath, base);
    const baseKnowledge = path.join(base, '.knowledge');
    const { canonicalOwnerText } = require(path.join(baseKnowledge, 'tools', 'lib', 'lock-owner-schema.js'));
    const { LOCKS } = require(path.join(baseKnowledge, 'tools', 'lib', 'lock-policy.js'));
    function owner(lockName, extra = {}) { const now = new Date().toISOString(); return { schema_version: 'knowledge-lock-owner.v1', lock_id: '123e4567-e89b-42d3-a456-426614174000', lock_name: lockName, purpose: LOCKS[lockName].purpose, pid: process.pid, hostname: os.hostname(), agent_id: null, workspace_id: null, process_started_at: now, acquired_at: now, nonce: 'a'.repeat(64), ...extra }; }
    function consumerFixture(consumer, scenario) { const repo = path.join(temp, `${consumer}-${scenario}`); fs.cpSync(base, repo, { recursive: true }); fs.writeFileSync(path.join(repo, 'package.json'), '{"name":"rc39-consumer","scripts":{}}\n', 'utf8'); return repo; }
    function setupFor(repo, consumer) {
      const knowledge = path.join(repo, '.knowledge');
      const manager = require(path.join(knowledge, 'tools', 'lib', 'contained-lock-manager.js'));
      const pathContext = require(path.join(knowledge, 'tools', 'lib', 'path-context.js'));
      const context = pathContext.resolveKnowledgeContext({ __skipCli: true, systemRoot: knowledge, targetRoot: repo, projectKnowledgeRoot: knowledge, stateRoot: knowledge, agentId: 'rc39-consumer-matrix' });
      let lockName; let resourceId = null; let rootPath = knowledge; let operation;
      const env = { ...process.env, KNOWLEDGE_SYSTEM_ROOT: knowledge, KNOWLEDGE_TARGET_ROOT: repo, KNOWLEDGE_PROJECT_KNOWLEDGE_ROOT: knowledge, KNOWLEDGE_STATE_ROOT: knowledge, KNOWLEDGE_AGENT_ID: 'rc39-consumer-matrix', KNOWLEDGE_LOCK_TIMEOUT_MS: '20', KNOWLEDGE_LOCK_STALE_MS: '1' };
      const tool = (name, args) => () => spawnSync(process.execPath, [path.join(knowledge, 'tools', name), ...args], { cwd: repo, env, encoding: 'utf8', windowsHide: true, timeout: 60000 });
      if (consumer === 'integration-installer') { lockName = 'agent-integrations'; operation = tool('install-agent-integrations.js', ['--runtime', 'codex', '--no-install-check']); }
      else if (consumer === 'doctor') { lockName = 'doctor'; operation = tool('doctor.js', ['--quiet']); }
      else if (consumer === 'task-routing') { lockName = 'task-routing'; const routing = require(path.join(knowledge, 'tools', 'lib', 'task-routing.js')); resourceId = routing.canonicalScope({ task: 'RC39 consumer matrix', paths: ['.knowledge'] }, context).task_scope_hash; operation = tool('task-routing.js', ['create', '--task=RC39 consumer matrix', '--scope-path=.knowledge', '--json']); }
      else if (consumer === 'field-report') { lockName = 'field-report'; operation = tool('field-report.js', ['start', '--new', '--json']); }
      else if (consumer === 'wiki-operation') { lockName = 'wiki-lint'; operation = tool('lint-wiki.js', []); }
      else if (consumer === 'inspector-operation') { lockName = 'visual-inspector'; operation = tool('build-visual-inspector.js', ['--quiet']); }
      else if (consumer === 'repair-on-touch') { lockName = 'repair-on-touch'; operation = tool('repair-on-touch.js', ['settings', 'reset']); }
      else if (consumer === 'team-mode') {
        lockName = 'team-flow'; const teamRoot = path.join(repo, 'team-state'); const repoId = 'rc39-consumer'; fs.mkdirSync(teamRoot, { recursive: true });
        const teamStorePath = path.join(knowledge, 'tools', 'lib', 'team-store.js'); const teamStore = require(teamStorePath); rootPath = teamStore.repoDir(teamRoot, repoId); fs.mkdirSync(rootPath, { recursive: true });
        const teamContext = { teamRoot, repoId, workspaceId: 'matrix', agentId: 'rc39-consumer-matrix', targetRoot: repo };
        const script = "const t=require(process.argv[1]),c=JSON.parse(process.argv[2]);const release=t.acquireTeamLock(c,'flow',{timeoutMs:20,staleMs:1});release();process.stdout.write('ok');";
        operation = () => spawnSync(process.execPath, ['-e', script, teamStorePath, JSON.stringify(teamContext)], { cwd: repo, env, encoding: 'utf8', windowsHide: true, timeout: 60000 });
      } else throw new Error(`unknown consumer ${consumer}`);
      const lockRequest = { context: { ...context, stateRoot: rootPath }, rootKind: 'state', rootPath, lockName, purpose: LOCKS[lockName].purpose, ...(resourceId ? { resourceId } : {}) };
      return { manager, lockName, lockRequest, operation };
    }
    function run(consumer, scenario) {
      const repo = consumerFixture(consumer, scenario); const sentinel = path.join(temp, `${consumer}-${scenario}-external.txt`); fs.writeFileSync(sentinel, SECRET, 'utf8'); const before = sha(sentinel);
      try {
        const item = setupFor(repo, consumer); const paths = item.manager.lockPaths(item.lockRequest); let expectedExitZero = scenario === 'normal' || scenario === 'stale-recovery';
        if (scenario === 'unsafe-lock-directory') { const external = path.join(temp, `${consumer}-${scenario}-external-dir`); fs.mkdirSync(external, { recursive: true }); fs.writeFileSync(path.join(external, 'owner.json'), SECRET); fs.mkdirSync(path.dirname(paths.lockDir), { recursive: true }); fs.symlinkSync(external, paths.lockDir, process.platform === 'win32' ? 'junction' : 'dir'); }
        else if (scenario === 'unsafe-owner') { fs.mkdirSync(paths.lockDir, { recursive: true }); const externalOwner = path.join(temp, `${consumer}-${scenario}-owner.json`); fs.writeFileSync(externalOwner, SECRET); fs.symlinkSync(externalOwner, path.join(paths.lockDir, 'owner.json'), 'file'); }
        else if (scenario === 'secret-redaction') { fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), `${JSON.stringify({ ...owner(item.lockName), secret: SECRET }, null, 2)}\n`); }
        else if (scenario === 'active-timeout') { fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), canonicalOwnerText(owner(item.lockName))); }
        else if (scenario === 'stale-recovery') { fs.mkdirSync(paths.lockDir, { recursive: true }); fs.writeFileSync(path.join(paths.lockDir, 'owner.json'), canonicalOwnerText(owner(item.lockName, { pid: 2147483647 }))); const old = new Date(Date.now() - 172_800_000); fs.utimesSync(paths.lockDir, old, old); }
        const result = item.operation(); const stdout = result.stdout || ''; const stderr = result.stderr || ''; const combined = `${stdout}\n${stderr}`; const externalChanged = sha(sentinel) !== before; const secretLeaked = combined.includes(SECRET);
        const exitOk = expectedExitZero ? result.status === 0 : result.status !== 0; const finalPresent = fs.existsSync(paths.lockDir);
        const stateOk = scenario === 'stale-recovery' || scenario === 'normal' ? !finalPresent : finalPresent;
        results.push({ id: `${consumer}:${scenario}`, consumer, scenario, status: exitOk && stateOk && !externalChanged && !secretLeaked ? 'pass' : 'fail', exit_code: result.status, signal: result.signal || null,
          external_read_detected: secretLeaked, external_write_detected: externalChanged, secret_leaked: secretLeaked, final_lock_state: finalPresent ? 'preserved' : 'released_or_absent',
          stdout: stdout.slice(0, 2000), stderr: stderr.replaceAll(SECRET, '[REDACTED]').slice(0, 2000) });
      } catch (error) { results.push({ id: `${consumer}:${scenario}`, consumer, scenario, status: 'fail', exit_code: 1, external_read_detected: false, external_write_detected: sha(sentinel) !== before, secret_leaked: String(error.message).includes(SECRET), final_lock_state: null, error: error.message.replaceAll(SECRET, '[REDACTED]'), code: error.code || null }); }
    }
    const consumers = ['integration-installer', 'doctor', 'task-routing', 'field-report', 'wiki-operation', 'inspector-operation', 'repair-on-touch', 'team-mode'];
    const scenarios = ['normal', 'unsafe-lock-directory', 'unsafe-owner', 'secret-redaction', 'active-timeout', 'stale-recovery'];
    for (const consumer of consumers) for (const scenario of scenarios) run(consumer, scenario);
    const report = { schema_version: 'knowledge-contained-lock-consumer-matrix.v1', generated_at: new Date().toISOString(), platform: process.platform, node: process.version,
      candidate: { path: zipPath, sha256: sha(zipPath), validation_status: validation.status }, consumers, scenarios, checks_total: results.length,
      passed_total: results.filter((item) => item.status === 'pass').length, failed_total: results.filter((item) => item.status === 'fail').length,
      secret_leaks_total: results.filter((item) => item.secret_leaked).length, status: results.every((item) => item.status === 'pass') ? 'PASS' : 'FAIL', results };
    const text = `${JSON.stringify(report, null, 2)}\n`; if (parsed.out) { fs.mkdirSync(path.dirname(path.resolve(parsed.out)), { recursive: true }); fs.writeFileSync(path.resolve(parsed.out), text); } process.stdout.write(text); if (report.status !== 'PASS') process.exitCode = 1; return report;
  } finally { removeTempDirStrict(temp); }
}

if (require.main === module) main();
module.exports = { main };
