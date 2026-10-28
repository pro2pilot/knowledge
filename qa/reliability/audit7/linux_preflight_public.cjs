'use strict';
// Ordinary-UID public API observation. It never changes host policy, uses an
// internal proof adapter, or turns an unavailable backend into qualification.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const runtime = path.resolve(process.argv[2]), root = path.resolve(process.argv[3]);
if (process.platform !== 'linux' || process.getuid() === 0) throw new Error('ordinary Linux UID required');
const backend = require(path.join(runtime, 'tools/lib/verification-linux-namespace'));
const state = path.join(root, '.knowledge'); fs.mkdirSync(state, { recursive: true });
const marker = path.join(root, 'work-ran.txt');
fs.writeFileSync(path.join(root, 'pass.js'), 'require("fs").writeFileSync("work-ran.txt","fixed public canary");\n');
function inventory(dir) {
  const result = [];
  function walk(parent) {
    for (const entry of fs.readdirSync(parent, { withFileTypes: true }).sort((a,b)=>a.name.localeCompare(b.name))) {
      const file = path.join(parent, entry.name), relative = path.relative(dir, file);
      if (entry.isSymbolicLink()) throw new Error('unexpected fixture symlink');
      if (entry.isDirectory()) walk(file);
      else if (entry.isFile()) {
        const bytes = fs.readFileSync(file); if (bytes.length > 4*1024*1024) throw new Error('fixture file exceeds cap');
        result.push({ path: relative.split(path.sep).join('/'), bytes: bytes.length,
          sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
      } else throw new Error('unexpected fixture object');
      if (result.length > 256) throw new Error('fixture inventory exceeds cap');
    }
  }
  walk(dir); return result;
}
const report = { schema_version: 'knowledge-linux-public-preflight.v1', platform: process.platform,
  architecture: process.arch, node: process.version, uid: process.getuid(), policy_changed: false,
  production_service_qualified: false, release_qualified: false, state_before: inventory(state) };
const began = process.hrtime.bigint();
report.host_capability = backend.containmentCapability();
try {
  const executions = require(path.join(runtime, 'tools/lib/repair-on-touch')).runVerificationTests({
    stateRoot: state, repoRoot: root, taskId: 'audit7-nested-preflight', sessionId: 'audit7-native-public',
    checkedBy: 'audit7-native-public', tests: [{ argv: ['node', 'pass.js'], cwd: '.', timeout_ms: 5000 }],
    timeoutMs: 15000, sourceFiles: ['pass.js']
  });
  const ids = executions.map(value => value.execution_id || value.record?.execution_id);
  const acceptance = require(path.join(runtime, 'tools/lib/verification-finalization'))
    .requireFinalizedExecutions(state, ids, executions.verification_acceptances);
  report.public = { status: 'accepted', execution_ids: ids, final_reader: acceptance.status,
    acceptance_count: executions.verification_acceptances?.length || 0, budget: executions.verification_budget };
} catch (error) {
  const details = {};
  for (const key of ['code','primary_error','containment','execution','completed_executions','teardown',
    'delivery_teardown','cleanup','recovery_required','result_visibility','terminal_commit','attempt_id',
    'invocation_recovery','recovery_teardown','verification_budget']) if (error[key] !== undefined) details[key] = error[key];
  report.public = { status: 'failed', error: details };
}
report.elapsed_ms = Number(process.hrtime.bigint()-began)/1e6;
report.work_ran = fs.existsSync(marker);
report.state_after = inventory(state);
const active = path.join(state, 'maintenance/verification-control/active.json');
report.active_attempt = fs.existsSync(active) ? JSON.parse(fs.readFileSync(active, 'utf8')) : null;
console.log(JSON.stringify(report, null, 2));
