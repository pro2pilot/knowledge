'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
test('public owner semantic scenarios reach their observation under real slow preparation', () => {
  const source = path.resolve(__dirname, '..');
  const script = process.env.KNOWLEDGE_SELFTEST_INPUT || path.join(source, 'tools/self-test-lock-owner-transitions.js');
  const child = spawnSync(process.execPath, ['--require', path.join(__dirname, 'helpers/reliability-owner-selftest-slow-sync.cjs'), script], {
    cwd: source, encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, KNOWLEDGE_AUDIT_SYSTEM_ROOT: source, NODE_OPTIONS: '', NODE_PATH: '' }
  });
  assert.ifError(child.error);
  const trace = child.stderr.trim().split('\n').filter(Boolean).map(JSON.parse);
  const output = JSON.parse(child.stdout);
  // Preserve the nested selftest's exact error and real delayed-I/O receipt.
  console.log(JSON.stringify({ scope: 'real runtime selftest with source-only fsync latency injection', trace, selftest: output }));
  for (const name of [
    'valid owner published after ownerless observation survives the contender',
    'correct live identity with reordered_fields remains invalid',
    'correct live identity with duplicate_identity remains invalid'
  ]) {
    const index = output.checks.findIndex(item => item.name === name);
    assert(index >= 0, name);
    assert(trace.some(row => row.fixture_index === index && row.elapsed_ms >= 100), name + ': required slow preparation was not exercised');
  }
  assert.equal(output.checks[19].name, 'repeated proven directory transitions respect acquisition timeout',
    'The source-only physical-transition fault scheduler must track this exact named fixture');
  assert(trace.some(row => row.fixture_index === 19 && row.reason === 'timed_physical_transition' && row.elapsed_ms >= 100),
    'The timed transition must experience real slow preparation before its first observation');
  assert.equal(child.status, 0, JSON.stringify(output));
  assert.equal(output.failed, 0);
  assert.equal(output.total, process.platform === 'win32' ? 29 : 22);
  assert.equal(output.passed, output.total);
});
