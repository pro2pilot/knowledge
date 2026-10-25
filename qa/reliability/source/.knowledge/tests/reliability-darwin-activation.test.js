'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const cp = require('node:child_process'), crypto = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../tools/lib/verification-darwin-broker.m'), 'utf8');
test('candidate admission is selected once and diagnostic/QA modes can only disable it', () => {
  const compiler = process.env.CC || 'cc';
  assert.equal(cp.spawnSync(compiler, ['--version']).status, 0, 'A local C compiler is required for exact policy extraction');
  const at = source.indexOf('static const bool kCapabilityImplemented');
  const end = source.indexOf('\n\n/* Apple private combined ABI', at);
  assert.ok(at >= 0 && end > at);
  const policy = source.slice(at, end);
  assert.equal((source.match(/gCapabilityQualified\s*=/g) || []).length, 1);
  const assignment = source.indexOf('gCapabilityQualified=capabilityForMode(gQualificationMode);');
  assert.ok(assignment > source.indexOf('int main('));
  assert.ok(assignment < source.indexOf('return initializing?initInstall():serve();'));
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-admission-policy-'));
  try {
    const file = path.join(root, 'policy.c');
    fs.writeFileSync(file, '#include <stdbool.h>\n'+policy+'\nint main(void){\n'+
      '#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO\n'+
      'return capabilityForMode(false)||capabilityForMode(true);\n#else\n'+
      'return !capabilityForMode(false)||capabilityForMode(true);\n#endif\n}\n');
    for (const qa of [false, true]) {
      const output = path.join(root, qa ? 'qa' : 'normal');
      const built = cp.spawnSync(compiler, ['-std=c11', ...(qa ? ['-DKNOWLEDGE_DARWIN_QA_IO=1'] : []), file, '-o', output], { encoding: 'utf8' });
      assert.equal(built.status, 0, built.stderr);assert.equal(cp.spawnSync(output, []).status, 0);
    }
    console.log(JSON.stringify({ scope: 'exact C policy on local host; not macOS service qualification',
      source_sha256: crypto.createHash('sha256').update(source).digest('hex') }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
