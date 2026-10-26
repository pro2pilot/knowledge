'use strict';

// Fixed, source-pinned QA programs. These files execute only in the disposable
// native copy; generated output is confined to its separate private scratch.
// They never address the user's project, installation, account, or host state.
const workloads = Object.freeze({
  scratch_readonly: Object.freeze({
    expected_exit: 0, no_progress_ms: 0, test_timeout_ms: 180000,
    source: String.raw`'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const scratch = process.env.TMPDIR;
assert.ok(path.isAbsolute(scratch));
for (const key of ['HOME', 'TMP', 'TEMP']) assert.equal(process.env[key], scratch);
assert.notEqual(scratch, path.dirname(__filename));
assert.equal(fs.statSync(scratch).uid, process.getuid());
const before = fs.readFileSync(__filename);
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const directory = fs.mkdtempSync(path.join(scratch, 'native-production-'));
const first = path.join(directory, 'first'), renamed = path.join(directory, 'renamed');
const fd = fs.openSync(first, 'wx', 0o600);
try { fs.writeFileSync(fd, 'scratch-physical-write'); fs.fsyncSync(fd); }
finally { fs.closeSync(fd); }
fs.renameSync(first, renamed);
assert.equal(fs.readFileSync(renamed, 'utf8'), 'scratch-physical-write');
let denied = 0;
function mustDeny(action) {
  let error;
  try { action(); } catch (caught) { error = caught; }
  assert.ok(error && ['EPERM', 'EACCES', 'EROFS'].includes(error.code), 'source mutation must be denied by the native boundary');
  denied++;
}
mustDeny(() => fs.appendFileSync(__filename, '\n// forbidden source write\n'));
mustDeny(() => fs.chmodSync(__filename, 0o600));
mustDeny(() => fs.writeFileSync(path.join(path.dirname(__filename), 'unexpected-output'), 'forbidden'));
mustDeny(() => fs.renameSync(__filename, path.join(directory, 'moved-source')));
mustDeny(() => fs.linkSync(__filename, path.join(directory, 'source-hardlink')));
assert.equal(denied, 5);
assert.equal(digest(fs.readFileSync(__filename)), digest(before));
fs.unlinkSync(renamed);fs.rmdirSync(directory);
process.stdout.write('scratch-write-and-source-readonly-confirmed\n');
`,
  }),
  silent_long: Object.freeze({
    expected_exit: 0, no_progress_ms: 500, test_timeout_ms: 180000,
    // Deliberately no output or file heartbeat before completion. This tests
    // real long-running silence, independently of the work deadline.
    source: "'use strict';\nsetTimeout(() => { process.stdout.write('silent-long-complete\\n'); }, 125000);\n",
  }),
  exit7: Object.freeze({
    expected_exit: 7, no_progress_ms: 0, test_timeout_ms: 180000,
    // Darwin preserves a failed execution as a durable KVE and returns a typed
    // command error after cleanup. This batch receives no finalization ACK.
    source: "'use strict';\nprocess.stderr.write('intentional-exit-seven\\n');\nprocess.exitCode = 7;\n",
  }),
});

module.exports = { workloads };
