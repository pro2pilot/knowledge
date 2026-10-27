'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { generatedProducerDependencyClosure } = require('../tools/lib/repair-on-touch');
const { verifyGeneratedProducerClosures } = require('../tools/self-test-repair-on-touch').__test;
const mutate = (suffix, edit) => ({ readSource(file, encoding) {
  const source = fs.readFileSync(file, encoding);
  return file.replace(/\\/g, '/').endsWith(suffix) ? edit(source) : source;
} });

test('current generated producer closures include all recursive literal and qualified native control dependencies', () => {
  verifyGeneratedProducerClosures();
});
test('an unapproved producer cannot acquire child_process merely because native observers use it', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/build-search-index.js',
    source => source + "\nrequire('child_process');\n")), /unexpected process-spawning producer dependency/);
});
test('an unapproved dynamic module is rejected even in an otherwise approved native control module', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/lib/command-runner.js',
    source => source + '\nrequire(process.env.UNTRUSTED_MODULE);\n')), /dynamic require is not pinned/);
});
test('a missing transitive Mac control pin is rejected before accepting a generated producer closure', () => {
  assert.throws(() => verifyGeneratedProducerClosures({ dependencyClosure(producer) {
    return generatedProducerDependencyClosure(producer).filter(file => !file.endsWith('/macos-command-scope.js'));
  } }), /producer closure omitted/);
});
test('fixed native backend selector cannot become an environment-controlled loader', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/lib/command-runner.js',
    source => source.replace("const backend = process.platform === 'win32' ? './command-windows-native' : './verification-linux-namespace';",
      'const backend = process.env.UNTRUSTED_BACKEND;'))), /dynamic require is not pinned/);
});
test('removing lock-publication pin refusal cannot retain the approved dynamic native load exception', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/lib/lock-publication.js',
    source => source.replace("throw unavailable('artifact_pin_mismatch')", 'void 0'))), /dynamic require is not pinned/);
});
test('removing Windows native snapshot validation cannot retain the approved dynamic load exception', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/lib/command-windows-native.js',
    source => source.replaceAll('validateSnapshot(record);', 'void record;'))), /dynamic require is not pinned/);
});
test('the trusted generated-producer no-git guard remains mandatory', () => {
  assert.throws(() => verifyGeneratedProducerClosures(mutate('/tools/lib/path-context.js',
    source => source.replace("KNOWLEDGE_DISABLE_GIT_DISCOVERY === '1'", "KNOWLEDGE_DISABLE_GIT_DISCOVERY === '0'"))),
  /no-git execution guard/);
});
