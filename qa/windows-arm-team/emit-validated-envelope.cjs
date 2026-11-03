'use strict';
// Last public-output boundary. Finalizer stdout/stderr were captured privately.
// This file never emits arbitrary captured text, exception bodies or paths.
const path = require('node:path');
const T = require('./evidence-transport.cjs');
const fail = code => { throw Object.assign(new Error(code), { code }); };
function selectPublic(log, capture, expected, options) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(log);
  const envelope = T.parseEnvelope(log, expected, options); // Full frame order/count/outerSHA and independently supplied binding.
  const lines = text.replace(/\r\n/g, '\n').split('\n').filter(Boolean);
  const frames = T.frameLines(log);
  const summaries = lines.filter(line => /^D5_STATUS (PASS|FAIL|NOT_RUN|UNCERTAIN) EXPORT_OK$/.test(line));
  const unexpected = lines.some(line => !line.startsWith('D5E1 ') && !/^D5_STATUS (PASS|FAIL|NOT_RUN|UNCERTAIN) EXPORT_OK$/.test(line));
  const captureOk = capture?.schema === 'knowledge-d5-export-capture.v1' && capture.started === true && capture.exited === true &&
    capture.stdout_eof === true && capture.stderr_eof === true && capture.overflow === false && capture.pipe_failure === false &&
    capture.timed_out === false && capture.kill_attempted === false && capture.kill_succeeded === false && capture.retained_handle_captured === true &&
    capture.stdout_observed_bytes === log.length && capture.stderr_observed_bytes === 0 && capture.failure_code === null &&
    Number.isSafeInteger(capture.elapsed_ms) && capture.elapsed_ms >= 0 && capture.elapsed_ms <= 20000 &&
    Number.isSafeInteger(capture.original_finalizer_exit);
  const ordered = summaries.length === 1 && lines.at(-1) === summaries[0] && JSON.stringify(lines.slice(0, -1)) === JSON.stringify(frames);
  const candidate = captureOk && !unexpected && ordered && summaries[0] === 'D5_STATUS PASS EXPORT_OK' && capture.original_finalizer_exit === 0;
  return { publicText: frames.join('\n') + '\n' +
    (candidate ? 'D5_PUBLIC SCOPED_EVIDENCE_EXPORTED_ROOT_REVIEW_REQUIRED\n' : 'D5_PUBLIC NONPASS_EVIDENCE_EXPORTED\n'),
    exitCode: candidate ? 0 : 1, unexpected_output_suppressed: unexpected, ciphertext_sha256: envelope.header.ciphertext_sha256 };
}
function main(argv) {
  const names = ['--log', '--capture-receipt', '--repository', '--run-id', '--run-attempt', '--commit'];
  if (argv.length !== names.length * 2) fail('D5_EMIT_ARGUMENTS'); const values = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) { if (!names.includes(argv[i]) || Object.hasOwn(values, argv[i]) || !argv[i + 1]) fail('D5_EMIT_ARGUMENTS'); values[argv[i]] = argv[i + 1]; }
  if (!names.every(n => Object.hasOwn(values, n)) || !path.isAbsolute(values['--log']) || !path.isAbsolute(values['--capture-receipt'])) fail('D5_EMIT_ARGUMENTS');
  const expected = { repository: values['--repository'], run_id: values['--run-id'], run_attempt: values['--run-attempt'], commit: values['--commit'], input_sha256: T.INPUT_SHA256, key_id: T.ROOT_KEY_ID };
  const log = T.readBoundedFile(values['--log'], T.LIMITS.log), capture = T.parseStrictJSON(T.readBoundedFile(values['--capture-receipt'], 8192), 8192);
  return selectPublic(log, capture, expected);
}
module.exports = { selectPublic, main };
if (require.main === module) {
  process.stdout.on('error', () => { process.exitCode = 74; });
  try { const result = main(process.argv.slice(2)); process.stdout.write(result.publicText); process.exitCode = result.exitCode; }
  catch { process.stdout.write('D5_PUBLIC NO_VALID_COMPLETE_ENVELOPE_UNCERTAIN\n'); process.exitCode = 74; }
}
