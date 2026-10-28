'use strict';
// QA adapter around the shipped native command runner. No taskkill/PID tree
// result, parent exit or missing Job name is accepted as descendant cleanup.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const started = process.hrtime.bigint();
const elapsed = () => Number(process.hrtime.bigint() - started) / 1e6;
const need = (value, name) => { if (!value) throw new Error(name); };
const hash = () => crypto.createHash('sha256');
const write = (fd, bytes) => { let offset = 0; while (offset < bytes.length) offset += fs.writeSync(fd, bytes, offset, bytes.length - offset); };

async function main(request) {
  need(process.platform === 'win32', 'physical_windows_required');
  need(['x64', 'arm64'].includes(request?.expected_arch) && request.expected_arch === process.arch, 'physical_architecture_required');
  need(request && /^[a-f0-9]{64}$/.test(request.nonce || ''), 'request_nonce_invalid');
  for (const key of ['source_root', 'cwd', 'receipt']) need(typeof request[key] === 'string' && path.isAbsolute(request[key]), 'request_path_invalid');
  need(Array.isArray(request.argv) && request.argv.length > 0 && path.isAbsolute(request.argv[0]) &&
    request.argv.every(x => typeof x === 'string' && !x.includes('\0')), 'request_argv_invalid');
  need(request.env && typeof request.env === 'object' && Object.values(request.env).every(x => typeof x === 'string'), 'request_env_invalid');
  for (const key of ['work_ms', 'setup_ms', 'cleanup_ms', 'max_output_bytes']) need(Number.isSafeInteger(request[key]) && request[key] > 0, 'request_budget_invalid');
  need(request.max_output_bytes <= 32 * 1024 * 1024, 'request_output_limit_invalid');
  need(request.cancel_on_team_native_ready === undefined || [1, 2].includes(request.cancel_on_team_native_ready), 'request_cancel_boundary_invalid');
  need(request.cancel_after_native_ready_ms === undefined || Number.isSafeInteger(request.cancel_after_native_ready_ms) &&
    request.cancel_after_native_ready_ms >= 0 && request.cancel_after_native_ready_ms <= 10000, 'request_cancel_delay_invalid');
  const runner = require(path.join(request.source_root, 'tools/lib/command-runner'));
  const protocol = require(path.join(request.source_root, 'tools/lib/command-windows-protocol'));
  const controller = new AbortController(), streams = { stdout: { bytes: 0, hash: hash() }, stderr: { bytes: 0, hash: hash() } };
  let nativeScope = null, cancelTimer, teamBuffer = '', cancellation = null;
  const teamReady = new Set();
  function cancel(reason) {
    if (controller.signal.aborted) return;
    cancellation = { reason, elapsed_ms: elapsed(), team_native_scopes_observed: teamReady.size };
    controller.abort();
  }
  const result = await runner.runOwnedCommand({ executable: request.argv[0], args: request.argv.slice(1), cwd: request.cwd, env: request.env }, {
    budgets: { workMs: request.work_ms, setupMs: request.setup_ms, cleanupMs: request.cleanup_ms, progressMs: 0 },
    maxOutputBytes: request.max_output_bytes, signal: controller.signal,
    // No proofRelay/custodyRelay is supplied: every nested custodian inherits
    // this outer Job. Its retained native handle covers the entire QA fixture.
    onNativeReady(descriptor) {
      nativeScope = protocol.commandScope(descriptor);
      need(protocol.validateScope(nativeScope) && descriptor.native.architecture === request.expected_arch, 'native_scope_binding_invalid');
      if (request.cancel_after_native_ready_ms !== undefined) cancelTimer = setTimeout(() => cancel('outer_native_ready'), request.cancel_after_native_ready_ms);
    },
    onOutput(name, bytes) {
      streams[name].bytes += bytes.length; streams[name].hash.update(bytes);
      write(name === 'stdout' ? 1 : 2, bytes);
      if (name !== 'stderr' || request.cancel_on_team_native_ready === undefined) return;
      teamBuffer += bytes.toString('utf8');
      if (Buffer.byteLength(teamBuffer) > 65536) throw new Error('team_diagnostic_frame_oversized');
      for (;;) {
        const at = teamBuffer.indexOf('\n'); if (at < 0) break;
        const line = teamBuffer.slice(0, at); teamBuffer = teamBuffer.slice(at + 1);
        let frame; try { frame = JSON.parse(line); } catch { continue; }
        if (frame?.schema_version === 'knowledge-team-selftest-phase.v1' && frame.event === 'native_ready' && /^[a-f0-9]{64}$/.test(frame.scope_id || '')) {
          teamReady.add(frame.scope_id);
          if (teamReady.size >= request.cancel_on_team_native_ready) cancel('team_native_ready');
        }
      }
    }
  });
  clearTimeout(cancelTimer);
  const report = { schema_version: 'knowledge-audit8-windows-owned-command.v1', nonce: request.nonce,
    platform: process.platform, arch: process.arch, node: process.version, argv: request.argv, cwd: request.cwd,
    budgets: { work_ms: request.work_ms, setup_ms: request.setup_ms, cleanup_ms: request.cleanup_ms },
    elapsed_ms: elapsed(), scope: nativeScope, cancellation,
    result: { status: result.status, signal: result.signal, error: result.error, cleanup: result.cleanup },
    streams: Object.fromEntries(Object.entries(streams).map(([name, value]) => [name, { bytes: value.bytes, sha256: value.hash.digest('hex') }])) };
  const pending = request.receipt + '.pending-' + request.nonce;
  fs.writeFileSync(pending, JSON.stringify(report) + '\n', { flag: 'wx' });
  fs.renameSync(pending, request.receipt);
}

let input = '', inputBytes = 0;
process.stdin.setEncoding('utf8');
process.stdin.on('data', part => { inputBytes += Buffer.byteLength(part); if (inputBytes > 2 * 1024 * 1024) process.exit(2); input += part; });
process.stdin.on('end', () => {
  Promise.resolve().then(() => main(JSON.parse(input))).catch(error => {
    process.stderr.write(JSON.stringify({ schema_version: 'knowledge-audit8-windows-owned-error.v1', code: error.code || 'qa_adapter_failed', message: error.message }) + '\n');
    process.exitCode = 2;
  });
});
