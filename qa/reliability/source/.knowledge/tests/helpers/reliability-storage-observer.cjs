'use strict';
// This observer itself runs in a native test container. A stuck predecessor
// is stopped explicitly and the outer container still proves final drain.
const fs = require('fs'), path = require('path');
const { spawn, spawnSync } = require('child_process');
const [source, fixture, kind, helper] = process.argv.slice(2);
const { contextEnv } = require(path.join(source, 'tools/lib/path-context.js'));
const context = JSON.parse(fs.readFileSync(path.join(fixture, 'context.json')));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function native(args) {
  const r = spawnSync(helper, args, { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
  try { return !r.error && r.status === 0 ? JSON.parse(r.stdout) : { status: 'unconfirmed', output: r.stdout, error: r.error?.code }; }
  catch { return { status: 'unconfirmed' }; }
}
function identity(procPid, depth) {
  const directory = `/proc/${procPid}`, stat = fs.readFileSync(`${directory}/stat`, 'utf8');
  const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  const chain = fs.readFileSync(`${directory}/status`, 'utf8').match(/^NSpid:\s+(.+)$/m)[1].trim().split(/\s+/).map(Number);
  const ns = fs.statSync(`${directory}/ns/pid`, { bigint: true });
  return { pid: chain[depth - 1], proc_pid: procPid, parent_proc_pid: Number(fields[1]), start_ticks: fields[19],
    namespace_pid: chain.at(-1), pid_namespace: { dev: String(ns.dev), ino: String(ns.ino) } };
}
(async () => {
  const observation = native(['--identity']);
  if (!observation.identity?.proc_pid_chain) throw new Error('Native observer unavailable');
  const child = spawn(process.execPath, [path.join(__dirname, 'reliability-storage-api.cjs'), source, fixture, kind],
    { env: contextEnv(context), stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', exited = false, actualExit;
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const exit = new Promise(resolve => child.once('exit', (code, signal) => { exited = true; actualExit = { code, signal }; resolve(actualExit); }));
  const closed = new Promise(resolve => child.once('close', resolve));
  try {
    let marker;
    const readyDeadline = performance.now() + 15000;
    while (!marker && performance.now() < readyDeadline && !exited) {
      try { marker = JSON.parse(fs.readFileSync(path.join(fixture, 'blocked.json'))); } catch {}
      if (!marker) await pause(10);
    }
    if (!marker) throw new Error(`Storage boundary not reached: ${stdout} ${stderr}`);
    const caller = JSON.parse(fs.readFileSync(path.join(fixture, 'caller.json'))), identities = [];
    let procPid = marker.proc_pid;
    for (let n = 0; n < 32; n++) {
      const row = identity(procPid, observation.identity.proc_pid_chain.length); identities.push(row);
      if (procPid === caller.proc_pid) break;
      procPid = row.parent_proc_pid;
    }
    if (identities.at(-1).proc_pid !== caller.proc_pid) throw new Error('Blocked writer is not an owned descendant');
    const cancelStarted = performance.now(); child.kill('SIGTERM');
    const deadline = performance.now() + 6000;
    while (!exited && performance.now() < deadline) await pause(10);
    const responsive = exited, cancelMs = performance.now() - cancelStarted;
    if (!exited) { child.kill('SIGKILL'); await exit; }
    await closed;
    let terminal; try { terminal = JSON.parse(stdout); } catch { terminal = null; }
    const exits = identities.map(row => ({ identity: row, proof: native(['--observe', observation.boot_id,
      observation.observer_pid_namespace.dev, observation.observer_pid_namespace.ino, observation.procfs_dev,
      String(row.pid), String(row.proc_pid), row.start_ticks, row.pid_namespace.dev, row.pid_namespace.ino, String(row.namespace_pid), '1000']) }));
    console.log(JSON.stringify({ scenario: kind, scope: 'real Flow/evaluation and native teardown; synchronous storage syscall held by an explicit Atomics barrier',
      responsive, cancel_ms: cancelMs, forced_test_kill: !responsive, caller, blocked_writer: marker, terminal, actual_exit: actualExit, exits, stderr,
      status: responsive && terminal?.code === 'command_cancelled' && terminal.cleanup?.status === 'completed' && exits.every(row => row.proof.status === 'exited') ? 'pass' : 'fail' }));
  } finally {
    if (!exited) { child.kill('SIGKILL'); await exit; }
  }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
