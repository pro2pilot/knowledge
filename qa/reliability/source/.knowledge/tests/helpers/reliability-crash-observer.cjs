'use strict';
// Runs inside a separate native test scope. Even the deliberately leaking
// baseline descendant is therefore collected after this observation returns.
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const [source, fixture, helper, signal] = process.argv.slice(2);
const beat = path.join(fixture, 'heartbeat.json'), ownerFile = path.join(fixture, 'owner.json');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function native(args) {
  const r = spawnSync(helper, args, { encoding: 'utf8', timeout: 7000, maxBuffer: 65536 });
  if (r.error || r.status !== 0) return { status: 'unconfirmed', detail: r.stderr, output: r.stdout };
  try { return JSON.parse(r.stdout); } catch { return { status: 'unconfirmed' }; }
}
function identity(pid, depth) {
  const directory = `/proc/${pid}`, stat = fs.readFileSync(`${directory}/stat`, 'utf8'), fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  const status = fs.readFileSync(`${directory}/status`, 'utf8');
  const chain = status.match(/^NSpid:\s+(.+)$/m)[1].trim().split(/\s+/).map(Number);
  const ns = fs.statSync(`${directory}/ns/pid`, { bigint: true });
  return { pid: chain[depth - 1], proc_pid: pid, parent_proc_pid: Number(fields[1]), start_ticks: fields[19], namespace_pid: chain[chain.length - 1],
    pid_namespace: { dev: String(ns.dev), ino: String(ns.ino) }, proc_pid_chain: chain };
}
(async () => {
  const observer = native(['--identity']);
  if (!observer.identity?.proc_pid_chain) throw new Error('Native observer unavailable');
  const owner = spawn(process.execPath, [path.join(__dirname, 'reliability-sync-owner.cjs'), source, fixture, ownerFile], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; owner.stderr.on('data', chunk => { stderr += chunk; }); owner.stdout.resume();
  let started;
  for (let n = 0; n < 500; n++) { try { started = JSON.parse(fs.readFileSync(beat)); break; } catch {} await pause(10); }
  if (!started) { owner.kill('SIGKILL'); throw new Error(`Work never admitted: ${stderr}`); }
  const ownerIdentity = JSON.parse(fs.readFileSync(ownerFile));
  const identities = [];
  let pid = started.proc_pid;
  for (let n = 0; n < 32 && pid !== ownerIdentity.proc_pid; n++) {
    const row = identity(pid, observer.identity.proc_pid_chain.length); identities.push(row); pid = row.parent_proc_pid;
  }
  if (pid !== ownerIdentity.proc_pid) throw new Error('Observed writer is not an owned descendant');
  const exit = new Promise(resolve => owner.once('exit', (code, term) => resolve({ code, signal: term })));
  owner.kill(signal); const ownerExit = await exit;
  let prior = fs.readFileSync(beat, 'utf8'), stableSince = performance.now(), current = prior;
  const limit = performance.now() + 4500;
  while (performance.now() < limit && performance.now() - stableSince < 700) {
    await pause(25); current = fs.readFileSync(beat, 'utf8');
    if (current !== prior) { prior = current; stableSince = performance.now(); }
  }
  const observations = identities.map(row => ({ identity: row, proof: native(['--observe', observer.boot_id,
    observer.observer_pid_namespace.dev, observer.observer_pid_namespace.ino, observer.procfs_dev,
    String(row.pid), String(row.proc_pid), row.start_ticks, row.pid_namespace.dev, row.pid_namespace.ino,
    String(row.namespace_pid), '5000']) }));
  const quiet = performance.now() - stableSince >= 700;
  console.log(JSON.stringify({ status: quiet && observations.every(row => row.proof.status === 'exited') ? 'pass' : 'fail',
    scenario: `sync-caller-${signal}`, owner: ownerIdentity, owner_exit: ownerExit, heartbeat_stopped: quiet,
    namespace_init_count: observations.filter(row => row.identity.namespace_pid === 1).length, observations, stderr }));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
