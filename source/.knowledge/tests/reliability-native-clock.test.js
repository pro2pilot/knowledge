'use strict';
// Exact native C with explicitly modeled clock errors. Namespace creation,
// pidfds, direct child handles and cleanup observations remain actual Linux.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), cp = require('node:child_process');
const system = path.resolve(process.env.KNOWLEDGE_TEST_SYSTEM_ROOT || path.join(__dirname, '..'));
const backend = require(path.join(system, 'tools/lib/verification-linux-namespace'));
const source = path.resolve(process.env.KNOWLEDGE_TEST_NATIVE_SOURCE || path.join(system, 'tools/lib/verification-linux-namespace.c'));
const evidence = process.env.KNOWLEDGE_TEST_NATIVE_EVIDENCE;
const linux = { skip: process.platform === 'linux' ? false : 'Actual Linux namespace contract only', timeout: 60000 };
const temporary = process.platform === 'linux' ? fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-native-clock-')) : null;
let executable, sequence = 0;
const pendingLifecycles = new Set(); let lifecycleSequence = 0;
test.after(() => {
  if (!temporary) return;
  if (pendingLifecycles.size) {
    console.error(JSON.stringify({ test_fixture_retained: temporary, lifecycle_unconfirmed: [...pendingLifecycles] }));
  } else fs.rmSync(temporary, { recursive: true, force: true });
});
function record(name, value) {
  if (!evidence) return;
  fs.mkdirSync(evidence, { recursive: true });
  fs.writeFileSync(path.join(evidence, `${++sequence}-${name}.json`), JSON.stringify(value, null, 2) + '\n');
}
function helper() {
  if (executable) return executable;
  const wrapper = String.raw`#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static unsigned clock_calls;
static int ready_emitted,permit_read,pidfd_exit_observed;
static int fault(const char *name){const char *value=getenv("KNOWLEDGE_NATIVE_CLOCK_FAULT");return value&&!strcmp(value,name);}
static int model_clock(clockid_t which,struct timespec *out) {
  ++clock_calls;
  if(fault("entry-eio")||(fault("after-ready-eio")&&ready_emitted)||(fault("permit-read-eio")&&permit_read)||
     (fault("after-pidfd-exit-eio")&&pidfd_exit_observed)){errno=EIO;return -1;}
  if(fault("rollback")){out->tv_sec=clock_calls==1?1000:999;out->tv_nsec=0;return 0;}
  if(fault("negative-seconds")){out->tv_sec=-1;out->tv_nsec=0;return 0;}
  if(fault("negative-nanoseconds")){out->tv_sec=1000;out->tv_nsec=-1;return 0;}
  if(fault("invalid-nanoseconds")){out->tv_sec=1000;out->tv_nsec=1000000000;return 0;}
  if(fault("millisecond-overflow")){out->tv_sec=LLONG_MAX/1000;out->tv_nsec=999000000;return 0;}
  return clock_gettime(which,out);
}
static int model_dprintf(int fd,const char *format,...) {
  va_list values;va_start(values,format);int result=vdprintf(fd,format,values);va_end(values);
  if(strstr(format,"\"status\":\"ready\""))ready_emitted=1;
  return result;
}
static ssize_t model_read(int fd,void *buffer,size_t size) {
  ssize_t result=read(fd,buffer,size);
  if(fd==4&&result>=7&&memmem(buffer,(size_t)result,"permit\n",7))permit_read=1;
  return result;
}
static int model_poll(struct pollfd *descriptors,nfds_t count,int timeout) {
  int result=poll(descriptors,count,timeout);
  if(result>0&&count==1&&(descriptors[0].revents&(POLLIN|POLLHUP)))pidfd_exit_observed=1;
  return result;
}
static int observed_clone(int (*fn)(void *),void *stack,int flags,void *argument) {
  // Observation only: the actual Linux clone executes unchanged.
  dprintf(2,"TEST_CLONE_CALLED\n");return clone(fn,stack,flags,argument);
}
#define clock_gettime model_clock
#define dprintf model_dprintf
#define read model_read
#define poll model_poll
#define clone observed_clone
#include ${JSON.stringify(source)}
`;
  const file = path.join(temporary, 'exact-native-clock.c'), binary = path.join(temporary, 'exact-native-clock');
  fs.writeFileSync(file, wrapper);
  const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', file, '-o', binary];
  const result = cp.spawnSync('/usr/bin/cc', args, { encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  if (evidence) { fs.mkdirSync(evidence, { recursive: true }); fs.writeFileSync(path.join(evidence, 'exact-native-clock.c'), wrapper); }
  record('compile', { command: ['/usr/bin/cc', ...args], status: result.status, error: result.error?.code,
    stdout: result.stdout, stderr: result.stderr, source_sha256: require('node:crypto').createHash('sha256').update(fs.readFileSync(source)).digest('hex') });
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr); executable = binary; return binary;
}
function environment(fault) {
  const env = { ...process.env }; delete env.KNOWLEDGE_NATIVE_CLOCK_FAULT;
  if (fault) env.KNOWLEDGE_NATIVE_CLOCK_FAULT = fault;
  return env;
}
function run(args, fault) {
  const binary = helper(), lifecycle = args[0] === '--probe' ? `probe-${++lifecycleSequence}` : null;
  if (lifecycle) pendingLifecycles.add(lifecycle);
  const result = cp.spawnSync(binary, args, { env: environment(fault), encoding: 'utf8', timeout: 20000, maxBuffer: 262144 });
  record('native', { args, fault: fault || null, status: result.status, signal: result.signal, error: result.error?.code,
    stdout: result.stdout, stderr: result.stderr });
  assert.ifError(result.error); assert.equal(result.signal, null);
  const rows = result.stdout.trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
  if (lifecycle && Number.isInteger(result.status) && (!result.stderr.includes('TEST_CLONE_CALLED') ||
      result.status === 0 && rows.some(row => row.status === 'closed' && row.active_processes === 0 &&
        row.init_exit_observed === true && row.init_reaped === true))) pendingLifecycles.delete(lifecycle);
  return { ...result, rows, lifecycle };
}
function unconfirmed(result, code = 'native_clock_unavailable') {
  assert.equal(result.status, 1, result.stdout); assert.equal(result.rows.at(-1)?.status, 'unconfirmed');
  assert.equal(result.rows.at(-1)?.code, code); assert.equal(result.rows.some(row => row.status === 'closed'), false);
}
async function closedBirths(ready, lifecycle) {
  const limit = process.hrtime.bigint() + 15000000000n;
  for (const role of ['init', 'worker']) {
    let observed;
    do {
      observed = run(backend.identityOperationArgs('--observe', ready, ready.identities[role], 5000));
      if (observed.status === 0 && observed.rows[0]?.status === 'exited') break;
      await new Promise(resolve => setTimeout(resolve, 20));
    } while (process.hrtime.bigint() < limit);
    assert.equal(observed.status, 0, JSON.stringify({ role, rows: observed.rows }));
    assert.equal(observed.rows[0]?.status, 'exited', JSON.stringify({ role, rows: observed.rows }));
  }
  if (lifecycle) pendingLifecycles.delete(lifecycle);
}

test('Linux missing monotonic clock rejects namespace admission instead of extending the budget', linux, () => {
  const result = run(['--probe'], 'entry-eio');
  unconfirmed(result); assert.equal(result.rows.length, 1); assert.equal(result.rows.some(row => row.status === 'ready'), false);
  assert.equal(result.stderr.includes('TEST_CLONE_CALLED'), false);
});

test('Linux backward or invalid monotonic observations fail before namespace admission', linux, async t => {
  for (const fault of ['rollback', 'negative-seconds', 'negative-nanoseconds', 'invalid-nanoseconds', 'millisecond-overflow']) {
    await t.test(fault, () => {
      const result = run(['--probe'], fault); unconfirmed(result); assert.equal(result.rows.length, 1);
      assert.equal(result.rows.some(row => row.status === 'ready'), false);
      assert.equal(result.stderr.includes('TEST_CLONE_CALLED'), false);
    });
  }
  t.diagnostic('Only clock_gettime results are modeled; no kernel monotonic rollback is claimed.');
});

test('Linux clock loss after real ready yields no successful receipt and the admitted namespace actually drains', linux, async () => {
  const result = run(['--probe'], 'after-ready-eio');
  const ready = result.rows.find(row => row.status === 'ready'); assert.ok(ready, result.stdout);
  await closedBirths(ready, result.lifecycle); unconfirmed(result);
});

test('Linux rechecks monotonic clock after permit input before releasing the actual worker', linux, async t => {
  const marker = path.join(temporary, 'worker-executed');
  const args = ['--run', '30000', 'worker', '--', process.execPath, '-e',
    `require('node:fs').writeFileSync(${JSON.stringify(marker)},'executed',{flag:'wx'});`];
  // Match the production ABI: fd 3 is the contained Node worker's IPC pipe.
  // An ignored (closed) fd 3 would let procfd reuse it before the keeper
  // deliberately closes its worker descriptors, changing the experiment.
  const binary = helper(), lifecycle = `permit-${++lifecycleSequence}`; pendingLifecycles.add(lifecycle);
  const child = cp.spawn(binary, args, { env: environment('permit-read-eio'), stdio: ['ignore', 'ignore', 'pipe', 'ipc', 'pipe'] });
  const control = child.stdio[4]; let text = '', stderr = '', pending = '', ready, closeRequested = false, streamEnded = false, stderrEnded = false;
  child.stderr.setEncoding('utf8'); child.stderr.on('data', chunk => { stderr += chunk; });
  child.stderr.once('end', () => { stderrEnded = true; });
  const rows = [], protocolErrors = [];
  const exit = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (status, signal) => resolve({ status, signal })); });
  const end = new Promise(resolve => { control.once('end', () => { streamEnded = true; resolve(); }); control.once('close', resolve); });
  control.on('error', error => protocolErrors.push(error.code)); control.setEncoding('utf8');
  control.on('data', chunk => {
    text += chunk; pending += chunk; let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline); pending = pending.slice(newline + 1);
      let row; try { row = JSON.parse(line); } catch { protocolErrors.push('json'); continue; }
      rows.push(row);
      if (row.status === 'ready') { ready = row; control.write('permit\n'); }
      if (row.status === 'worker_exit' && !closeRequested) { closeRequested = true; control.write('close 10000\n'); }
    }
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exit; control.destroy();
    if (pendingLifecycles.has(lifecycle)) {
      if (ready) await closedBirths(ready, lifecycle);
      else if (stderrEnded && !stderr.includes('TEST_CLONE_CALLED')) pendingLifecycles.delete(lifecycle);
    }
  });
  const timeout = setTimeout(() => { protocolErrors.push('test_deadline'); child.kill('SIGKILL'); }, 20000);
  let result;
  try { result = await exit; await end; } finally { clearTimeout(timeout); }
  record('permit-native', { args, ...result, rows, raw_control: text, stderr, stderrEnded, streamEnded, protocolErrors, worker_marker_exists: fs.existsSync(marker) });
  assert.ok(ready, text); await closedBirths(ready, lifecycle);
  assert.deepEqual(protocolErrors, []); assert.equal(streamEnded, true); assert.equal(pending, '');
  unconfirmed({ ...result, rows, stdout: text }); assert.equal(fs.existsSync(marker), false, 'No actual worker code may execute after clock failure');
});

test('Linux exact-child stop reports clock uncertainty separately from actual process exit', linux, async t => {
  for (const fault of ['entry-eio', 'after-pidfd-exit-eio']) await t.test(fault, async t => {
  const executable = helper();
  const script = `const c=require('node:child_process').spawnSync(${JSON.stringify(executable)},['--parent',String(process.pid),'--identity-link'],{encoding:'utf8'});` +
    `if(c.status!==0)process.exit(2);process.stdout.write(c.stdout);setInterval(()=>{},1000);`;
  const lifecycle = `direct-child-${++lifecycleSequence}`; pendingLifecycles.add(lifecycle); let identityObserved = false;
  const child = cp.spawn(process.execPath, ['-e', script], { env: environment(), stdio: ['ignore', 'pipe', 'pipe'] });
  const exit = new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', (status, signal) => resolve({ status, signal })); });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit;
    if (identityObserved) pendingLifecycles.delete(lifecycle); });
  const context = await new Promise((resolve, reject) => {
    let buffer = ''; const timer = setTimeout(() => reject(new Error('Exact child identity was not observed')), 10000);
    child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => { buffer += chunk; if (buffer.includes('\n')) {
      clearTimeout(timer); try { resolve(JSON.parse(buffer.trim())); } catch (error) { reject(error); }
    } });
    child.once('error', error => { clearTimeout(timer); reject(error); });
  });
  identityObserved = true;
  assert.equal(context.identity.pid, child.pid); assert.notEqual(child.pid, process.pid);
  const result = run(backend.identityOperationArgs('--stop', context, context.identity, 5000), fault);
  const actual = await exit; record('direct-child-exit', { pid: child.pid, ...actual });
  assert.equal(actual.signal, 'SIGKILL'); unconfirmed(result);
  });
});
