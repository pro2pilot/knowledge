'use strict';
// Physical Linux processes/procfs plus explicitly labelled syscall faults.
// The test-only source override never participates in product qualification.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const cp = require('node:child_process');
const backend = require('../tools/lib/verification-linux-namespace');
const { validateExecutionScope } = require('../tools/lib/command-scope-proof');
const source = path.resolve(process.env.KNOWLEDGE_TEST_NATIVE_SOURCE || path.join(__dirname, '../tools/lib/verification-linux-namespace.c'));
const artifacts = process.env.KNOWLEDGE_TEST_NATIVE_EVIDENCE;
const root = process.platform === 'linux' ? fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-ns-link-')) : null;
const binaries = new Map();
const linux = { skip: process.platform === 'linux' ? false : 'Actual Linux provider only; no other platform qualification', timeout: 60000 };
test.after(() => { if (root) fs.rmSync(root, { recursive: true, force: true }); });
function compile(name, contents) {
  if (binaries.has(name)) return binaries.get(name);
  const file = path.join(root, `${name}.c`), binary = path.join(root, name);
  fs.writeFileSync(file, contents);
  const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
    '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2', file, '-o', binary];
  const result = cp.spawnSync('/usr/bin/cc', args, { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  if (artifacts) {
    fs.mkdirSync(artifacts, { recursive: true }); fs.writeFileSync(path.join(artifacts, `${name}.c`), contents);
    fs.writeFileSync(path.join(artifacts, `${name}-compile.json`), JSON.stringify({ executable: '/usr/bin/cc', args, status: result.status,
      signal: result.signal, error: result.error?.code, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n');
  }
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr);
  binaries.set(name, binary); return binary;
}
function actual() { return compile('exact-native', fs.readFileSync(source, 'utf8')); }
function model() {
  return compile('exact-native-modeled-lsm', `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
static int fault(const char *name) { const char *value=getenv("KNOWLEDGE_NATIVE_LINK_FAULT");return value&&!strcmp(value,name); }
static int model_fstatat(int fd,const char *name,struct stat *out,int flags) {
  if(fault("deny-nsfs-follow")&&!flags&&(!strcmp(name,"self/ns/pid")||!strcmp(name,"ns/pid"))) {errno=EACCES;return -1;}
  return fstatat(fd,name,out,flags);
}
static ssize_t model_readlinkat(int fd,const char *name,char *out,size_t size) {
  if(!*name) {
    if(fault("deny-link")){errno=EACCES;return -1;}
    if(fault("truncate-link")){memset(out,'x',size);return (ssize_t)size;}
    const char *text=fault("wrong-type")?"net:[4026531836]":fault("leading-zero")?"pid:[04026531836]":fault("overflow")?"pid:[4294967296]":NULL;
    if(text){size_t n=strlen(text);if(n>size)n=size;memcpy(out,text,n);return (ssize_t)n;}
  }
  return readlinkat(fd,name,out,size);
}
static int model_fstat(int fd,struct stat *out) {
  int r=fstat(fd,out);static int links;
  if(!r&&S_ISLNK(out->st_mode)) {
    if(fault("changed-link")&&++links==2)out->st_ino++;
    if(fault("wrong-proc-device"))out->st_dev++;
  }
  return r;
}
static int model_fstatfs(int fd,struct statfs *out) {
  int r=fstatfs(fd,out);struct stat s;
  if(!r&&fault("non-proc-link")&&!fstat(fd,&s)&&S_ISLNK(s.st_mode))out->f_type=TMPFS_MAGIC;
  return r;
}
#define fstatat model_fstatat
#define readlinkat model_readlinkat
#define fstat model_fstat
#define fstatfs model_fstatfs
#include ${JSON.stringify(source)}
`);
}
let sequence = 0;
function run(binary, args, fault) {
  const env = { ...process.env, ...(fault ? { KNOWLEDGE_NATIVE_LINK_FAULT: fault } : {}) };
  const result = cp.spawnSync(binary, args, { env, encoding: 'utf8', timeout: 20000, maxBuffer: 262144 });
  if (artifacts) fs.writeFileSync(path.join(artifacts, `run-${++sequence}.json`), JSON.stringify({ binary, args,
    fault: fault || null, status: result.status, signal: result.signal, error: result.error?.code,
    stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n');
  assert.ifError(result.error); assert.equal(result.signal, null);
  return { ...result, rows: String(result.stdout || '').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) };
}

test('Linux namespace link provider survives denied nsfs getattr and still creates and drains actual scopes', linux, t => {
  const result = run(model(), ['--probe'], 'deny-nsfs-follow');
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const ready = result.rows.find(row => row.status === 'ready'), closed = result.rows.find(row => row.status === 'closed');
  assert.equal(ready?.namespace_identity_provider, 'linux_procfs_pid_namespace_link.v1');
  assert.deepEqual(Object.keys(ready.observer_pid_namespace).sort(), ['ino', 'provider']);
  assert.deepEqual(Object.keys(ready.identities.init.pid_namespace).sort(), ['ino', 'provider']);
  assert.equal(closed?.active_processes, 0); assert.equal(closed?.init_exit_observed, true); assert.equal(closed?.init_reaped, true);
  t.diagnostic('Full exact C with only followed nsfs fstatat forced EACCES. Namespace creation, procfs links and final pidfd/reap are real; actual AppArmor host has a separate CI gate.');
});

test('Linux namespace link provider refuses denied, truncated, substituted and non-procfs link observations', linux, async t => {
  for (const fault of ['deny-link', 'truncate-link', 'wrong-type', 'leading-zero', 'overflow', 'changed-link', 'wrong-proc-device', 'non-proc-link']) {
    await t.test(fault, () => {
      const result = run(model(), ['--identity-link'], fault);
      assert.equal(result.status, 1); assert.equal(result.rows.length, 1);
      assert.equal(result.rows[0].status, 'unconfirmed'); assert.equal(result.rows[0].code, 'native_observer_unavailable');
    });
  }
  t.diagnostic('Explicit syscall-result faults around exact C; no runtime fallback to legacy stat after any error.');
});

test('Linux link proof keeps exact birth finality separate from a matching namespace number and retains legacy device checks', linux, t => {
  const binary = actual(), identity = run(binary, ['--identity-link']);
  assert.equal(identity.status, 0, identity.stdout); const context = identity.rows[0], current = context.identity;
  assert.equal(current.pid, process.pid);
  const active = run(binary, backend.identityOperationArgs('--observe', context, current, 5000));
  assert.equal(active.rows[0].status, 'active');
  // Simulated old birth against a real live PID and the SAME namespace inum.
  // No actual PID/inum recycling is claimed. The exact old birth can be final,
  // but the new live process must never receive a signal from this request.
  const old = { ...current, start_ticks: String(BigInt(current.start_ticks) - 1n) };
  const stale = run(binary, backend.identityOperationArgs('--stop', context, old, 5000));
  assert.equal(stale.status, 0); assert.equal(stale.rows[0].method, 'linux_boot_birth_replaced');
  assert.equal(run(binary, backend.identityOperationArgs('--observe', context, current, 5000)).rows[0].status, 'active');
  const wrongNamespace = { ...current, pid_namespace: { ...current.pid_namespace, ino: String(BigInt(current.pid_namespace.ino) + 1n) } };
  const wrong = run(binary, backend.identityOperationArgs('--stop', context, wrongNamespace, 5000));
  assert.equal(wrong.status, 1); assert.equal(wrong.rows[0].code, 'native_namespace_mismatch');
  const legacy = run(binary, ['--identity']).rows[0];
  const badDevice = { ...legacy.identity, pid_namespace: { ...legacy.identity.pid_namespace, dev: String(BigInt(legacy.identity.pid_namespace.dev) + 1n) } };
  const legacyWrong = run(binary, backend.identityOperationArgs('--observe', legacy, badDevice, 5000));
  assert.equal(legacyWrong.status, 1); assert.equal(legacyWrong.rows[0].code, 'native_namespace_mismatch');
  t.diagnostic('Actual current process survives both stop challenges; changed birth is a labelled synthetic ABA witness, not forced kernel PID reuse.');
});

test('Linux versioned namespace descriptors reject invented devices, mixed providers and noncanonical identifiers', linux, () => {
  const good = { provider: backend.NAMESPACE_PROVIDER, ino: '4026531840' }, legacy = { dev: '4', ino: good.ino };
  assert.equal(backend.validNamespaceIdentity(good), true); assert.equal(backend.validNamespaceIdentity(legacy), true);
  assert.equal(backend.sameNamespaceIdentity(good, legacy), false); assert.equal(backend.sameNamespaceIdentity(legacy, good), false);
  for (const bad of [{ ...good, dev: '0' }, { ...good, provider: 'unknown' }, { ...good, ino: '0' }, { ...good, ino: '04026531840' },
    { ...good, ino: '4294967296' }, { ...good, ino: '+1' }, { ...good, ino: '1\n' }, { ...good, ino: 1 }, { ...good, extra: true }]) {
    assert.equal(backend.validNamespaceIdentity(bad), false, JSON.stringify(bad));
  }
  const context = run(actual(), ['--identity-link']).rows[0];
  assert.throws(() => backend.identityOperationArgs('--observe', { ...context, namespace_identity_provider: undefined }, context.identity, 1000), { code: 'native_identity_invalid' });
  assert.throws(() => backend.identityOperationArgs('--observe', context, { ...context.identity, pid_namespace: legacy }, 1000), { code: 'native_identity_invalid' });
  const args = backend.identityOperationArgs('--observe', context, context.identity, 1000);
  assert.equal(args[2], '--observe-link'); assert.equal(args.length, 12); assert.equal(args.includes(undefined), false);
});

test('Linux link scope closure requires a fresh bound observation before and after real namespace drain', linux, async t => {
  const helper = backend.preparePackagedHelper();
  const { worker, job } = backend.spawnLinuxContainedWorker(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] }, { preparedHelper: helper, lifetimeMs: 60000 });
  t.after(async () => { await job.close(15000); if (worker.connected) worker.disconnect(); });
  const descriptor = await job.ready;
  const scope = { schema_version: 'knowledge-command-scope.v1', backend: 'linux_pid_namespace', descriptor,
    observer_lineage: [{ namespace: descriptor.observer_pid_namespace, depth: descriptor.controller.proc_pid_chain.length }] };
  assert.equal(descriptor.schema_version, 'knowledge-linux-pid-namespace.v2'); assert.equal(validateExecutionScope(scope), true);
  const mixed = structuredClone(scope); mixed.observer_lineage[0].namespace = { dev: '4', ino: descriptor.observer_pid_namespace.ino };
  assert.equal(validateExecutionScope(mixed), false);
  const invented = structuredClone(scope); invented.descriptor.init.pid_namespace.dev = '0'; assert.equal(validateExecutionScope(invented), false);
  assert.equal(backend.queryCommandScope(descriptor, scope.observer_lineage, { timeoutMs: 15000 }).status, 'active');
  job.permit(); await job.started; const closure = await job.close(15000); assert.equal(closure.status, 'completed', JSON.stringify(closure));
  const proof = backend.queryCommandScope(descriptor, scope.observer_lineage, { timeoutMs: 15000 });
  assert.equal(proof.status, 'completed', JSON.stringify(proof)); assert.equal(proof.namespace_drained, true); assert.equal(proof.active_processes, 0);
});
