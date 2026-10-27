'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

// This override selects exact historical source bytes for audit reproduction.
// It is confined to this test harness and is never a runtime identity provider.
const sourcePath = process.env.KNOWLEDGE_TEST_NATIVE_SOURCE || path.join(__dirname, '../tools/lib/verification-linux-namespace.c');
const source = fs.readFileSync(sourcePath, 'utf8');
function exactFunction(name, optional = false) {
  const match = new RegExp(`static (?:int|void|long long) ${name}\\(`).exec(source);
  if (!match) { if (optional) return ''; throw new Error(`Missing product function ${name}`); }
  let cursor = source.indexOf('{', match.index), depth = 0, quote = null, comment = null;
  for (; cursor < source.length; cursor++) {
    const c = source[cursor], next = source[cursor + 1];
    if (comment === 'line') { if (c === '\n') comment = null; continue; }
    if (comment === 'block') { if (c === '*' && next === '/') { comment = null; cursor++; } continue; }
    if (quote) { if (c === '\\') { cursor++; continue; } if (c === quote) quote = null; continue; }
    if (c === '/' && next === '/') { comment = 'line'; cursor++; continue; }
    if (c === '/' && next === '*') { comment = 'block'; cursor++; continue; }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '{') depth++;
    if (c === '}' && --depth === 0) return source.slice(match.index, cursor + 1);
  }
  throw new Error(`Unclosed product function ${name}`);
}
const headers = `#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#define MAX_TEXT 16384
#define MAX_MOUNT_TEXT (1024 * 1024)
struct proc_visibility { unsigned long long dev, ino, mount_id; char row[MAX_TEXT]; };
`;
function compile(root, name, text) {
  const file = path.join(root, `${name}.c`), binary = path.join(root, name);
  fs.writeFileSync(file, text);
  const result = childProcess.spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-Wno-misleading-indentation', '-Wno-unused-function', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2',
    file, '-o', binary], { encoding:'utf8', timeout:60_000, maxBuffer:1024 * 1024 });
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr);
  return binary;
}
function run(binary, args = []) {
  const result = childProcess.spawnSync(binary, args, { encoding:'utf8', timeout:15_000, maxBuffer:1024 * 1024 });
  assert.ifError(result.error);
  return { ...result, record:JSON.parse(result.stdout) };
}

test('Linux native absence requires current visible procfs, even when pidfd returns ESRCH', { timeout:120_000 }, async t => {
  if (process.platform !== 'linux') { t.skip('Linux-only actual C decision logic; not another platform qualification'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-linux-absence-'));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  const harness = headers + `
struct identity { int pid, proc_pid, ns_pid, depth; unsigned long long ticks, ns_dev, ns_ino, exe_dev, exe_ino, born_ms; char state; };
static unsigned long long procdev = 30, observer_dev = 4, observer_ino = 10;
/* This fixture exercises the unchanged legacy absence branch. The v2 live
 * pidfd mapping is covered by the separate native provider regression. */
static int namespace_link_provider __attribute__((unused));
static int pidfd_matches_identity(int fd, const struct identity *v) { (void)fd; (void)v; return -1; }
static char boot_id[] = "fixture-boot";
static const char *mode;
static int dir_calls, visibility_calls;
/* This standalone observer never calls prepare_report and owns no process
 * tree. Its production report_printf path therefore delegates to vdprintf.
 * Keep the excerpt's plain output equivalent without importing keeper state;
 * actual nonblocking keeper reports have their separate full-source test. */
#define report_printf dprintf
static int setup_observer(void) { return 0; }
static int process_dir(int pid) {
  (void)pid; dir_calls++;
  if ((!strcmp(mode,"appeared-before") && dir_calls == 2) || (!strcmp(mode,"appeared-after") && dir_calls == 3)) return 91;
  errno = !strcmp(mode,"denied-directory") && dir_calls > 1 ? EACCES : ENOENT; return -1;
}
static int pidfd_open_local(int pid) { (void)pid; if (!strcmp(mode,"pidfd-visible")) return 92; errno = !strcmp(mode,"pidfd-denied") ? EPERM : ESRCH; return -1; }
static int fixture_close(int fd) { (void)fd; return 0; }
#define close fixture_close
static int proc_visibility_snapshot(struct proc_visibility *v) {
  visibility_calls++;
  if (!strcmp(mode,"hidden") || !strcmp(mode,"ambiguous") || !strcmp(mode,"unavailable") ||
      (!strcmp(mode,"hidden-after") && visibility_calls == 2)) { errno = EACCES; return -1; }
  v->dev = 30; v->ino = 1; v->mount_id = 17; strcpy(v->row,"17 5 0:30 / /proc rw - proc proc rw");
  if (visibility_calls == 2) {
    if (!strcmp(mode,"changed-row")) strcat(v->row,",nosuid");
    if (!strcmp(mode,"changed-mount")) v->mount_id++;
    if (!strcmp(mode,"changed-root")) v->ino++;
  }
  return 0;
}
static void print_error(int fd, const char *code) { dprintf(fd,"{\\"status\\":\\"unconfirmed\\",\\"code\\":\\"%s\\"}\\n",code); }
static int identity_at(int fd, int pid, struct identity *v) { (void)fd; (void)pid; (void)v; return -1; }
static int exited_fd(int fd) { (void)fd; return 0; }
static int pidfd_kill(int fd) { (void)fd; return -1; }
static long long now_ms(void) { return 0; }
` + exactFunction('decimal') + '\n' + exactFunction('absent_birth_confirmed', true) + '\n' + exactFunction('observe') + `
int main(int argc, char **argv) {
  if (argc != 2) return 64; mode = argv[1];
  char *request[] = {"helper","--observe","fixture-boot","4","10","30","123","123","77","4","20","1","5000"};
  return observe(13, request, 0);
}
`;
  const binary = compile(root, 'actual-observe-faults', harness);
  const cases = [
    ['visible', true], ['hidden', false], ['ambiguous', false], ['unavailable', false],
    ['hidden-after', false], ['changed-row', false], ['changed-mount', false], ['changed-root', false],
    ['appeared-before', false], ['appeared-after', false], ['denied-directory', false],
    ['pidfd-visible', false], ['pidfd-denied', false]
  ];
  for (const [name, expected] of cases) await t.test(name, () => {
    const result = run(binary, [name]);
    assert.equal(result.record.status === 'exited', expected, JSON.stringify(result.record));
    assert.equal(result.status, expected ? 0 : 1);
    if (expected) assert.deepEqual(result.record, { status:'exited', method:'linux_boot_birth_absent', process_reaped:false, release_inferred:true });
  });
  t.diagnostic('Exact product observe/absence C functions with inert syscalls: protocol fault regression, not a physical hidepid-mount test.');
});

test('Linux native proc visibility parser rejects hidden, malformed and ambiguous witnesses', { timeout:120_000 }, async t => {
  if (process.platform !== 'linux') { t.skip('Linux C parser'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-linux-visibility-'));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  const functions = ['decimal', 'canonical_unsigned', 'proc_mount_id', 'proc_visible_options', 'parse_proc_visibility'].map(name => exactFunction(name)).join('\n');
  const harness = headers + functions + `
int main(int argc, char **argv) {
  if (argc != 2) return 64;
  const char *mode = argv[1];
  const char *fdinfo = "pos:\\t0\\nmnt_id:\\t17\\nino:\\t1\\n";
  char rows[4096] = "17 5 0:30 / /proc rw,nosuid - proc proc rw\\n";
  if (!strcmp(mode,"hidepid-0")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=0\\n");
  if (!strcmp(mode,"hidepid-off")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=off\\n");
  if (!strcmp(mode,"hidepid-2")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=2\\n");
  if (!strcmp(mode,"hidepid-4")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=4\\n");
  if (!strcmp(mode,"hidepid-invisible")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=invisible\\n");
  if (!strcmp(mode,"hidepid-unknown")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=new\\n");
  if (!strcmp(mode,"hidepid-duplicate")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw,hidepid=0,hidepid=0\\n");
  if (!strcmp(mode,"hidepid-left")) strcpy(rows,"17 5 0:30 / /proc rw,hidepid=2 - proc proc rw\\n");
  if (!strcmp(mode,"duplicate-row")) strcat(rows,"17 5 0:30 / /proc rw,nosuid - proc proc rw\\n");
  if (!strcmp(mode,"missing-row")) strcpy(rows,"18 5 0:30 / /proc rw - proc proc rw\\n");
  if (!strcmp(mode,"wrong-device")) strcpy(rows,"17 5 0:31 / /proc rw - proc proc rw\\n");
  if (!strcmp(mode,"noncanonical-device")) strcpy(rows,"17 5 00:30 / /proc rw - proc proc rw\\n");
  if (!strcmp(mode,"wrong-fs")) strcpy(rows,"17 5 0:30 / /proc rw - tmpfs tmpfs rw\\n");
  if (!strcmp(mode,"wrong-root")) strcpy(rows,"17 5 0:30 /other /proc rw - proc proc rw\\n");
  if (!strcmp(mode,"wrong-mountpoint")) strcpy(rows,"17 5 0:30 / /other rw - proc proc rw\\n");
  if (!strcmp(mode,"extra-fields")) strcpy(rows,"17 5 0:30 / /proc rw - proc proc rw extra\\n");
  if (!strcmp(mode,"duplicate-fd-id")) fdinfo = "mnt_id:\\t17\\nmnt_id:\\t17\\n";
  if (!strcmp(mode,"noncanonical-fd-id")) fdinfo = "mnt_id:\\t017\\n";
  if (!strcmp(mode,"overflow-fd-id")) fdinfo = "mnt_id:\\t18446744073709551616\\n";
  char *large = NULL; const char *input = rows;
  if (!strcmp(mode,"oversize")) { large = malloc(MAX_MOUNT_TEXT + 1); if (!large) return 70; memset(large,'1',MAX_MOUNT_TEXT); large[MAX_MOUNT_TEXT] = 0; input = large; }
  struct proc_visibility v; int result = parse_proc_visibility(fdinfo,input,makedev(0,30),&v);
  free(large); printf("{\\"accepted\\":%s}\\n",result ? "false" : "true"); return 0;
}
`;
  const binary = compile(root, 'actual-visibility-parser', harness);
  const valid = ['default', 'hidepid-0', 'hidepid-off'];
  const invalid = ['hidepid-2', 'hidepid-4', 'hidepid-invisible', 'hidepid-unknown', 'hidepid-duplicate', 'hidepid-left',
    'duplicate-row', 'missing-row', 'wrong-device', 'noncanonical-device', 'wrong-fs', 'wrong-root', 'wrong-mountpoint',
    'extra-fields', 'duplicate-fd-id', 'noncanonical-fd-id', 'overflow-fd-id', 'oversize'];
  for (const name of [...valid, ...invalid]) await t.test(name, () => {
    const result = run(binary, [name]); assert.equal(result.status, 0);
    assert.equal(result.record.accepted, valid.includes(name));
  });
});

test('Linux native bounded visibility reader rejects truncation and embedded NUL', { timeout:120_000 }, async t => {
  if (process.platform !== 'linux') { t.skip('Linux C I/O helper'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-linux-reader-'));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  const binary = compile(root, 'actual-bounded-reader', headers + exactFunction('bounded_kernel_text') + `
int main(int argc, char **argv) {
  if (argc != 2) return 64; char data[17];
  int result = bounded_kernel_text(AT_FDCWD,argv[1],data,sizeof(data));
  printf("{\\"accepted\\":%s}\\n",result ? "false" : "true"); return 0;
}
`);
  for (const [name, contents, valid] of [['short', 'ok\n', true], ['exact-maximum', 'a'.repeat(16), true],
    ['oversize', 'a'.repeat(17), false], ['empty', '', false], ['nul', 'a\0b', false]]) await t.test(name, () => {
      const file = path.join(root, name); fs.writeFileSync(file, contents);
      const result = run(binary, [file]); assert.equal(result.status, 0); assert.equal(result.record.accepted, valid);
    });
});

test('Linux native live-child and waited-child observations use the actual helper and proc mount', { timeout:120_000 }, async t => {
  if (process.platform !== 'linux') { t.skip('Actual Linux kernel observation required'); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-linux-observer-'));
  t.after(() => fs.rmSync(root, { recursive:true, force:true }));
  const helper = compile(root, 'actual-helper', source);
  const childSource = `const cp=require('node:child_process'); const r=cp.spawnSync(process.argv[1],['--identity'],{encoding:'utf8',timeout:15000}); if(r.status!==0){process.stderr.write(r.stderr+r.stdout);process.exit(70);} process.stdout.write(r.stdout); process.stdin.once('data',()=>process.exit(0));`;
  const child = childProcess.spawn(process.execPath, ['-e', childSource, helper], { stdio:['pipe', 'pipe', 'pipe'] });
  let exited = false;
  const exit = new Promise((resolve, reject) => { child.once('exit', (code, signal) => { exited=true; resolve({code,signal}); }); child.once('error', reject); });
  t.after(async () => { if (!exited) { child.kill('SIGKILL'); await exit; } });
  let stderr = ''; child.stderr.on('data', c => { stderr += c; });
  const context = await new Promise((resolve, reject) => {
    let text = ''; const timer = setTimeout(() => reject(new Error(`Own child identity timeout: ${stderr}`)), 30_000);
    child.stdout.on('data', c => { text += c; const end=text.indexOf('\n'); if(end>=0){clearTimeout(timer);try{resolve(JSON.parse(text.slice(0,end)));}catch(error){reject(error);}} });
    child.once('exit', () => { clearTimeout(timer); if (!text.includes('\n')) reject(new Error(`Own child identity missing: ${stderr}`)); });
  });
  assert.equal(context.identity.pid, child.pid);
  const identity = context.identity;
  const args = ['--observe', context.boot_id, context.observer_pid_namespace.dev, context.observer_pid_namespace.ino, context.procfs_dev,
    String(identity.pid), String(identity.proc_pid), identity.start_ticks, identity.pid_namespace.dev, identity.pid_namespace.ino,
    String(identity.namespace_pid), '5000'];
  const active = run(helper, args); assert.equal(active.status, 0, JSON.stringify(active.record)); assert.equal(active.record.status, 'active');
  child.stdin.end('finish\n'); const completed = await exit; assert.deepEqual(completed, {code:0, signal:null});
  const gone = run(helper, args);
  assert.equal(gone.status, 0, JSON.stringify(gone.record));
  assert.deepEqual(gone.record, {status:'exited', method:'linux_boot_birth_absent', process_reaped:false, release_inferred:true});
  t.diagnostic('Physical own-child proof: alive before challenge; child exit awaited; absent-birth recovery succeeds on this procfs visibility. No host mounts or accounts changed.');
});
