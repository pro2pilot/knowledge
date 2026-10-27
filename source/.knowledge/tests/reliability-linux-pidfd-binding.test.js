'use strict';
// Exact native observer, with narrowly labelled handle/fdinfo substitutions.
// Production code has no test hook or environment-selected identity provider.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), cp = require('node:child_process');
const backend = require('../tools/lib/verification-linux-namespace');
const source = path.resolve(process.env.KNOWLEDGE_TEST_NATIVE_SOURCE || path.join(__dirname, '../tools/lib/verification-linux-namespace.c'));
const evidence = process.env.KNOWLEDGE_TEST_NATIVE_EVIDENCE;
const linux = { skip: process.platform === 'linux' ? false : 'Actual Linux pidfd contract only', timeout: 60000 };
const root = process.platform === 'linux' ? fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-pidfd-bind-')) : null;
test.after(() => { if (root) fs.rmSync(root, { force: true, recursive: true }); });
let binary, sequence = 0;
function helper() {
  if (binary) return binary;
  const contents = String.raw`#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static int target_fd=-1,info_fd=-1,info_read;
static int fault(const char *name){const char *value=getenv("KNOWLEDGE_PIDFD_TEST_FAULT");return value&&!strcmp(value,name);}
static long model_syscall(long number,...) {
  va_list args;va_start(args,number);long result;
  if(number==SYS_pidfd_open){int pid=va_arg(args,int),flags=va_arg(args,int);
    if(fault("other-live-handle"))pid=getpid();
    if(fault("other-exited-handle")){pid_t child=fork();if(!child)_exit(0);if(child<0){va_end(args);return -1;}
      result=syscall(number,child,flags);int status;while(waitpid(child,&status,0)<0&&errno==EINTR){};
    }else result=syscall(number,pid,flags);
    target_fd=(int)result;
  }else if(number==SYS_pidfd_send_signal){int fd=va_arg(args,int),sig=va_arg(args,int);void *info=va_arg(args,void*);unsigned flags=va_arg(args,unsigned);result=syscall(number,fd,sig,info,flags);
  }else if(number==SYS_close_range){unsigned first=va_arg(args,unsigned),last=va_arg(args,unsigned);int flags=va_arg(args,int);result=syscall(number,first,last,flags);
  }else if(number==SYS_capset||number==SYS_capget){void *header=va_arg(args,void*),*data=va_arg(args,void*);result=syscall(number,header,data);
  }else{errno=ENOSYS;result=-1;}
  va_end(args);return result;
}
static int model_openat(int dir,const char *name,int flags,...) {
  char expected[64];snprintf(expected,sizeof(expected),"self/fdinfo/%d",target_fd);
  if(target_fd>=0&&!strcmp(name,expected)&&fault("denied-fdinfo")){errno=EACCES;return -1;}
  int result=openat(dir,name,flags);
  if(result>=0&&target_fd>=0&&!strcmp(name,expected)){info_fd=result;info_read=0;}
  return result;
}
static ssize_t model_read(int fd,void *buffer,size_t size) {
  if(fd==info_fd&&info_read++)return 0;
  ssize_t count=read(fd,buffer,size);
  if(fd==info_fd&&count>0) {
    char *text=buffer,*nspid=memmem(text,(size_t)count,"NSpid:",6);
    if(fault("nul-fdinfo"))text[0]=0;
    if(fault("truncated-fdinfo")&&nspid)count=(ssize_t)(nspid-text)+6;
    if(fault("duplicate-pid")&&(size_t)count+8<size){memcpy(text+count,"Pid:\t1\n",7);count+=7;}
    if(fault("duplicate-chain")&&(size_t)count+10<size){memcpy(text+count,"NSpid:\t1\n",9);count+=9;}
    if(fault("extra-chain-member")&&nspid){char *end=memchr(nspid,'\n',(size_t)count-(size_t)(nspid-text));if(end&&(size_t)count+2<size){memmove(end+2,end,(size_t)count-(size_t)(end-text));memcpy(end,"\t1",2);count+=2;}}
  }
  return count;
}
static int model_close(int fd) { if(fd==info_fd){info_fd=-1;info_read=0;}return close(fd); }
#define syscall model_syscall
#define openat model_openat
#define read model_read
#define close model_close
#include ${JSON.stringify(source)}
`;
  const file = path.join(root, 'exact-observer.c'); fs.writeFileSync(file, contents);
  const target = path.join(root, 'exact-observer');
  const args = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', file, '-o', target];
  const result = cp.spawnSync('/usr/bin/cc', args, { encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  if (evidence) { fs.mkdirSync(evidence, { recursive: true }); fs.writeFileSync(path.join(evidence, 'exact-observer.c'), contents);
    fs.writeFileSync(path.join(evidence, 'compile.json'), JSON.stringify({ command: ['/usr/bin/cc', ...args], status: result.status,
      error: result.error?.code, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n'); }
  assert.ifError(result.error); assert.equal(result.status, 0, result.stderr); binary = target; return binary;
}
function run(args, fault) {
  const result = cp.spawnSync(helper(), args, { encoding: 'utf8', timeout: 15000, maxBuffer: 65536,
    env: { ...process.env, ...(fault ? { KNOWLEDGE_PIDFD_TEST_FAULT: fault } : {}) } });
  if (evidence) fs.writeFileSync(path.join(evidence, `run-${++sequence}.json`), JSON.stringify({ args, fault: fault || null,
    status: result.status, signal: result.signal, error: result.error?.code, stdout: result.stdout, stderr: result.stderr }, null, 2) + '\n');
  assert.ifError(result.error); assert.equal(result.signal, null); return { ...result, value: JSON.parse(result.stdout) };
}
function context() { const result = run(['--identity-link']); assert.equal(result.status, 0, result.stdout); return result.value; }
function observe(context, identity = context.identity, fault) {
  // No parent prefix: a substituted target pidfd is the only modeled handle.
  return run(backend.identityOperationArgs('--observe', context, identity, 5000).slice(2), fault);
}

test('Linux same live birth with inconsistent translated PID is unconfirmed, never old-birth completion', linux, () => {
  const current = context(); assert.equal(observe(current).value.status, 'active');
  const wrong = observe(current, { ...current.identity, pid: current.identity.pid + 1 });
  assert.equal(wrong.status, 1); assert.equal(wrong.value.code, 'native_observer_translation_unconfirmed');
  assert.equal(observe(current).value.status, 'active');
});

test('Linux pidfd binding rejects another live or exited process handle before using its exit state', linux, async t => {
  const current = context();
  for (const fault of ['other-live-handle', 'other-exited-handle']) await t.test(fault, () => {
    const result = observe(current, current.identity, fault);
    assert.equal(result.status, 1, result.stdout); assert.equal(result.value.code, 'native_pidfd_identity_unconfirmed');
    assert.equal(observe(current).value.status, 'active');
  });
  t.diagnostic('Exact C; pidfd_open is explicitly redirected to this helper or its own waited child. Target process and both substituted handles are real; no actual kernel misbinding is claimed.');
});

test('Linux pidfd fdinfo must contain exactly one complete matching Pid and full NSpid chain', linux, async t => {
  const current = context();
  for (const fault of ['denied-fdinfo', 'truncated-fdinfo', 'nul-fdinfo', 'duplicate-pid', 'duplicate-chain', 'extra-chain-member']) await t.test(fault, () => {
    const result = observe(current, current.identity, fault);
    assert.equal(result.status, 1, result.stdout); assert.equal(result.value.code, 'native_pidfd_identity_unconfirmed');
  });
  assert.equal(observe(current).value.status, 'active');
  t.diagnostic('Only target pidfd fdinfo reads are faulted. Proc mount qualification and process birth reads remain actual.');
});
