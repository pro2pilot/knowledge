'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const crypto = require('node:crypto'), cp = require('node:child_process');
const filename = process.env.KNOWLEDGE_DARWIN_SCRATCH_STUB || path.join(__dirname, '../tools/lib/verification-darwin-stub.c');
const source = fs.readFileSync(filename, 'utf8');
// Linux filesystem + exact production bound_fds, while private credentials are
// modeled as controller UID0. No Darwin sandbox/UID claim is made here.
const compiler = process.env.CC || 'cc', available = process.platform === 'linux' &&
  process.getuid?.() === 0 && cp.spawnSync(compiler, ['--version']).status === 0;
test('exact native FD predicate binds scratch independently from source and admission',
  { skip: !available ? 'Root-owned local Linux FD fixture and C compiler are required' : false }, () => {
    const root = fs.mkdtempSync(path.join(process.env.TMPDIR || os.tmpdir(), 'darwin-scratch-fds-'));
    const file = path.join(root, 'fixture.c'), binary = path.join(root, 'fixture');
    const begin = source.indexOf('static bool bound_fds(');let i = source.indexOf('{', begin), depth = 0, end;
    for (; i < source.length; i++) { if (source[i] === '{') depth++;else if (source[i] === '}' && --depth === 0) { end = i + 1;break; } }
    assert.ok(begin >= 0 && end > begin);
    fs.writeFileSync(file, `#define _GNU_SOURCE 1
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct Config { uid_t uid;uint64_t lock_device,lock_inode,workspace_device,workspace_inode,scratch_device,scratch_inode; };
${source.slice(begin, end)}
static void check(bool ok,const char *label){if(!ok){fprintf(stderr,"FAIL %s\\n",label);exit(1);}printf("PASS %s\\n",label);}
static void set_fd(int source,int target){if(dup2(source,target)!=target){perror("dup2");exit(2);}}
int main(void){
  if(mkdir("workspace",0700)||mkdir("scratch",0700)||mkdir("replacement",0700))return 2;
  int lock=open("admission",O_RDWR|O_CREAT|O_EXCL,0600),work=open("workspace",O_RDONLY|O_DIRECTORY),scratch=open("scratch",O_RDONLY|O_DIRECTORY),replacement=open("replacement",O_RDONLY|O_DIRECTORY);
  if(lock<0||work<0||scratch<0||replacement<0)return 2;
  struct stat a,w,s;if(fstat(lock,&a)||fstat(work,&w)||fstat(scratch,&s))return 2;
  struct Config c={.uid=0,.lock_device=a.st_dev,.lock_inode=a.st_ino,.workspace_device=w.st_dev,.workspace_inode=w.st_ino,.scratch_device=s.st_dev,.scratch_inode=s.st_ino};
  set_fd(lock,13);set_fd(work,14);set_fd(scratch,15);
  check(bound_fds(&c),"stable-distinct-private-scratch");
  close(15);check(!bound_fds(&c),"missing-scratch-never-permitted");
  set_fd(work,15);check(!bound_fds(&c),"source-directory-cannot-be-scratch");
  set_fd(replacement,15);check(!bound_fds(&c),"replacement-scratch-inode-rejected");
  set_fd(scratch,15);c.scratch_inode++;check(!bound_fds(&c),"wire-scratch-identity-bound");c.scratch_inode--;
  if(fchmod(scratch,0777))return 2;check(!bound_fds(&c),"writable-scratch-mode-rejected");
  if(fchmod(scratch,0700))return 2;set_fd(lock,15);check(!bound_fds(&c),"regular-file-is-not-scratch");
  set_fd(scratch,15);check(bound_fds(&c),"stable-scratch-restored");return 0;
}
`);
    try {
      const compile = cp.spawnSync(compiler, ['-std=c11', '-Wall', '-Wextra', file, '-o', binary], { encoding: 'utf8', timeout: 30000 });
      assert.equal(compile.status, 0, compile.stderr || compile.error?.message);
      const run = cp.spawnSync(binary, [], { cwd: root, encoding: 'utf8', timeout: 5000 });
      assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
      assert.equal(run.stdout.trim().split('\n').length, 8);
      console.log(JSON.stringify({ scope: 'exact-production-bound_fds; actual-Linux-FDs; private-UID-modeled-as-root; not-Darwin',
        source_sha256: crypto.createHash('sha256').update(source).digest('hex'), checks: run.stdout.trim().split('\n') }));
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
