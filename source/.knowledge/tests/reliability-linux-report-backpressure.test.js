'use strict';

// Exact native report primitive with actual pipe/socket backpressure. These
// tests deliberately do not claim namespace or production service acceptance.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
const source = path.resolve(process.env.KNOWLEDGE_TEST_NATIVE_SOURCE || path.join(__dirname, '../tools/lib/verification-linux-namespace.c'));
const root = process.platform === 'linux' ? fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-report-pressure-')) : null;
test.after(() => { if (root) fs.rmSync(root, { recursive: true, force: true }); });
let binary;
function compile() {
  if (binary) return binary;
  const body = String.raw`#define _GNU_SOURCE
#include <sys/socket.h>
#define main namespace_program_main
#include ${JSON.stringify(source)}
#undef main
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"failed line %d: %s errno=%d\n",__LINE__,#x,errno); return 1; } } while (0)
static int fill(int fd) {
  char bytes[1024]; memset(bytes,'x',sizeof(bytes));
  int flags=fcntl(fd,F_GETFL); if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK))return -1;
  for(;;){ssize_t n=write(fd,bytes,sizeof(bytes));if(n>0)continue;if(n<0&&errno==EINTR)continue;
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;return -1;}
  return fcntl(fd,F_SETFL,flags&~O_NONBLOCK);
}
int main(int argc,char **argv) {
  CHECK(argc==2); signal(SIGPIPE,SIG_IGN); int fds[2];
  if(!strcmp(argv[1],"regular-rejected")){
    int regular=(int)syscall(SYS_memfd_create,"knowledge-report-test",1U);CHECK(regular>=0);
    CHECK(prepare_report(regular)==-1);CHECK(report_fd==-1);close(regular);return 0;
  }
  int socket_case=!strcmp(argv[1],"socket-full");
  CHECK(socket_case?socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,fds)==0:pipe2(fds,O_CLOEXEC)==0);
  int target=socket_case?fds[0]:fds[1],reader=socket_case?fds[1]:fds[0];
  if(!strcmp(argv[1],"pipe-full")||socket_case){
    CHECK(fill(target)==0);CHECK((fcntl(target,F_GETFL)&O_NONBLOCK)==0);CHECK(prepare_report(target)==0);
    long long start=now_ms();CHECK(report_printf(target,"{\"status\":\"ready\"}\n")==-1);
    CHECK(report_failed==1);CHECK(now_ms()-start<1000);
    CHECK(fcntl(reader,F_SETFL,fcntl(reader,F_GETFL)|O_NONBLOCK)==0);
    char bytes[4096];while(read(reader,bytes,sizeof(bytes))>0){}
    CHECK(report_printf(target,"{\"status\":\"closed\"}\n")==-1);
    CHECK(read(reader,bytes,sizeof(bytes))==-1&&(errno==EAGAIN||errno==EWOULDBLOCK));
  }else if(!strcmp(argv[1],"peer-closed")){
    CHECK(prepare_report(target)==0);close(reader);reader=-1;
    CHECK(report_printf(target,"closed\n")==-1);CHECK(report_failed==1);
  }else if(!strcmp(argv[1],"oversize")){
    CHECK(prepare_report(target)==0);char large[5000];memset(large,'x',sizeof(large)-1);large[sizeof(large)-1]=0;
    CHECK(report_printf(target,"%s",large)==-1);CHECK(report_failed==1);CHECK(errno==EOVERFLOW);
  }else if(!strcmp(argv[1],"normal")){
    CHECK(prepare_report(target)==0);CHECK(report_printf(target,"{\"status\":\"ready\"}\n")==19);
    char received[32]={0};CHECK(read(reader,received,sizeof(received))==19);CHECK(!strcmp(received,"{\"status\":\"ready\"}\n"));CHECK(!report_failed);
  }else return 2;
  close(target);if(reader>=0)close(reader);return 0;
}
`;
  const file = path.join(root, 'report-pressure.c');
  const target = path.join(root, 'report-pressure');
  fs.writeFileSync(file, body);
  const built = cp.spawnSync('/usr/bin/cc', ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', file, '-o', target],
    { encoding: 'utf8', timeout: 60000, maxBuffer: 1048576 });
  assert.ifError(built.error); assert.equal(built.status, 0, built.stderr); binary = target; return binary;
}
for (const name of ['normal', 'pipe-full', 'socket-full', 'peer-closed', 'oversize', 'regular-rejected']) {
  test(`native control reports: ${name}`, { skip: process.platform !== 'linux', timeout: 65000 }, () => {
    const result = cp.spawnSync(compile(), [name], { encoding: 'utf8', timeout: 5000, maxBuffer: 65536 });
    assert.ifError(result.error); assert.equal(result.signal, null); assert.equal(result.status, 0, result.stderr);
  });
}
