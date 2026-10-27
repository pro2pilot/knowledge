/* QA ONLY: fixed native actors, no interpreter, project input, or arbitrary exec.
 * The system manager starts this root daemon; it is never a caller child.
 * All path/UID constants are compiled into a fresh protected installation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef QA_ROOT
#error QA_ROOT, QA_CGROUP, QA_CALLER_UID and QA_UID_FIRST must be fixed at build time
#endif
#ifndef QA_CGROUP
#error QA_CGROUP is required
#endif
#ifndef QA_CALLER_UID
#error QA_CALLER_UID is required
#endif
#ifndef QA_UID_FIRST
#error QA_UID_FIRST is required
#endif
#define MAGIC UINT32_C(0x4b425331)
#define MAX_ATTEMPTS 4
#define WORK_MS 15000
#define CLEANUP_MS 10000
#define STACK_BYTES (1024 * 1024)
struct request { uint32_t magic, version, op, ordinal; unsigned char nonce[16]; };
struct event { int kind, role, pid, uid, fd, ok; uint64_t address,completed_ms; };
struct attempt {
  unsigned char nonce[16]; int sequence, keeper, keeperfd, channel, init, authority, worker;
  int authority_uid, worker_uid, authority_fd, done, closed, exit_status, stop_reason,keeper_wait_status,init_wait_status;
  uint64_t authority_address,output_bytes; int worker_memory_denied,output_fd,output_eof,expired; long long started,cleanup_end;
};
struct init_args { int report, keeperfd, gate,output; uid_t authority, worker; };
static volatile uint64_t authority_canary = UINT64_C(0x4b4e4f574c454447);
static struct attempt attempts[MAX_ATTEMPTS];
static int attempt_count, quarantine, daemonfd, rootfd, qa_anchor_pid;
static void reap_unpermitted_child(pid_t child);
static long long monotonic_ms(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(110);return (long long)t.tv_sec*1000+t.tv_nsec/1000000; }
static int pidfd_open_exact(int pid) { return (int)syscall(SYS_pidfd_open,pid,0); }
static int pidfd_kill(int fd) { return (int)syscall(SYS_pidfd_send_signal,fd,SIGKILL,NULL,0); }
static int ready(int fd) { struct pollfd p={fd,POLLIN,0};int rc=poll(&p,1,0);return rc>0&&(p.revents&(POLLIN|POLLHUP|POLLERR)); }
static int write_all(int fd,const void *data,size_t size) { const char *p=data;while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;size-=(size_t)n;}return 0; }
static int close_except(const int *keep,size_t count) {
  int sorted[8];if(count>8)return -1;
  for(size_t i=0;i<count;i++){if(keep[i]<0)return -1;sorted[i]=keep[i];}
  for(size_t i=0;i<count;i++)for(size_t j=i+1;j<count;j++)if(sorted[j]<sorted[i]){int v=sorted[j];sorted[j]=sorted[i];sorted[i]=v;}
  unsigned first=0;
  for(size_t i=0;i<count;i++){
    unsigned fd=(unsigned)sorted[i];if(fd<first)continue;
    if(fd>first&&syscall(SYS_close_range,first,fd-1,0))return -1;first=fd+1;
  }
  return syscall(SYS_close_range,first,UINT_MAX,0)?-1:0;
}
static int caps_zero(void) {
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0},{0}};
  if(syscall(SYS_capget,&h,d))return 0;
  return !(d[0].effective|d[0].permitted|d[0].inheritable|d[1].effective|d[1].permitted|d[1].inheritable);
}
static int drop_ids(uid_t uid) {
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0},{0}};
  if(setgroups(0,NULL)||setresgid(uid,uid,uid)||setresuid(uid,uid,uid)||
     syscall(SYS_capset,&h,d)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_DUMPABLE,1,0,0,0))return -1;
  uid_t r,e,s;gid_t gr,ge,gs;
  if(getresuid(&r,&e,&s)||getresgid(&gr,&ge,&gs)||r!=uid||e!=uid||s!=uid||gr!=uid||ge!=uid||gs!=uid||!caps_zero())return -1;
  /* Make ptrace as permissive as this actor may: DAC/UID must still protect A. */
  if(prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0))return -1;
  return 0;
}
static int event_send(int fd,const struct event *event) { return send(fd,event,sizeof(*event),MSG_NOSIGNAL|MSG_DONTWAIT)==sizeof(*event)?0:-1; }
static int event_recv(int fd,struct event *event,struct ucred *cred) {
  union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(16*sizeof(int))];} control={0};
  struct iovec io={event,sizeof(*event)};
  struct msghdr msg={0};msg.msg_iov=&io;msg.msg_iovlen=1;msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);
  ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
  if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))return 0;
  if(n<0)return -1;
  int credentials=0,unexpected=0;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)){
    if(c->cmsg_len<CMSG_LEN(0))return -1;
    if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof(*cred))){memcpy(cred,CMSG_DATA(c),sizeof(*cred));credentials++;}
    else if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){unexpected=1;size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);int *fds=(int *)CMSG_DATA(c);for(size_t i=0;i<count;i++)close(fds[i]);}
    else unexpected=1;
  }
  if(n==0&&!credentials&&!unexpected&&!(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)))return 2;
  return n==sizeof(*event)&&!(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))&&credentials==1&&!unexpected?1:-1;
}
static int namespace_init(void *pointer) {
  struct init_args *a=pointer;
  int allowed[]={a->report,a->keeperfd,a->gate,a->output};if(close_except(allowed,4))return 109;
  if(getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||ready(a->keeperfd))return 111;
  char gate; if(read(a->gate,&gate,1)!=1||gate!='G')return 112;close(a->gate);close(a->keeperfd);
  int admitted[2];if(pipe2(admitted,O_CLOEXEC))return 107;
  pid_t authority=fork();if(authority<0)return 113;
  if(!authority){
    close(admitted[0]);close(a->output);
    if(drop_ids(a->authority)||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=1)_exit(114);
    /* A synthetic private FD, not real secret material. */
    int fd=(int)syscall(SYS_memfd_create,"knowledge-qa-authority",1);
    if(fd<0||write_all(fd,"QA_CANARY",9))_exit(115);
    struct event e={.kind=2,.role=1,.pid=getpid(),.uid=(int)getuid(),.fd=fd,.ok=1,.address=(uint64_t)(uintptr_t)&authority_canary};
    if(event_send(a->report,&e))_exit(116);
    if(write_all(admitted[1],"A",1))_exit(106);close(admitted[1]);
    close(a->report);for(;;)pause();
  }
  close(admitted[1]);char authority_ready;
  if(read(admitted[0],&authority_ready,1)!=1||authority_ready!='A')return 105;
  close(admitted[0]);
  pid_t worker=fork();if(worker<0)return 117;
  if(!worker){
    if(drop_ids(a->worker)||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=1)_exit(118);
    uint64_t copy=0;struct iovec local={&copy,sizeof(copy)},remote={(void *)&authority_canary,sizeof(copy)};
    errno=0;ssize_t count=process_vm_readv(authority,&local,1,&remote,1,0);int memory_denied=count==-1&&(errno==EPERM||errno==EACCES);
    struct event e={.kind=2,.role=2,.pid=getpid(),.uid=(int)getuid(),.fd=-1,.ok=memory_denied};
    if(event_send(a->report,&e))_exit(119);close(a->report);
    pid_t child=fork();if(child<0)_exit(120);
    if(!child){if(setsid()<0)_exit(121);char tick[128];memset(tick,'W',sizeof(tick));for(;;){if(write_all(a->output,tick,sizeof(tick)))_exit(104);usleep(10000);}}
    close(a->output);
    for(;;)pause();
  }
  close(a->report);close(a->output);
  /* Fixed init only; never parses caller bytes or runs an interpreter. */
  for(;;){int status;pid_t p=waitpid(-1,&status,0);if(p<0&&errno==EINTR)continue;if(p<0)return errno==ECHILD?0:122;}
}
static int join_cgroup(int sequence) {
  char file[PATH_MAX],pid[32];snprintf(file,sizeof(file),QA_CGROUP "/attempt-%d/cgroup.procs",sequence);
  int fd=open(file,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
  int n=snprintf(pid,sizeof(pid),"%d",getpid());int rc=write_all(fd,pid,(size_t)n);close(fd);return rc;
}
static void keeper(int channel,int sequence,uid_t authority,uid_t worker,int startgate,int callerfd,int output) {
  long long setup_end=monotonic_ms()+5000;
  int allowed[]={channel,daemonfd,startgate,callerfd,output};if(close_except(allowed,5))_exit(108);
  /* Nothing below touches persistent storage after cgroup enrollment. */
  int permitted=0;
  while(monotonic_ms()<setup_end){
    struct pollfd gates[3]={{startgate,POLLIN,0},{daemonfd,POLLIN,0},{callerfd,POLLIN,0}};
    int rc=poll(gates,3,50);if(rc<0&&errno==EINTR)continue;if(rc<0||gates[1].revents||gates[2].revents)_exit(123);
    if(gates[0].revents){char gate;if(read(startgate,&gate,1)!=1||gate!='K')_exit(123);permitted=1;break;}
  }
  if(!permitted||join_cgroup(sequence)||monotonic_ms()>setup_end)_exit(123);close(startgate);
  int actors[2],birth[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,actors)||pipe2(birth,O_CLOEXEC))_exit(124);
  int one=1;if(setsockopt(actors[0],SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)))_exit(125);
  int self=pidfd_open_exact(getpid());if(self<0)_exit(126);
  char *stack=malloc(STACK_BYTES);if(!stack)_exit(127);
  if(ready(callerfd)||ready(daemonfd))_exit(103);
  struct init_args args={actors[1],self,birth[0],output,authority,worker};
  pid_t init=clone(namespace_init,stack+STACK_BYTES,CLONE_NEWPID|SIGCHLD,&args);
  if(init<0)_exit(128);
  close(actors[1]);close(birth[0]);close(self);close(output);
  int initfd=pidfd_open_exact(init);if(initfd<0){kill(init,SIGKILL);_exit(129);}
  if(monotonic_ms()>setup_end||ready(callerfd)||ready(daemonfd)){
    pidfd_kill(initfd);close(birth[1]);reap_unpermitted_child(init);close(initfd);_exit(102);
  }
  struct event born={.kind=1,.pid=init,.ok=1};
  if(event_send(channel,&born)||write_all(birth[1],"G",1)){pidfd_kill(initfd);_exit(130);}close(birth[1]);
  long long start=monotonic_ms(),end=start+WORK_MS;int reason=0,actor_count=0,actor_mask=0,actor_ok=1;
  while(!reason){
    struct pollfd p[4]={{daemonfd,POLLIN,0},{channel,POLLIN,0},{actors[0],POLLIN,0},{callerfd,POLLIN,0}};
    if(poll(p,4,50)<0&&errno!=EINTR){reason=5;break;}
    if(p[0].revents)reason=2;
    if(p[3].revents)reason=6;
    if(p[1].revents&(POLLHUP|POLLERR))reason=2;
    if(p[1].revents&POLLIN){char command[2];ssize_t n=recv(channel,command,sizeof(command),MSG_DONTWAIT);if(n!=1||command[0]!='S')reason=5;else reason=1;}
    if(p[2].revents&POLLIN){
      struct event event;struct ucred cred;int rc=event_recv(actors[0],&event,&cred);
      if(rc==0){/* Spurious readiness: preserve pending state and check budgets below. */}
      else if(rc==2&&(p[2].revents&POLLHUP)&&actor_count==2&&actor_mask==3){close(actors[0]);actors[0]=-1;}
      else if(rc!=1||event.kind!=2||!((event.role==1&&cred.uid==authority&&!(actor_mask&1))||(event.role==2&&cred.uid==worker&&!(actor_mask&2)))||++actor_count>2){actor_ok=0;reason=5;}
      else{actor_mask|=event.role;event.pid=cred.pid;if(!event.ok)actor_ok=0;if(event_send(channel,&event)){reason=5;actor_ok=0;}}
    }
    if(ready(initfd))reason=4;
    if(monotonic_ms()>=end)reason=3;
  }
  int sent=pidfd_kill(initfd);if(sent<0&&errno!=ESRCH)_exit(131);
  long long cleanup_end=monotonic_ms()+CLEANUP_MS;
  while(!ready(initfd)&&monotonic_ms()<cleanup_end){struct pollfd p={initfd,POLLIN,0};poll(&p,1,50);}
  int status=0;pid_t reaped=waitpid(init,&status,WNOHANG);
  long long completed=monotonic_ms();
  struct event terminal={.kind=3,.role=reason,.pid=init,.fd=status,.ok=ready(initfd)&&reaped==init&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL&&actor_ok&&actor_count==2&&completed<=cleanup_end,
    .address=(uint64_t)cleanup_end,.completed_ms=(uint64_t)completed};
  event_send(channel,&terminal);close(initfd);close(actors[0]);close(channel);free(stack);_exit(terminal.ok?0:132);
}
static int cgroup_empty(int sequence) {
  char file[PATH_MAX],text[256];snprintf(file,sizeof(file),QA_CGROUP "/attempt-%d/cgroup.events",sequence);
  int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
  ssize_t n=read(fd,text,sizeof(text)-1);close(fd);if(n<=0||n==(ssize_t)sizeof(text)-1)return 0;text[n]=0;
  return !strncmp(text,"populated 0\n",12)||strstr(text,"\npopulated 0\n");
}
static void close_pair(int pair[2]) { for(int i=0;i<2;i++)if(pair[i]>=0){close(pair[i]);pair[i]=-1;} }
static void reap_unpermitted_child(pid_t child) {
  /* This exact, unreaped direct child has never received its birth permit.
   * There is no other wait/reaper thread and its PID cannot yet be reused. */
  long long end=monotonic_ms()+2000;int status;
  while(monotonic_ms()<end){pid_t got=waitpid(child,&status,WNOHANG);if(got==child||got<0)return;usleep(10000);}
  if(waitpid(child,&status,WNOHANG)!=0)return;
  kill(child,SIGKILL);end=monotonic_ms()+2000;
  while(monotonic_ms()<end){pid_t got=waitpid(child,&status,WNOHANG);if(got==child||got<0)return;usleep(10000);}
  /* Quarantine and system unit custody remain; no successful cleanup claim. */
}
static void observe(void) {
  for(int i=0;i<attempt_count;i++){
    struct attempt *a=&attempts[i];if(a->closed||a->keeper<1)continue;
    if(!a->output_eof){char chunk[65536];ssize_t bytes=read(a->output_fd,chunk,sizeof(chunk));
      if(bytes>0)a->output_bytes+=(uint64_t)bytes;else if(bytes==0){a->output_eof=1;close(a->output_fd);}
      else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)quarantine=1;}
    struct event e;ssize_t n;unsigned char packet[sizeof(e)+1];
    while((n=recv(a->channel,packet,sizeof(packet),MSG_DONTWAIT))>0){
      if(n!=sizeof(e)){quarantine=1;break;}
      memcpy(&e,packet,sizeof(e));
      if(e.kind==1&&a->init==0)a->init=e.pid;
      else if(e.kind==2&&e.role==1&&a->authority==0&&e.uid==a->authority_uid){a->authority=e.pid;a->authority_fd=e.fd;a->authority_address=e.address;}
      else if(e.kind==2&&e.role==2&&a->worker==0&&e.uid==a->worker_uid){a->worker=e.pid;a->worker_memory_denied=e.ok;}
      else if(e.kind==3&&!a->done&&e.pid==a->init&&e.address<=LLONG_MAX&&e.completed_ms<=LLONG_MAX){a->done=e.ok&&e.completed_ms<=e.address?1:-1;a->stop_reason=e.role;a->cleanup_end=(long long)e.address;a->init_wait_status=e.fd;}
      else quarantine=1;
    }
    if(ready(a->keeperfd)&&!a->exit_status){int status;pid_t r=waitpid(a->keeper,&status,WNOHANG);if(r==a->keeper){a->exit_status=WIFEXITED(status)&&WEXITSTATUS(status)==0?1:-1;a->keeper_wait_status=status;}}
    if(a->cleanup_end&&monotonic_ms()>a->cleanup_end){a->expired=1;quarantine=1;}
    if(!a->expired&&a->done==1&&a->exit_status==1&&a->output_eof&&cgroup_empty(a->sequence)&&monotonic_ms()<=a->cleanup_end){a->closed=1;close(a->channel);close(a->keeperfd);}
    if(a->exit_status==-1)quarantine=1;
  }
}
static int burn_and_start(const unsigned char nonce[16],int callerfd) {
  if(quarantine||attempt_count==MAX_ATTEMPTS)return -1;
  for(int i=0;i<attempt_count;i++)if(!attempts[i].closed)return -1;
  int seq=attempt_count+1;char leaf[32],cg[PATH_MAX];snprintf(leaf,sizeof(leaf),"uid-burn-%d",seq);
  /* The history is never removed/reused. Incomplete prior history quarantines restart. */
  int fd=openat(rootfd,leaf,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return -1;
  struct { unsigned char nonce[16];uint32_t authority,worker; } record;
  memcpy(record.nonce,nonce,16);record.authority=QA_UID_FIRST+(unsigned)(seq-1)*2;record.worker=record.authority+1;
  int ok=write_all(fd,&record,sizeof(record))==0&&fsync(fd)==0;close(fd);
  if(!ok||fsync(rootfd)){quarantine=1;return -1;}
  snprintf(cg,sizeof(cg),QA_CGROUP "/attempt-%d",seq);if(mkdir(cg,0700)){quarantine=1;return -1;}
  int channel[2]={-1,-1},gate[2]={-1,-1},output[2]={-1,-1};
  if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,channel)||pipe2(gate,O_CLOEXEC)||pipe2(output,O_CLOEXEC)||fcntl(output[0],F_SETFL,O_NONBLOCK)){
    quarantine=1;close_pair(channel);close_pair(gate);close_pair(output);return -1;
  }
  pid_t pid=fork();if(pid<0){quarantine=1;close_pair(channel);close_pair(gate);close_pair(output);return -1;}
  if(!pid){close(channel[0]);close(gate[1]);close(output[0]);keeper(channel[1],seq,record.authority,record.worker,gate[0],callerfd,output[1]);_exit(133);}
  close(channel[1]);close(gate[0]);close(output[1]);int pidfd=pidfd_open_exact(pid);
  if(pidfd<0){close(gate[1]);close(channel[0]);close(output[0]);quarantine=1;reap_unpermitted_child(pid);return -1;}
  struct attempt *a=&attempts[attempt_count++];memcpy(a->nonce,nonce,16);a->sequence=seq;a->keeper=pid;a->keeperfd=pidfd;a->channel=channel[0];
  a->authority_uid=record.authority;a->worker_uid=record.worker;a->started=monotonic_ms();a->output_fd=output[0];
  if(write_all(gate[1],"K",1)){quarantine=1;}close(gate[1]);return seq-1;
}
static int request_read(int fd,struct request *out,int *callerfd) {
  unsigned char raw[sizeof(*out)+1];union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(16*sizeof(int))];} control={0};
  struct iovec io={raw,sizeof(raw)};struct msghdr m={0};m.msg_iov=&io;m.msg_iovlen=1;m.msg_control=control.bytes;m.msg_controllen=sizeof(control.bytes);
  ssize_t n=recvmsg(fd,&m,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);int creds=0,rights=0;struct ucred peer={0};
  if(n<0)return -1;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
    if(c->cmsg_len<CMSG_LEN(0)||c->cmsg_len>(size_t)((char *)m.msg_control+m.msg_controllen-(char *)c))return -1;
    if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof(peer))){memcpy(&peer,CMSG_DATA(c),sizeof(peer));creds++;}
    else if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){rights=1;size_t count=(c->cmsg_len-CMSG_LEN(0))/sizeof(int);int *fds=(int *)CMSG_DATA(c);for(size_t i=0;i<count;i++)close(fds[i]);}
    else rights=1;
  }
  if(n!=sizeof(*out)||(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||creds!=1||rights||peer.uid!=QA_CALLER_UID)return -1;
  struct ucred initial={0};socklen_t length=sizeof(initial);
  if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&initial,&length)||length!=sizeof(initial)||initial.pid!=peer.pid||initial.uid!=peer.uid)return -1;
  length=sizeof(*callerfd);if(getsockopt(fd,SOL_SOCKET,SO_PEERPIDFD,callerfd,&length)||length!=sizeof(*callerfd)||*callerfd<0||ready(*callerfd))return -1;
  memcpy(out,raw,sizeof(*out));return out->magic==MAGIC&&out->version==1&&out->ordinal==1&&out->op>=1&&out->op<=4?0:-1;
}
static void reply(int fd,const struct request *r,int callerfd) {
  observe();int index=-1;for(int i=0;i<attempt_count;i++)if(!memcmp(r->nonce,attempts[i].nonce,16))index=i;
  if(r->op==2&&index<0)index=burn_and_start(r->nonce,callerfd);
  if(r->op==3&&index>=0&&!attempts[index].closed)send(attempts[index].channel,"S",1,MSG_NOSIGNAL|MSG_DONTWAIT);
  char text[2048];int n;
  if(index<0)n=snprintf(text,sizeof(text),"{\"protocol\":\"knowledge-linux-service-qa.v1\",\"status\":\"%s\",\"attempts\":%d,\"quarantine\":%s,\"broker_pid\":%d,\"broker_parent\":%d,\"qa_anchor_pid\":%d}",r->op==1?"ready":"unavailable",attempt_count,quarantine?"true":"false",getpid(),getppid(),qa_anchor_pid);
  else{struct attempt *a=&attempts[index];n=snprintf(text,sizeof(text),"{\"protocol\":\"knowledge-linux-service-qa.v1\",\"status\":\"%s\",\"sequence\":%d,\"keeper_pid\":%d,\"init_pid\":%d,\"authority_pid\":%d,\"worker_pid\":%d,\"authority_uid\":%d,\"worker_uid\":%d,\"authority_address\":%llu,\"authority_fd\":%d,\"worker_memory_denied\":%s,\"init_exit_confirmed\":%s,\"keeper_exit_confirmed\":%s,\"cgroup_empty\":%s,\"output_eof\":%s,\"output_bytes\":%llu,\"stop_reason\":%d,\"keeper_wait_known\":%s,\"keeper_wait_status\":%d,\"init_wait_known\":%s,\"init_wait_status\":%d,\"quarantine\":%s}",a->closed?"closed":a->expired||a->exit_status<0||a->done<0?"cleanup_unconfirmed":a->authority&&a->worker?"running":"starting",a->sequence,a->keeper,a->init,a->authority,a->worker,a->authority_uid,a->worker_uid,(unsigned long long)a->authority_address,a->authority_fd,a->worker_memory_denied?"true":"false",a->done==1?"true":"false",a->exit_status==1?"true":"false",a->closed?"true":"false",a->output_eof?"true":"false",(unsigned long long)a->output_bytes,a->stop_reason,a->exit_status?"true":"false",a->keeper_wait_status,a->done?"true":"false",a->init_wait_status,quarantine?"true":"false");}
  if(n>0&&(size_t)n<sizeof(text))send(fd,text,(size_t)n,MSG_NOSIGNAL|MSG_DONTWAIT);
}
int main(int argc,char **argv) {
  (void)argv;if(argc!=1||getuid()!=0||geteuid()!=0||getppid()!=1||QA_CALLER_UID==0||QA_UID_FIRST<1000000000)_exit(140);
  signal(SIGPIPE,SIG_IGN);umask(077);
  rootfd=open(QA_ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat s;
  if(rootfd<0||fstat(rootfd,&s)||s.st_uid!=0||(s.st_mode&0022))_exit(141);
  for(int i=1;i<=MAX_ATTEMPTS;i++){char leaf[32];snprintf(leaf,sizeof(leaf),"uid-burn-%d",i);if(fstatat(rootfd,leaf,&s,AT_SYMLINK_NOFOLLOW)==0)quarantine=1;else if(errno!=ENOENT)_exit(142);}
  daemonfd=pidfd_open_exact(getpid());if(daemonfd<0)_exit(143);
  int server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);int one=1;
  if(server<0||setsockopt(server,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)))_exit(144);
  struct sockaddr_un address={.sun_family=AF_UNIX};if(strlen(QA_ROOT "/control.sock")>=sizeof(address.sun_path))_exit(145);strcpy(address.sun_path,QA_ROOT "/control.sock");
  /* On restart only our root-owned socket may be replaced; no caller pathname. */
  if(fstatat(rootfd,"control.sock",&s,AT_SYMLINK_NOFOLLOW)==0){if(!S_ISSOCK(s.st_mode)||s.st_uid!=0||unlinkat(rootfd,"control.sock",0))_exit(146);}else if(errno!=ENOENT)_exit(147);
  if(bind(server,(struct sockaddr *)&address,sizeof(address))||chmod(address.sun_path,0666)||listen(server,8))_exit(148);
  /* QA observation anchor only, outside every attempt cgroup. It neither owns
   * nor stops work. Keeping the service populated lets the root harness read
   * the actual empty attempt cgroup after broker death, rather than treating
   * systemd's removal of a cgroup as evidence of emptiness. */
  qa_anchor_pid=fork();if(qa_anchor_pid<0)_exit(150);
  if(!qa_anchor_pid){if(close_except(NULL,0))_exit(151);long long end=monotonic_ms()+120000;while(monotonic_ms()<end)poll(NULL,0,100);_exit(0);}
  for(;;){
    observe();struct pollfd p={server,POLLIN,0};if(poll(&p,1,50)<0&&errno!=EINTR)_exit(149);if(!(p.revents&POLLIN))continue;
    int fd=accept4(server,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);if(fd<0)continue;
    if(setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))){close(fd);continue;}
    struct pollfd q={fd,POLLIN,0};if(poll(&q,1,500)>0){struct request r;int callerfd=-1;if(request_read(fd,&r,&callerfd)==0)reply(fd,&r,callerfd);else {const char denied[]="{\"status\":\"denied\"}";send(fd,denied,sizeof(denied)-1,MSG_NOSIGNAL|MSG_DONTWAIT);}if(callerfd>=0)close(callerfd);}
    close(fd);
  }
}
