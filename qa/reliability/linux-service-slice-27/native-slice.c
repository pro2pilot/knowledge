/* Closed Linux component experiment, NOT a production service/backend.
 * Fixed system-manager launch, opaque installer-provided input blob, one
 * readonly Node test. There is no public RPC, arbitrary root exec or KVE.
 * All installation paths and reserved identities are fixed by the QA build. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if !defined(SLICE_ROOT) || !defined(SLICE_CGROUP) || !defined(SLICE_A_UID) || !defined(SLICE_W_UID)
#error Fixed installation and reserved identities required
#endif
#define WORK_MS 30000
#define CLEANUP_MS 10000
#define STACK_BYTES (1024 * 1024)
#define INPUT_CAP (2 * 1024 * 1024)
#define OUTPUT_CAP 65536
struct work_result { int phase, importer_drained, importer_detached_writer, readonly, authority_readback, worker_status, authority_status, importer_wait_status;
  char importer_report[257];
  char manifest[65], directories[65]; unsigned files, bytes; };
struct keeper_result { int kind, init, init_status, init_reaped, cgroup_empty, cleanup_confirmed, reason;
  long long work_ms, cleanup_ms, completed_ms; struct work_result work; };
struct init_args { int gate, keeperfd, report, output; };
static volatile sig_atomic_t cancelled;
static long long now_ms(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) _exit(110); return (long long)t.tv_sec*1000+t.tv_nsec/1000000; }
static int pidfd(int pid) { return (int)syscall(SYS_pidfd_open,pid,0); }
static int dead(int fd) { struct pollfd p={fd,POLLIN,0}; int rc=poll(&p,1,0); return rc>0&&(p.revents&(POLLIN|POLLHUP|POLLERR)); }
static int kill_exact(int fd) { return (int)syscall(SYS_pidfd_send_signal,fd,SIGKILL,NULL,0); }
static int send_birth(int channel,const struct keeper_result *result,int held) {
  union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(int))];} control={0};
  struct iovec io={(void *)result,sizeof(*result)};struct msghdr message={0};
  message.msg_iov=&io;message.msg_iovlen=1;message.msg_control=control.bytes;message.msg_controllen=sizeof(control.bytes);
  struct cmsghdr *c=CMSG_FIRSTHDR(&message);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(c),&held,sizeof(held));
  return sendmsg(channel,&message,MSG_NOSIGNAL|MSG_DONTWAIT)==sizeof(*result)?0:-1;
}
static ssize_t receive_keeper(int channel,struct keeper_result *result,int *received) {
  union {struct cmsghdr align;char bytes[CMSG_SPACE(16*sizeof(int))];} control={0};
  struct iovec io={result,sizeof(*result)};struct msghdr message={0};
  message.msg_iov=&io;message.msg_iovlen=1;message.msg_control=control.bytes;message.msg_controllen=sizeof(control.bytes);
  ssize_t n=recvmsg(channel,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);*received=-1;
  if(n<=0)return n;
  int count=0,bad=0;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)){
    if(c->cmsg_level!=SOL_SOCKET||c->cmsg_type!=SCM_RIGHTS||c->cmsg_len<CMSG_LEN(0)){bad=1;continue;}
    size_t bytes=c->cmsg_len-CMSG_LEN(0);if(bytes%sizeof(int))bad=1;
    int *fds=(int *)CMSG_DATA(c);
    for(size_t i=0;i<bytes/sizeof(int);i++){if(count++==0)*received=fds[i];else close(fds[i]);}
  }
  if(n!=sizeof(*result)||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||bad||count>1||
      (result->kind==1?count!=1:count!=0)){
    if(*received>=0)close(*received);*received=-1;return -2;
  }
  return n;
}
static void cancel_signal(int sig) { (void)sig; cancelled=1; }
static int write_all(int fd,const void *body,size_t length) {
  const unsigned char *p=body;
  while(length) { ssize_t n=write(fd,p,length); if(n<0&&errno==EINTR)continue; if(n<=0)return -1; p+=n;length-=(size_t)n; }
  return 0;
}
static int close_except(const int *keep,size_t count) {
  int sorted[12]; if(count>12)return -1;
  for(size_t i=0;i<count;i++){if(keep[i]<0)return -1;sorted[i]=keep[i];}
  for(size_t i=0;i<count;i++)for(size_t j=i+1;j<count;j++)if(sorted[j]<sorted[i]){int n=sorted[j];sorted[j]=sorted[i];sorted[i]=n;}
  unsigned first=0;
  for(size_t i=0;i<count;i++){unsigned fd=(unsigned)sorted[i];if(fd<first)continue;if(fd>first&&syscall(SYS_close_range,first,fd-1,0))return -1;first=fd+1;}
  return syscall(SYS_close_range,first,UINT_MAX,0)?-1:0;
}
static int drop_role(uid_t uid,int importer) {
  if(uid<1000000000U||uid>=1900000000U||(uid!=SLICE_A_UID&&uid!=SLICE_W_UID)||
      (importer&&uid!=SLICE_A_UID))return -1;
  gid_t group=SLICE_W_UID;
  if(setgroups(importer?1:0,importer?&group:NULL))return -1;
  for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)return -1;
  if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||setresgid(uid,uid,uid)||setresuid(uid,uid,uid))return -1;
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0},{0}};
  if(syscall(SYS_capset,&h,d)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||
     prctl(PR_SET_DUMPABLE,1,0,0,0)||prctl(PR_SET_PTRACER,PR_SET_PTRACER_ANY,0,0,0))return -1;
  uid_t r,e,s;gid_t gr,ge,gs,groups[2];int n=getgroups(2,groups);
  if(getresuid(&r,&e,&s)||getresgid(&gr,&ge,&gs)||r!=uid||e!=uid||s!=uid||gr!=uid||ge!=uid||gs!=uid||
     n!=(importer?1:0)||(importer&&groups[0]!=SLICE_W_UID)||syscall(SYS_capget,&h,d))return -1;
  if(d[0].effective|d[0].permitted|d[0].inheritable|d[1].effective|d[1].permitted|d[1].inheritable)return -1;
  return prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=1?-1:0;
}
static int make_dir(const char *name,uid_t uid,gid_t gid,mode_t mode) {
  if(mkdir(name,0700)||chown(name,uid,gid)||chmod(name,mode))return -1;
  struct stat s;if(lstat(name,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=uid||s.st_gid!=gid||(s.st_mode&07777)!=mode)return -1;
  return 0;
}
static int bind_readonly(const char *from,const char *to) {
  if(mount(from,to,NULL,MS_BIND,NULL)||mount(NULL,to,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))return -1;
  struct statvfs s;return statvfs(to,&s)||(s.f_flag&ST_RDONLY)==0?-1:0;
}
static int opaque_input(void) {
  int source=open(SLICE_ROOT "/input.json",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
  struct stat s;if(source<0||fstat(source,&s)||!S_ISREG(s.st_mode)||s.st_uid!=0||s.st_nlink!=1||
      (s.st_mode&07777)!=0400||s.st_size<1||s.st_size>INPUT_CAP){if(source>=0)close(source);return -1;}
  int target=(int)syscall(SYS_memfd_create,"knowledge-slice-input",MFD_CLOEXEC|MFD_ALLOW_SEALING);
  if(target<0){close(source);return -1;}
  unsigned char buffer[16384];off_t count=0;int ok=1;
  for(;;){ssize_t n=read(source,buffer,sizeof(buffer));if(n<0&&errno==EINTR)continue;if(n<0){ok=0;break;}if(!n)break;
    count+=n;if(count>s.st_size||write_all(target,buffer,(size_t)n)){ok=0;break;}}
  struct stat after;if(fstat(source,&after)||after.st_dev!=s.st_dev||after.st_ino!=s.st_ino||after.st_size!=s.st_size||count!=s.st_size)ok=0;
  close(source);int seals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE;
  if(!ok||fcntl(target,F_ADD_SEALS,seals)||fcntl(target,F_GET_SEALS)!=seals||lseek(target,0,SEEK_SET)!=0){close(target);return -1;}
  return target;
}
static int layout(void) {
  if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)||
     make_dir(SLICE_ROOT "/workroot",0,0,0755)||make_dir(SLICE_ROOT "/workroot/runtime",0,0,0755)||
     make_dir(SLICE_ROOT "/workroot/lib",0,0,0755)||make_dir(SLICE_ROOT "/workroot/proc",0,0,0555)||
     make_dir(SLICE_ROOT "/workroot/dev",0,0,0755)||
     make_dir(SLICE_ROOT "/workroot/source",SLICE_A_UID,SLICE_W_UID,0750)||
     make_dir(SLICE_ROOT "/workroot/state",SLICE_A_UID,SLICE_A_UID,0700)||
     make_dir(SLICE_ROOT "/workroot/scratch",SLICE_W_UID,SLICE_W_UID,0700)||
     make_dir(SLICE_ROOT "/workroot/tmp",SLICE_W_UID,SLICE_W_UID,0700))return -1;
  int loader=open(SLICE_ROOT "/workroot/lib/ld-linux-aarch64.so.1",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0555);
  int nullfile=open(SLICE_ROOT "/workroot/dev/null",O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0666);
  if(loader<0||nullfile<0)return -1;close(loader);close(nullfile);
  if(bind_readonly(SLICE_ROOT "/runtime",SLICE_ROOT "/workroot/runtime")||
     bind_readonly(SLICE_ROOT "/runtime/loader",SLICE_ROOT "/workroot/lib/ld-linux-aarch64.so.1")||
     mount("/dev/null",SLICE_ROOT "/workroot/dev/null",NULL,MS_BIND,NULL)||
     mount("proc",SLICE_ROOT "/workroot/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||
     chroot(SLICE_ROOT "/workroot")||chdir("/"))return -1;
  return 0;
}
static void node_exec(const char *entry,int importer,int input,int receipt,int output) {
  /* Resolve all dup collisions before mapping the fixed role descriptors. */
  int a=fcntl(input,F_DUPFD_CLOEXEC,20),b=fcntl(receipt,F_DUPFD_CLOEXEC,20),c=fcntl(output,F_DUPFD_CLOEXEC,20);
  if(a<0||b<0||c<0)_exit(121);
  int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)_exit(122);
  if(dup2(nullfd,0)<0||dup2(c,1)<0||dup2(c,2)<0||dup2(a,3)<0||dup2(b,4)<0)_exit(123);
  int keep[]={0,1,2,3,4};if(close_except(keep,5)||drop_role(SLICE_A_UID,importer))_exit(124);
  char authority[32],worker[32];snprintf(authority,sizeof(authority),"%u",(unsigned)SLICE_A_UID);snprintf(worker,sizeof(worker),"%u",(unsigned)SLICE_W_UID);
  char *args[]={"/runtime/node",(char *)entry,"/source","/state",authority,worker,NULL};
  char *env[]={"PATH=/runtime","LD_LIBRARY_PATH=/runtime/lib","LANG=C","LC_ALL=C","HOME=/state","TMPDIR=/state",NULL};
  execve(args[0],args,env);_exit(125);
}
struct importer_args { int input,receipt,gate,alias_gate; };
static int importer_failure(int receipt,int code,int detail) {
  char line[80];int size=snprintf(line,sizeof(line),"KSE2 native_stage %d detail %d\n",code,detail);
  if(size>0&&(size_t)size<sizeof(line))(void)write_all(receipt,line,(size_t)size);
  return code;
}
static int detached_import_writer(int alias_gate) {
  /* Fixed QA injection: a grandchild retains a writable source FD, removes
   * its parent-death signal, and creates a new session. Reaping only Node I
   * or using a process group would not close this alias. Never product code. */
  int ready_pipe[2];if(pipe2(ready_pipe,O_CLOEXEC))return -1;
  pid_t child=fork();if(child<0)return -1;
  if(!child){
    close(ready_pipe[0]);int keep[]={ready_pipe[1],alias_gate};
    if(close_except(keep,2)||drop_role(SLICE_A_UID,0)||prctl(PR_SET_PDEATHSIG,0)||chmod("/source/input.txt",0640))_exit(181);
    int file=open("/source/input.txt",O_RDWR|O_CLOEXEC|O_NOFOLLOW);struct stat s;
    if(file<0||fstat(file,&s)||!S_ISREG(s.st_mode)||s.st_nlink!=1||s.st_uid!=SLICE_A_UID||chmod("/source/input.txt",0440))_exit(182);
    pid_t descendant=fork();if(descendant<0)_exit(183);
    if(descendant>0)_exit(0);
    if(setsid()<0||write_all(ready_pipe[1],"W",1))_exit(184);close(ready_pipe[1]);
    /* The outer init releases this only after reaping the importer namespace.
     * A real leak would retain the read end; no timing/scheduler guess is used. */
    char permit;if(read(alias_gate,&permit,1)==1&&permit=='X')(void)pwrite(file,"mutated\n",8,0);
    for(;;)pause();
  }
  close(ready_pipe[1]);char ready_byte;ssize_t count=read(ready_pipe[0],&ready_byte,1);close(ready_pipe[0]);
  int status;while(waitpid(child,&status,0)<0){if(errno!=EINTR)return -1;}
  return count==1&&ready_byte=='W'&&WIFEXITED(status)&&WEXITSTATUS(status)==0?0:-1;
}
static int importer_namespace(void *pointer) {
  struct importer_args *args=pointer;
  int keep[]={args->input,args->receipt,args->gate,args->alias_gate};
  if(close_except(keep,4)||getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=0)return importer_failure(args->receipt,130,errno);
  char permit;if(read(args->gate,&permit,1)!=1||permit!='I')return importer_failure(args->receipt,131,errno);close(args->gate);
  /* QA regression: layout already made the outer mount namespace private.
   * After chroot, '/' is an ordinary directory, not a mount root. Repeating
   * the propagation operation here was invalid. Prove that exact old call
   * is rejected, then inherit the private layout through CLONE_NEWNS. */
  errno=0;int legacy=mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL),legacy_errno=errno;
  if(legacy!=-1||legacy_errno!=EINVAL)return importer_failure(args->receipt,139,legacy_errno);
  const char mount_probe[]="KSM1 chroot_root_not_mountpoint EINVAL\n";
  if(write_all(args->receipt,mount_probe,sizeof(mount_probe)-1))return importer_failure(args->receipt,139,errno);
  if(umount2("/proc",MNT_DETACH)||
      mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return importer_failure(args->receipt,132,errno);
  int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)return 133;
  pid_t child=fork();if(child<0)return 134;
  if(!child)node_exec("/runtime/importer.js",1,args->input,args->receipt,nullfd);
  close(args->input);close(nullfd);
  int status=0;while(waitpid(child,&status,0)<0){if(errno!=EINTR)return 135;}
  if(!WIFEXITED(status)||WEXITSTATUS(status)!=0)return importer_failure(args->receipt,136,status);
  if(detached_import_writer(args->alias_gate))return importer_failure(args->receipt,138,errno);
  close(args->alias_gate);
  const char probe[]="KSD1 writable_alias_ready\n";
  if(write_all(args->receipt,probe,sizeof(probe)-1))return 137;close(args->receipt);
  /* Exiting the PID-namespace init kills/drains every remaining descendant.
   * The outer init must reap THIS init, not merely the Node importer. */
  return 0;
}
static int exact_reap(pid_t pid,int *status) {
  for(;;){pid_t got=waitpid(pid,status,0);if(got==pid)return 0;if(got<0&&errno==EINTR)continue;return -1;}
}
static int line_read(int fd,char *line,size_t cap) {
  size_t count=0;
  while(count<cap-1){ssize_t n=read(fd,line+count,cap-1-count);if(n<0&&errno==EINTR)continue;if(n<0)return -1;if(!n){line[count]=0;return (int)count;}count+=(size_t)n;}
  return -1;
}
static int hex64(const char *s) { if(strlen(s)!=64)return 0;for(int i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1; }
static int importer_phase(int input,struct work_result *result) {
  int report[2],gate[2],alias_gate[2];if(pipe2(report,O_CLOEXEC)||pipe2(gate,O_CLOEXEC)||pipe2(alias_gate,O_CLOEXEC))return -1;
  char *stack=malloc(STACK_BYTES);if(!stack)return -1;
  struct importer_args args={input,report[1],gate[0],alias_gate[0]};
  pid_t init=clone(importer_namespace,stack+STACK_BYTES,CLONE_NEWPID|CLONE_NEWNS|SIGCHLD,&args);
  if(init<0)return -1;close(report[1]);close(gate[0]);close(alias_gate[0]);
  int held=pidfd(init);if(held<0){close(gate[1]);return -1;}
  if(write_all(gate[1],"I",1)){close(gate[1]);return -1;}close(gate[1]);
  int status;if(exact_reap(init,&status))return -1;
  result->importer_wait_status=status;
  char line[257]={0};int size=line_read(report[0],line,sizeof(line));close(report[0]);
  memcpy(result->importer_report,line,sizeof(line));
  if(!dead(held)||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return -1;
  errno=0;ssize_t released=write(alias_gate[1],"X",1);int alias_closed=released==-1&&errno==EPIPE;close(alias_gate[1]);
  if(!alias_closed)return -1;
  close(held);free(stack);close(input);result->importer_drained=1;
  int used=0;if(size<1||sscanf(line,"KSM1 chroot_root_not_mountpoint EINVAL\nKSI1 %64[0-9a-f] %64[0-9a-f] %u %u\n%n",result->manifest,result->directories,&result->files,&result->bytes,&used)!=4||
    used<1||used>=size||strcmp(line+used,"KSD1 writable_alias_ready\n")||!hex64(result->manifest)||!hex64(result->directories)||result->files>128||result->bytes>1048576)return -1;
  result->importer_detached_writer=1;
  return 0;
}
static void worker_exec(int output) {
  int copy=fcntl(output,F_DUPFD_CLOEXEC,20),nullfd=open("/dev/null",O_RDONLY|O_CLOEXEC);
  if(copy<0||nullfd<0||dup2(nullfd,0)<0||dup2(copy,1)<0||dup2(copy,2)<0)_exit(140);
  int keep[]={0,1,2};if(close_except(keep,3)||chdir("/source")||drop_role(SLICE_W_UID,0))_exit(141);
  char *args[]={"/runtime/node","--test","/source/tests/read-only.test.js",NULL};
  char *env[]={"PATH=/runtime","LD_LIBRARY_PATH=/runtime/lib","LANG=C","LC_ALL=C","HOME=/scratch","TMPDIR=/scratch","KNOWLEDGE_SLICE_SCRATCH=/scratch",NULL};
  execve(args[0],args,env);_exit(142);
}
static int execute_phase(struct work_result *result,int output) {
  if(bind_readonly("/source","/source"))return -1;result->readonly=1;
  int control[2],ready_pipe[2];if(pipe2(control,O_CLOEXEC)||pipe2(ready_pipe,O_CLOEXEC))return -1;
  int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)return -1;
  pid_t authority=fork();if(authority<0)return -1;
  if(!authority)node_exec("/runtime/authority.js",0,control[0],ready_pipe[1],nullfd);
  close(control[0]);close(ready_pipe[1]);close(nullfd);
  char line[257],manifest[65]={0},directories[65]={0};unsigned files=0,bytes=0;int used=0;
  int size=line_read(ready_pipe[0],line,sizeof(line));close(ready_pipe[0]);
  if(size<1||sscanf(line,"KSA1 %64[0-9a-f] %64[0-9a-f] %u %u EROFS\n%n",manifest,directories,&files,&bytes,&used)!=4||used!=size||
     strcmp(manifest,result->manifest)||strcmp(directories,result->directories)||files!=result->files||bytes!=result->bytes)return -1;
  result->authority_readback=1;
  pid_t worker=fork();if(worker<0)return -1;if(!worker)worker_exec(output);close(output);
  if(exact_reap(worker,&result->worker_status)||write_all(control[1],"STOP\n",5))return -1;close(control[1]);
  if(exact_reap(authority,&result->authority_status))return -1;
  return WIFEXITED(result->worker_status)&&WEXITSTATUS(result->worker_status)==0&&
    WIFEXITED(result->authority_status)&&WEXITSTATUS(result->authority_status)==0?0:-1;
}
static int work_init(void *pointer) {
  struct init_args *a=pointer;int keep[]={a->gate,a->keeperfd,a->report,a->output};
  if(close_except(keep,4)||getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||dead(a->keeperfd))return 150;
  char gate;if(read(a->gate,&gate,1)!=1||gate!='G')return 151;close(a->gate);close(a->keeperfd);
  int cg=open(SLICE_CGROUP "/cgroup.procs",O_WRONLY|O_CLOEXEC|O_NOFOLLOW);
  if(cg<0||write_all(cg,"0",1))return 152;close(cg);
  struct work_result result={.phase=1,.worker_status=-1,.authority_status=-1,.importer_wait_status=-1};
  int input=opaque_input(),ok=0;
  if(input>=0&&layout()==0){result.phase=2;if(importer_phase(input,&result)==0){result.phase=3;if(execute_phase(&result,a->output)==0){result.phase=4;ok=1;}}}
  (void)write_all(a->report,&result,sizeof(result));close(a->report);
  return ok?0:153;
}
static int cgroup_empty(void) {
  int fd=open(SLICE_CGROUP "/cgroup.events",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
  char body[256];ssize_t n=read(fd,body,sizeof(body)-1);close(fd);if(n<=0||n>=(ssize_t)sizeof(body)-1)return 0;body[n]=0;
  return !strncmp(body,"populated 0\n",12)||strstr(body,"\npopulated 0\n")!=NULL;
}
static int create_work_cgroup(void) {
  /* Never move a workload outside this service's actual systemd custody. */
  int current=open("/proc/self/cgroup",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(current<0)return -1;
  char text[4096],expected[PATH_MAX];ssize_t size=read(current,text,sizeof(text)-1);close(current);
  if(size<=4||size>=(ssize_t)sizeof(text)-1)return -1;text[size]=0;
  if(strncmp(text,"0::/",4)||text[size-1]!='\n'||memchr(text,'\n',(size_t)size-1))return -1;text[size-1]=0;
  int count=snprintf(expected,sizeof(expected),"/sys/fs/cgroup%s/work",text+3);
  if(count<0||(size_t)count>=sizeof(expected)||strcmp(expected,SLICE_CGROUP))return -1;
  expected[strlen(expected)-5]=0;
  int parent=open(expected,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat s;struct statfs type;
  if(parent<0)return -1;
  int ok=fstat(parent,&s)==0&&s.st_uid==0&&(s.st_mode&0022)==0&&fstatfs(parent,&type)==0&&
    (unsigned long)type.f_type==0x63677270UL&&mkdirat(parent,"work",0700)==0;
  close(parent);return ok?0:-1;
}
static int observation_gate(struct stat *identity) {
  if(mkfifo(SLICE_ROOT "/observer.fifo",0600))return -1;
  int fd=open(SLICE_ROOT "/observer.fifo",O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return -1;
  if(fstat(fd,identity)||!S_ISFIFO(identity->st_mode)||identity->st_uid!=0||identity->st_nlink!=1||
     (identity->st_mode&07777)!=0600){close(fd);return -1;}
  return fd;
}
static int observe_and_remove(int fd,const struct stat *identity) {
  int acknowledged=0;long long end=now_ms()+30000;
  while(!cancelled&&now_ms()<end){
    struct pollfd p={fd,POLLIN,0};if(poll(&p,1,25)<0&&errno!=EINTR)break;
    if(p.revents&POLLIN){char bytes[2];ssize_t n=read(fd,bytes,sizeof(bytes));acknowledged=n==1&&bytes[0]=='A'&&now_ms()<end;break;}
    if(p.revents&(POLLERR|POLLHUP))break;
  }
  struct stat named;int same=lstat(SLICE_ROOT "/observer.fifo",&named)==0&&S_ISFIFO(named.st_mode)&&
    named.st_dev==identity->st_dev&&named.st_ino==identity->st_ino&&named.st_uid==0&&named.st_nlink==1;
  close(fd);if(!same||unlink(SLICE_ROOT "/observer.fifo"))return 0;
  /* This is the QA-observer terminal boundary; later signals cannot change
   * already completed native work, but no expired observation becomes PASS. */
  return acknowledged&&!cancelled&&now_ms()<end;
}
static void keeper(int channel,int ownerfd,int output,long long started) {
  int keep[]={channel,ownerfd,output};if(close_except(keep,3))_exit(160);
  int report[2],gate[2];if(pipe2(report,O_CLOEXEC|O_NONBLOCK)||pipe2(gate,O_CLOEXEC))_exit(161);
  int self=pidfd(getpid());if(self<0)_exit(162);char *stack=malloc(STACK_BYTES);if(!stack)_exit(163);
  struct init_args args={gate[0],self,report[1],output};
  pid_t init=clone(work_init,stack+STACK_BYTES,CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|SIGCHLD,&args);
  if(init<0)_exit(164);close(gate[0]);close(report[1]);close(self);close(output);
  int held=pidfd(init);if(held<0){close(gate[1]);_exit(165);}
  struct keeper_result result={.kind=1,.init=init,.init_status=-1};
  if(send_birth(channel,&result,held)){close(gate[1]);_exit(166);}
  int permitted=0;long long setup_end=started+5000;
  while(now_ms()<setup_end&&!dead(ownerfd)){
    struct pollfd p={channel,POLLIN,0};if(poll(&p,1,20)<0&&errno!=EINTR)break;
    if(p.revents&POLLIN){char byte[2];if(recv(channel,byte,sizeof(byte),MSG_DONTWAIT)==1&&byte[0]=='G')permitted=1;break;}
    if(p.revents&(POLLHUP|POLLERR))break;
  }
  if(permitted&&write_all(gate[1],"G",1)==0)result.reason=0;else result.reason=5;close(gate[1]);
  while(!result.reason){
    struct pollfd p={channel,POLLIN,0};if(poll(&p,1,20)<0&&errno!=EINTR){result.reason=5;break;}
    if(dead(ownerfd)||(p.revents&(POLLHUP|POLLERR)))result.reason=2;
    if(!result.reason&&(p.revents&POLLIN)){char byte[2];ssize_t n=recv(channel,byte,sizeof(byte),MSG_DONTWAIT);result.reason=n==1&&byte[0]=='S'?1:5;}
    if(!result.reason&&now_ms()>=started+WORK_MS)result.reason=3;
    if(!result.reason&&dead(held))result.reason=4;
  }
  long long cleanup_start=now_ms(),cleanup_end=cleanup_start+CLEANUP_MS;result.work_ms=cleanup_start-started;
  if(!dead(held)&&kill_exact(held)&&errno!=ESRCH)result.reason=5;
  while(!dead(held)&&now_ms()<cleanup_end){struct pollfd p={held,POLLIN,0};poll(&p,1,20);}
  pid_t got=waitpid(init,&result.init_status,WNOHANG);result.init_reaped=got==init;
  if(result.init_reaped){ssize_t n=read(report[0],&result.work,sizeof(result.work));if(n!=sizeof(result.work))memset(&result.work,0,sizeof(result.work));}
  while(result.init_reaped&&now_ms()<cleanup_end){if(cgroup_empty()){result.cgroup_empty=1;break;}poll(NULL,0,20);}
  result.completed_ms=now_ms();result.cleanup_ms=result.completed_ms-cleanup_start;
  result.cleanup_confirmed=result.init_reaped&&dead(held)&&result.cgroup_empty&&result.completed_ms<=cleanup_end;
  result.kind=2;(void)send(channel,&result,sizeof(result),MSG_NOSIGNAL|MSG_DONTWAIT);
  close(held);close(report[0]);close(channel);free(stack);_exit(result.cleanup_confirmed?0:167);
}
int main(int argc,char **argv) {
  (void)argv;if(argc!=1||getuid()!=0||geteuid()!=0||getppid()!=1||SLICE_A_UID<1000000000||SLICE_W_UID<1000000000||
    SLICE_A_UID>=1900000000||SLICE_W_UID>=1900000000||SLICE_A_UID==SLICE_W_UID)return 170;
  struct stat root;if(lstat(SLICE_ROOT,&root)||!S_ISDIR(root.st_mode)||root.st_uid!=0||(root.st_mode&0022))return 171;
  signal(SIGPIPE,SIG_IGN);signal(SIGTERM,cancel_signal);signal(SIGINT,cancel_signal);umask(077);
  if(prctl(PR_SET_CHILD_SUBREAPER,1)||create_work_cgroup())return 172;
  long long started=now_ms();int owner=pidfd(getpid()),channel[2],output[2];
  if(owner<0||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0,channel)||pipe2(output,O_NONBLOCK|O_CLOEXEC))return 173;
  pid_t child=fork();if(child<0)return 174;
  if(!child){close(channel[0]);close(output[0]);keeper(channel[1],owner,output[1],started);_exit(175);}
  close(channel[1]);close(output[1]);close(owner);int keeperfd=pidfd(child),initfd=-1;
  if(keeperfd<0){close(channel[0]);return 176;}
  struct keeper_result final={0};int eof=0,overflow=0,keeper_status=-1,keeper_reaped=0,protocol_bad=0,have_final=0;
  unsigned char bytes[OUTPUT_CAP];size_t used=0;long long limit=started+WORK_MS+CLEANUP_MS+2000;
  while(now_ms()<limit){
    if(cancelled||overflow){(void)send(channel[0],"S",1,MSG_NOSIGNAL|MSG_DONTWAIT);cancelled=2;}
    struct keeper_result message;ssize_t n;int received=-1;
    while((n=receive_keeper(channel[0],&message,&received))>0){
      if(message.kind==1&&initfd<0&&!have_final){initfd=received;received=-1;(void)send(channel[0],"G",1,MSG_NOSIGNAL|MSG_DONTWAIT);}
      else if(message.kind==2&&initfd>=0&&!have_final){final=message;have_final=1;}
      else protocol_bad=1;
      if(received>=0)close(received);
    }
    if(n==-2)protocol_bad=1;
    unsigned char buffer[4096];n=read(output[0],buffer,sizeof(buffer));
    if(n>0){if((size_t)n>OUTPUT_CAP-used)overflow=1;else{memcpy(bytes+used,buffer,(size_t)n);used+=(size_t)n;}}
    else if(n==0)eof=1;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)protocol_bad=1;
    if(dead(keeperfd)&&!keeper_reaped){pid_t got=waitpid(child,&keeper_status,WNOHANG);if(got==child)keeper_reaped=1;}
    if(keeper_reaped&&eof)break;
    if(protocol_bad)(void)send(channel[0],"S",1,MSG_NOSIGNAL|MSG_DONTWAIT);
    poll(NULL,0,10);
  }
  int closed=have_final&&final.cleanup_confirmed&&keeper_reaped&&WIFEXITED(keeper_status)&&WEXITSTATUS(keeper_status)==0&&
    initfd>=0&&dead(initfd)&&eof&&cgroup_empty();
  if(!closed){if(initfd>=0&&!dead(initfd))(void)kill_exact(initfd);if(!dead(keeperfd))(void)kill_exact(keeperfd);}
  int pass=closed&&!cancelled&&!overflow&&!protocol_bad&&final.reason==4&&WIFEXITED(final.init_status)&&WEXITSTATUS(final.init_status)==0&&
    final.work.phase==4&&final.work.importer_drained&&final.work.importer_detached_writer&&final.work.readonly&&final.work.authority_readback;
  struct stat observer_identity;int observer=pass?observation_gate(&observer_identity):-1;if(pass&&observer<0)pass=0;
  printf("{\"status\":\"%s\",\"production_admission\":false,\"release_gate_qualified\":false,\"component\":\"readonly_node_namespace\",\"observer_ack_required\":true,"
    "\"cleanup_confirmed\":%s,\"importer_namespace_drained\":%s,\"importer_detached_writer_ready\":%s,\"source_readonly\":%s,\"authority_readback\":%s,\"phase\":%d,"
    "\"work_ms\":%lld,\"cleanup_ms\":%lld,\"proof_emitted_ms\":%lld,\"stop_reason\":%d,\"init_wait_status\":%d,\"keeper_wait_status\":%d,"
    "\"worker_wait_status\":%d,\"authority_wait_status\":%d,\"importer_wait_status\":%d,\"cgroup_empty\":%s,\"output_eof\":%s,\"output_bytes\":%zu,"
    "\"input_manifest_sha256\":\"%s\",\"directories_sha256\":\"%s\",\"output_hex\":\"",
    pass?"WORK_CLOSED":"FAIL",closed?"true":"false",final.work.importer_drained?"true":"false",final.work.importer_detached_writer?"true":"false",final.work.readonly?"true":"false",
    final.work.authority_readback?"true":"false",final.work.phase,final.work_ms,final.cleanup_ms,now_ms()-started,final.reason,
    final.init_status,keeper_status,final.work.worker_status,final.work.authority_status,final.work.importer_wait_status,final.cgroup_empty?"true":"false",eof?"true":"false",used,
    final.work.manifest,final.work.directories);
  for(size_t i=0;i<used;i++)printf("%02x",bytes[i]);printf("\",\"importer_report_hex\":\"");
  for(size_t i=0;i<strnlen(final.work.importer_report,sizeof(final.work.importer_report));i++)printf("%02x",(unsigned char)final.work.importer_report[i]);
  puts("\"}");
  if(fflush(stdout))pass=0;
  if(observer>=0&&!observe_and_remove(observer,&observer_identity))pass=0;
  if(initfd>=0)close(initfd);close(keeperfd);close(channel[0]);close(output[0]);return pass?0:1;
}
