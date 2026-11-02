/* ORDINARY MODEL ONLY. Every OS entry used by the included source is replaced.
 * No real clone, credentials, pidfd, clock, FD, signal, namespace or exec call.
 * Compile/run only after source review. Model observations are not native proof. */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/nsfs.h>
#include <linux/sched.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long mx_syscall(long number,...);
static int mx_prctl(int option,...);
static int mx_getresuid(uid_t *,uid_t *,uid_t *);
static int mx_getresgid(gid_t *,gid_t *,gid_t *);
static int mx_getgroups(int,gid_t *);
static int mx_setgroups(size_t,const gid_t *);
static int mx_setresuid(uid_t,uid_t,uid_t);
static int mx_setresgid(gid_t,gid_t,gid_t);
static int mx_setfsuid(uid_t);
static int mx_setfsgid(gid_t);
static int mx_clock_gettime(clockid_t,struct timespec *);
static int mx_poll(struct pollfd *,nfds_t,int);
static int mx_fcntl(int,int,...);
static int mx_fstat(int,struct stat *);
static int mx_open(const char *,int,...);
static int mx_ioctl(int,unsigned long,...);
static int mx_close(int);
static int mx_dup3(int,int,int);
static ssize_t mx_read(int,void *,size_t);
static int mx_pipe2(int [2],int);
static pid_t mx_getpid(void);
static pid_t mx_getppid(void);
static int mx_sigaction(int,const struct sigaction *,struct sigaction *);
static int mx_setrlimit(__rlimit_resource_t,const struct rlimit *);
static int mx_waitid(idtype_t,id_t,siginfo_t *,int);
static _Noreturn void mx_exit(int);

#define syscall(...) mx_syscall(__VA_ARGS__)
#define prctl(...) mx_prctl(__VA_ARGS__)
#define getresuid(...) mx_getresuid(__VA_ARGS__)
#define getresgid(...) mx_getresgid(__VA_ARGS__)
#define getgroups(...) mx_getgroups(__VA_ARGS__)
#define setgroups(...) mx_setgroups(__VA_ARGS__)
#define setresuid(...) mx_setresuid(__VA_ARGS__)
#define setresgid(...) mx_setresgid(__VA_ARGS__)
#define setfsuid(...) mx_setfsuid(__VA_ARGS__)
#define setfsgid(...) mx_setfsgid(__VA_ARGS__)
#define clock_gettime(...) mx_clock_gettime(__VA_ARGS__)
#define poll(...) mx_poll(__VA_ARGS__)
#define fcntl(...) mx_fcntl(__VA_ARGS__)
#define fstat(...) mx_fstat(__VA_ARGS__)
#define open(...) mx_open(__VA_ARGS__)
#define ioctl(...) mx_ioctl(__VA_ARGS__)
#define close(...) mx_close(__VA_ARGS__)
#define dup3(...) mx_dup3(__VA_ARGS__)
#define read(...) mx_read(__VA_ARGS__)
#define pipe2(...) mx_pipe2(__VA_ARGS__)
#define getpid(...) mx_getpid(__VA_ARGS__)
#define getppid(...) mx_getppid(__VA_ARGS__)
#define sigaction(...) mx_sigaction(__VA_ARGS__)
#define setrlimit(...) mx_setrlimit(__VA_ARGS__)
#define waitid(...) mx_waitid(__VA_ARGS__)
#define _exit(...) mx_exit(__VA_ARGS__)
#include "../main-h-birth-core.inc"
#undef syscall
#undef prctl
#undef getresuid
#undef getresgid
#undef getgroups
#undef setgroups
#undef setresuid
#undef setresgid
#undef setfsuid
#undef setfsgid
#undef clock_gettime
#undef poll
#undef fcntl
#undef fstat
#undef open
#undef ioctl
#undef close
#undef dup3
#undef read
#undef pipe2
#undef getpid
#undef getppid
#undef sigaction
#undef setrlimit
#undef waitid
#undef _exit

enum mx_op { O_CLOCK,O_POLL,O_FCNTL,O_FSTAT,O_OPEN,O_IOCTL,O_CLOSE,O_DUP,
 O_READ,O_PIPE,O_GETUID,O_GETGID,O_GROUPS,O_SETGROUPS,O_SETUID,O_SETGID,
 O_FSUID,O_FSGID,O_PRCTL,O_CAPGET,O_CAPSET,O_SELF_PIDFD,O_CLONE,O_KILL,
 O_CLOSE_RANGE,O_EXEC,O_GETPID,O_GETPPID,O_SIGACTION,O_RLIMIT,O_WAIT,O_EXIT,O_UNKNOWN,O_COUNT };
static const char *const mx_names[O_COUNT]={"clock","poll","fcntl","fstat","open","ioctl","close","dup3",
 "read","pipe2","getresuid","getresgid","getgroups","setgroups","setresuid","setresgid",
 "setfsuid","setfsgid","prctl","capget","capset","self_pidfd_open","clone","pidfd_signal",
 "close_range","exec","getpid","getppid","sigaction","setrlimit","waitid","child_exit","UNKNOWN"};
enum mx_kind { K_NONE,K_PIPE_R,K_PIPE_W,K_PIDFD,K_SEALED,K_USERNS,K_CONTROL,K_SINGLETON,K_LISTENER };
enum { MX_FDS=256,MX_EVENTS=4096,MX_MAIN=400,MX_CHILD=501,MX_V=601,MX_FOREIGN=701 };
struct mx_fd {int open,kind,fdflags,flflags,seals,alive,pid;uint64_t object;};
struct mx_event {int op;long a,b,result;int error;};
struct mx_model {
 struct mx_fd fd[MX_FDS],initial_fd[MX_FDS];struct mx_event ev[MX_EVENTS];unsigned count,calls[O_COUNT];
 uid_t uid[3],fsuid;gid_t gid[3],fsgid;int groups,keepcaps,nnp,dumpable;
 uint64_t effective,permitted,inheritable,bounding,ambient,now,next_object;
 int fail_op,fail_n,fail_errno,unexpected,overflow;
 int identity_pid,parent_pid,ns_mismatch,ns_type,clock_error,clock_backwards;
 int chld_ignore,chld_nocldwait,wait_ready,wait_error,wait_wrong_pid,wait_code,wait_uid,wait_signo;
 int out_mode,err_mode,gate_mode,poll_error,poll_timeout_advance;
 int clone_mode,born_fd,born_pid,clone_store_violation,check_clone_store;
 int setuid_wrong,setgid_wrong,fsuid_wrong,fsgid_wrong,groups_wrong,capset_wrong;
 int death_on_uid,pdeath,early_singleton,foreign_signals,foreign_reaps,reaps,gate_writes;
 int prctl_fail_option,prctl_fail_suboption,close_failure_consumes,exit_code;
 int terminal_child,child_model;
 int jump_op,jump_n;uint64_t jump_to;
 int nnp_after_uid,keepcaps_wrong,ambient_wrong,dumpable_wrong,pdeath_calls,fail_pdeath_n;
 int fail_fcntl_cmd,fail_fcntl_n,fcntl_selected_calls,close_error_after_clone;
 int reuse_closed,reused_fd,reused_closes,listener_at_exit,gate_death_pid;
};
static struct mx_model mx;
static jmp_buf mx_escape;
static int mx_escape_ready;
static unsigned mx_passed,mx_failed;
static int mx_case_failed;
static const char *mx_case_name;
static const char *mx_errors[64];
static unsigned mx_error_count;

static int mx_note(int op,long a,long b){
 if(mx.check_clone_store&&op!=O_CLONE){
  if(mh_owned.child_pid!=mx.born_pid||mh_owned.pidfd!=mx.born_fd||!mh_raw.born)
   mx.clone_store_violation++;
  mx.check_clone_store=0;
 }
 errno=0;mx.calls[op]++;
 if(mx.count>=MX_EVENTS){mx.overflow=1;return -1;}
 int n=(int)mx.count++;mx.ev[n]=(struct mx_event){op,a,b,0,0};return n;
}
static long mx_done(int n,long r){
 if(n>=0){mx.ev[n].result=r;mx.ev[n].error=r<0?errno:0;
  if(mx.jump_op==mx.ev[n].op&&(int)mx.calls[mx.ev[n].op]==mx.jump_n)mx.now=mx.jump_to;
 }return r;
}
static int mx_should_fail(int op){
 if(mx.fail_op==op&&(int)mx.calls[op]==mx.fail_n){errno=mx.fail_errno;return 1;}return 0;
}
static int mx_fd_good(int fd){return fd>=0&&fd<MX_FDS&&mx.fd[fd].open;}
static int mx_writer_alias(uint64_t object){
 for(int i=0;i<MX_FDS;i++)if(mx.fd[i].open&&mx.fd[i].kind==K_PIPE_W&&mx.fd[i].object==object)return 1;
 return 0;
}
static int mx_alloc(int low,int kind,uint64_t object){
 for(int i=low;i<MX_FDS;i++)if(!mx.fd[i].open){
  mx.fd[i]=(struct mx_fd){.open=1,.kind=kind,.fdflags=FD_CLOEXEC,.flflags=O_NONBLOCK,.alive=1,.object=object};return i;
 }errno=EMFILE;return -1;
}
static void mx_singleton_check(void){
 int singleton=0,listener=0;
 for(int i=0;i<MX_FDS;i++)if(mx.fd[i].open){singleton+=mx.fd[i].kind==K_SINGLETON;listener+=mx.fd[i].kind==K_LISTENER;}
 if(mx.child_model&&!singleton&&listener)mx.early_singleton++;
}
static int mx_unknown(int n){mx.unexpected++;errno=ENOSYS;return (int)mx_done(n,-1);}
static int mx_open(const char *name,int flags,...){
 int n=mx_note(O_OPEN,flags,0);if(mx_should_fail(O_OPEN))return (int)mx_done(n,-1);
 if(strcmp(name,"/proc/self/ns/user"))return mx_unknown(n);
 int fd=mx_alloc(0,K_USERNS,mx.ns_mismatch?9002:9001);return (int)mx_done(n,fd);
}
static int mx_close(int fd){
 int n=mx_note(O_CLOSE,fd,0);
 if(mx.reused_fd==fd)mx.reused_closes++;
 if(mx_should_fail(O_CLOSE)){
  if(mx.close_failure_consumes&&mx_fd_good(fd)){
   mx.fd[fd].open=0;
   if(mx.reuse_closed){mx.fd[fd]=(struct mx_fd){.open=1,.kind=K_PIDFD,.fdflags=FD_CLOEXEC,.alive=1,.pid=MX_FOREIGN,.object=19999};mx.reused_fd=fd;}
  }
  return (int)mx_done(n,-1);
 }
 if(!mx_fd_good(fd)){errno=EBADF;return (int)mx_done(n,-1);}
 mx.fd[fd].open=0;mx_singleton_check();return (int)mx_done(n,0);
}
static int mx_fcntl(int fd,int cmd,...){
 int n=mx_note(O_FCNTL,fd,cmd);if(mx_should_fail(O_FCNTL))return (int)mx_done(n,-1);
 if(cmd==mx.fail_fcntl_cmd&&++mx.fcntl_selected_calls==mx.fail_fcntl_n){errno=EMFILE;return (int)mx_done(n,-1);}
 if(!mx_fd_good(fd)){errno=EBADF;return (int)mx_done(n,-1);}
 va_list a;va_start(a,cmd);int r=-1;
 switch(cmd){
  case F_GETFD:r=mx.fd[fd].fdflags;break;
  case F_GETFL:r=mx.fd[fd].flflags;break;
  case F_GET_SEALS:if(mx.fd[fd].kind!=K_SEALED)errno=EINVAL;else r=mx.fd[fd].seals;break;
  case F_SETFD:mx.fd[fd].fdflags=va_arg(a,int);r=0;break;
  case F_SETFL:mx.fd[fd].flflags=va_arg(a,int);r=0;break;
  case F_DUPFD_CLOEXEC:case F_DUPFD:{int low=va_arg(a,int);r=mx_alloc(low,mx.fd[fd].kind,mx.fd[fd].object);if(r>=0){mx.fd[r]=mx.fd[fd];mx.fd[r].fdflags=cmd==F_DUPFD_CLOEXEC?FD_CLOEXEC:0;}break;}
  default:mx.unexpected++;errno=ENOSYS;
 }
 va_end(a);return (int)mx_done(n,r);
}
static int mx_fstat(int fd,struct stat *s){
 int n=mx_note(O_FSTAT,fd,0);if(mx_should_fail(O_FSTAT))return (int)mx_done(n,-1);
 if(!mx_fd_good(fd)){errno=EBADF;return (int)mx_done(n,-1);}
 memset(s,0,sizeof *s);s->st_dev=(dev_t)(mx.fd[fd].kind==K_USERNS?33:44);s->st_ino=(ino_t)mx.fd[fd].object;
 s->st_mode=mx.fd[fd].kind==K_PIPE_R||mx.fd[fd].kind==K_PIPE_W?S_IFIFO|0600:S_IFREG|0600;
 s->st_nlink=mx.fd[fd].kind==K_SEALED?0:1;s->st_size=mx.fd[fd].kind==K_SEALED?128:0;
 return (int)mx_done(n,0);
}
static int mx_ioctl(int fd,unsigned long request,...){
 int n=mx_note(O_IOCTL,fd,(long)request);if(mx_should_fail(O_IOCTL))return (int)mx_done(n,-1);
 if(!mx_fd_good(fd)){errno=EBADF;return (int)mx_done(n,-1);}
 if(request!=NS_GET_NSTYPE||mx.fd[fd].kind!=K_USERNS)return mx_unknown(n);
 return (int)mx_done(n,mx.ns_type);
}
static int mx_dup3(int source,int target,int flags){
 int n=mx_note(O_DUP,source,target);if(mx_should_fail(O_DUP))return (int)mx_done(n,-1);
 if(!mx_fd_good(source)||target<0||target>=MX_FDS||source==target){errno=EBADF;return (int)mx_done(n,-1);}
 mx.fd[target]=mx.fd[source];mx.fd[target].fdflags=flags&O_CLOEXEC?FD_CLOEXEC:0;mx_singleton_check();
 return (int)mx_done(n,target);
}
static int mx_pipe2(int p[2],int flags){
 int n=mx_note(O_PIPE,flags,0);if(mx_should_fail(O_PIPE))return (int)mx_done(n,-1);
 uint64_t object=++mx.next_object;int a=mx_alloc(0,K_PIPE_R,object);if(a<0)return (int)mx_done(n,-1);
 int b=mx_alloc(0,K_PIPE_W,object);if(b<0){mx.fd[a].open=0;return (int)mx_done(n,-1);}
 mx.fd[a].flflags=O_RDONLY|(flags&O_NONBLOCK);mx.fd[b].flflags=O_WRONLY|(flags&O_NONBLOCK);
 mx.fd[a].fdflags=mx.fd[b].fdflags=flags&O_CLOEXEC?FD_CLOEXEC:0;p[0]=a;p[1]=b;return (int)mx_done(n,0);
}
static ssize_t mx_read(int fd,void *buf,size_t size){
 int n=mx_note(O_READ,fd,(long)size);if(mx_should_fail(O_READ))return (ssize_t)mx_done(n,-1);
 if(!mx_fd_good(fd)||mx.fd[fd].kind!=K_PIPE_R){errno=EBADF;return (ssize_t)mx_done(n,-1);}
 int mode=mx.fd[fd].object==5001?mx.out_mode:mx.fd[fd].object==5002?mx.err_mode:mx.gate_mode;
 if(mode==1&&!mx_writer_alias(mx.fd[fd].object))return (ssize_t)mx_done(n,0);
 if(mode==2&&size){((unsigned char *)buf)[0]='B';return (ssize_t)mx_done(n,1);}
 errno=EAGAIN;return (ssize_t)mx_done(n,-1);
}
static int mx_poll(struct pollfd *p,nfds_t count,int timeout){
 int n=mx_note(O_POLL,(long)count,timeout);if(mx_should_fail(O_POLL)||mx.poll_error){if(mx.poll_error)errno=mx.poll_error;return (int)mx_done(n,-1);}
 if(count==3&&mx.gate_death_pid){
  for(int i=0;i<MX_FDS;i++)if(mx.fd[i].kind==K_PIDFD&&mx.fd[i].pid==mx.gate_death_pid)mx.fd[i].alive=0;
  if(mx.gate_death_pid==MX_MAIN)mx.parent_pid=1;
 }
 int ready=0;
 for(nfds_t i=0;i<count;i++){
  p[i].revents=0;if(p[i].fd<0)continue;
  if(!mx_fd_good(p[i].fd))p[i].revents=POLLNVAL;
  else if(mx.fd[p[i].fd].kind==K_PIDFD&&!mx.fd[p[i].fd].alive)p[i].revents=POLLIN;
  else if(mx.fd[p[i].fd].kind==K_PIPE_R){
   int mode=mx.fd[p[i].fd].object==5001?mx.out_mode:mx.fd[p[i].fd].object==5002?mx.err_mode:mx.gate_mode;
   if(mode==1&&!mx_writer_alias(mx.fd[p[i].fd].object))p[i].revents=POLLHUP;else if(mode==2)p[i].revents=POLLIN;
  }
  if(p[i].revents)ready++;
 }
 if(!ready&&timeout>0&&mx.poll_timeout_advance)mx.now+=(uint64_t)timeout*UINT64_C(1000000);
 return (int)mx_done(n,ready);
}
static int mx_clock_gettime(clockid_t clock,struct timespec *t){
 int n=mx_note(O_CLOCK,clock,0);if(mx_should_fail(O_CLOCK)||mx.clock_error){errno=EIO;return (int)mx_done(n,-1);}
 if(clock!=CLOCK_MONOTONIC)return mx_unknown(n);
 uint64_t at=mx.clock_backwards?1:mx.now;t->tv_sec=(time_t)(at/UINT64_C(1000000000));t->tv_nsec=(long)(at%UINT64_C(1000000000));return (int)mx_done(n,0);
}
static int mx_getresuid(uid_t *a,uid_t *b,uid_t *c){int n=mx_note(O_GETUID,0,0);if(mx_should_fail(O_GETUID))return (int)mx_done(n,-1);*a=mx.uid[0];*b=mx.uid[1];*c=mx.uid[2];return (int)mx_done(n,0);}
static int mx_getresgid(gid_t *a,gid_t *b,gid_t *c){int n=mx_note(O_GETGID,0,0);if(mx_should_fail(O_GETGID))return (int)mx_done(n,-1);*a=mx.gid[0];*b=mx.gid[1];*c=mx.gid[2];return (int)mx_done(n,0);}
static int mx_getgroups(int count,gid_t *groups){int n=mx_note(O_GROUPS,count,groups!=NULL);if(mx_should_fail(O_GROUPS))return (int)mx_done(n,-1);return (int)mx_done(n,mx.groups);}
static int mx_setgroups(size_t count,const gid_t *groups){
 int n=mx_note(O_SETGROUPS,(long)count,groups!=NULL);if(mx_should_fail(O_SETGROUPS))return (int)mx_done(n,-1);
 if(count||groups)return mx_unknown(n);
 mx.groups=mx.groups_wrong?1:0;
 return (int)mx_done(n,0);
}
static int mx_setresuid(uid_t a,uid_t b,uid_t c){
 int n=mx_note(O_SETUID,a,b);if(mx_should_fail(O_SETUID))return (int)mx_done(n,-1);
 if(!mx.setuid_wrong){if(a!=(uid_t)-1)mx.uid[0]=a;if(b!=(uid_t)-1)mx.uid[1]=b;if(c!=(uid_t)-1)mx.uid[2]=c;}
 if(!mx.fsuid_wrong)mx.fsuid=mx.uid[1];
 mx.pdeath=0;
 mx.nnp=mx.nnp_after_uid;
 if(mx.death_on_uid){mx.parent_pid=1;for(int i=0;i<MX_FDS;i++)if(mx.fd[i].kind==K_PIDFD&&mx.fd[i].pid==MX_MAIN)mx.fd[i].alive=0;}
 return (int)mx_done(n,0);
}
static int mx_setresgid(gid_t a,gid_t b,gid_t c){
 int n=mx_note(O_SETGID,a,b);if(mx_should_fail(O_SETGID))return (int)mx_done(n,-1);
 if(!mx.setgid_wrong){if(a!=(gid_t)-1)mx.gid[0]=a;if(b!=(gid_t)-1)mx.gid[1]=b;if(c!=(gid_t)-1)mx.gid[2]=c;}
 if(!mx.fsgid_wrong)mx.fsgid=mx.gid[1];
 mx.pdeath=0;return (int)mx_done(n,0);
}
static int mx_setfsuid(uid_t uid){int n=mx_note(O_FSUID,uid,0);if(mx_should_fail(O_FSUID))return (int)mx_done(n,-1);uid_t old=mx.fsuid;if(uid!=(uid_t)-1)mx.fsuid=uid;return (int)mx_done(n,(int)old);}
static int mx_setfsgid(gid_t gid){int n=mx_note(O_FSGID,gid,0);if(mx_should_fail(O_FSGID))return (int)mx_done(n,-1);gid_t old=mx.fsgid;if(gid!=(gid_t)-1)mx.fsgid=gid;return (int)mx_done(n,(int)old);}
static int mx_prctl(int option,...){
 int n=mx_note(O_PRCTL,option,0);if(mx_should_fail(O_PRCTL)){return (int)mx_done(n,-1);}
 va_list a;va_start(a,option);int r=-1,sub=0;
 switch(option){
  case PR_GET_NO_NEW_PRIVS:r=mx.nnp;break;
  case PR_GET_KEEPCAPS:r=mx.keepcaps;break;
  case PR_GET_DUMPABLE:r=mx.dumpable;break;
  case PR_SET_KEEPCAPS:sub=va_arg(a,int);mx.keepcaps=mx.keepcaps_wrong?1:sub;r=0;break;
  case PR_SET_DUMPABLE:sub=va_arg(a,int);mx.dumpable=mx.dumpable_wrong?1:sub;r=0;break;
  case PR_SET_PDEATHSIG:sub=va_arg(a,int);mx.pdeath_calls++;mx.pdeath=sub;r=0;if(mx.fail_pdeath_n==mx.pdeath_calls){r=-1;errno=EPERM;}break;
  case PR_CAPBSET_READ:sub=va_arg(a,int);if(sub<0||sub>CAP_LAST_CAP)errno=EINVAL;else r=(int)((mx.bounding>>sub)&1U);break;
  case PR_CAP_AMBIENT:sub=va_arg(a,int);if(sub==PR_CAP_AMBIENT_CLEAR_ALL){mx.ambient=mx.ambient_wrong?UINT64_C(1)<<CAP_CHOWN:0;r=0;}else if(sub==PR_CAP_AMBIENT_IS_SET){int cap=va_arg(a,int);r=cap>=0&&cap<64?(int)((mx.ambient>>cap)&1U):-1;}else{mx.unexpected++;errno=ENOSYS;}break;
  default:mx.unexpected++;errno=ENOSYS;
 }
 va_end(a);if(n>=0)mx.ev[n].b=sub;
 if(mx.prctl_fail_option==option&&(mx.prctl_fail_suboption<0||mx.prctl_fail_suboption==sub)){errno=EPERM;r=-1;}
 return (int)mx_done(n,r);
}
static pid_t mx_getpid(void){int n=mx_note(O_GETPID,0,0);return (pid_t)mx_done(n,mx.identity_pid);}
static pid_t mx_getppid(void){int n=mx_note(O_GETPPID,0,0);return (pid_t)mx_done(n,mx.parent_pid);}
static int mx_sigaction(int signal,const struct sigaction *action,struct sigaction *old){
 int n=mx_note(O_SIGACTION,signal,action!=NULL);if(mx_should_fail(O_SIGACTION))return (int)mx_done(n,-1);
 if(signal!=SIGCHLD||action)return mx_unknown(n);
 if(old){memset(old,0,sizeof *old);old->sa_handler=mx.chld_ignore?SIG_IGN:SIG_DFL;old->sa_flags=mx.chld_nocldwait?SA_NOCLDWAIT:0;}
 return (int)mx_done(n,0);
}
static int mx_setrlimit(__rlimit_resource_t resource,const struct rlimit *limit){
 int n=mx_note(O_RLIMIT,resource,(long)limit->rlim_cur);if(mx_should_fail(O_RLIMIT))return (int)mx_done(n,-1);
 if(resource!=RLIMIT_CORE||limit->rlim_cur||limit->rlim_max)return mx_unknown(n);
 return (int)mx_done(n,0);
}
static int mx_waitid(idtype_t type,id_t id,siginfo_t *info,int options){
 int n=mx_note(O_WAIT,id,options);if(mx_should_fail(O_WAIT)||mx.wait_error){if(mx.wait_error)errno=mx.wait_error;return (int)mx_done(n,-1);}
 if(type!=P_PIDFD||!mx_fd_good((int)id)||mx.fd[id].kind!=K_PIDFD){errno=EBADF;return (int)mx_done(n,-1);}
 memset(info,0,sizeof *info);
 if(mx.wait_ready){info->si_signo=mx.wait_signo;info->si_pid=mx.wait_wrong_pid?mx.wait_wrong_pid:mx.fd[id].pid;info->si_uid=(uid_t)mx.wait_uid;info->si_code=mx.wait_code;info->si_status=0;
  if(!(options&WNOWAIT)){mx.reaps++;if(mx.fd[id].pid!=MX_CHILD||mx.fd[id].object!=10002)mx.foreign_reaps++;}
 }
 return (int)mx_done(n,0);
}
static long mx_syscall(long number,...){
 va_list a;va_start(a,number);long r=-1;int n;
 if(number==SYS_capget||number==SYS_capset){
  struct __user_cap_header_struct *h=va_arg(a,struct __user_cap_header_struct *);
  struct __user_cap_data_struct *data=va_arg(a,struct __user_cap_data_struct *);
  int op=number==SYS_capget?O_CAPGET:O_CAPSET;n=mx_note(op,h->version,h->pid);
  if(mx_should_fail(op))r=-1;
  else if(h->version!=_LINUX_CAPABILITY_VERSION_3||h->pid)r=mx_unknown(n);
  else if(op==O_CAPGET){for(unsigned i=0;i<2;i++){data[i].effective=(uint32_t)(mx.effective>>(i*32));data[i].permitted=(uint32_t)(mx.permitted>>(i*32));data[i].inheritable=(uint32_t)(mx.inheritable>>(i*32));}r=0;}
  else{if(!mx.capset_wrong){mx.effective=(uint64_t)data[0].effective|((uint64_t)data[1].effective<<32);mx.permitted=(uint64_t)data[0].permitted|((uint64_t)data[1].permitted<<32);mx.inheritable=(uint64_t)data[0].inheritable|((uint64_t)data[1].inheritable<<32);}r=0;}
  r=mx_done(n,r);
 }else if(number==SYS_pidfd_open){
  int pid=va_arg(a,int),flags=va_arg(a,int);n=mx_note(O_SELF_PIDFD,pid,flags);
  if(mx_should_fail(O_SELF_PIDFD))r=-1;
  else if(pid!=mx.identity_pid||pid!=MX_MAIN||flags)r=mx_unknown(n);
  else{r=mx_alloc(0,K_PIDFD,10001);if(r>=0)mx.fd[r].pid=pid;}
  r=mx_done(n,r);
 }else if(number==SYS_clone){
  unsigned flags=va_arg(a,unsigned);void *stack=va_arg(a,void *);int *fd=va_arg(a,int *);void *child_tid=va_arg(a,void *);int tls=va_arg(a,int);
  n=mx_note(O_CLONE,flags,0);
  if(mx_should_fail(O_CLONE))r=-1;
  else if(flags!=(CLONE_PIDFD|SIGCHLD)||stack||child_tid||tls||!fd)r=mx_unknown(n);
  else if(mx.clone_mode==3){*fd=-1;mx.identity_pid=MX_CHILD;mx.child_model=1;r=0;}
  else{*fd=mx.clone_mode==1?-1:mx_alloc(0,K_PIDFD,10002);if(*fd>=0){mx.fd[*fd].pid=MX_CHILD;mx.fd[*fd].alive=mx.clone_mode==2?0:1;}mx.born_fd=*fd;mx.born_pid=MX_CHILD;mx.check_clone_store=1;r=MX_CHILD;
   if(mx.close_error_after_clone){mx.fail_op=O_CLOSE;mx.fail_n=(int)mx.calls[O_CLOSE]+1;mx.fail_errno=EINTR;}
  }
  r=mx_done(n,r);
 }else if(number==SYS_pidfd_send_signal){
  int fd=va_arg(a,int),signal=va_arg(a,int);void *info=va_arg(a,void *);int flags=va_arg(a,int);n=mx_note(O_KILL,fd,signal);
  if(mx_fd_good(fd)&&mx.fd[fd].kind==K_PIDFD&&(mx.fd[fd].pid!=MX_CHILD||mx.fd[fd].object!=10002))mx.foreign_signals++;
  if(mx_should_fail(O_KILL))r=-1;
  else if(!mx_fd_good(fd)||mx.fd[fd].kind!=K_PIDFD){errno=EBADF;r=-1;}
  else if(signal!=SIGKILL||info||flags)r=mx_unknown(n);
  else r=0;
  r=mx_done(n,r);
 }else if(number==SYS_close_range){
  unsigned first=va_arg(a,unsigned),last=va_arg(a,unsigned),flags=va_arg(a,unsigned);n=mx_note(O_CLOSE_RANGE,first,last);
  if(mx_should_fail(O_CLOSE_RANGE))r=-1;
  else if(flags)r=mx_unknown(n);
  else{for(unsigned i=first;i<MX_FDS&&i<=last;i++)mx.fd[i].open=0;mx_singleton_check();r=0;}r=mx_done(n,r);
 }else if(number==SYS_execveat){n=mx_note(O_EXEC,0,0);r=mx_unknown(n);}
 else{n=mx_note(O_UNKNOWN,number,0);r=mx_unknown(n);}
 va_end(a);return r;
}
static _Noreturn void mx_exit(int code){
 int n=mx_note(O_EXIT,code,0);mx.exit_code=code;
 for(int i=0;i<MX_FDS;i++)if(mx.fd[i].open&&mx.fd[i].kind==K_LISTENER)mx.listener_at_exit++;
 (void)mx_done(n,0);if(mx_escape_ready)longjmp(mx_escape,1);
 printf("{\"kind\":\"fatal\",\"unexpected_child_exit\":%d}\n",code);exit(98);
}

static void mx_assert(int ok,const char *text){
 if(!ok){mx_case_failed=1;if(mx_error_count<64)mx_errors[mx_error_count++]=text;}
}
#define MX_ASSERT(value) mx_assert(!!(value),#value)
static void mx_json_string(const char *text){
 putchar('"');for(const unsigned char *p=(const unsigned char *)text;*p;p++){
  if(*p=='"'||*p=='\\')putchar('\\');
  if(*p<32)printf("\\u%04x",*p);else putchar(*p);
 }putchar('"');
}
static void mx_receipt(void){
 printf("{\"owner_pid\":%d,\"child_pid\":%d,",mh_raw.owner_pid,mh_raw.child_pid);
 printf("\"phase\":%d,\"spent\":%d,\"born\":%d,\"birth_unknown\":%d,\"cancelled\":%d,\"release_requested\":%d,\"released\":%d,\"exec_attempted\":%d,\"reaped\":%d,\"out_eof\":%d,\"err_eof\":%d,\"cleanup_observed\":%d,\"failed\":%d,\"close_fault\":%d,\"wait_unknown\":%d,\"deadline_expired\":%d,\"timing_unknown\":%d,\"timely_cleanup\":%d,\"gate_bytes_sent\":%d,\"signal_fd\":%d,\"wait_fd\":%d,\"w_ns\":%llu,\"c_ns\":%llu,\"last_ns\":%llu,\"cleanup_ns\":%llu,\"out_bytes\":%llu,\"err_bytes\":%llu,",
  (int)mh_raw.phase,mh_raw.spent,mh_raw.born,mh_raw.birth_unknown,mh_raw.cancelled,mh_raw.release_requested,mh_raw.released,mh_raw.exec_attempted,mh_raw.reaped,mh_raw.out_eof,mh_raw.err_eof,mh_raw.cleanup_observed,mh_raw.failed,mh_raw.close_fault,mh_raw.wait_unknown,mh_raw.deadline_expired,mh_raw.timing_unknown,mh_raw.timely_cleanup,mh_raw.gate_bytes_sent,mh_raw.signal_fd,mh_raw.wait_fd,
  (unsigned long long)mh_raw.w_ns,(unsigned long long)mh_raw.c_ns,(unsigned long long)mh_raw.last_observed_ns,(unsigned long long)mh_raw.cleanup_observed_ns,(unsigned long long)mh_raw.out_bytes,(unsigned long long)mh_raw.err_bytes);
 const char *names[]={"self_pidfd","pipe","clone","signal","wait","out_read","err_read"};
 const struct mh_observation *obs[]={&mh_raw.self_pidfd,&mh_raw.pipe,&mh_raw.clone,&mh_raw.signal,&mh_raw.wait,&mh_raw.out_read,&mh_raw.err_read};
 for(unsigned i=0;i<sizeof obs/sizeof obs[0];i++)printf("\"%s\":{\"calls\":%u,\"result\":%ld,\"errno\":%d},",names[i],obs[i]->calls,obs[i]->result,obs[i]->error);
 printf("\"signals\":[");
 for(unsigned i=0;i<mh_raw.signal.calls&&i<MH_SIGNAL_ATTEMPTS;i++)printf("%s{\"fd\":%d,\"rc\":%ld,\"errno\":%d,\"attempted_ns\":%llu,\"returned_ns\":%llu}",i?",":"",mh_raw.signals[i].fd,mh_raw.signals[i].result,mh_raw.signals[i].error,(unsigned long long)mh_raw.signals[i].attempted_ns,(unsigned long long)mh_raw.signals[i].returned_ns);
 printf("],\"wait_info\":{\"signo\":%d,\"pid\":%d,\"uid\":%u,\"code\":%d,\"status\":%d},\"closes\":[",mh_raw.wait_info.si_signo,mh_raw.wait_info.si_pid,mh_raw.wait_info.si_uid,mh_raw.wait_info.si_code,mh_raw.wait_info.si_status);
 for(unsigned i=0;i<mh_raw.close_count&&i<MH_CLOSE_RECORDS;i++)printf("%s{\"fd\":%d,\"rc\":%d,\"errno\":%d}",i?",":"",mh_raw.closes[i].fd,mh_raw.closes[i].result,mh_raw.closes[i].error);
 printf("]}");
}
static void mx_end(void){
 MX_ASSERT(mx.calls[O_EXEC]==0);MX_ASSERT(mx.unexpected==0);MX_ASSERT(mx.overflow==0);
 MX_ASSERT(mx.foreign_signals==0);MX_ASSERT(mx.foreign_reaps==0);MX_ASSERT(mx.clone_store_violation==0);
 MX_ASSERT(mx.early_singleton==0);MX_ASSERT(!mx.child_model||mx.listener_at_exit==0);
 MX_ASSERT(mh_raw.gate_bytes_sent==0);MX_ASSERT(!mh_raw.released);MX_ASSERT(!mh_raw.exec_attempted);
 if(mx_case_failed)mx_failed++;else mx_passed++;
 printf("{\"kind\":\"case\",\"id\":");mx_json_string(mx_case_name);
 printf(",\"mode\":\"SYSCALL_MODEL_NOT_NATIVE_PROOF\",\"passed\":%s,\"errors\":[",mx_case_failed?"false":"true");
 for(unsigned i=0;i<mx_error_count;i++){if(i)putchar(',');mx_json_string(mx_errors[i]);}
 printf("],\"receipt\":");mx_receipt();printf(",\"trace\":[");
 for(unsigned i=0;i<mx.count;i++){struct mx_event *e=&mx.ev[i];printf("%s{\"op\":\"%s\",\"a\":%ld,\"b\":%ld,\"rc\":%ld,\"errno\":%d}",i?",":"",mx_names[e->op],e->a,e->b,e->result,e->error);}
 printf("]}\n");
}
static void mx_assign_fd(int fd,int kind,uint64_t object){
 mx.fd[fd]=(struct mx_fd){.open=1,.kind=kind,.fdflags=FD_CLOEXEC,.flflags=O_NONBLOCK,.seals=MH_SEALS,.alive=1,.object=object};
 if(kind==K_PIPE_W)mx.fd[fd].flflags|=O_WRONLY;
}
static struct mh_slot mx_begin(const char *name){
 memset(&mx,0,sizeof mx);mx.fail_op=-1;mx.fail_n=1;mx.fail_errno=EIO;mx.jump_op=-1;
 mx.reused_fd=-1;mx.fail_fcntl_cmd=-1;mx.prctl_fail_option=-1;mx.prctl_fail_suboption=-1;
 mx.effective=mx.permitted=mx.bounding=MH_CAPS;mx.nnp=mx.nnp_after_uid=1;
 mx.now=UINT64_C(1000000000);mx.next_object=20000;mx.identity_pid=MX_MAIN;mx.parent_pid=MX_MAIN;
 mx.ns_type=CLONE_NEWUSER;mx.wait_code=CLD_EXITED;mx.wait_signo=SIGCHLD;mx.born_fd=-1;mx.exit_code=-1;
 mh_actual_offer=NULL;mh_owned=(struct mh_custody){.pidfd=-1,.main_pidfd=-1,.gate_read=-1,.gate_write=-1,.out_read=-1,.err_read=-1};
 memset(&mh_raw,0,sizeof mh_raw);mh_stopping=0;mh_clock_high=0;
 mx_case_name=name;mx_case_failed=0;mx_error_count=0;mx_escape_ready=0;
 mx_assign_fd(32,K_CONTROL,4001);mx_assign_fd(33,K_PIPE_W,5001);mx_assign_fd(34,K_PIPE_W,5002);
 mx_assign_fd(35,K_CONTROL,4002);mx_assign_fd(36,K_PIDFD,11001);mx.fd[36].pid=MX_V;
 for(int fd=37;fd<=39;fd++)mx_assign_fd(fd,K_SEALED,(uint64_t)fd+3000);
 mx_assign_fd(40,K_USERNS,9001);mx_assign_fd(41,K_SEALED,3041);mx_assign_fd(42,K_SINGLETON,8001);
 mx_assign_fd(43,K_PIPE_R,5001);mx_assign_fd(44,K_PIPE_R,5002);mx_assign_fd(70,K_LISTENER,7001);
 struct mh_slot s={.main_pid=MX_MAIN,.v_pid=MX_V,.policy={.caller_uid=1000,.caller_gid=1001,.h_uid=2000,.h_gid=2001,.ledger_first=1000000000,.ledger_last=1899999999},
  .requested_start=UINT64_C(900000000),.requested_w=UINT64_C(2500000000),.requested_c=UINT64_C(4000000000),.w=UINT64_C(2000000000),.c=UINT64_C(3000000000),
  .input=32,.out_write=33,.err_write=34,.h_control=35,.v_pidfd=36,.context=37,.bundle=38,.addon=39,.main_userns=40,.node_image=41,.singleton=42,.out_read=43,.err_read=44,.listener=70,
  .gate_read=-1,.gate_write=-1,.h_pidfd=-1};
 s.userns.st_dev=33;s.userns.st_ino=9001;memcpy(mx.initial_fd,mx.fd,sizeof mx.fd);return s;
}
static int mx_spawn(struct mh_slot *s){mh_actual_offer=s;return mh_spawn_original();}
static void mx_refusal(struct mh_slot *s){
 MX_ASSERT(mx_spawn(s)<0);MX_ASSERT(mx.calls[O_CLONE]==0);MX_ASSERT(!mh_actual_offer);
 MX_ASSERT(s->spent);MX_ASSERT(!mh_raw.born);MX_ASSERT(mx.calls[O_KILL]==0);
}
static int mx_held(struct mh_slot *s){
 int r=mx_spawn(s);MX_ASSERT(r==MH_CHILD_HELD);MX_ASSERT(mx.calls[O_CLONE]==1);
 MX_ASSERT(mh_raw.born&&!mh_raw.reaped);MX_ASSERT(mh_owned.pidfd==mx.born_fd);
 return r==MH_CHILD_HELD;
}
static void mx_terminal(void){
 mx.wait_ready=1;
 for(int i=0;i<MX_FDS;i++)if(mx.fd[i].kind==K_PIDFD&&mx.fd[i].pid==MX_CHILD)mx.fd[i].alive=0;
}
static void mx_both_eof(void){mx.out_mode=mx.err_mode=1;}
static void mx_check_borrowed(void){
 const int borrowed[]={32,35,36,37,38,39,40,41,42,70};
 for(unsigned i=0;i<sizeof borrowed/sizeof borrowed[0];i++)MX_ASSERT(mx_fd_good(borrowed[i]));
}
static void mx_exact_remaining_fds(int outputs_transferred){
 for(int fd=0;fd<MX_FDS;fd++){
  int transferred=outputs_transferred&&(fd==33||fd==34||fd==43||fd==44);
  int expected=mx.initial_fd[fd].open&&!transferred;
  MX_ASSERT(mx.fd[fd].open==expected);
  if(expected){MX_ASSERT(mx.fd[fd].kind==mx.initial_fd[fd].kind);MX_ASSERT(mx.fd[fd].object==mx.initial_fd[fd].object);MX_ASSERT(mx.fd[fd].fdflags==mx.initial_fd[fd].fdflags);MX_ASSERT(mx.fd[fd].flflags==mx.initial_fd[fd].flflags);}
 }
}
static void mx_main_profiles(void){
 const char *names[]={"M01_real_uid","M01_effective_uid","M01_saved_uid","M02_real_gid","M02_effective_gid","M02_saved_gid","M03_fsuid","M03_fsgid","M04_nnp0","M05_groups","M06_extra_effective","M06_missing_effective","M07_extra_permitted","M07_missing_permitted","M08_inheritable","M09_extra_bounding","M09_missing_bounding","M10_keepcaps","M10_ambient","M11_dumpable","M12_sigchld_ignore","M12_nocldwait","M04_nnp_query_error","M01_uid_query_error","M06_capget_error"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);
  switch(i){
   case 0:case 1:case 2:mx.uid[i]=1;break;
   case 3:case 4:case 5:mx.gid[i-3]=1;break;
   case 6:mx.fsuid=1;break;case 7:mx.fsgid=1;break;case 8:mx.nnp=0;break;case 9:mx.groups=1;break;
   case 10:mx.effective|=UINT64_C(1)<<CAP_SYS_ADMIN;break;case 11:mx.effective&=~(UINT64_C(1)<<CAP_SETUID);break;
   case 12:mx.permitted|=UINT64_C(1)<<CAP_SYS_ADMIN;break;case 13:mx.permitted&=~(UINT64_C(1)<<CAP_SETUID);break;
   case 14:mx.inheritable=1;break;case 15:mx.bounding|=UINT64_C(1)<<CAP_SETPCAP;break;case 16:mx.bounding&=~(UINT64_C(1)<<CAP_KILL);break;
   case 17:mx.keepcaps=1;break;case 18:mx.ambient=UINT64_C(1)<<CAP_CHOWN;break;case 19:mx.dumpable=1;break;
   case 20:mx.chld_ignore=1;break;case 21:mx.chld_nocldwait=1;break;
   case 22:mx.prctl_fail_option=PR_GET_NO_NEW_PRIVS;break;
   case 23:mx.fail_op=O_GETUID;break;case 24:mx.fail_op=O_CAPGET;break;
  }
  mx_refusal(&s);mx_check_borrowed();mx_end();
 }
}
static void mx_identity_cases(void){
 const char *names[]={"I01_uid0","I01_gid0","I02_uid_sentinel","I02_gid_sentinel","I03_uid_caller_uid","I03_uid_caller_gid","I03_gid_caller_uid","I03_gid_caller_gid","I04_uid_ledger_first","I04_uid_ledger_last","I04_gid_ledger_first","I04_gid_ledger_last","I05_future_uid","I05_future_gid","I06_reversed_ledger"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);
  switch(i){
   case 0:s.policy.h_uid=0;break;case 1:s.policy.h_gid=0;break;case 2:s.policy.h_uid=(uid_t)-1;break;case 3:s.policy.h_gid=(gid_t)-1;break;
   case 4:s.policy.h_uid=s.policy.caller_uid;break;case 5:s.policy.h_uid=s.policy.caller_gid;break;case 6:s.policy.h_gid=s.policy.caller_uid;break;case 7:s.policy.h_gid=s.policy.caller_gid;break;
   case 8:s.policy.h_uid=s.policy.ledger_first;break;case 9:s.policy.h_uid=s.policy.ledger_last;break;case 10:s.policy.h_gid=s.policy.ledger_first;break;case 11:s.policy.h_gid=s.policy.ledger_last;break;
   case 12:s.policy.h_uid=s.policy.ledger_first+100;break;case 13:s.policy.h_gid=s.policy.ledger_first+100;break;case 14:s.policy.ledger_first=s.policy.ledger_last+1;break;
  }
  mx_refusal(&s);mx_end();
 }
 struct mh_slot s=mx_begin("I07_same_H_uid_gid_policy_allowed");s.policy.h_gid=s.policy.h_uid;MX_ASSERT(mh_identity_policy(&s.policy)==0);mx_end();
}
static void mx_deadline_namespace_sources(void){
 const char *names[]={"N01_held_namespace_mismatch","N02_self_namespace_mismatch","N03_wrong_ns_type","N03_ioctl_error","F01_low_source_fd","F01_duplicate_roles","F01_missing_cloexec","F05_unsealed_bundle","F05_wrong_output_pair","L14_zero_clock","L14_clock_error","L14_future_start","L14_zero_start","L14_reversed_bounds","L14_uint64_bounds","L14_work_expired","L12_dead_V","L12_deadline_during_preclone_ns"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);
  switch(i){
   case 0:s.userns.st_ino++;break;case 1:mx.ns_mismatch=1;break;case 2:mx.ns_type=CLONE_NEWNET;break;case 3:mx.fail_op=O_IOCTL;break;
   case 4:s.input=1;break;case 5:s.addon=s.bundle;break;case 6:mx.fd[s.input].fdflags=0;break;case 7:mx.fd[s.bundle].seals=0;break;case 8:mx.fd[s.err_write].object++;break;
   case 9:mx.now=0;break;case 10:mx.clock_error=1;break;case 11:s.requested_start=mx.now+1;break;case 12:s.requested_start=0;break;case 13:s.w=s.c;break;
   case 14:s.requested_w=UINT64_MAX-1;s.requested_c=UINT64_MAX;s.w=UINT64_MAX-2;s.c=UINT64_MAX-1;break;
   case 15:mx.now=s.w;break;case 16:mx.fd[s.v_pidfd].alive=0;break;
   case 17:mx.jump_op=O_IOCTL;mx.jump_n=4;mx.jump_to=s.w+1;break;
  }
  mx_refusal(&s);mx_end();
 }
}
static void mx_acquisition_cases(void){
 const char *names[]={"A01_self_pidfd_failure","A02_self_relocation_failure","A03_pipe_failure","A04_gate_reader_relocation_failure","A05_gate_writer_relocation_failure","A06_clone_failure","A07_clone_malformed_missing_fd","A08_child_died_at_birth","A09_first_postclone_close_EINTR_fd_reuse"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);
  switch(i){
   case 0:mx.fail_op=O_SELF_PIDFD;break;
   case 1:mx.fail_fcntl_cmd=F_DUPFD_CLOEXEC;mx.fail_fcntl_n=1;break;
   case 2:mx.fail_op=O_PIPE;break;
   case 3:mx.fail_fcntl_cmd=F_DUPFD_CLOEXEC;mx.fail_fcntl_n=2;break;
   case 4:mx.fail_fcntl_cmd=F_DUPFD_CLOEXEC;mx.fail_fcntl_n=3;break;
   case 5:mx.fail_op=O_CLONE;mx.fail_errno=EAGAIN;break;
   case 6:mx.clone_mode=1;break;case 7:mx.clone_mode=2;break;
   case 8:mx.close_error_after_clone=1;mx.close_failure_consumes=1;mx.reuse_closed=1;break;
  }
  MX_ASSERT(mx_spawn(&s)<0);MX_ASSERT(s.spent);MX_ASSERT(!mh_actual_offer);
  if(i<5)MX_ASSERT(mx.calls[O_CLONE]==0);
  if(i==5){MX_ASSERT(mx.calls[O_CLONE]==1);MX_ASSERT(!mh_raw.born);MX_ASSERT(mh_raw.clone.error==EAGAIN);}
  if(i>=6){MX_ASSERT(mh_raw.born);MX_ASSERT(mx.clone_store_violation==0);}
  if(i==6){MX_ASSERT(mh_raw.birth_unknown);MX_ASSERT(mh_finish_original()<0&&errno==EBUSY);MX_ASSERT(mx.calls[O_KILL]==0);}
  if(i==8){MX_ASSERT(mh_raw.close_fault);MX_ASSERT(mx.reused_fd>=0);MX_ASSERT(mx.reused_closes==0);MX_ASSERT(mx_fd_good(mx.reused_fd));}
  if(i<6){MX_ASSERT(mh_finish_original()==0);mx_check_borrowed();mx_exact_remaining_fds(0);}
  mx_end();
 }
}
static void mx_release_and_custody(void){
 struct mh_slot s=mx_begin("R01_held_does_not_mean_release_or_exec");
 if(mx_held(&s)){
  MX_ASSERT(mh_release_original()<0&&errno==EOPNOTSUPP);MX_ASSERT(mh_raw.cancelled&&mh_raw.release_requested);
  MX_ASSERT(mh_owned.pidfd==mx.born_fd&&mx_fd_good(mx.born_fd));MX_ASSERT(mh_finish_original()<0&&errno==EBUSY);
  unsigned kills=mx.calls[O_KILL];MX_ASSERT(mh_release_original()<0&&errno==EOPNOTSUPP);MX_ASSERT(mx.calls[O_KILL]==kills);
 }mx_end();
 for(int release=0;release<2;release++){
  s=mx_begin(release?"R03_release_before_spawn_burns":"R02_cancel_before_spawn_burns");mh_actual_offer=&s;
  if(release)MX_ASSERT(mh_release_original()<0&&errno==EOPNOTSUPP);else MX_ASSERT(mh_cancel_original()==0);
  MX_ASSERT(s.spent&&!mh_actual_offer);MX_ASSERT(mx.calls[O_CLONE]==0);MX_ASSERT(mx.calls[O_CLOSE]==0);MX_ASSERT(mx.calls[O_KILL]==0);
  MX_ASSERT(mh_spawn_original()<0);MX_ASSERT(mx.calls[O_CLONE]==0);mx_end();
 }
 s=mx_begin("R04_foreign_public_mirrors_do_not_replace_atomic_custody");
 if(mx_held(&s)){
  int retained=mh_owned.pidfd;mx_assign_fd(90,K_PIDFD,19998);mx.fd[90].pid=MX_FOREIGN;
  s.h_pidfd=90;s.h_pid=MX_FOREIGN;s.policy.h_uid=0;s.w=UINT64_MAX;s.c=UINT64_MAX;s.failed=0;s.spent=0;s.born=0;
  MX_ASSERT(mh_cancel_original()==0);MX_ASSERT(mh_raw.signal_fd==retained);MX_ASSERT(mx.foreign_signals==0);
  mx_terminal();mx_both_eof();(void)mh_progress_original();MX_ASSERT(mh_raw.wait_fd==retained);MX_ASSERT(mh_raw.reaped);
  MX_ASSERT(mh_raw.c_ns==UINT64_C(3000000000));MX_ASSERT(mx_fd_good(90));
 }mx_end();
 s=mx_begin("R05_second_offer_cannot_replace_unknown_custody");struct mh_slot second=s;
 if(mx_held(&s)){
  int retained=mh_owned.pidfd;mh_actual_offer=&second;MX_ASSERT(mh_spawn_original()<0&&errno==EBUSY);
  MX_ASSERT(mh_owned.slot==&s&&mh_owned.pidfd==retained);MX_ASSERT(mx.calls[O_CLONE]==1);
 }mx_end();
 s=mx_begin("R06_signal_stop_burns_without_late_clone");mh_actual_offer=&s;mh_stop_original();mx_refusal(&s);mx_end();
 s=mx_begin("R07_reused_numeric_PID_after_reap_pending_EOF");
 if(mx_held(&s)){
  int retained=mh_owned.pidfd;mx_terminal();mx.out_mode=1;(void)mh_progress_original();
  MX_ASSERT(mh_raw.reaped&&mh_raw.out_eof&&!mh_raw.err_eof&&!mh_raw.cleanup_observed);
  MX_ASSERT(mx_fd_good(retained)&&mx.fd[retained].object==10002);
  mx_assign_fd(90,K_PIDFD,19998);mx.fd[90].pid=MX_CHILD;
  s.h_pid=MX_CHILD;s.h_pidfd=90;
  unsigned kills=mx.calls[O_KILL],waits=mx.calls[O_WAIT];
  for(int i=0;i<3;i++){(void)mh_cancel_original();(void)mh_progress_original();}
  MX_ASSERT(mx.calls[O_KILL]==kills&&mx.calls[O_WAIT]==waits);
  MX_ASSERT(mh_owned.pidfd==retained&&mx_fd_good(retained));
  MX_ASSERT(mh_finish_original()<0&&errno==EBUSY);
  MX_ASSERT(mx_fd_good(90)&&mx.fd[90].object==19998&&mx.fd[90].alive);
  mx.err_mode=1;MX_ASSERT(mh_progress_original()==1);MX_ASSERT(mh_finish_original()==0);
  MX_ASSERT(!mx_fd_good(retained));MX_ASSERT(mx_fd_good(90)&&mx.fd[90].object==19998&&mx.fd[90].alive);
 }mx_end();
}
static void mx_wait_cases(void){
 const char *names[]={"W01_no_wait_no_eof","W02_wait_only","W03_eof_only","W04_wait_one_eof","W05_wait_both_eof","W06_ECHILD_unknown","W07_EINTR_not_reap","W08_wrong_pid","W09_wrong_uid","W10_nonterminal_code","W11_output_writer_alias_hides_EOF","W12_wait_return_after_C","W13_last_EOF_return_after_C","W14_clock_backwards_sticky","W15_after_C_no_new_wait_read","W16_signal_returns_after_C_no_wait","W17_work_poll_crosses_C_no_wait","W19_wrong_wait_signo"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);if(!mx_held(&s)){mx_end();continue;}
  if(i==1||i==3||i==4||i==7||i==8||i==9||i==10||i==11||i==12||i==17)mx_terminal();
  if(i==2||i==4||i==7||i==8||i==9||i==10||i==11||i==12||i==17)mx_both_eof();
  if(i==3)mx.out_mode=1;
  if(i==5)mx.wait_error=ECHILD;
  if(i==6)mx.wait_error=EINTR;
  if(i==7)mx.wait_wrong_pid=999;
  if(i==8)mx.wait_uid=2000;
  if(i==9)mx.wait_code=CLD_STOPPED;
  if(i==10)mx_assign_fd(91,K_PIPE_W,5002);
  if(i==11){mx.jump_op=O_WAIT;mx.jump_n=1;mx.jump_to=s.c+1;}
  if(i==12){mx.jump_op=O_READ;mx.jump_n=2;mx.jump_to=s.c+1;}
  if(i==13)mx.now--;
  if(i==14)mx.now=s.c+1;
  if(i==15){mx.now=s.w;mx.jump_op=O_KILL;mx.jump_n=1;mx.jump_to=s.c+1;}
  if(i==16){mx.jump_op=O_POLL;mx.jump_n=(int)mx.calls[O_POLL]+1;mx.jump_to=s.c+1;}
  if(i==17)mx.wait_signo=SIGUSR1;
  unsigned reads=mx.calls[O_READ],waits=mx.calls[O_WAIT];(void)mh_progress_original();
  if(i==0){MX_ASSERT(!mh_raw.reaped&&!mh_raw.out_eof&&!mh_raw.err_eof);}
  if(i==1){MX_ASSERT(mh_raw.reaped&&!mh_raw.cleanup_observed);}
  if(i==2){MX_ASSERT(!mh_raw.reaped&&mh_raw.out_eof&&mh_raw.err_eof&&!mh_raw.cleanup_observed);}
  if(i==3||i==10){MX_ASSERT(mh_raw.reaped&&mh_raw.out_eof&&!mh_raw.err_eof&&!mh_raw.cleanup_observed);}
  if(i==4){MX_ASSERT(mh_raw.reaped&&mh_raw.out_eof&&mh_raw.err_eof&&mh_raw.cleanup_observed&&mh_raw.timely_cleanup);MX_ASSERT(mh_finish_original()==0);mx_check_borrowed();mx_exact_remaining_fds(1);}
  if(i==5){MX_ASSERT(mh_raw.wait_unknown&&!mh_raw.reaped);MX_ASSERT(mh_raw.wait.error==ECHILD);}
  if(i==6){MX_ASSERT(!mh_raw.reaped);MX_ASSERT(mh_raw.wait.error==EINTR);}
  if(i==7||i==8||i==9||i==17)MX_ASSERT(mh_raw.wait_unknown&&!mh_raw.reaped);
  if(i==11){MX_ASSERT(mh_raw.reaped);MX_ASSERT(mx.calls[O_READ]==reads);MX_ASSERT(!mh_raw.timely_cleanup&&mh_raw.deadline_expired);}
  if(i==12){MX_ASSERT(mh_raw.reaped&&mh_raw.out_eof&&mh_raw.err_eof);MX_ASSERT(mh_raw.cleanup_observed&&!mh_raw.timely_cleanup&&mh_raw.deadline_expired);}
  if(i==13){MX_ASSERT(mh_raw.timing_unknown);mx.now=s.requested_start+UINT64_C(300000000);mx_terminal();mx_both_eof();(void)mh_progress_original();MX_ASSERT(!mh_raw.timely_cleanup&&mh_raw.timing_unknown);}
  if(i>=14&&i<=16){MX_ASSERT(mx.calls[O_WAIT]==waits);MX_ASSERT(mx.calls[O_READ]==reads);MX_ASSERT(!mh_raw.timely_cleanup);}
  if(i!=4)MX_ASSERT(!mh_raw.released&&!mh_raw.exec_attempted);
  mx_end();
 }
}
static void mx_kill_cases(void){
 const int errors[]={ESRCH,EPERM,EINTR,EAGAIN};const char *names[]={"K01_ESRCH_not_reap","K02_EPERM_retained","K03_EINTR_bounded_retries","K04_EAGAIN_bounded_retries"};
 for(unsigned i=0;i<4;i++){
  struct mh_slot s=mx_begin(names[i]);if(!mx_held(&s)){mx_end();continue;}
  for(unsigned attempt=0;attempt<MH_SIGNAL_ATTEMPTS+3;attempt++){
   mx.fail_op=O_KILL;mx.fail_n=(int)mx.calls[O_KILL]+1;mx.fail_errno=errors[i];(void)mh_cancel_original();
  }
  MX_ASSERT(!mh_raw.reaped&&!mh_raw.cleanup_observed);MX_ASSERT(mh_finish_original()<0&&errno==EBUSY);
  if(i<2)MX_ASSERT(mx.calls[O_KILL]==1);else MX_ASSERT(mx.calls[O_KILL]==MH_SIGNAL_ATTEMPTS);
  unsigned calls=mx.calls[O_KILL];mx.now=s.c+1;(void)mh_cancel_original();MX_ASSERT(mx.calls[O_KILL]==calls);mx_end();
 }
}
static void mx_cleanup_idempotence(void){
 struct mh_slot s=mx_begin("W18_observed_cleanup_is_immutable_and_idempotent");
 if(mx_held(&s)){
  mx_terminal();mx_both_eof();MX_ASSERT(mh_progress_original()==1);uint64_t at=mh_raw.cleanup_observed_ns;
  unsigned waits=mx.calls[O_WAIT],reads=mx.calls[O_READ],kills=mx.calls[O_KILL];
  mx.now=s.c+1;
  for(int i=0;i<3;i++){(void)mh_progress_original();(void)mh_cancel_original();(void)mh_release_original();}
  MX_ASSERT(mh_raw.cleanup_observed_ns==at&&mh_raw.timely_cleanup);
  MX_ASSERT(!mh_raw.deadline_expired);MX_ASSERT(mx.calls[O_WAIT]==waits&&mx.calls[O_READ]==reads&&mx.calls[O_KILL]==kills);
  MX_ASSERT(mh_finish_original()==0);
 }mx_end();
}
static void mx_drop_cases(void){
 const char *names[]={"D00_full_drop_model_not_connected","D01_setgroups_failure","D02_setgid_failure","D02_setuid_failure","D03_uid_readback_wrong","D03_gid_readback_wrong","D04_fsuid_wrong","D04_fsgid_wrong","D05_groups_remain","D06_capset_failure","D06_caps_remain","D07_keepcaps_remain","D07_ambient_remain","D08_nnp_after_drop_wrong","D10_core_limit_failure","D10_dumpable_wrong","P02_parent_dies_during_uid_drop","P02_postdrop_rearm_failure","D11_no_drop_after_W"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot s=mx_begin(names[i]);mx_assign_fd(80,K_PIDFD,10001);mx.fd[80].pid=MX_MAIN;mx.identity_pid=MX_CHILD;
  switch(i){
   case 1:mx.fail_op=O_SETGROUPS;break;case 2:mx.fail_op=O_SETGID;break;case 3:mx.fail_op=O_SETUID;break;
   case 4:mx.setuid_wrong=1;break;case 5:mx.setgid_wrong=1;break;case 6:mx.fsuid_wrong=1;break;case 7:mx.fsgid_wrong=1;break;
   case 8:mx.groups_wrong=1;break;case 9:mx.fail_op=O_CAPSET;break;case 10:mx.capset_wrong=1;break;case 11:mx.keepcaps_wrong=1;break;case 12:mx.ambient_wrong=1;break;
   case 13:mx.nnp_after_uid=0;break;case 14:mx.fail_op=O_RLIMIT;break;case 15:mx.dumpable_wrong=1;break;case 16:mx.death_on_uid=1;break;case 17:mx.fail_pdeath_n=2;break;case 18:mx.now=s.w;break;
  }
  int rc=mh_child_drop_checked(&s,80,s.v_pidfd,s.main_userns);
  if(i==0){
   MX_ASSERT(rc==0);for(unsigned j=0;j<3;j++){MX_ASSERT(mx.uid[j]==s.policy.h_uid);MX_ASSERT(mx.gid[j]==s.policy.h_gid);}
   MX_ASSERT(mx.fsuid==s.policy.h_uid&&mx.fsgid==s.policy.h_gid&&mx.groups==0);
   MX_ASSERT(mx.effective==0&&mx.permitted==0&&mx.inheritable==0&&mx.ambient==0&&mx.bounding==MH_CAPS&&mx.nnp==1);
   MX_ASSERT(mx.pdeath==SIGKILL&&mx.pdeath_calls>=2);
   int uid_at=-1,last_arm=-1;for(unsigned j=0;j<mx.count;j++){if(mx.ev[j].op==O_SETUID)uid_at=(int)j;if(mx.ev[j].op==O_PRCTL&&mx.ev[j].a==PR_SET_PDEATHSIG)last_arm=(int)j;}MX_ASSERT(uid_at>=0&&last_arm>uid_at);
  }else MX_ASSERT(rc<0);
  if(i==18)MX_ASSERT(mx.calls[O_SETUID]==0&&mx.calls[O_SETGID]==0&&mx.calls[O_SETGROUPS]==0);
  MX_ASSERT(mx.calls[O_CLONE]==0);mx_end();
 }
}
static void mx_invoke_child(const struct mh_slot *child,int mainfd,int gr,int gw){
 mx_escape_ready=1;
 if(setjmp(mx_escape)==0)mh_child_hold(child,mainfd,gr,gw);
 mx_escape_ready=0;
}
static void mx_invoke_spawn_child(void){
 mx_escape_ready=1;
 if(setjmp(mx_escape)==0){(void)mh_spawn_original();MX_ASSERT(0&&"child dispatch must exit");}
 mx_escape_ready=0;
}
static void mx_child_cases(void){
 const char *names[]={"C01_parent_dead_before_first_arm","C02_gate_EOF_terminal","C03_gate_B_is_not_release","C04_gate_EINTR_terminal","C05_gate_timeout_terminal","C06_child_uses_fork_snapshot","C07_child_dup_failure","C08_child_close_range_failure","C09_parent_pid_matches_but_pidfd_dead","C10_postpoll_C_no_gate_read","C12_Main_dies_during_gate_poll","C13_V_dies_during_gate_poll"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  struct mh_slot parent=mx_begin(names[i]);struct mh_slot child=parent;
  mx_assign_fd(80,K_PIDFD,10001);mx.fd[80].pid=MX_MAIN;mx_assign_fd(81,K_PIPE_R,20001);mx_assign_fd(82,K_PIPE_W,20001);
  mx.child_model=1;mx.identity_pid=MX_CHILD;
  /* The child model owns a separate pre-clone slot AND FD table. There are
   * no pointers back into mutable parent state; fd values below represent
   * the child's copied table, with remote parent writers as gate_mode. */
  struct mx_fd fork_fds[MX_FDS];memcpy(fork_fds,mx.fd,sizeof fork_fds);
  parent.failed=1;parent.w=1;parent.out_write=-1;
  memcpy(mx.fd,fork_fds,sizeof fork_fds);
  if(i==0)mx.parent_pid=1;
  if(i==1)mx.gate_mode=1;
  if(i==2)mx.gate_mode=2;
  if(i==3){mx.fail_op=O_POLL;mx.fail_n=5;mx.fail_errno=EINTR;}
  if(i==4)mx.poll_timeout_advance=1;
  if(i==5)mx.gate_mode=1;
  if(i==6){mx.fail_op=O_DUP;mx.fail_n=2;}
  if(i==7){mx.fail_op=O_CLOSE_RANGE;mx.fail_n=3;}
  if(i==8)mx.fd[80].alive=0;
  if(i==9){mx.gate_mode=2;mx.jump_op=O_POLL;mx.jump_n=5;mx.jump_to=child.c+1;}
  if(i==10)mx.gate_death_pid=MX_MAIN;
  if(i==11)mx.gate_death_pid=MX_V;
  mx_invoke_child(&child,80,81,82);
  MX_ASSERT(mx.exit_code==120);MX_ASSERT(mx.count>0&&mx.ev[0].op==O_CLOSE&&mx.ev[0].a==child.listener);
  MX_ASSERT(mx.calls[O_SETUID]==0&&mx.calls[O_CAPSET]==0);MX_ASSERT(mx.calls[O_EXEC]==0);
  if(i==1||i==2||i==5)MX_ASSERT(mx.calls[O_READ]==1);
  if(i==0||i==3||i==4||i==6||i==7||i==8||i==9||i==10||i==11)MX_ASSERT(mx.calls[O_READ]==0);
  if(i==5){MX_ASSERT(mx.calls[O_DUP]>=12);MX_ASSERT(mx_fd_good(20)&&mx.fd[20].fdflags==FD_CLOEXEC);MX_ASSERT(!mx_fd_good(70));}
  mx_end();
 }
 static struct mh_slot s;s=mx_begin("C11_actual_source_clone_child0_dispatch");mx.clone_mode=3;mx.gate_mode=1;mh_actual_offer=&s;
 mx_invoke_spawn_child();
 MX_ASSERT(mx.calls[O_CLONE]==1&&mx.calls[O_SELF_PIDFD]==1);MX_ASSERT(mx.exit_code==120&&mx.calls[O_READ]==1);
 MX_ASSERT(mx.calls[O_DUP]>=12&&mx.calls[O_SETUID]==0&&mx.calls[O_EXEC]==0);
 int clone_at=-1;for(unsigned i=0;i<mx.count;i++)if(mx.ev[i].op==O_CLONE)clone_at=(int)i;
 MX_ASSERT(clone_at>=0&&(unsigned)(clone_at+1)<mx.count&&mx.ev[clone_at+1].op==O_CLOSE&&mx.ev[clone_at+1].a==s.listener);
 mx_end();
}
int main(void){
 mx_main_profiles();mx_identity_cases();mx_deadline_namespace_sources();mx_acquisition_cases();
 mx_release_and_custody();mx_wait_cases();mx_kill_cases();mx_cleanup_idempotence();mx_drop_cases();mx_child_cases();
 printf("{\"kind\":\"summary\",\"mode\":\"MODEL_NOT_NATIVE_PROOF\",\"passed\":%u,\"failed\":%u}\n",mx_passed,mx_failed);
 return mx_failed?1:0;
}
