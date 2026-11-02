/* A2 ORDINARY MODEL ONLY. Exact unchanged stage-A source is reused solely for
 * the core/profile OS replacement layer; its old cases are not executed.
 * Every new intake OS entry is replaced below. Object IDs and OFD IDs are
 * distinct from descriptor numbers; this is a model, not a Linux fixture. */
#include <sys/vfs.h>
#include <linux/magic.h>
#define main stage_a_model_main_not_executed
#include "../../tests/main_h_core_model.c"
#undef main

static pid_t ix_getpid(void);
static int ix_open(const char *,int,...);
static int ix_openat(int,const char *,int,...);
static int ix_close(int);
static int ix_fstat(int,struct stat *);
static int ix_fstatfs(int,struct statfs *);
static int ix_ioctl(int,unsigned long,...);
static int ix_fcntl(int,int,...);
static int ix_getsockopt(int,int,int,void *,socklen_t *);
static int ix_accept4(int,struct sockaddr *,socklen_t *,int);
static int ix_poll(struct pollfd *,nfds_t,int);
static ssize_t ix_recvmsg(int,struct msghdr *,int);
static ssize_t ix_read(int,void *,size_t);
static int ix_pipe2(int [2],int);
static int ix_clock_gettime(clockid_t,struct timespec *);
#define getpid(...) ix_getpid(__VA_ARGS__)
#define open(...) ix_open(__VA_ARGS__)
#define openat(...) ix_openat(__VA_ARGS__)
#define close(...) ix_close(__VA_ARGS__)
#define fstat(...) ix_fstat(__VA_ARGS__)
#define fstatfs(...) ix_fstatfs(__VA_ARGS__)
#define ioctl(...) ix_ioctl(__VA_ARGS__)
#define fcntl(...) ix_fcntl(__VA_ARGS__)
#define getsockopt(...) ix_getsockopt(__VA_ARGS__)
#define accept4(...) ix_accept4(__VA_ARGS__)
#define poll(...) ix_poll(__VA_ARGS__)
#define recvmsg(...) ix_recvmsg(__VA_ARGS__)
#define read(...) ix_read(__VA_ARGS__)
#define pipe2(...) ix_pipe2(__VA_ARGS__)
#define clock_gettime(...) ix_clock_gettime(__VA_ARGS__)
#include "../main-intake.inc"
#undef getpid
#undef open
#undef openat
#undef close
#undef fstat
#undef fstatfs
#undef ioctl
#undef fcntl
#undef getsockopt
#undef accept4
#undef poll
#undef recvmsg
#undef read
#undef pipe2
#undef clock_gettime

enum { IX_FDS=512,IX_OBJECTS=1024,IX_EVENTS=16384,IX_MAX_CMSG=12,IX_MAX_RIGHTS=253 };
enum ix_kind { I_NONE,I_LISTENER,I_SINGLETON,I_SOCKET,I_PIDFD,I_PROC_ROOT,I_PROC_MAIN,I_PROC_PEER,
 I_USERNS,I_TIMENS,I_PIDNS,I_STATUS_MAIN,I_STATUS_PEER,I_PIPE_R,I_PIPE_W,I_FOREIGN };
enum ix_op { I_GETPID,I_OPEN,I_OPENAT,I_CLOSE,I_FSTAT,I_FSTATFS,I_IOCTL,I_FCNTL,
 I_GETSOCKOPT,I_SETSOCKOPT,I_ACCEPT,I_POLL,I_RECV,I_READ,I_PIPE,I_CLOCK,I_COUNT };
static const char *const ix_names[I_COUNT]={"getpid","open","openat","close","fstat","fstatfs",
 "ioctl","fcntl","getsockopt","setsockopt","accept4","poll","recvmsg","read","pipe2","clock"};
struct ix_object {int kind,flags,alive,pid,type,read_once;uint64_t kernel;};
struct ix_fd {int open,ofd,fdflags,initial,installed;};
struct ix_event {int phase,op;long a,b,rc;int error;uint64_t object;};
struct ix_cmsg {int level,type;unsigned count;int values[IX_MAX_RIGHTS];size_t declared;};
struct ix_model {
 struct ix_fd fd[IX_FDS];struct ix_object obj[IX_OBJECTS];unsigned objects;
 struct ix_event ev[IX_EVENTS];unsigned events,calls[I_COUNT];
 struct ix_cmsg cmsg[IX_MAX_CMSG];unsigned cmsgs;
 unsigned char packet[512];size_t packet_bytes;int packet_flags;
 uint64_t now,next_kernel,original_peer_object;int owner,peer,peer_uid,peer_gid;
 int fail_op,fail_n,fail_error,unexpected,overflow,borrowed_close,foreign_close,recv_flags;
 int dead,death_op,death_n,jump_op,jump_n;uint64_t jump_to;
 int ns_mismatch,ns_type_error,proc_magic_error,status_mode,cred_drift,peercred_calls;
 int socket_domain,socket_type,listener_flag,passcred,peerpidfd_error,peerpidfd_short,peercred_short;
 int pipe_alias,pipe_pair_mismatch,pipe_calls,reader_blocking;
 int close_ancillary_error,close_error_n,close_errors,reuse_on_close,reused_fd,reused_close;
 int clock_error,clock_backwards,recv_error,recv_eof,accept_error,socket_eof,socket_extra,socket_eof_after_pipe;
 int stop_phase,stop_clock_n,ns_main_mismatch,initpid_mismatch,status_uid_index,status_gid_index,status_cap_kind;
 int peer_proc_opens,main_proc_opens,peer_pidfd_acquisitions,status_reads,installed,installed_closed;
 unsigned fatal_syscalls;int case_failed;const char *case_id;const char *errors[96];unsigned error_count;
};
static struct ix_model ix;
static unsigned ix_passed,ix_failed;

static int ix_note(int op,long a,long b){
 if(ix.events>=IX_EVENTS){ix.overflow=1;return 0;}
 int n=(int)ix.events++;ix.ev[n]=(struct ix_event){.phase=(int)mi_state.phase,.op=op,.a=a,.b=b};ix.calls[op]++;
 if(ix.stop_phase>=0&&(int)mi_state.phase==ix.stop_phase)mi_stop_original();
 if(op==ix.death_op&&(int)ix.calls[op]==ix.death_n)ix.dead=1;
 if(op==ix.jump_op&&(int)ix.calls[op]==ix.jump_n)ix.now=ix.jump_to;
 return n;
}
static long ix_done(int n,long result){
 ix.ev[n].rc=result;ix.ev[n].error=result<0?errno:0;return result;
}
static int ix_bad(int n){ix.unexpected++;errno=ENOSYS;return (int)ix_done(n,-1);}
static int ix_fail(int op){
 if(op==ix.fail_op&&(int)ix.calls[op]==ix.fail_n){errno=ix.fail_error;return 1;}return 0;
}
static int ix_good(int fd){return fd>=0&&fd<IX_FDS&&ix.fd[fd].open;}
static struct ix_object *ix_object(int fd){return ix_good(fd)?&ix.obj[ix.fd[fd].ofd]:NULL;}
static int ix_new_ofd(int kind,uint64_t kernel,int flags){
 if(ix.objects+1>=IX_OBJECTS){ix.overflow=1;return -1;}
 int n=(int)++ix.objects;ix.obj[n]=(struct ix_object){.kind=kind,.flags=flags,.alive=1,.kernel=kernel};return n;
}
static int ix_assign(int fd,int ofd,int initial){
 if(fd<0||fd>=IX_FDS||ix.fd[fd].open||ofd<1){ix.unexpected++;return -1;}
 ix.fd[fd]=(struct ix_fd){.open=1,.ofd=ofd,.fdflags=FD_CLOEXEC,.initial=initial};return fd;
}
static int ix_alloc_ofd(int low,int ofd){
 for(int fd=low;fd<IX_FDS;fd++)if(!ix.fd[fd].open)return ix_assign(fd,ofd,0);
 errno=EMFILE;return -1;
}
static int ix_alloc(int kind,uint64_t kernel,int flags){return ix_alloc_ofd(3,ix_new_ofd(kind,kernel,flags));}
static void ix_assert(int good,const char *text){
 if(!good){ix.case_failed=1;if(ix.error_count<96)ix.errors[ix.error_count++]=text;}
}
#define IX_ASSERT(x) ix_assert(!!(x),#x)
static pid_t ix_getpid(void){int n=ix_note(I_GETPID,0,0);return (pid_t)ix_done(n,ix.owner);}
static int ix_open(const char *path,int flags,...){
 int n=ix_note(I_OPEN,flags,0);if(ix_fail(I_OPEN))return (int)ix_done(n,-1);
 int kind=0;uint64_t kernel=0;
 if(!strcmp(path,"/proc")){kind=I_PROC_ROOT;kernel=40010;}
 else if(!strcmp(path,"/proc/self")){kind=I_PROC_MAIN;kernel=40000;ix.main_proc_opens++;}
 else if(!strcmp(path,"/proc/1/ns/pid")){kind=I_PIDNS;kernel=30003;}
 else if(!strcmp(path,"/proc/self/ns/user")){kind=I_USERNS;kernel=30001;}
 else if(!strcmp(path,"/proc/self/ns/time")){kind=I_TIMENS;kernel=30002;}
 else if(!strcmp(path,"/proc/self/ns/pid")){kind=I_PIDNS;kernel=30003;}
 else if(!strcmp(path,"/proc/601")){kind=I_PROC_PEER;kernel=60100;ix.peer_proc_opens++;}
 else return ix_bad(n);
 int fd=ix_alloc(kind,kernel,flags&O_ACCMODE);if(fd>=0){ix.ev[n].object=kernel;if(kind==I_PIDNS)ix.obj[ix.fd[fd].ofd].type=CLONE_NEWPID;}
 return (int)ix_done(n,fd);
}
static int ix_openat(int dir,const char *path,int flags,...){
 int n=ix_note(I_OPENAT,dir,flags);if(ix_fail(I_OPENAT))return (int)ix_done(n,-1);
 struct ix_object *parent=ix_object(dir);if(!parent)return ix_bad(n);
 if(parent->kind==I_PROC_ROOT){
  int kind;uint64_t kernel;
  if(!strcmp(path,"self")){kind=I_PROC_MAIN;kernel=40000;ix.main_proc_opens++;}
  else if(!strcmp(path,"1/ns/pid")){kind=I_PIDNS;kernel=30003+(ix.initpid_mismatch?100:0);}
  else if(!strcmp(path,"601")){kind=I_PROC_PEER;kernel=60100;ix.peer_proc_opens++;}
  else return ix_bad(n);
  int result=ix_alloc(kind,kernel,flags&O_ACCMODE);
  if(result>=0){ix.ev[n].object=kernel;if(kind==I_PIDNS)ix.obj[ix.fd[result].ofd].type=CLONE_NEWPID;}
  return (int)ix_done(n,result);
 }
 int peer=parent->kind==I_PROC_PEER;
 if(!peer&&parent->kind!=I_PROC_MAIN)return ix_bad(n);
 int kind=0,type=0;uint64_t kernel=0;
 if(!strcmp(path,"ns/user")){kind=I_USERNS;type=CLONE_NEWUSER;kernel=30001;}
 else if(!strcmp(path,"ns/time")){kind=I_TIMENS;type=CLONE_NEWTIME;kernel=30002;}
 else if(!strcmp(path,"ns/pid")){kind=I_PIDNS;type=CLONE_NEWPID;kernel=30003;}
 else if(!strcmp(path,"status")){kind=peer?I_STATUS_PEER:I_STATUS_MAIN;kernel=peer?60101:40001;}
 else return ix_bad(n);
 if((peer&&ix.ns_mismatch==kind)||(!peer&&ix.ns_main_mismatch==kind))kernel+=100;
 int fd=ix_alloc(kind,kernel,flags&O_ACCMODE);if(fd>=0){ix.obj[ix.fd[fd].ofd].type=type;ix.ev[n].object=kernel;}
 return (int)ix_done(n,fd);
}
static int ix_close(int fd){
 int n=ix_note(I_CLOSE,fd,0);if(!ix_good(fd)){errno=EBADF;return (int)ix_done(n,-1);}
 struct ix_fd old=ix.fd[fd];ix.ev[n].object=ix.obj[old.ofd].kernel;
 if(old.initial)ix.borrowed_close++;
 if(fd==ix.reused_fd&&ix.obj[old.ofd].kind==I_FOREIGN)ix.reused_close++;
 if(old.installed)ix.installed_closed++;
 ix.fd[fd].open=0;
 int failure=(ix.close_ancillary_error&&old.installed&&ix.close_errors==0)||(ix.close_error_n>0&&(int)ix.calls[I_CLOSE]==ix.close_error_n)||ix_fail(I_CLOSE);
 if(failure){ix.close_errors++;errno=EINTR;if(ix.reuse_on_close){ix.reused_fd=fd;(void)ix_assign(fd,ix_new_ofd(I_FOREIGN,99000+fd,O_RDONLY),0);}return (int)ix_done(n,-1);}
 return (int)ix_done(n,0);
}
static int ix_fstat(int fd,struct stat *st){
 int n=ix_note(I_FSTAT,fd,0);if(ix_fail(I_FSTAT))return (int)ix_done(n,-1);
 struct ix_object *o=ix_object(fd);if(!o)return ix_bad(n);
 memset(st,0,sizeof *st);st->st_dev=45;st->st_ino=(ino_t)o->kernel;st->st_nlink=1;
 switch(o->kind){
 case I_PROC_ROOT:case I_PROC_MAIN:case I_PROC_PEER:st->st_mode=S_IFDIR|0555;break;
 case I_PIPE_R:case I_PIPE_W:st->st_mode=S_IFIFO|0600;break;
 case I_SOCKET:case I_LISTENER:st->st_mode=S_IFSOCK|0600;break;
 default:st->st_mode=S_IFREG|0600;break;
 }
 if(o->kind==I_PROC_PEER){st->st_uid=(uid_t)ix.peer_uid;st->st_gid=(gid_t)ix.peer_gid;}
 ix.ev[n].object=o->kernel;return (int)ix_done(n,0);
}
static int ix_fstatfs(int fd,struct statfs *st){
 int n=ix_note(I_FSTATFS,fd,0);if(ix_fail(I_FSTATFS))return (int)ix_done(n,-1);
 if(!ix_good(fd))return ix_bad(n);
 memset(st,0,sizeof *st);st->f_type=ix.proc_magic_error?0:PROC_SUPER_MAGIC;return (int)ix_done(n,0);
}
static int ix_ioctl(int fd,unsigned long request,...){
 int n=ix_note(I_IOCTL,fd,(long)request);if(ix_fail(I_IOCTL))return (int)ix_done(n,-1);
 struct ix_object *o=ix_object(fd);if(!o||request!=NS_GET_NSTYPE)return ix_bad(n);
 int type=o->type;if(!type){if(o->kind==I_USERNS)type=CLONE_NEWUSER;else if(o->kind==I_TIMENS)type=CLONE_NEWTIME;else if(o->kind==I_PIDNS)type=CLONE_NEWPID;}
 return (int)ix_done(n,ix.ns_type_error?CLONE_NEWNS:type);
}
static int ix_fcntl(int fd,int command,...){
 int n=ix_note(I_FCNTL,fd,command);if(ix_fail(I_FCNTL))return (int)ix_done(n,-1);
 struct ix_object *o=ix_object(fd);if(!o)return ix_bad(n);
 if(command==F_GETFD)return (int)ix_done(n,ix.fd[fd].fdflags);
 if(command==F_GETFL)return (int)ix_done(n,o->flags);
 va_list ap;va_start(ap,command);int value=va_arg(ap,int);va_end(ap);
 if(command==F_DUPFD_CLOEXEC){int out=ix_alloc_ofd(value,ix.fd[fd].ofd);ix.ev[n].object=o->kernel;return (int)ix_done(n,out);}
 if(command==F_SETFD){ix.fd[fd].fdflags=value;return (int)ix_done(n,0);}
 if(command==F_SETFL){o->flags=(o->flags&O_ACCMODE)|(value&~O_ACCMODE);return (int)ix_done(n,0);}
 return ix_bad(n);
}
static int ix_getsockopt(int fd,int level,int option,void *value,socklen_t *len){
 int n=ix_note(I_GETSOCKOPT,fd,option);if(ix_fail(I_GETSOCKOPT))return (int)ix_done(n,-1);
 struct ix_object *o=ix_object(fd);if(!o||level!=SOL_SOCKET||(o->kind!=I_LISTENER&&o->kind!=I_SOCKET))return ix_bad(n);
 if(option==SO_PEERCRED){
  ix.peercred_calls++;struct ucred u={.pid=ix.peer,.uid=(uid_t)ix.peer_uid,.gid=(gid_t)ix.peer_gid};
  if(ix.cred_drift&&ix.peercred_calls>1)u.uid++;
  if(*len<sizeof u)return ix_bad(n);
 memcpy(value,&u,sizeof u);*len=ix.peercred_short?sizeof u-1:sizeof u;return (int)ix_done(n,0);
 }
 if(option==SO_PEERPIDFD){
  if(ix.peerpidfd_error){errno=ix.peerpidfd_error;return (int)ix_done(n,-1);}
  if(*len<sizeof(int))return ix_bad(n);
  int p=ix_alloc(I_PIDFD,60110,O_RDONLY);if(p>=0){ix.obj[ix.fd[p].ofd].pid=ix.peer;ix.peer_pidfd_acquisitions++;}
  memcpy(value,&p,sizeof p);*len=ix.peerpidfd_short?sizeof p-1:sizeof p;return (int)ix_done(n,0);
 }
 int v;
 if(option==SO_DOMAIN)v=ix.socket_domain;
 else if(option==SO_TYPE)v=ix.socket_type;
 else if(option==SO_ACCEPTCONN)v=o->kind==I_LISTENER?ix.listener_flag:0;
 else if(option==SO_PASSCRED)v=ix.passcred;
 else return ix_bad(n);
 if(*len<sizeof v)return ix_bad(n);
 memcpy(value,&v,sizeof v);*len=sizeof v;return (int)ix_done(n,0);
}
static int ix_accept4(int listener,struct sockaddr *address,socklen_t *length,int flags){
 int n=ix_note(I_ACCEPT,listener,flags);(void)address;(void)length;
 if(ix_fail(I_ACCEPT))return (int)ix_done(n,-1);
 if(ix.accept_error){errno=ix.accept_error;return (int)ix_done(n,-1);}
 struct ix_object *o=ix_object(listener);if(!o||o->kind!=I_LISTENER)return ix_bad(n);
 return (int)ix_done(n,ix_alloc(I_SOCKET,70001,(flags&SOCK_NONBLOCK)?O_NONBLOCK|O_RDWR:O_RDWR));
}
static int ix_poll(struct pollfd *fds,nfds_t count,int timeout){
 int n=ix_note(I_POLL,(long)count,timeout);if(ix_fail(I_POLL))return (int)ix_done(n,-1);
 int ready=0;
 for(nfds_t i=0;i<count;i++){
  struct ix_object *o=ix_object(fds[i].fd);fds[i].revents=0;
  if(!o){fds[i].revents=POLLNVAL;ready++;continue;}
  if(o->kind==I_PIDFD&&ix.dead&&o->kernel==ix.original_peer_object){fds[i].revents=POLLIN;ready++;}
  if(o->kind==I_SOCKET){
   if(ix.calls[I_RECV]==0||ix.socket_extra)fds[i].revents|=POLLIN;
   if(ix.socket_eof)fds[i].revents|=POLLHUP|POLLRDHUP;
   if(fds[i].revents)ready++;
  }
 }
 return (int)ix_done(n,ready);
}
static ssize_t ix_read(int fd,void *buffer,size_t size){
 int n=ix_note(I_READ,fd,(long)size);if(ix_fail(I_READ))return (ssize_t)ix_done(n,-1);
 struct ix_object *o=ix_object(fd);if(!o)return ix_bad(n);
 if(o->kind!=I_STATUS_PEER&&o->kind!=I_STATUS_MAIN)return ix_bad(n);
 if(o->read_once)return (ssize_t)ix_done(n,0);
 o->read_once=1;ix.status_reads++;
 int peer=o->kind==I_STATUS_PEER;unsigned uid=peer?(unsigned)ix.peer_uid:0,gid=peer?(unsigned)ix.peer_gid:0;
 int pid=peer?ix.peer:ix.owner;char text[4096];
 unsigned ids[4]={uid,uid,uid,uid},gids[4]={gid,gid,gid,gid};
 if(ix.status_uid_index>0&&ix.status_uid_index<=4)ids[ix.status_uid_index-1]++;
 if(ix.status_gid_index>0&&ix.status_gid_index<=4)gids[ix.status_gid_index-1]++;
 if(ix.status_mode==1)ids[1]++;
 unsigned long long caps[4]={0,0,0,0};if(ix.status_cap_kind>0&&ix.status_cap_kind<=4)caps[ix.status_cap_kind-1]=UINT64_C(1)<<CAP_SYS_PTRACE;
 if(ix.status_mode==3)caps[1]=1;
 int status_pid=ix.status_mode==9?pid+1:pid,status_tgid=ix.status_mode==10?pid+1:pid;
 int count=snprintf(text,sizeof text,
  "Name:\tmodel\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t900\nTracerPid:\t0\nUid:\t%u\t%u\t%u\t%u\nGid:\t%u\t%u\t%u\t%u\nGroups:\t\nNSpid:\t%d%s\nThreads:\t1\nCapInh:\t%016llx\nCapPrm:\t%016llx\nCapEff:\t%016llx\nCapBnd:\t0000000000000000\nCapAmb:\t%016llx\nNoNewPrivs:\t0\n",
  status_tgid,status_pid,ids[0],ids[1],ids[2],ids[3],gids[0],gids[1],gids[2],gids[3],pid,ix.status_mode==2?"\t88":"",caps[0],caps[1],caps[2],caps[3]);
 if(count<0||(size_t)count>=sizeof text)return ix_bad(n);
 if(ix.status_mode==4){char *at=strstr(text,"Pid:");if(at)*at='X';}
 if(ix.status_mode==6){int extra=snprintf(text+count,sizeof text-(size_t)count,"Pid:\t%d\n",pid);if(extra<0)return ix_bad(n);
 count+=extra;}
 if(ix.status_mode==7&&count>0)text[count-1]='!';
 size_t bytes=(size_t)count;if(ix.status_mode==5){bytes=size;memset(buffer,'x',size);}else{if(bytes>size)bytes=size;memcpy(buffer,text,bytes);}
 return (ssize_t)ix_done(n,(long)bytes);
}
static int ix_pipe2(int pair[2],int flags){
 int n=ix_note(I_PIPE,flags,0);if(ix_fail(I_PIPE))return (int)ix_done(n,-1);
 ix.pipe_calls++;if(ix.socket_eof_after_pipe&&ix.pipe_calls==1)ix.socket_eof=1;
 uint64_t kernel=80000+(ix.pipe_alias?0:(uint64_t)ix.pipe_calls);
 int reader=ix_new_ofd(I_PIPE_R,kernel,O_RDONLY|((flags&O_NONBLOCK)&&!ix.reader_blocking?O_NONBLOCK:0));
 int writer=ix_new_ofd(I_PIPE_W,kernel+(ix.pipe_pair_mismatch?100:0),O_WRONLY|(flags&O_NONBLOCK));
 pair[0]=ix_alloc_ofd(3,reader);pair[1]=ix_alloc_ofd(3,writer);
 if(pair[0]<0||pair[1]<0)return ix_bad(n);
 return (int)ix_done(n,0);
}
static int ix_clock_gettime(clockid_t clock,struct timespec *t){
 int n=ix_note(I_CLOCK,clock,0);if(ix_fail(I_CLOCK)||ix.clock_error){errno=EIO;return (int)ix_done(n,-1);}
 if(clock!=CLOCK_MONOTONIC)return ix_bad(n);
 if(ix.stop_clock_n>0&&(int)ix.calls[I_CLOCK]==ix.stop_clock_n)mi_stop_original();
 uint64_t now=ix.now;if(ix.clock_backwards&&ix.calls[I_CLOCK]>1)now-=UINT64_C(100000000);
 t->tv_sec=(time_t)(now/UINT64_C(1000000000));t->tv_nsec=(long)(now%UINT64_C(1000000000));return (int)ix_done(n,0);
}

static ssize_t ix_recvmsg(int fd,struct msghdr *message,int flags){
 int n=ix_note(I_RECV,fd,flags);ix.recv_flags=flags;
 if(ix_fail(I_RECV))return (ssize_t)ix_done(n,-1);
 if(ix.recv_error){errno=ix.recv_error;return (ssize_t)ix_done(n,-1);}
 struct ix_object *o=ix_object(fd);
 if(!o||o->kind!=I_SOCKET||message->msg_iovlen!=1)return ix_bad(n);
 size_t capacity=message->msg_controllen,at=0;
 for(unsigned i=0;i<ix.cmsgs;i++){
  struct ix_cmsg *c=&ix.cmsg[i];size_t payload=(size_t)c->count*sizeof(int);
  size_t extent=CMSG_SPACE(payload);
  if(at+extent>capacity)return ix_bad(n);
  struct cmsghdr h={.cmsg_len=c->declared?c->declared:CMSG_LEN(payload),.cmsg_level=c->level,.cmsg_type=c->type};
  unsigned char *base=(unsigned char*)message->msg_control+at;memset(base,0,extent);memcpy(base,&h,sizeof h);
  for(unsigned j=0;j<c->count;j++){
   int value=c->values[j];
   if(c->level==SOL_SOCKET&&(c->type==SCM_RIGHTS||c->type==SCM_PIDFD)&&value<0){
    value=ix_alloc(c->type==SCM_PIDFD?I_PIDFD:I_FOREIGN,++ix.next_kernel,O_RDONLY);
    if(value<0)return ix_bad(n);
    ix.fd[value].installed=1;ix.installed++;
   }
   memcpy(base+CMSG_LEN(0)+j*sizeof value,&value,sizeof value);
  }
  at+=extent;
 }
 message->msg_controllen=at;message->msg_flags=ix.packet_flags;
 size_t bytes=ix.packet_bytes;
 if(bytes>message->msg_iov[0].iov_len){bytes=message->msg_iov[0].iov_len;message->msg_flags|=MSG_TRUNC;}
 memcpy(message->msg_iov[0].iov_base,ix.packet,bytes);
 return (ssize_t)ix_done(n,ix.recv_eof?0:(long)bytes);
}
static void ix_u64(unsigned char *p,uint64_t value){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(value>>(8*i));}
static void ix_credential(int pid,int uid,int gid){
 ix.cmsg[ix.cmsgs++]=(struct ix_cmsg){.level=SOL_SOCKET,.type=SCM_CREDENTIALS,.count=3,.values={pid,uid,gid}};
}
static void ix_rights(int type,unsigned count){
 IX_ASSERT(ix.cmsgs<IX_MAX_CMSG&&count<=IX_MAX_RIGHTS);
 struct ix_cmsg *c=&ix.cmsg[ix.cmsgs++];memset(c,0,sizeof *c);c->level=SOL_SOCKET;c->type=type;c->count=count;
 for(unsigned i=0;i<count;i++)c->values[i]=-1;
}
static struct mi_admin ix_admin;
static void ix_begin(const char *id){
 (void)mx_begin(id);
 memset(&ix,0,sizeof ix);ix.case_id=id;ix.owner=MX_MAIN;ix.peer=MX_V;ix.peer_uid=1000;ix.peer_gid=1001;
 ix.fail_op=ix.death_op=ix.jump_op=ix.stop_phase=-1;ix.fail_n=1;ix.fail_error=EIO;ix.reused_fd=-1;
 ix.now=UINT64_C(1000000000);ix.next_kernel=90000;ix.original_peer_object=60110;ix.socket_domain=AF_UNIX;ix.socket_type=SOCK_SEQPACKET;
 ix.listener_flag=ix.passcred=1;
 (void)ix_assign(70,ix_new_ofd(I_LISTENER,70000,O_RDWR|O_NONBLOCK),1);
 (void)ix_assign(71,ix_new_ofd(I_SINGLETON,71000,O_RDWR|O_NONBLOCK),1);
 mi_state=(struct mi_owner){.listener=-1};for(unsigned i=0;i<MI_ROLE_COUNT;i++)mi_state.fd[i]=-1;
 memset(&mi_raw,0,sizeof mi_raw);mi_stopping=0;
 ix_admin=(struct mi_admin){.authorized_uid=1000,.authorized_gid=1001,.setup_ns=UINT64_C(5000000000),.work_ns=UINT64_C(2000000000),.cleanup_ns=UINT64_C(1000000000)};
 static const unsigned char marker[16]={'K','V','M','H','A','2',0,0,1,0,0,0,64,0,0,0};
 memcpy(ix.packet,marker,sizeof marker);ix.packet_bytes=MI_HEADER_BYTES;
 ix_u64(ix.packet+16,UINT64_C(900000000));ix_u64(ix.packet+24,UINT64_C(4000000000));ix_u64(ix.packet+32,UINT64_C(6000000000));
 ix_credential(ix.peer,ix.peer_uid,ix.peer_gid);
}
static int ix_capture(void){return mi_main_capture(70,&ix_admin);}
static int ix_to_peer(void){
 if(ix_capture())return -1;
 return mi_accept_original()==1?0:-1;
}
static int ix_to_ready(void){
 if(ix_to_peer())return -1;
 return mi_receive_original()==1?0:-1;
}
static unsigned ix_owned_count(void){
 unsigned count=0;for(int fd=0;fd<IX_FDS;fd++)if(ix.fd[fd].open&&!ix.fd[fd].initial&&fd!=ix.reused_fd)count++;return count;
}
static void ix_expect_retired(void){
 for(unsigned i=0;i<MI_ROLE_COUNT;i++)IX_ASSERT(mi_state.fd[i]==-1);
 IX_ASSERT(ix_owned_count()==0);IX_ASSERT(ix.fd[70].open&&ix.fd[71].open);IX_ASSERT(ix.borrowed_close==0);
}
static void ix_receipt(void){
 printf("{\"phase\":%d,\"failed\":%d,\"cancelled\":%d,\"finished\":%d,\"close_fault\":%d,\"timing_unknown\":%d,\"deadline_expired\":%d,\"failure_errno\":%d,\"ancillary_bad\":%d,\"ancillary_collision\":%d,\"closed_ancillary\":%u,\"peer_proc_lookups\":%d,\"core_offer_blocked\":%d,\"births\":%d,\"release_bytes\":%d,\"exec_attempts\":%d,",
  mi_raw.phase,mi_raw.failed,mi_raw.cancelled,mi_raw.finished,mi_raw.close_fault,mi_raw.timing_unknown,mi_raw.deadline_expired,mi_raw.failure_errno,mi_raw.ancillary_bad,mi_raw.ancillary_collision,mi_raw.closed_ancillary,mi_raw.peer_proc_lookups,mi_raw.core_offer_blocked,mi_raw.births,mi_raw.release_bytes,mi_raw.exec_attempts);
 printf("\"close_total\":%u,\"receipt_overflow\":%d,",mi_raw.close_total,mi_raw.receipt_overflow);
 printf("\"accept_calls\":%u,\"receive_calls\":%u,\"accept_result\":%d,\"accept_errno\":%d,\"receive_result\":%ld,\"receive_errno\":%d,\"receive_flags\":%d,",mi_raw.accept_calls,mi_raw.receive_calls,mi_raw.accept_result,mi_raw.accept_errno,(long)mi_raw.receive_result,mi_raw.receive_errno,mi_raw.receive_flags);
 printf("\"captured_ns\":%llu,\"accepted_ns\":%llu,\"admission_end\":%llu,\"requested_s\":%llu,\"requested_w\":%llu,\"requested_c\":%llu,\"effective_w\":%llu,\"effective_c\":%llu,\"last_ns\":%llu,",(unsigned long long)mi_raw.captured_ns,(unsigned long long)mi_raw.accepted_ns,(unsigned long long)mi_raw.admission_end,(unsigned long long)mi_raw.requested_s,(unsigned long long)mi_raw.requested_w,(unsigned long long)mi_raw.requested_c,(unsigned long long)mi_raw.effective_w,(unsigned long long)mi_raw.effective_c,(unsigned long long)mi_raw.last_ns);
 printf("\"peer\":{\"pid\":%d,\"uid\":%u,\"gid\":%u},\"message\":{\"pid\":%d,\"uid\":%u,\"gid\":%u},\"pipe_inodes\":[%llu,%llu],\"closes\":[",mi_raw.connection_cred.pid,mi_raw.connection_cred.uid,mi_raw.connection_cred.gid,mi_raw.message_cred.pid,mi_raw.message_cred.uid,mi_raw.message_cred.gid,(unsigned long long)mi_raw.out_pipe.st_ino,(unsigned long long)mi_raw.err_pipe.st_ino);
 for(unsigned i=0;i<mi_raw.close_count&&i<MI_CLOSE_RECORDS;i++)printf("%s{\"fd\":%d,\"rc\":%d,\"errno\":%d,\"ancillary\":%d}",i?",":"",mi_raw.closes[i].fd,mi_raw.closes[i].rc,mi_raw.closes[i].error,mi_raw.closes[i].ancillary);
 printf("]}");
}
static void ix_end(void){
 ix.fail_op=-1;ix.stop_phase=-1;
 if(mi_state.main_pid&&ix.owner!=mi_state.main_pid)ix.owner=mi_state.main_pid;
 (void)mi_finish_original();ix_expect_retired();
 IX_ASSERT(ix.unexpected==0);IX_ASSERT(ix.overflow==0);IX_ASSERT(ix.reused_close==0);
 IX_ASSERT(ix.installed==ix.installed_closed);IX_ASSERT(ix.peer_proc_opens<=1);
 IX_ASSERT(mx.calls[O_CLONE]==0&&mx.calls[O_KILL]==0&&mx.calls[O_EXEC]==0&&mx.calls[O_CAPSET]==0);
 IX_ASSERT(mx.calls[O_SELF_PIDFD]==0&&mx.calls[O_SETUID]==0&&mx.calls[O_SETGID]==0&&mx.calls[O_SETGROUPS]==0);
 IX_ASSERT(mx.unexpected==0&&mx.overflow==0);IX_ASSERT(!mh_actual_offer);
 IX_ASSERT(!mi_raw.births&&!mi_raw.release_bytes&&!mi_raw.exec_attempts);
 if(ix.case_failed)ix_failed++;else ix_passed++;
 printf("{\"kind\":\"case\",\"id\":");mx_json_string(ix.case_id);
 printf(",\"mode\":\"ACTUAL_INTAKE_SYSCALL_MODEL_NOT_NATIVE_PROOF\",\"passed\":%s,\"errors\":[",ix.case_failed?"false":"true");
 for(unsigned i=0;i<ix.error_count;i++){if(i)putchar(',');mx_json_string(ix.errors[i]);}
 printf("],\"installed_fds\":%d,\"closed_installed_fds\":%d,\"core_profile_events\":%u,\"receipt\":",ix.installed,ix.installed_closed,mx.count);ix_receipt();printf(",\"trace\":[");
 for(unsigned i=0;i<ix.events;i++){
  struct ix_event *e=&ix.ev[i];printf("%s{\"op\":\"%s\",\"phase\":%d,\"a\":%ld,\"b\":%ld,\"object\":%llu,\"rc\":%ld,\"errno\":%d}",i?",":"",ix_names[e->op],e->phase,e->a,e->b,(unsigned long long)e->object,e->rc,e->error);
 }
 printf("],\"core_profile_trace_separate_not_globally_interleaved\":[");
 for(unsigned i=0;i<mx.count;i++){
  struct mx_event *e=&mx.ev[i];printf("%s{\"op\":\"%s\",\"a\":%ld,\"b\":%ld,\"rc\":%ld,\"errno\":%d}",i?",":"",mx_names[e->op],e->a,e->b,e->result,e->error);
 }
 printf("]}\n");
}
static void ix_basic_cases(void){
 ix_begin("B01_capture_is_not_parent_attestation_and_core_offer_blocked");
 IX_ASSERT(ix_to_ready()==0);IX_ASSERT(mi_state.phase==MI_B1_READY);
 IX_ASSERT(mi_raw.connection_cred.pid==MX_V&&mi_raw.connection_cred.uid==1000);
 IX_ASSERT(mi_raw.requested_s==UINT64_C(900000000));IX_ASSERT(mi_raw.effective_w==UINT64_C(2900000000));IX_ASSERT(mi_raw.effective_c==UINT64_C(3900000000));
 IX_ASSERT(mi_raw.out_pipe.st_ino!=mi_raw.err_pipe.st_ino);IX_ASSERT(ix.peer_proc_opens==1&&ix.peer_pidfd_acquisitions==1);
 IX_ASSERT(mi_core_offer_original()<0&&errno==EOPNOTSUPP);IX_ASSERT(mi_raw.core_offer_blocked&&mi_state.phase==MI_TERMINAL);ix_expect_retired();
 unsigned calls=ix.events;IX_ASSERT(mi_core_offer_original()<0&&errno==EINVAL);IX_ASSERT(ix.events==calls);ix_end();
 const char *names[]={"B02_foreign_peer_uid","B03_foreign_peer_gid","B04_peer_pid_zero","B05_synthetic_peercred_Main_PID_rejected_not_parent_proof","B06_wrong_socket_domain","B07_wrong_socket_type","B08_not_listener","B09_PASSCRED_absent","B10_peercred_short","B11_SO_PEERPIDFD_unsupported","B12_pidfd_installed_then_short_length","B13_snapshot_credential_drift","B14_wrong_procfs_mount","B15_procfs_PID_view_mismatch","B16_wrong_namespace_type","B17_Main_NNP0","B18_Main_extra_capability"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  ix_begin(names[i]);
  switch(i){
  case 0:ix.peer_uid++;break;case 1:ix.peer_gid++;break;case 2:ix.peer=0;break;case 3:ix.peer=MX_MAIN;break;
  case 4:ix.socket_domain=AF_INET;break;case 5:ix.socket_type=SOCK_STREAM;break;case 6:ix.listener_flag=0;break;
  case 7:ix.passcred=0;break;case 8:ix.peercred_short=1;break;case 9:ix.peerpidfd_error=ENOPROTOOPT;break;
  case 10:ix.peerpidfd_short=1;break;case 11:ix.cred_drift=1;break;case 12:ix.proc_magic_error=1;break;
  case 13:ix.initpid_mismatch=1;break;case 14:ix.ns_type_error=1;break;case 15:mx.nnp=0;break;
  case 16:mx.effective|=UINT64_C(1)<<CAP_SYS_ADMIN;break;
  }
  IX_ASSERT(ix_to_ready()<0);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 }
}
static void ix_namespace_status_cases(void){
 const int ns[]={I_USERNS,I_TIMENS,I_PIDNS};
 const char *names[]={"N01_peer_userns_mismatch","N02_peer_timens_mismatch","N03_peer_pidns_mismatch"};
 for(unsigned i=0;i<3;i++){ix_begin(names[i]);ix.ns_mismatch=ns[i];IX_ASSERT(ix_to_peer()<0);ix_expect_retired();ix_end();}
 ix_begin("N04_original_Main_userns_drift_before_accept");IX_ASSERT(ix_capture()==0);ix.ns_main_mismatch=I_USERNS;IX_ASSERT(mi_accept_original()<0);IX_ASSERT(ix.calls[I_ACCEPT]==0);ix_end();
 ix_begin("N05_peer_time_namespace_drift_after_capture");IX_ASSERT(ix_to_peer()==0);ix.ns_mismatch=I_TIMENS;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_RECV]==0);ix_end();
 for(int kind=0;kind<3;kind++)for(int i=1;i<=4;i++){
  char id[80];snprintf(id,sizeof id,"N06_status_%s_position_%d",kind==0?"Uid":kind==1?"Gid":"capability",i);ix_begin(id);
  if(kind==0)ix.status_uid_index=i;else if(kind==1)ix.status_gid_index=i;else ix.status_cap_kind=i;
  IX_ASSERT(ix_to_peer()<0);ix_expect_retired();ix_end();
 }
 const int modes[]={2,4,5,6,7,9,10};
 for(unsigned i=0;i<sizeof modes/sizeof modes[0];i++){
  char id[80];snprintf(id,sizeof id,"N07_malformed_status_mode_%d",modes[i]);ix_begin(id);ix.status_mode=modes[i];IX_ASSERT(ix_to_peer()<0);ix_end();
 }
}
static void ix_ancillary_cases(void){
 const char *names[]={"A01_missing_credentials","A02_duplicate_credentials","A03_message_foreign_pid_same_uid","A04_message_uid_drift","A05_message_gid_drift","A06_unknown_cmsg","A07_wrong_cmsg_level","A08_short_credentials_payload","A09_short_cmsg_header","A10_MSG_CTRUNC","A11_MSG_TRUNC","A12_rights_before_and_after_duplicate_creds_plus_pidfd","A13_unexpected_pidfd","A14_EOF_with_received_rights","A15_late_received_rights_are_closed"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  ix_begin(names[i]);IX_ASSERT(ix_to_peer()==0);
  switch(i){
  case 0:ix.cmsgs=0;break;
  case 1:ix_credential(ix.peer,ix.peer_uid,ix.peer_gid);break;
  case 2:ix.cmsg[0].values[0]++;break;
  case 3:ix.cmsg[0].values[1]++;break;
  case 4:ix.cmsg[0].values[2]++;break;
  case 5:ix.cmsg[ix.cmsgs++]=(struct ix_cmsg){.level=SOL_SOCKET,.type=0x7fff,.count=1,.values={0}};break;
  case 6:ix.cmsg[0].level=0x7fff;break;
  case 7:ix.cmsg[0].count=2;break;
  case 8:ix.cmsg[0].declared=sizeof(struct cmsghdr)-1;break;
  case 9:ix.packet_flags=MSG_CTRUNC;ix_rights(SCM_RIGHTS,3);break;
  case 10:ix.packet_flags=MSG_TRUNC;ix_rights(SCM_RIGHTS,2);break;
  case 11:ix.cmsgs=0;ix_rights(SCM_RIGHTS,3);ix_credential(ix.peer,ix.peer_uid,ix.peer_gid);ix_credential(ix.peer,ix.peer_uid,ix.peer_gid);ix_rights(SCM_RIGHTS,2);ix_rights(SCM_PIDFD,1);break;
  case 12:ix_rights(SCM_PIDFD,1);break;
  case 13:ix.recv_eof=1;ix_rights(SCM_RIGHTS,2);break;
  case 14:ix_rights(SCM_RIGHTS,2);ix.jump_op=I_RECV;ix.jump_n=1;ix.jump_to=mi_state.admission_end+1;break;
  }
  IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_state.phase==MI_TERMINAL);
  IX_ASSERT(ix.installed==ix.installed_closed);IX_ASSERT(mi_raw.closed_ancillary==(unsigned)ix.installed);
  IX_ASSERT((ix.recv_flags&(MSG_DONTWAIT|MSG_CMSG_CLOEXEC))==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC));ix_expect_retired();ix_end();
 }
 ix_begin("A17_maximum_253_SCM_RIGHTS_all_retired_history_is_not_close_failure");IX_ASSERT(ix_to_peer()==0);
 ix_rights(SCM_RIGHTS,253);IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.installed==253&&ix.installed_closed==253);
 IX_ASSERT(mi_raw.closed_ancillary==253&&!mi_raw.close_fault);ix_expect_retired();ix_end();
 ix_begin("A18_history_saturation_preserves_total_without_fabricated_close_error");IX_ASSERT(ix_to_peer()==0);
 ix.recv_error=EAGAIN;for(unsigned i=0;i<20;i++)IX_ASSERT(mi_receive_original()==0);
 ix.recv_error=0;ix_rights(SCM_RIGHTS,253);IX_ASSERT(mi_receive_original()<0);
 IX_ASSERT(ix.installed==253&&ix.installed_closed==253);IX_ASSERT(mi_raw.receipt_overflow&&mi_raw.close_total>mi_raw.close_count&&!mi_raw.close_fault);
 ix_end();
 ix_begin("A19_impossible_kernel_retained_FD_collision_does_not_close_listener");IX_ASSERT(ix_to_peer()==0);
 ix.cmsg[ix.cmsgs++]=(struct ix_cmsg){.level=SOL_SOCKET,.type=SCM_RIGHTS,.count=1,.values={70}};
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_raw.ancillary_collision&&ix.fd[70].open&&ix.borrowed_close==0);ix_end();
 ix_begin("A16_ancillary_close_EINTR_no_reused_number_close");IX_ASSERT(ix_to_peer()==0);
 ix_rights(SCM_RIGHTS,2);ix.close_ancillary_error=1;ix.reuse_on_close=1;
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_raw.close_fault&&ix.reused_fd>=0);IX_ASSERT(ix.reused_close==0);ix_end();
}
static void ix_header_cases(void){
 const char *names[]={"H01_wrong_marker","H02_reserved_nonzero","H03_short_packet","H04_oversize_packet","H05_zero_S","H06_S_equals_W","H07_W_equals_C","H08_C_overflow","H09_S_after_accepted_even_before_now","H10_expired_requested_W","H11_header_clock_crosses_admission_end","H12_clock_latches_stop_inside_guard"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  ix_begin(names[i]);if(i==10)ix_admin.setup_ns=UINT64_C(100000000);IX_ASSERT(ix_to_peer()==0);
  switch(i){
  case 0:ix.packet[0]='X';break;case 1:ix.packet[63]=1;break;case 2:ix.packet_bytes=63;break;case 3:ix.packet_bytes=65;break;
  case 4:ix_u64(ix.packet+16,0);break;case 5:ix_u64(ix.packet+16,UINT64_C(4000000000));break;
  case 6:ix_u64(ix.packet+24,UINT64_C(6000000000));break;case 7:ix_u64(ix.packet+32,UINT64_MAX);break;
  case 8:ix.now=UINT64_C(2000000000);ix_u64(ix.packet+16,UINT64_C(1500000000));break;
  case 9:ix_u64(ix.packet+24,UINT64_C(950000000));break;
  case 10:ix.now=UINT64_C(1200000000);IX_ASSERT(mi_header(ix.packet)<0);IX_ASSERT(mi_state.phase==MI_PEER_HELD);ix_end();continue;
  case 11:ix.stop_clock_n=(int)ix.calls[I_CLOCK]+1;IX_ASSERT(mi_guard()<0);IX_ASSERT(mi_stopping);ix_end();continue;
  }
  IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_end();
 }
 ix_begin("H13_requested_effective_bounds_only_shrink");IX_ASSERT(ix_to_peer()==0);ix_u64(ix.packet+24,UINT64_C(1600000000));ix_u64(ix.packet+32,UINT64_C(1900000000));
 IX_ASSERT(mi_receive_original()==1);IX_ASSERT(mi_raw.effective_w==UINT64_C(1600000000));IX_ASSERT(mi_raw.effective_c==UINT64_C(1900000000));ix_end();
 ix_begin("H14_original_bounds_no_rearm_after_EAGAIN");IX_ASSERT(ix_to_peer()==0);uint64_t old_end=mi_state.admission_end;ix.recv_error=EAGAIN;IX_ASSERT(mi_receive_original()==0);IX_ASSERT(mi_state.phase==MI_PEER_HELD&&mi_state.admission_end==old_end);ix.recv_error=0;ix.now=old_end;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_raw.receive_calls==1);ix_end();
 ix_begin("H15_backwards_clock_sticky_no_late_receive");IX_ASSERT(ix_to_peer()==0);ix.now-=1;IX_ASSERT(mi_receive_original()<0);unsigned received=ix.calls[I_RECV];ix.now+=2;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_RECV]==received&&mi_raw.timing_unknown);ix_end();
}
static void ix_pipe_cases(void){
 ix_begin("P01_distinct_FD_numbers_same_stdout_stderr_pipe_rejected");ix.pipe_alias=1;IX_ASSERT(ix_to_ready()<0);IX_ASSERT(ix.pipe_calls==2);IX_ASSERT(mi_raw.out_pipe.st_ino==mi_raw.err_pipe.st_ino);ix_end();
 ix_begin("P02_reader_writer_different_kernel_objects_rejected");ix.pipe_pair_mismatch=1;IX_ASSERT(ix_to_ready()<0);ix_end();
 ix_begin("P03_missing_nonblock_reader_rejected");ix.reader_blocking=1;IX_ASSERT(ix_to_ready()<0);ix_end();
 ix_begin("P04_all_temporary_pipe_OFD_aliases_retired");IX_ASSERT(ix_to_ready()==0);
 for(unsigned role=MI_OUT_READ;role<=MI_ERR_WRITE;role++){
  int fd=mi_state.fd[role];IX_ASSERT(ix_good(fd));int aliases=0;
  for(int i=0;i<IX_FDS;i++)if(ix.fd[i].open&&ix.fd[i].ofd==ix.fd[fd].ofd)aliases++;
  IX_ASSERT(aliases==1);IX_ASSERT(ix.obj[ix.fd[fd].ofd].flags&O_NONBLOCK);
 }ix_end();
 ix_begin("P05_OFD_alias_changes_flags_not_physical_interruptibility_proof");IX_ASSERT(ix_to_ready()==0);
 int reader=mi_state.fd[MI_OUT_READ],alias=ix_fcntl(reader,F_DUPFD_CLOEXEC,100);IX_ASSERT(alias>=100);
 IX_ASSERT(ix_fcntl(alias,F_SETFL,O_RDONLY)==0);IX_ASSERT(!(ix_fcntl(reader,F_GETFL)&O_NONBLOCK));
 IX_ASSERT(ix_close(alias)==0);IX_ASSERT(mi_core_offer_original()<0&&errno==EOPNOTSUPP);ix_end();
}
static void ix_ownership_cases(void){
 const char *names[]={"O01_cancel_COLD","O02_cancel_MAIN_CAPTURED","O03_stop_ACCEPTED_partial_acquisition","O04_cancel_PEER_HELD","O05_stop_HEADER_BOUND","O06_cancel_B1_READY","O07_idempotent_TERMINAL_and_FINISHED"};
 for(unsigned i=0;i<sizeof names/sizeof names[0];i++){
  ix_begin(names[i]);
  if(i==0){IX_ASSERT(mi_cancel_original()==0);IX_ASSERT(ix.calls[I_OPEN]==0);}
  else if(i==1){IX_ASSERT(ix_capture()==0);IX_ASSERT(mi_cancel_original()==0);}
  else if(i==2){IX_ASSERT(ix_capture()==0);ix.stop_phase=MI_ACCEPTED;IX_ASSERT(mi_accept_original()<0);}
  else if(i==3){IX_ASSERT(ix_to_peer()==0);IX_ASSERT(mi_cancel_original()==0);}
  else if(i==4){IX_ASSERT(ix_to_peer()==0);ix.stop_phase=MI_HEADER_BOUND;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_PIPE]==0);}
  else {IX_ASSERT(ix_to_ready()==0);IX_ASSERT(mi_cancel_original()==0);}
  ix_expect_retired();unsigned closes=ix.calls[I_CLOSE];IX_ASSERT(mi_cancel_original()==0);IX_ASSERT(ix.calls[I_CLOSE]==closes);
  IX_ASSERT(mi_finish_original()==0);IX_ASSERT(mi_finish_original()==0);IX_ASSERT(ix.calls[I_CLOSE]==closes);IX_ASSERT(ix_capture()<0);ix_end();
 }
 ix_begin("O08_foreign_owner_cannot_close_held_descriptors");IX_ASSERT(ix_to_peer()==0);unsigned held=ix_owned_count();ix.owner++;
 IX_ASSERT(mi_cancel_original()<0&&errno==ECHILD);IX_ASSERT(ix_owned_count()==held);ix.owner--;ix_end();
 ix_begin("O09_peer_death_PID_reuse_never_reopens_proc");IX_ASSERT(ix_to_peer()==0);int exact=mi_state.fd[MI_PEER_PIDFD];uint64_t old=ix_object(exact)->kernel;
 ix.dead=1;int other=ix_alloc(I_PIDFD,old+1,O_RDONLY);ix.obj[ix.fd[other].ofd].pid=MX_V;
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.peer_proc_opens==1);IX_ASSERT(ix_good(other)&&ix_object(other)->kernel==old+1);struct pollfd foreign={other,POLLIN,0};IX_ASSERT(ix_poll(&foreign,1,0)==0&&foreign.revents==0);IX_ASSERT(ix_close(other)==0);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O10_accept_EAGAIN_then_cancel_without_rearming");IX_ASSERT(ix_capture()==0);uint64_t end=mi_state.admission_end;ix.accept_error=EAGAIN;IX_ASSERT(mi_accept_original()==0);IX_ASSERT(mi_state.phase==MI_MAIN_CAPTURED&&mi_state.admission_end==end);ix_end();
 ix_begin("O11_recv_EINTR_terminal_without_retry");IX_ASSERT(ix_to_peer()==0);ix.recv_error=EINTR;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_RECV]==1);ix_end();
 ix_begin("O12_EOF_PEER_HELD_terminal");IX_ASSERT(ix_to_peer()==0);ix.recv_eof=1;IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_raw.receive_result==0);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O13_receive_wrong_states_never_calls_recvmsg");IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix_capture()==0);IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_cancel_original()==0);IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_finish_original()==0);IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_RECV]==0);ix_end();
 ix_begin("O14_death_during_initial_proc_acquisition");IX_ASSERT(ix_capture()==0);ix.death_op=I_OPENAT;ix.death_n=(int)ix.calls[I_OPENAT]+4;IX_ASSERT(mi_accept_original()<0);IX_ASSERT(ix.peer_proc_opens<=1);ix_end();
 ix_begin("O16_queued_valid_header_with_connection_EOF_refused");IX_ASSERT(ix_to_peer()==0);ix.socket_eof=1;
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_RECV]==0);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O17_connection_EOF_after_B1_READY_no_offer");IX_ASSERT(ix_to_ready()==0);ix.socket_eof=1;
 IX_ASSERT(mi_core_offer_original()<0);IX_ASSERT(!mi_raw.core_offer_blocked&&!mh_actual_offer);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O18_EOF_after_first_output_pipe_retires_all_resources");IX_ASSERT(ix_to_peer()==0);ix.socket_eof_after_pipe=1;
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.pipe_calls>=1);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O19_extra_queued_frame_after_header_bound_is_terminal");IX_ASSERT(ix_to_peer()==0);ix.socket_extra=1;
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(mi_state.phase==MI_TERMINAL);IX_ASSERT(ix.calls[I_PIPE]==0);ix_expect_retired();ix_end();
 ix_begin("O20_first_pipe_returns_after_W_no_second_acquisition");IX_ASSERT(ix_to_peer()==0);ix.jump_op=I_PIPE;ix.jump_n=1;ix.jump_to=UINT64_C(3000000000);
 IX_ASSERT(mi_receive_original()<0);IX_ASSERT(ix.calls[I_PIPE]==1);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 ix_begin("O15_close_EINTR_reuse_not_retried");ix.close_error_n=1;ix.reuse_on_close=1;IX_ASSERT(ix_capture()<0);IX_ASSERT(mi_raw.close_fault&&ix.reused_fd>=0&&ix.reused_close==0);ix_end();
}
static void ix_partial_failures(void){
 unsigned counts[I_COUNT];
 ix_begin("F00_baseline_acquisition_counts");IX_ASSERT(ix_to_ready()==0);memcpy(counts,ix.calls,sizeof counts);ix_end();
 const int ops[]={I_OPEN,I_OPENAT,I_FCNTL,I_FSTAT,I_FSTATFS,I_IOCTL,I_GETSOCKOPT,I_ACCEPT,I_POLL,I_RECV,I_READ,I_PIPE};
 for(unsigned k=0;k<sizeof ops/sizeof ops[0];k++)for(unsigned at=1;at<=counts[ops[k]];at++){
  char id[96];snprintf(id,sizeof id,"F01_partial_%s_call_%u",ix_names[ops[k]],at);ix_begin(id);
  ix.fail_op=ops[k];ix.fail_n=(int)at;IX_ASSERT(ix_to_ready()<0);IX_ASSERT(ix.calls[ops[k]]>=at);IX_ASSERT(mi_state.phase==MI_TERMINAL);ix_expect_retired();ix_end();
 }
 const unsigned points[]={1,counts[I_CLOCK]/2,counts[I_CLOCK]};
 for(unsigned i=0;i<3;i++){
  char id[96];snprintf(id,sizeof id,"F02_clock_error_at_%u",points[i]);ix_begin(id);ix.fail_op=I_CLOCK;ix.fail_n=(int)points[i];IX_ASSERT(ix_to_ready()<0);IX_ASSERT(mi_raw.timing_unknown);ix_end();
 }
}
int main(void){
 ix_basic_cases();ix_namespace_status_cases();ix_ancillary_cases();ix_header_cases();ix_pipe_cases();ix_ownership_cases();ix_partial_failures();
 printf("{\"kind\":\"summary\",\"passed\":%u,\"failed\":%u,\"native_Main_H\":\"NOT_RUN\",\"stage_A_cases_executed\":0,\"physical_proof\":false}\n",ix_passed,ix_failed);
 return ix_failed?1:0;
}
