/* A2 PRIVATE fixed-Main intake. Include AFTER unchanged main-h-birth-core.inc.
 * Only the fixed derivative calls these static functions with its actual
 * listener/configuration. B1 facts are never published as mh_actual_offer.
 * No H creation, gate release, exec, project/graph I/O or public API exists. */
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdio.h>
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef SCM_PIDFD
#define SCM_PIDFD 4
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif
#define MI_HEADER_BYTES 64U
#define MI_CONTROL_BYTES 8192U
#define MI_STATUS_BYTES 16384U
#define MI_CLOSE_RECORDS 512U

enum mi_phase { MI_COLD,MI_MAIN_CAPTURED,MI_ACCEPTED,MI_PEER_HELD,
  MI_HEADER_BOUND,MI_B1_READY,MI_TERMINAL,MI_FINISHED };
enum mi_role { MI_PROC_ROOT,MI_MAIN_PROC,MI_MAIN_USERNS,MI_MAIN_TIMENS,
  MI_MAIN_PIDNS,MI_CONNECTION,MI_PEER_PIDFD,MI_PEER_PROC,MI_PEER_USERNS,
  MI_PEER_TIMENS,MI_PEER_PIDNS,MI_OUT_READ,MI_OUT_WRITE,MI_ERR_READ,
  MI_ERR_WRITE,MI_ROLE_COUNT };
struct mi_admin {
  uid_t authorized_uid;gid_t authorized_gid;
  uint64_t setup_ns,work_ns,cleanup_ns;
};
struct mi_close_record { int fd,rc,error,ancillary; };
struct mi_receipt {
  enum mi_phase phase;
  int failed,cancelled,finished,close_fault,timing_unknown,deadline_expired;
  int failure_errno,ancillary_bad,ancillary_collision,peer_proc_lookups,receipt_overflow;
  int core_offer_blocked,births,release_bytes,exec_attempts;
  unsigned accept_calls,receive_calls,closed_ancillary,close_count,close_total;
  int accept_result,accept_errno,receive_flags;ssize_t receive_result;
  int receive_errno;
  uint64_t captured_ns,accepted_ns,request_observed_ns,last_ns;
  uint64_t admission_end,requested_s,requested_w,requested_c,effective_w,effective_c;
  struct ucred connection_cred,message_cred;
  struct stat original_main_user,original_main_time,original_main_pid;
  struct stat original_peer_user,original_peer_time,original_peer_pid;
  struct stat out_pipe,err_pipe;
  struct mi_close_record closes[MI_CLOSE_RECORDS];
};
struct mi_owner {
  enum mi_phase phase;pid_t main_pid;
  int listener,fd[MI_ROLE_COUNT];
  struct stat listener_identity;
  struct mi_admin admin;struct ucred peer;
  uint64_t clock_high,admission_end,requested_s,requested_w,requested_c,w,c;
  struct stat main_ns[3],peer_ns[3];
};
static struct mi_owner mi_state={.listener=-1,
 .fd={-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1}};
static struct mi_receipt mi_raw;
static volatile sig_atomic_t mi_stopping;
static int mi_cancel_original(void);
static int mi_guard(void);
static void mi_stop_original(void){mi_stopping=1;}
static int mi_same(const struct stat *a,const struct stat *b){
  return a->st_dev==b->st_dev && a->st_ino==b->st_ino;
}
static void mi_phase_set(enum mi_phase p){mi_state.phase=p;mi_raw.phase=p;}
static int mi_close_fd(int *owned,int ancillary){
  if(*owned<0)return 0;
  int fd=*owned;*owned=-1;errno=0;int rc=close(fd),saved=errno;
  if(mi_raw.close_total<UINT_MAX)mi_raw.close_total++;
  else mi_raw.receipt_overflow=1;
  if(mi_raw.close_count<MI_CLOSE_RECORDS){
    struct mi_close_record *r=&mi_raw.closes[mi_raw.close_count++];
    r->fd=fd;r->rc=rc;r->error=rc<0?saved:0;r->ancillary=ancillary;
  }else mi_raw.receipt_overflow=1;
  if(rc)mi_raw.close_fault=1;
  if(ancillary){
    if(mi_raw.closed_ancillary<UINT_MAX)mi_raw.closed_ancillary++;
    else mi_raw.receipt_overflow=1;
  }
  return rc;
}
static int mi_raise_fd(int *owned){
  if(*owned<0||mi_guard())return -1;
  int n=fcntl(*owned,F_DUPFD_CLOEXEC,32);
  if(n<0)return -1;
  int old=*owned;*owned=n;
  int closed=mi_close_fd(&old,0);
  return closed||mi_guard()?-1:0;
}
static uint64_t mi_now(void){
  struct timespec ts;
  if(mi_raw.timing_unknown)return 0;
  if(clock_gettime(CLOCK_MONOTONIC,&ts)||ts.tv_sec<0||ts.tv_nsec<0||
     ts.tv_nsec>=1000000000L||
     (uint64_t)ts.tv_sec>INT64_MAX/UINT64_C(1000000000))goto bad;
  uint64_t n=(uint64_t)ts.tv_sec*UINT64_C(1000000000)+(uint64_t)ts.tv_nsec;
  if(!n||n>INT64_MAX||n<mi_state.clock_high)goto bad;
  mi_state.clock_high=n;mi_raw.last_ns=n;return n;
bad:mi_raw.timing_unknown=1;return 0;
}
static int mi_guard(void){
  if(mi_stopping||mi_raw.failed||mi_raw.deadline_expired||
     (mi_state.main_pid && mi_state.main_pid!=getpid()))return -1;
  uint64_t n=mi_now();if(!n||mi_stopping||mi_raw.failed)return -1;
  uint64_t end=mi_state.phase>=MI_HEADER_BOUND?mi_state.w:mi_state.admission_end;
  if(!end||n>=end){mi_raw.deadline_expired=1;return -1;}
  return mi_stopping||mi_raw.failed?-1:0;
}
static int mi_fail(int error){
  mi_raw.failed=1;if(!mi_raw.failure_errno)mi_raw.failure_errno=error?error:EIO;
  (void)mi_cancel_original();errno=error?error:EIO;return -1;
}
static int mi_get_int(int fd,int option,int expected){
  int got=-1;socklen_t n=sizeof got;
  return !getsockopt(fd,SOL_SOCKET,option,&got,&n)&&n==sizeof got&&got==expected?0:-1;
}
static int mi_fd_shape(int fd,int access,int nonblock){
  int d=fcntl(fd,F_GETFD),f=fcntl(fd,F_GETFL);
  return d>=0&&(d&FD_CLOEXEC)&&f>=0&&(access<0||(f&O_ACCMODE)==access)&&
    (!nonblock||(f&O_NONBLOCK))?0:-1;
}
static int mi_live(void){
  if(mi_guard())return -1;
  struct pollfd p={mi_state.fd[MI_PEER_PIDFD],POLLIN,0};
  int n=poll(&p,1,0);
  return n==0&&!p.revents&&!mi_guard()?0:-1;
}
static int mi_ns_observe(int proc,const char *name,int type,int *owned,struct stat *st){
  if(mi_guard())return -1;
  *owned=openat(proc,name,O_RDONLY|O_CLOEXEC);
  if(*owned<0||mi_raise_fd(owned)||mi_guard()||fstat(*owned,st)||
     mi_guard()||ioctl(*owned,NS_GET_NSTYPE)!=type||mi_guard())return -1;
  return 0;
}
static int mi_ns_current(int proc,const struct stat expected[3]){
  static const char *names[]={"ns/user","ns/time","ns/pid"};
  static const int types[]={CLONE_NEWUSER,CLONE_NEWTIME,CLONE_NEWPID};
  for(unsigned i=0;i<3;i++){
    int fd=-1;struct stat st;
    int rc=mi_ns_observe(proc,names[i],types[i],&fd,&st);
    int closed=mi_close_fd(&fd,0);
    if(rc||closed||!mi_same(&st,&expected[i])||mi_guard())return -1;
  }
  return 0;
}
static int mi_main_current(void){
  return mi_guard()||mh_main_profile()||mi_guard()||
    mi_ns_current(mi_state.fd[MI_MAIN_PROC],mi_state.main_ns)?-1:0;
}
static int mi_cred_same(const struct ucred *a,const struct ucred *b){
  return a->pid==b->pid&&a->uid==b->uid&&a->gid==b->gid;
}
static int mi_peercred(struct ucred *out){
  socklen_t n=sizeof *out;memset(out,0,sizeof *out);
  return !mi_guard()&&!getsockopt(mi_state.fd[MI_CONNECTION],SOL_SOCKET,
    SO_PEERCRED,out,&n)&&n==sizeof *out&&!mi_guard()?0:-1;
}
static int mi_number(const char **cursor,const char *end,unsigned base,uint64_t *value){
  const char *p=*cursor;while(p<end&&(*p==' '||*p=='\t'))p++;
  uint64_t v=0;unsigned digits=0;
  while(p<end){
    unsigned d=(unsigned)(*p-'0');
    if(base==16&&*p>='a'&&*p<='f')d=(unsigned)(*p-'a')+10;
    else if(base==16&&*p>='A'&&*p<='F')d=(unsigned)(*p-'A')+10;
    if(d>=base)break;
    if(v>(UINT64_MAX-d)/base)return -1;
    v=v*base+d;p++;digits++;
  }
  if(!digits)return -1;
  *cursor=p;*value=v;return 0;
}
static int mi_numbers(const char *p,const char *end,unsigned base,unsigned count,uint64_t expected){
  for(unsigned i=0;i<count;i++){
    uint64_t got=0;if(mi_number(&p,end,base,&got)||got!=expected)return -1;
  }
  while(p<end&&(*p==' '||*p=='\t'))p++;
  return p==end?0:-1;
}
static int mi_status(void){
  if(mi_live())return -1;
  int fd=openat(mi_state.fd[MI_PEER_PROC],"status",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
  if(fd<0)return -1;
  char bytes[MI_STATUS_BYTES];ssize_t n=-1;
  if(!mi_guard())n=read(fd,bytes,sizeof bytes);
  int saved=errno,closed=mi_close_fd(&fd,0);errno=saved;
  if(closed||n<=0||(size_t)n>=sizeof bytes||bytes[n-1]!='\n'||mi_guard())return -1;
  static const char *keys[]={"Pid:","Tgid:","NSpid:","Uid:","Gid:",
    "CapInh:","CapPrm:","CapEff:","CapAmb:"};
  unsigned mask=0;const char *p=bytes,*end=bytes+n;
  while(p<end){
    const char *e=memchr(p,'\n',(size_t)(end-p));if(!e)return -1;
    for(unsigned i=0;i<sizeof keys/sizeof keys[0];i++){
      size_t k=strlen(keys[i]);
      if((size_t)(e-p)>=k&&!memcmp(p,keys[i],k)){
        if(mask&(1U<<i))return -1;
        mask|=1U<<i;
        uint64_t expected=i<=2?(uint64_t)mi_state.peer.pid:
          i==3?(uint64_t)mi_state.peer.uid:i==4?(uint64_t)mi_state.peer.gid:0;
        if(mi_numbers(p+k,e,i>=5?16U:10U,i==3||i==4?4U:1U,expected))return -1;
      }
    }
    p=e+1;
  }
  return mask==0x1ffU&&!mi_live()?0:-1;
}
static int mi_connection_current(void){
  if(mi_guard())return -1;
  struct pollfd p={mi_state.fd[MI_CONNECTION],POLLIN|POLLRDHUP,0};
  int rc=poll(&p,1,0);
  if(rc<0||(p.revents&(POLLHUP|POLLRDHUP|POLLERR|POLLNVAL))||
     (mi_state.phase>=MI_HEADER_BOUND&&(p.revents&POLLIN)))return -1;
  /* Before the one header, POLLIN is pending DATA, not a death indication.
   * Afterwards additional packets/EOF are terminal; nothing is consumed. */
  return mi_guard();
}
static int mi_peer_current(void){
  struct ucred current;
  return mi_main_current()||mi_live()||mi_connection_current()||mi_peercred(&current)||
    !mi_cred_same(&current,&mi_state.peer)||mi_status()||
    mi_ns_current(mi_state.fd[MI_PEER_PROC],mi_state.peer_ns)||
    mi_live()||mi_connection_current()||mi_guard()?-1:0;
}
static int mi_main_capture(int listener,const struct mi_admin *admin){
  if(mi_state.phase!=MI_COLD||mi_stopping||!admin){errno=EALREADY;return -1;}
  mi_state.main_pid=getpid();mi_state.listener=listener;
  if(!admin->authorized_uid||!admin->authorized_gid||
     admin->authorized_uid==(uid_t)-1||admin->authorized_gid==(gid_t)-1||
     !admin->setup_ns||!admin->work_ns||!admin->cleanup_ns||
     admin->setup_ns>INT64_MAX||admin->work_ns>INT64_MAX||admin->cleanup_ns>INT64_MAX)
    return mi_fail(EINVAL);
  mi_state.admin=*admin;
  uint64_t n=mi_now();if(!n||admin->setup_ns>(uint64_t)INT64_MAX-n)return mi_fail(EOVERFLOW);
  mi_state.admission_end=n+admin->setup_ns;mi_raw.admission_end=mi_state.admission_end;
  mi_raw.captured_ns=n;
  if(mi_guard()||mh_main_profile()||mi_guard()||mi_fd_shape(listener,-1,1)||
     mi_get_int(listener,SO_DOMAIN,AF_UNIX)||mi_get_int(listener,SO_TYPE,SOCK_SEQPACKET)||
     mi_get_int(listener,SO_ACCEPTCONN,1)||mi_get_int(listener,SO_PASSCRED,1)||
     fstat(listener,&mi_state.listener_identity)||!S_ISSOCK(mi_state.listener_identity.st_mode)||mi_guard())
    return mi_fail(EPERM);
  mi_state.fd[MI_PROC_ROOT]=open("/proc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  struct statfs fs;
  if(mi_state.fd[MI_PROC_ROOT]<0||mi_raise_fd(&mi_state.fd[MI_PROC_ROOT])||mi_guard()||
     fstatfs(mi_state.fd[MI_PROC_ROOT],&fs)||fs.f_type!=PROC_SUPER_MAGIC||mi_guard())return mi_fail(EPERM);
  mi_state.fd[MI_MAIN_PROC]=openat(mi_state.fd[MI_PROC_ROOT],"self",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
  if(mi_state.fd[MI_MAIN_PROC]<0||mi_raise_fd(&mi_state.fd[MI_MAIN_PROC])||mi_guard())return mi_fail(EIO);
  static const char *names[]={"ns/user","ns/time","ns/pid"};
  static const int types[]={CLONE_NEWUSER,CLONE_NEWTIME,CLONE_NEWPID};
  for(unsigned i=0;i<3;i++)
    if(mi_ns_observe(mi_state.fd[MI_MAIN_PROC],names[i],types[i],
         &mi_state.fd[MI_MAIN_USERNS+i],&mi_state.main_ns[i]))return mi_fail(EPERM);
  /* Mount's PID1 namespace must equal actual Main namespace. /proc/self or
   * coincidentally equal PID text alone cannot bind the procfs PID view. */
  int initns=-1;struct stat initst;
  int check=mi_ns_observe(mi_state.fd[MI_PROC_ROOT],"1/ns/pid",CLONE_NEWPID,&initns,&initst);
  int closed=mi_close_fd(&initns,0);
  if(check||closed||!mi_same(&initst,&mi_state.main_ns[2])||mi_main_current())return mi_fail(EPERM);
  mi_raw.original_main_user=mi_state.main_ns[0];mi_raw.original_main_time=mi_state.main_ns[1];
  mi_raw.original_main_pid=mi_state.main_ns[2];
  mi_phase_set(MI_MAIN_CAPTURED);return 0;
}
static int mi_accept_original(void){
  if(mi_state.phase!=MI_MAIN_CAPTURED){errno=EINVAL;return -1;}
  struct stat current;
  if(mi_main_current()||fstat(mi_state.listener,&current)||
     !mi_same(&current,&mi_state.listener_identity)||mi_guard())return mi_fail(EPERM);
  errno=0;int fd=accept4(mi_state.listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
  int saved=errno;mi_raw.accept_calls++;mi_raw.accept_result=fd;mi_raw.accept_errno=fd<0?saved:0;
  if(fd<0){
    if((saved==EAGAIN||saved==EWOULDBLOCK)&&!mi_guard())return 0;
    return mi_fail(saved);
  }
  /* Store actual accept result before the first fallible operation. */
  mi_state.fd[MI_CONNECTION]=fd;mi_phase_set(MI_ACCEPTED);
  mi_raw.accepted_ns=mi_now();
  if(mi_raise_fd(&mi_state.fd[MI_CONNECTION])||mi_guard()||
     mi_fd_shape(mi_state.fd[MI_CONNECTION],-1,1)||
     mi_get_int(mi_state.fd[MI_CONNECTION],SO_DOMAIN,AF_UNIX)||
     mi_get_int(mi_state.fd[MI_CONNECTION],SO_TYPE,SOCK_SEQPACKET)||
     mi_get_int(mi_state.fd[MI_CONNECTION],SO_ACCEPTCONN,0)||
     mi_get_int(mi_state.fd[MI_CONNECTION],SO_PASSCRED,1)||mi_peercred(&mi_state.peer)||
     mi_state.peer.pid<=0||mi_state.peer.pid==mi_state.main_pid||
     mi_state.peer.uid!=mi_state.admin.authorized_uid||mi_state.peer.gid!=mi_state.admin.authorized_gid)
    return mi_fail(EPERM);
  int pidfd=-1;socklen_t length=sizeof pidfd;
  if(mi_guard())return mi_fail(ETIMEDOUT);
  errno=0;int rc=getsockopt(mi_state.fd[MI_CONNECTION],SOL_SOCKET,SO_PEERPIDFD,&pidfd,&length);
  saved=errno;
  if(rc)return mi_fail(saved);
  /* Even a malformed successful getsockopt length may have installed the fd. */
  mi_state.fd[MI_PEER_PIDFD]=pidfd;
  if(pidfd<0||length!=sizeof pidfd||mi_raise_fd(&mi_state.fd[MI_PEER_PIDFD])||
     mi_fd_shape(mi_state.fd[MI_PEER_PIDFD],-1,0)||mi_live())return mi_fail(EPERM);
  struct ucred again;
  if(mi_peercred(&again)||!mi_cred_same(&again,&mi_state.peer)||mi_live())return mi_fail(EPERM);
  char name[32];int count=snprintf(name,sizeof name,"%ld",(long)mi_state.peer.pid);
  if(count<=0||(size_t)count>=sizeof name||mi_guard())return mi_fail(EOVERFLOW);
  /* ONE initial metadata lookup using the kernel credential PID, protected
   * by held exact SO_PEERPIDFD liveness brackets. Never pidfd_open(peer),
   * never relookup this numeric proc path after capture or failure. */
  mi_raw.peer_proc_lookups++;
  mi_state.fd[MI_PEER_PROC]=openat(mi_state.fd[MI_PROC_ROOT],name,
    O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(mi_state.fd[MI_PEER_PROC]<0||mi_raise_fd(&mi_state.fd[MI_PEER_PROC])||mi_live())return mi_fail(EPERM);
  static const char *names[]={"ns/user","ns/time","ns/pid"};
  static const int types[]={CLONE_NEWUSER,CLONE_NEWTIME,CLONE_NEWPID};
  for(unsigned i=0;i<3;i++){
    if(mi_ns_observe(mi_state.fd[MI_PEER_PROC],names[i],types[i],
       &mi_state.fd[MI_PEER_USERNS+i],&mi_state.peer_ns[i])||
       !mi_same(&mi_state.peer_ns[i],&mi_state.main_ns[i])||mi_live())return mi_fail(EPERM);
  }
  if(mi_status()||mi_peer_current())return mi_fail(EPERM);
  mi_raw.connection_cred=mi_state.peer;
  mi_raw.original_peer_user=mi_state.peer_ns[0];mi_raw.original_peer_time=mi_state.peer_ns[1];
  mi_raw.original_peer_pid=mi_state.peer_ns[2];
  mi_phase_set(MI_PEER_HELD);return 1;
}
static int mi_is_retained(int fd){
  if(fd==mi_state.listener)return 1;
  for(unsigned i=0;i<MI_ROLE_COUNT;i++)if(fd==mi_state.fd[i])return 1;
  return 0;
}
static int mi_ancillary(struct msghdr *message,struct ucred *cred){
  unsigned char *bytes=message->msg_control;
  size_t size=message->msg_controllen,at=0;unsigned credentials=0;
  int bad=(message->msg_flags&(MSG_CTRUNC|MSG_TRUNC))!=0;
  int seen[MI_CONTROL_BYTES/sizeof(int)];unsigned seen_n=0;
  if(size>MI_CONTROL_BYTES){size=MI_CONTROL_BYTES;bad=1;}
  while(at<size){
    size_t remain=size-at;
    if(remain<sizeof(struct cmsghdr)){bad=1;break;}
    struct cmsghdr h;memcpy(&h,bytes+at,sizeof h);
    size_t header=CMSG_LEN(0);
    if(h.cmsg_len<header){bad=1;break;}
    size_t visible=h.cmsg_len<remain?h.cmsg_len:remain;
    if(visible<header){bad=1;break;}
    size_t payload=visible-header;
    if(h.cmsg_level==SOL_SOCKET&&(h.cmsg_type==SCM_RIGHTS||h.cmsg_type==SCM_PIDFD)){
      bad=1;
      for(size_t i=0;i+sizeof(int)<=payload;i+=sizeof(int)){
        int fd;memcpy(&fd,bytes+at+header+i,sizeof fd);
        if(fd<0){bad=1;continue;}
        int duplicate=0;for(unsigned j=0;j<seen_n;j++)if(seen[j]==fd)duplicate=1;
        if(duplicate)continue;
        seen[seen_n++]=fd;
        /* A kernel-installed new FD cannot alias an already-open number.
         * Do not close retained authority on impossible/corrupt framing. */
        if(mi_is_retained(fd)){mi_raw.ancillary_collision=1;continue;}
        (void)mi_close_fd(&fd,1);
      }
      if(payload%sizeof(int))bad=1;
    }else if(h.cmsg_level==SOL_SOCKET&&h.cmsg_type==SCM_CREDENTIALS){
      credentials++;
      if(payload!=sizeof *cred||h.cmsg_len!=CMSG_LEN(sizeof *cred))bad=1;
      else memcpy(cred,bytes+at+header,sizeof *cred);
    }else bad=1;
    if(h.cmsg_len>remain){bad=1;break;}
    size_t step=CMSG_ALIGN(h.cmsg_len);
    if(step<h.cmsg_len){bad=1;break;}
    if(step>remain){at=size;break;}
    at+=step;
  }
  if(credentials!=1)bad=1;
  mi_raw.ancillary_bad|=bad;
  return bad||mi_raw.close_fault?-1:0;
}
static uint64_t mi_u64(const unsigned char *p){
  uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static int mi_header(const unsigned char bytes[MI_HEADER_BYTES]){
  static const unsigned char marker[16]={'K','V','M','H','A','2',0,0,1,0,0,0,64,0,0,0};
  if(memcmp(bytes,marker,sizeof marker))return -1;
  for(unsigned i=40;i<MI_HEADER_BYTES;i++)if(bytes[i])return -1;
  uint64_t s=mi_u64(bytes+16),w=mi_u64(bytes+24),c=mi_u64(bytes+32),n=mi_now();
  if(!n||mi_stopping||mi_raw.failed||n>=mi_state.admission_end||
     !s||s>=w||w>=c||c>INT64_MAX||s>n||s>mi_raw.accepted_ns||
     mi_state.admin.work_ns>(uint64_t)INT64_MAX-s)return -1;
  uint64_t ew=s+mi_state.admin.work_ns;if(ew>w)ew=w;
  if(mi_state.admin.cleanup_ns>(uint64_t)INT64_MAX-ew)return -1;
  uint64_t ec=ew+mi_state.admin.cleanup_ns;if(ec>c)ec=c;
  if(n>=ew||ew<=s||ec<=ew)return -1;
  mi_state.requested_s=s;mi_state.requested_w=w;mi_state.requested_c=c;
  mi_state.w=ew;mi_state.c=ec;
  mi_raw.requested_s=s;mi_raw.requested_w=w;mi_raw.requested_c=c;
  mi_raw.effective_w=ew;mi_raw.effective_c=ec;mi_raw.request_observed_ns=n;
  mi_phase_set(MI_HEADER_BOUND);return mi_guard();
}
static int mi_pipe_pair(int read_role,int write_role,struct stat *identity){
  if(mi_guard())return -1;
  int pair[2]={-1,-1};if(pipe2(pair,O_NONBLOCK|O_CLOEXEC))return -1;
  mi_state.fd[read_role]=pair[0];mi_state.fd[write_role]=pair[1];
  if(mi_raise_fd(&mi_state.fd[read_role])||mi_raise_fd(&mi_state.fd[write_role])||mi_guard())return -1;
  struct stat r,w;
  if(mi_fd_shape(mi_state.fd[read_role],O_RDONLY,1)||
     mi_fd_shape(mi_state.fd[write_role],O_WRONLY,1)||
     fstat(mi_state.fd[read_role],&r)||fstat(mi_state.fd[write_role],&w)||
     !S_ISFIFO(r.st_mode)||!S_ISFIFO(w.st_mode)||!mi_same(&r,&w)||mi_guard())return -1;
  *identity=r;return 0;
}
static int mi_receive_original(void){
  if(mi_state.phase!=MI_PEER_HELD){errno=EINVAL;return -1;}
  if(mi_peer_current())return mi_fail(EPERM);
  unsigned char bytes[MI_HEADER_BYTES];
  union { struct cmsghdr align;unsigned char bytes[MI_CONTROL_BYTES]; } control;
  memset(&control,0,sizeof control);
  struct iovec iov={bytes,sizeof bytes};struct msghdr message;
  memset(&message,0,sizeof message);message.msg_iov=&iov;message.msg_iovlen=1;
  message.msg_control=control.bytes;message.msg_controllen=sizeof control.bytes;
  if(mi_guard())return mi_fail(ETIMEDOUT);
  errno=0;ssize_t n=recvmsg(mi_state.fd[MI_CONNECTION],&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
  int saved=errno;mi_raw.receive_calls++;mi_raw.receive_result=n;mi_raw.receive_errno=n<0?saved:0;
  mi_raw.receive_flags=message.msg_flags;
  if(n<0){
    if((saved==EAGAIN||saved==EWOULDBLOCK)&&!mi_guard())return 0;
    return mi_fail(saved);
  }
  /* Always sweep control before any length/EOF/credential/deadline return. */
  struct ucred cred;memset(&cred,0,sizeof cred);
  int ancillary=mi_ancillary(&message,&cred);mi_raw.message_cred=cred;
  if(ancillary||n!=(ssize_t)sizeof bytes||!mi_cred_same(&cred,&mi_state.peer)||
     mi_guard()||mi_peer_current()||mi_header(bytes)||mi_peer_current())return mi_fail(EPERM);
  if(mi_pipe_pair(MI_OUT_READ,MI_OUT_WRITE,&mi_raw.out_pipe)||
     mi_pipe_pair(MI_ERR_READ,MI_ERR_WRITE,&mi_raw.err_pipe)||
     mi_same(&mi_raw.out_pipe,&mi_raw.err_pipe)||mi_peer_current())return mi_fail(EPERM);
  /* pipe2 owns fresh distinct objects. Temporary dup aliases were retired.
   * No F_SETFL, descriptor export, fork or publication occurs in this slice. */
  mi_phase_set(MI_B1_READY);return 1;
}
static int mi_core_offer_original(void){
  if(mi_state.phase!=MI_B1_READY){errno=EINVAL;return -1;}
  if(mi_peer_current())return mi_fail(EPERM);
  /* B1 facts alone cannot construct the pinned core's required graph,
   * H administrative identity or full listener/loop ownership. No assignment
   * to mh_actual_offer and no mh_spawn_original call exists here. */
  mi_raw.core_offer_blocked=1;
  (void)mi_cancel_original();errno=EOPNOTSUPP;return -1;
}
static int mi_cancel_original(void){
  if(mi_state.main_pid && mi_state.main_pid!=getpid()){errno=ECHILD;return -1;}
  if(mi_state.phase==MI_FINISHED)return mi_raw.close_fault?-1:0;
  mi_raw.cancelled=1;mi_phase_set(MI_TERMINAL);
  /* Invalidate before close, never retry by a potentially reused number.
   * No output transfer/birth happened, so all fifteen roles remain ours. */
  for(unsigned i=MI_ROLE_COUNT;i>0;i--)(void)mi_close_fd(&mi_state.fd[i-1],0);
  if(mi_raw.close_fault){errno=EIO;return -1;}
  return 0;
}
static int mi_finish_original(void){
  if(mi_cancel_original())return -1;
  mi_raw.finished=1;mi_phase_set(MI_FINISHED);return 0;
}
