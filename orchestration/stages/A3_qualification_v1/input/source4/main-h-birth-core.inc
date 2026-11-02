/* PRIVATE fixed-Main source slice, NOT wired into any Main or public route.
 * Closed portion: one-shot birth -> held native child -> terminal cleanup.
 * RELEASE AND EXEC ARE UNAVAILABLE. No gate token or exec syscall exists.
 * The old b932 bundle is inert DATA, not a compatible Main/NNP1 entry.
 * See CORE_SLICE_CONTRACT_RU.md for ownership, premises and exact blockers.
 * No native execution or physical privilege qualification is implied. */
#if !defined(__linux__) || !defined(__x86_64__)
#error "Main-H source slice requires the Linux x86_64 raw clone ABI"
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/nsfs.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(uid_t)==4 && sizeof(gid_t)==4,"fixed Linux credential ABI");
#define MH_CAPS ((UINT64_C(1)<<CAP_SETUID)|(UINT64_C(1)<<CAP_SETGID)|\
 (UINT64_C(1)<<CAP_CHOWN)|(UINT64_C(1)<<CAP_KILL)|\
 (UINT64_C(1)<<CAP_SYS_PTRACE)|(UINT64_C(1)<<CAP_SETFCAP))
#define MH_SEALS (F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)
#define MH_SIGNAL_ATTEMPTS 8U
#define MH_CLOSE_RECORDS 24U

enum mh_phase {
  MH_IDLE=0, MH_REFUSED=1, MH_CHILD_HELD=2, MH_CANCEL_PENDING=3,
  MH_CLEANUP_OBSERVED=4, MH_FINISHED=5
};
struct mh_policy {
  uid_t caller_uid,h_uid;gid_t caller_gid,h_gid;
  uint32_t ledger_first,ledger_last;
};
struct mh_slot {
  pid_t main_pid,v_pid,h_pid;
  struct mh_policy policy;
  uint64_t requested_start,requested_w,requested_c,w,c;
  /* Main-native resources only; no packet/argv/FD constructor. All inputs
   * are >=32, distinct and CLOEXEC. out_read/err_read are nonblocking readers
   * of corresponding exclusive pipes. Other input descriptors are borrowed;
   * on successful birth ONLY the output readers/writers transfer to custody.
   * No duplicate output writer exists outside this parent/actual child. */
  int input,out_write,err_write,h_control,v_pidfd,context,bundle,addon;
  int main_userns,node_image,singleton,listener,out_read,err_read;
  /* Diagnostic mirrors only: NEVER the authority used for signal/wait/close. */
  int gate_read,gate_write,h_pidfd,spent,born,released,failed;
  struct stat userns;
};
struct mh_observation { unsigned calls;long result;int error; };
struct mh_close_observation { int fd,result,error; };
struct mh_signal_observation {
  int fd,error;long result;uint64_t attempted_ns,returned_ns;
};
struct mh_receipt {
  enum mh_phase phase;
  pid_t owner_pid,child_pid;
  int spent,born,birth_unknown,cancelled,release_requested;
  int released,exec_attempted,reaped,out_eof,err_eof,cleanup_observed;
  int failed,close_fault,wait_unknown,deadline_expired,timing_unknown;
  int timely_cleanup,gate_bytes_sent,signal_fd,wait_fd;
  uint64_t start_ns,w_ns,c_ns,last_observed_ns,cleanup_observed_ns;
  uint64_t out_bytes,err_bytes;
  struct mh_observation self_pidfd,pipe,clone,signal,wait,out_read,err_read;
  struct mh_signal_observation signals[MH_SIGNAL_ATTEMPTS];
  siginfo_t wait_info;
  unsigned close_count;
  struct mh_close_observation closes[MH_CLOSE_RECORDS];
};
struct mh_custody {
  struct mh_slot *slot;
  pid_t owner_pid,child_pid;
  int pidfd,main_pidfd,gate_read,gate_write,out_read,err_read;
  int cancelled,signal_done;
  uint64_t w,c;
};
/* Program-private storage, never exported/deserialized. One retained attempt
 * is supported. Exclusive descriptor custody is a fixed-program premise,
 * not an fstat theorem. No Main/service integration is added here. */
static struct mh_slot *mh_actual_offer;
static struct mh_custody mh_owned={.pidfd=-1,.main_pidfd=-1,
  .gate_read=-1,.gate_write=-1,.out_read=-1,.err_read=-1};
static struct mh_receipt mh_raw;
static volatile sig_atomic_t mh_stopping;
static uint64_t mh_clock_high;
static int mh_close_owned(int *owned);

static uint64_t mh_now(void){
  struct timespec t;
  if(mh_raw.timing_unknown)return 0;
  if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||
     t.tv_nsec>=1000000000L||
     (uint64_t)t.tv_sec>INT64_MAX/UINT64_C(1000000000)){
    mh_raw.timing_unknown=1;return 0;
  }
  uint64_t n=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
  if(!n||n>INT64_MAX||n<mh_clock_high){mh_raw.timing_unknown=1;return 0;}
  mh_clock_high=n;return n;
}
static void mh_note(struct mh_observation *o,long result,int error){
  if(o->calls<UINT_MAX)o->calls++;
  o->result=result;o->error=result<0?error:0;
}
static int mh_live(int fd){
  struct pollfd p={fd,POLLIN,0};
  return fd>=0 && poll(&p,1,0)==0 && !p.revents;
}
static int mh_identity_policy(const struct mh_policy *p){
  if(!p || !p->caller_uid || !p->caller_gid || !p->h_uid || !p->h_gid ||
     p->caller_uid==(uid_t)-1 || p->caller_gid==(gid_t)-1 ||
     p->h_uid==(uid_t)-1 || p->h_gid==(gid_t)-1 ||
     !p->ledger_first || p->ledger_last==UINT32_MAX ||
     p->ledger_first>p->ledger_last)return -1;
  if(p->h_uid==p->caller_uid || p->h_uid==p->caller_gid ||
     p->h_gid==p->caller_uid || p->h_gid==p->caller_gid)return -1;
  if((p->h_uid>=p->ledger_first && p->h_uid<=p->ledger_last) ||
     (p->h_gid>=p->ledger_first && p->h_gid<=p->ledger_last))return -1;
  return 0;
}
static int mh_bounding_six(void){
  for(int i=0;i<64;i++){
    errno=0;int present=prctl(PR_CAPBSET_READ,i,0,0,0);
    if(present<0){
      if(errno==EINVAL && !(MH_CAPS&(UINT64_C(1)<<i)))continue;
      return -1;
    }
    if(present!=(int)((MH_CAPS>>i)&1))return -1;
  }
  return 0;
}
static int mh_ambient_zero(void){
  for(int i=0;i<64;i++){
    errno=0;int present=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,i,0,0);
    if(present<0 && errno==EINVAL && i>CAP_LAST_CAP)continue;
    if(present!=0)return -1;
  }
  return 0;
}
static int mh_main_profile(void){
  uid_t a,b,c;gid_t d,e,f;struct sigaction action;
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
  struct __user_cap_data_struct caps[2];memset(caps,0xff,sizeof caps);
  if(getresuid(&a,&b,&c)||getresgid(&d,&e,&f)||a||b||c||d||e||f||
     getgroups(0,NULL)!=0||setfsuid((uid_t)-1)||setfsgid((gid_t)-1)||
     prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||
     prctl(PR_GET_KEEPCAPS,0,0,0,0)!=0||prctl(PR_GET_DUMPABLE,0,0,0,0)!=0||
     sigaction(SIGCHLD,NULL,&action)||action.sa_handler!=SIG_DFL||
     (action.sa_flags&SA_NOCLDWAIT)||syscall(SYS_capget,&h,caps))return -1;
  uint64_t ep=(uint64_t)caps[0].effective|((uint64_t)caps[1].effective<<32);
  uint64_t pp=(uint64_t)caps[0].permitted|((uint64_t)caps[1].permitted<<32);
  return ep==MH_CAPS && pp==MH_CAPS && !caps[0].inheritable &&
    !caps[1].inheritable && !mh_bounding_six() && !mh_ambient_zero()?0:-1;
}
static int mh_work_current(const struct mh_slot *s){
  if(!(s && !s->failed && !mh_stopping && s->requested_start &&
    s->requested_start<s->w && s->requested_w<=INT64_MAX &&
    s->requested_c<=INT64_MAX && s->w<=s->requested_w && s->w<s->c &&
    s->c<=s->requested_c && s->requested_w<s->requested_c))return 0;
  if(!mh_live(s->v_pidfd))return 0;
  /* Clock is sampled AFTER the possibly delayed liveness observation. */
  uint64_t n=mh_now();
  return !mh_stopping && !s->failed && n && s->requested_start<=n && n<s->w;
}
static int mh_sealed(int fd){
  struct stat st;int seals=fcntl(fd,F_GET_SEALS);
  return fd>=0 && seals>=0 && (seals&MH_SEALS)==MH_SEALS &&
    !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_nlink==0 && st.st_size>0;
}
static int mh_same_userns(int held,const struct stat *expected){
  struct stat a,b;int self=open("/proc/self/ns/user",O_RDONLY|O_CLOEXEC);
  if(self<0)return -1;
  int ok=!fstat(held,&a) && !fstat(self,&b) &&
    a.st_dev==expected->st_dev && a.st_ino==expected->st_ino &&
    b.st_dev==a.st_dev && b.st_ino==a.st_ino &&
    ioctl(held,NS_GET_NSTYPE)==CLONE_NEWUSER &&
    ioctl(self,NS_GET_NSTYPE)==CLONE_NEWUSER;
  /* Linux close is not retried after EINTR: a reused number is not custody. */
  int closed=mh_close_owned(&self);return ok && !closed?0:-1;
}
static int mh_pipe_pair(int reader,int writer){
  struct stat a,b;int rf=fcntl(reader,F_GETFL),wf=fcntl(writer,F_GETFL);
  return rf>=0 && wf>=0 && (rf&O_ACCMODE)==O_RDONLY &&
    (wf&O_ACCMODE)==O_WRONLY && (rf&O_NONBLOCK) &&
    !fstat(reader,&a) && !fstat(writer,&b) &&
    S_ISFIFO(a.st_mode) && S_ISFIFO(b.st_mode) &&
    a.st_dev==b.st_dev && a.st_ino==b.st_ino;
}
static int mh_sources_valid(const struct mh_slot *s){
  const int fds[]={s->input,s->out_write,s->err_write,s->h_control,
    s->v_pidfd,s->context,s->bundle,s->addon,s->main_userns,s->node_image,
    s->singleton,s->listener,s->out_read,s->err_read};
  for(unsigned i=0;i<sizeof fds/sizeof fds[0];i++){
    if(fds[i]<32)return 0;
    for(unsigned j=0;j<i;j++)if(fds[i]==fds[j])return 0;
    int flags=fcntl(fds[i],F_GETFD);
    if(flags<0 || !(flags&FD_CLOEXEC))return 0;
  }
  return mh_pipe_pair(s->out_read,s->out_write) &&
    mh_pipe_pair(s->err_read,s->err_write);
}
/* Full transition helper, independently modelled. The held-child path DOES
 * NOT call it: a protected new entry and release remain unavailable. */
static int mh_child_drop(const struct mh_slot *s){
  if(mh_identity_policy(&s->policy)||prctl(PR_SET_KEEPCAPS,0,0,0,0)||
     prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||setgroups(0,NULL)||
     setresgid(s->policy.h_gid,s->policy.h_gid,s->policy.h_gid)||
     setresuid(s->policy.h_uid,s->policy.h_uid,s->policy.h_uid))return -1;
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
  struct __user_cap_data_struct zero[2]={{0},{0}},caps[2];
  uid_t a,b,c;gid_t d,e,f;memset(caps,0xff,sizeof caps);
  if(syscall(SYS_capset,&h,zero)||
     prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||
     getresuid(&a,&b,&c)||getresgid(&d,&e,&f)||
     a!=s->policy.h_uid||b!=a||c!=a||d!=s->policy.h_gid||e!=d||f!=d||
     getgroups(0,NULL)!=0||(uid_t)setfsuid((uid_t)-1)!=a||
     (gid_t)setfsgid((gid_t)-1)!=d||syscall(SYS_capget,&h,caps)||
     prctl(PR_GET_KEEPCAPS,0,0,0,0)!=0||
     prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return -1;
  for(unsigned i=0;i<2;i++)
    if(caps[i].effective||caps[i].permitted||caps[i].inheritable)return -1;
  if(mh_ambient_zero()||mh_bounding_six())return -1;
  struct rlimit core={0,0};
  return setrlimit(RLIMIT_CORE,&core)||prctl(PR_SET_DUMPABLE,0,0,0,0)||
    prctl(PR_GET_DUMPABLE,0,0,0,0)!=0?-1:0;
}
static int mh_child_drop_checked(const struct mh_slot *s,int mainfd,int vfd,int nsfd){
  if(!s)return -1;
  struct mh_slot checked=*s;checked.v_pidfd=vfd;
  if(!mh_work_current(&checked)||mh_main_profile()||
     getppid()!=s->main_pid||!mh_live(mainfd)||!mh_live(vfd)||
     mh_same_userns(nsfd,&s->userns)||prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||
     getppid()!=s->main_pid||!mh_live(mainfd)||
     !mh_work_current(&checked)||mh_child_drop(s))return -1;
  /* Credential changes can clear PDEATHSIG. Rearm AFTER the final drop,
   * then bracket actual parent and original namespace again. */
  if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||getppid()!=s->main_pid||
     !mh_live(mainfd)||!mh_live(vfd)||mh_same_userns(nsfd,&s->userns))return -1;
  uint64_t n=mh_now();return n && s->requested_start<=n && n<s->w?0:-1;
}
static int mh_close_owned(int *owned){
  if(*owned<0)return 0;
  int fd=*owned;*owned=-1;errno=0;int rc=close(fd),saved=errno;
  if(mh_raw.close_count<MH_CLOSE_RECORDS){
    struct mh_close_observation *o=&mh_raw.closes[mh_raw.close_count++];
    o->fd=fd;o->result=rc;o->error=rc<0?saved:0;
  }else mh_raw.close_fault=1;
  if(rc){mh_raw.close_fault=1;mh_raw.failed=1;}
  return rc;
}
static int mh_raise_owned(int *owned){
  errno=0;int high=fcntl(*owned,F_DUPFD_CLOEXEC,32),saved=errno;
  if(high<0){errno=saved;return -1;}
  int old=*owned;*owned=high;
  if(mh_close_owned(&old))return -1;
  return 0;
}
/* Only actual CLONE_PIDFD child. No CLONE_VM/CLONE_FILES: later parent slot
 * changes are NOT notification. Gate closure, pidfds and original W are. */
static _Noreturn void mh_child_hold(const struct mh_slot *s,int mainfd,int gr,int gw){
  /* Actual sole inherited listener is known by the fixed native producer.
   * Retire it FIRST, even before a fallible parent-liveness/PDEATHSIG check:
   * otherwise _exit fdtable order could release singleton before listener. */
  if(close(s->listener)||close(gw)||prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||
     getppid()!=s->main_pid||!mh_live(mainfd)||!mh_work_current(s))_exit(120);
  /* Preserve singleton15 before targets are replaced, and until every
   * inherited listener/authority descriptor has been retired. */
  if(dup3(s->singleton,15,O_CLOEXEC)!=15)_exit(120);
  const int source[]={s->input,s->out_write,s->err_write,s->h_control,mainfd,
    s->v_pidfd,s->context,s->bundle,s->addon,s->main_userns,gr,s->node_image};
  const int target[]={0,1,2,4,5,6,7,8,9,10,12,20};
  for(unsigned i=0;i<sizeof source/sizeof source[0];i++)
    if(source[i]<32||dup3(source[i],target[i],
       target[i]==12||target[i]==20?O_CLOEXEC:0)!=target[i])_exit(120);
  if(syscall(SYS_close_range,3U,3U,0U)||
     syscall(SYS_close_range,11U,11U,0U)||
     syscall(SYS_close_range,13U,14U,0U)||
     syscall(SYS_close_range,16U,19U,0U)||
     syscall(SYS_close_range,21U,~0U,0U)||close(15)||
     mh_same_userns(10,&s->userns)||mh_main_profile()||
     getppid()!=s->main_pid||!mh_live(5)||!mh_live(6))_exit(120);
  uint64_t n=mh_now();if(!n||n<s->requested_start||n>=s->w)_exit(120);
  uint64_t ms=(s->w-n)/UINT64_C(1000000);
  if(ms>(uint64_t)INT_MAX)ms=INT_MAX;
  struct pollfd watches[3]={{12,POLLIN|POLLHUP,0},{5,POLLIN,0},{6,POLLIN,0}};
  /* One bounded wait. EINTR never restarts it. No positive token is accepted:
   * data, EOF, peer death, timeout and any error all terminate the child.
   * This is not a hard bound on kernel/scheduler blocking latency. */
  int ready=poll(watches,3,(int)ms);
  uint64_t after=mh_now();
  if(after && after<s->w && ready>0 &&
     (watches[0].revents&(POLLIN|POLLHUP))){
    unsigned char byte;ssize_t observed=read(12,&byte,1);
    /* Successful byte/EOF is terminal too; read errors take the same exit. */
    if(observed>=0)_exit(120);
  }
  _exit(120);
}
static int mh_owner_current(void){
  if(!mh_owned.slot || mh_owned.owner_pid!=getpid()){
    errno=ECHILD;return 0;
  }
  return 1;
}
static void mh_stop_original(void){mh_stopping=1;}
static int mh_cancel_original(void){
  if(!mh_owned.slot){
    /* Terminal cancellation may precede spawn. Consume that exact pending
     * offer without inspecting/closing any of its supplied descriptors. */
    struct mh_slot *s=mh_actual_offer;mh_actual_offer=NULL;
    if(!s){errno=ECHILD;return -1;}
    if(s->spent||s->born){errno=EALREADY;return -1;}
    s->spent=1;
    mh_owned=(struct mh_custody){.slot=s,.owner_pid=getpid(),.pidfd=-1,
      .main_pidfd=-1,.gate_read=-1,.gate_write=-1,.out_read=-1,.err_read=-1,
      .w=s->w,.c=s->c};
    mh_raw=(struct mh_receipt){.phase=MH_REFUSED,.owner_pid=mh_owned.owner_pid,
      .spent=1,.start_ns=s->requested_start,.w_ns=s->w,.c_ns=s->c,
      .signal_fd=-1,.wait_fd=-1};
  }
  if(!mh_owner_current())return -1;
  mh_owned.cancelled=1;mh_raw.cancelled=1;mh_raw.failed=1;
  mh_owned.slot->failed=1;
  if(mh_raw.cleanup_observed)return 0;
  if(!mh_raw.cleanup_observed && mh_raw.phase!=MH_FINISHED)mh_raw.phase=MH_CANCEL_PENDING;
  (void)mh_close_owned(&mh_owned.gate_write);
  uint64_t n=mh_now();
  if(n && mh_owned.c && n>=mh_owned.c)mh_raw.deadline_expired=1;
  int may_signal=!mh_raw.signal.calls ||
    (!mh_raw.deadline_expired && !mh_raw.timing_unknown && n && n<mh_owned.c);
  /* Only immutable atomic birth custody is used, never the diagnostic slot.
   * ESRCH is a raw signal result, not death/reap/EOF. A first mandatory kill
   * is allowed after C; retries are limited and allowed only before C. */
  if(mh_raw.born && !mh_raw.reaped && mh_owned.pidfd>=0 &&
     !mh_owned.signal_done && may_signal && mh_raw.signal.calls<MH_SIGNAL_ATTEMPTS){
    mh_raw.signal_fd=mh_owned.pidfd;
    struct mh_signal_observation *record=&mh_raw.signals[mh_raw.signal.calls];
    record->fd=mh_owned.pidfd;record->attempted_ns=n;
    errno=0;long rc=syscall(SYS_pidfd_send_signal,mh_owned.pidfd,SIGKILL,NULL,0);
    int saved=errno;mh_note(&mh_raw.signal,rc,saved);
    record->result=rc;record->error=rc<0?saved:0;record->returned_ns=mh_now();
    if(record->returned_ns && record->returned_ns>=mh_owned.c)mh_raw.deadline_expired=1;
    if(!rc || saved==ESRCH || (saved!=EINTR && saved!=EAGAIN))mh_owned.signal_done=1;
  }
  return 0;
}
static int mh_release_original(void){
  if(mh_cancel_original())return -1;
  mh_raw.release_requested=1;
  /* No graph_ready Boolean, hash-as-authority, gate byte or compatibility
   * bypass. New protected entry/graph/intake are absent. */
  errno=EOPNOTSUPP;return -1;
}
static int mh_spawn_original(void){
  struct mh_slot *s=mh_actual_offer;
  if(mh_owned.slot){errno=EBUSY;return -1;}
  if(!s){errno=EINVAL;return -1;}
  /* Consume before every fallible validation/acquisition. Invalid input
   * never closes supplied resources or signals supplied pidfds. */
  mh_actual_offer=NULL;
  if(s->spent||s->born){errno=EALREADY;return -1;}
  s->spent=1;
  mh_owned=(struct mh_custody){.slot=s,.owner_pid=getpid(),.pidfd=-1,
    .main_pidfd=-1,.gate_read=-1,.gate_write=-1,.out_read=-1,.err_read=-1,
    .w=s->w,.c=s->c};
  mh_raw=(struct mh_receipt){.phase=MH_REFUSED,.owner_pid=mh_owned.owner_pid,
    .spent=1,.start_ns=s->requested_start,.w_ns=s->w,.c_ns=s->c,
    .signal_fd=-1,.wait_fd=-1};
  if(mh_stopping||s->main_pid!=mh_owned.owner_pid||s->v_pid<=0||
     s->v_pid==s->main_pid||s->h_pid!=0||s->h_pidfd!=-1||
     s->gate_read!=-1||s->gate_write!=-1||s->released||s->failed||
     mh_main_profile()||mh_identity_policy(&s->policy)||!mh_sources_valid(s)||
     !mh_work_current(s)||mh_same_userns(s->main_userns,&s->userns)||
     !mh_sealed(s->context)||!mh_sealed(s->bundle)||!mh_sealed(s->addon)||
     !mh_sealed(s->node_image)||!mh_work_current(s)){
    s->failed=1;mh_raw.failed=1;errno=EINVAL;return -1;
  }
  /* Self lookup is neither child nor peer PID lookup: this running Main
   * cannot be replaced during the call. No offered main_pidfd is trusted. */
  errno=0;long self=syscall(SYS_pidfd_open,getpid(),0);
  int saved=errno;mh_note(&mh_raw.self_pidfd,self,saved);
  if(self<0)goto failed;
  mh_owned.main_pidfd=(int)self;
  if(mh_raise_owned(&mh_owned.main_pidfd))goto failed;
  if(!mh_work_current(s))goto failed;
  int pair[2]={-1,-1};errno=0;int made=pipe2(pair,O_CLOEXEC|O_NONBLOCK);
  saved=errno;mh_note(&mh_raw.pipe,made,saved);
  if(made)goto failed;
  mh_owned.gate_read=pair[0];mh_owned.gate_write=pair[1];
  if(mh_raise_owned(&mh_owned.gate_read)||mh_raise_owned(&mh_owned.gate_write))goto failed;
  if(mh_main_profile()||mh_same_userns(s->main_userns,&s->userns)||
     !mh_work_current(s))goto failed;
  int bornfd=-1;errno=0;
  long child=syscall(SYS_clone,CLONE_PIDFD|SIGCHLD,NULL,&bornfd,NULL,0);
  saved=errno;
  if(child==0)mh_child_hold(s,mh_owned.main_pidfd,mh_owned.gate_read,mh_owned.gate_write);
  if(child<0){
    mh_note(&mh_raw.clone,child,saved);
    /* Real failed clone creates no child/pidfd. Contradictory results stay
     * unknown; a number written on failure is not ownership to close. */
    if(bornfd!=-1)mh_raw.birth_unknown=1;
    goto failed;
  }
  /* First parent operations are infallible actual birth-custody stores.
   * No fcntl/close/poll/clock/relocation precedes retaining this returned fd. */
  mh_owned.child_pid=(pid_t)child;mh_owned.pidfd=bornfd;
  s->h_pid=(pid_t)child;s->h_pidfd=bornfd;s->born=1;
  mh_raw.born=1;mh_raw.child_pid=(pid_t)child;mh_raw.phase=MH_CHILD_HELD;
  mh_note(&mh_raw.clone,child,0);
  mh_owned.out_read=s->out_read;mh_owned.err_read=s->err_read;
  (void)mh_close_owned(&mh_owned.gate_read);
  (void)mh_close_owned(&mh_owned.main_pidfd);
  /* Parent writers transfer; actual child already has its private copies.
   * Borrowed singleton/graph/peer resources are not closed by this parent. */
  (void)mh_close_owned(&s->out_write);(void)mh_close_owned(&s->err_write);
  s->gate_read=-1;s->gate_write=mh_owned.gate_write;
  if(bornfd<0){mh_raw.birth_unknown=1;goto failed;}
  if(mh_raw.close_fault||!mh_live(bornfd)||!mh_work_current(s))goto failed;
  mh_raw.last_observed_ns=mh_now();
  if(!mh_raw.last_observed_ns||mh_raw.last_observed_ns>=s->w)goto failed;
  return MH_CHILD_HELD;
failed:
  saved=errno;s->failed=1;mh_raw.failed=1;
  (void)mh_close_owned(&mh_owned.gate_read);
  (void)mh_close_owned(&mh_owned.main_pidfd);
  (void)mh_cancel_original();errno=saved?saved:EIO;return -1;
}
static void mh_read_output(int fd,int *eof,struct mh_observation *o,uint64_t *total){
  if(*eof||fd<0)return;
  unsigned char bytes[4096];errno=0;ssize_t n=read(fd,bytes,sizeof bytes);
  int saved=errno;mh_note(o,(long)n,saved);
  if(n==0)*eof=1;
  else if(n>0){
    if((uint64_t)n>UINT64_MAX-*total){mh_raw.failed=1;*total=UINT64_MAX;}
    else *total+=(uint64_t)n;
  }else if(saved!=EAGAIN&&saved!=EWOULDBLOCK&&saved!=EINTR)mh_raw.failed=1;
}
static int mh_progress_original(void){
  if(!mh_owner_current())return -1;
  /* Freeze the first complete observation. Later calls cannot retime or
   * demote it, and cannot initiate another wait/read/signal operation. */
  if(mh_raw.cleanup_observed)return 1;
  uint64_t n=mh_now();mh_raw.last_observed_ns=n;
  if(!n){mh_raw.timing_unknown=1;(void)mh_cancel_original();return 0;}
  if(mh_raw.deadline_expired||n>=mh_owned.c){
    mh_raw.deadline_expired=1;
    /* First mandatory cancellation remains possible after C. There is no
     * late body/gate/drain/wait attempt or replacement deadline. */
    (void)mh_cancel_original();
    return 0;
  }
  if(mh_stopping||n>=mh_owned.w||!mh_work_current(mh_owned.slot))
    (void)mh_cancel_original();
  if(mh_owned.cancelled)(void)mh_cancel_original();
  if(!mh_raw.born)return !mh_raw.birth_unknown;
  /* Work/liveness/cancellation can themselves return after C. Recheck
   * immediately before beginning any biological wait observation. */
  n=mh_now();
  if(!n||mh_raw.deadline_expired||n>=mh_owned.c){
    mh_raw.timing_unknown|=!n;mh_raw.deadline_expired|=n>=mh_owned.c;
    (void)mh_cancel_original();return 0;
  }
  if(!mh_raw.reaped && mh_owned.pidfd>=0){
    siginfo_t info;memset(&info,0,sizeof info);mh_raw.wait_fd=mh_owned.pidfd;
    errno=0;int rc=waitid(P_PIDFD,(id_t)mh_owned.pidfd,&info,WEXITED|WNOHANG);
    int saved=errno;mh_note(&mh_raw.wait,rc,saved);mh_raw.wait_info=info;
    if(rc){
      if(saved!=EINTR)mh_raw.wait_unknown=1;
      (void)mh_cancel_original();
    }else if(info.si_pid){
      if(info.si_signo==SIGCHLD && info.si_pid==mh_owned.child_pid && info.si_uid==0 &&
         (info.si_code==CLD_EXITED||info.si_code==CLD_KILLED||info.si_code==CLD_DUMPED))
        mh_raw.reaped=1;
      else mh_raw.wait_unknown=1;
      (void)mh_cancel_original();
    }
  }
  n=mh_now();
  if(!n||n>=mh_owned.c){
    mh_raw.timing_unknown|=!n;mh_raw.deadline_expired|=n>=mh_owned.c;
    (void)mh_cancel_original();return 0;
  }
  mh_read_output(mh_owned.out_read,&mh_raw.out_eof,&mh_raw.out_read,&mh_raw.out_bytes);
  if(mh_raw.out_eof)(void)mh_cancel_original();
  n=mh_now();
  if(!n||n>=mh_owned.c){
    mh_raw.timing_unknown|=!n;mh_raw.deadline_expired|=n>=mh_owned.c;
    (void)mh_cancel_original();return 0;
  }
  mh_read_output(mh_owned.err_read,&mh_raw.err_eof,&mh_raw.err_read,&mh_raw.err_bytes);
  if(mh_raw.err_eof)(void)mh_cancel_original();
  n=mh_now();mh_raw.last_observed_ns=n;
  if(!n)mh_raw.timing_unknown=1;
  if(n>=mh_owned.c)mh_raw.deadline_expired=1;
  if(mh_raw.reaped && mh_raw.out_eof && mh_raw.err_eof){
    mh_raw.cleanup_observed=1;mh_raw.cleanup_observed_ns=n;
    mh_raw.timely_cleanup=n && n<mh_owned.c && !mh_raw.timing_unknown &&
      !mh_raw.deadline_expired && !mh_raw.wait_unknown;
    mh_raw.phase=MH_CLEANUP_OBSERVED;return 1;
  }
  if(mh_raw.failed)(void)mh_cancel_original();
  return 0;
}
static int mh_finish_original(void){
  if(!mh_owner_current())return -1;
  if(mh_raw.birth_unknown ||
     (mh_raw.born && !(mh_raw.reaped && mh_raw.out_eof && mh_raw.err_eof))){
    errno=EBUSY;return -1;
  }
  (void)mh_close_owned(&mh_owned.gate_read);
  (void)mh_close_owned(&mh_owned.gate_write);
  (void)mh_close_owned(&mh_owned.main_pidfd);
  (void)mh_close_owned(&mh_owned.pidfd);
  (void)mh_close_owned(&mh_owned.out_read);
  (void)mh_close_owned(&mh_owned.err_read);
  mh_raw.phase=MH_FINISHED;mh_owned.slot=NULL;
  if(mh_raw.close_fault){errno=EIO;return -1;}
  return 0;
}
