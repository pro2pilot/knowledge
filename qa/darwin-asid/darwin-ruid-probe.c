/* Probe 2: dedicated RUID kernel membership. Includes probe 1 only for owned
 * leaf/SUID reporting utilities. This is audit code, never product authority. */
#define main asid_probe1_main
#include "darwin-asid-probe.c"
#undef main
#include <sys/event.h>
#include <sys/resource.h>
#include <mach/task_special_ports.h>
#include <pwd.h>
#include <time.h>

/* Apple XNU proc_info.h/private: PROC_PIDT_BSDINFOWITHUNIQID == 18.
 * Declare an isolated layout to avoid enabling SDK-wide PRIVATE declarations.
 * Kernel returns BSD info and birth/PID version in one proc reference. */
struct kk_uniqinfo {
  uint8_t executable_uuid[16];
  uint64_t uniqueid, parent_uniqueid;
  int32_t pidversion;
  uint32_t parent_or_reserved;
  uint64_t reserved2, reserved3;
};
struct kk_bsduniq {struct proc_bsdinfo bsd;struct kk_uniqinfo uniq;};
_Static_assert(sizeof(struct kk_uniqinfo)==56,"Apple unique identity ABI");

static long long monotonic_ms(void) {
  struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);
  return (long long)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
static void nap_ms(long ms) {
  struct timespec ts={ms/1000,(ms%1000)*1000000};
  while(nanosleep(&ts,&ts)<0&&errno==EINTR){}
}
static int uid_members(uid_t uid,pid_t *pids,size_t capacity,int *saved_errno) {
  errno=0;
  int bytes=proc_listpids(PROC_RUID_ONLY,uid,pids,(int)(capacity*sizeof(*pids)));
  *saved_errno=errno;
  if(bytes<0 || bytes%(int)sizeof(*pids))return -1;
  return bytes/(int)sizeof(*pids);
}
static int bsduniq(pid_t pid,struct kk_bsduniq *info) {
  memset(info,0,sizeof(*info));errno=0;
  return proc_pidinfo(pid,18,0,info,sizeof(*info))==(int)sizeof(*info)?0:-1;
}
static int token_for_uid(pid_t pid,uid_t expected,audit_token_t *token) {
  struct kk_bsduniq info;
  if(bsduniq(pid,&info)||info.bsd.pbi_pid!=(uint32_t)pid||info.bsd.pbi_ruid!=expected)return -1;
  memset(token,0,sizeof(*token));
  token->val[5]=(uint32_t)pid;token->val[7]=(uint32_t)info.uniq.pidversion;
  return 0;
}
static uid_t fresh_uid(void) {
  pid_t pids[8];int error;
  for(unsigned n=0;n<100;n++) {
    uid_t uid=(uid_t)(1000000000u+arc4random_uniform(900000000u));
    if(getpwuid(uid)!=NULL)continue;
    if(uid_members(uid,pids,8,&error)==0)return uid;
  }
  return 0;
}

static int credential_profiles(uid_t private_uid,uid_t original_uid,const char *fixture) {
  if(private_uid<1000000000u||original_uid==0||original_uid==private_uid)return 90;
  char dir[4096],file[4096];
  const char *slash=strrchr(fixture,'/');if(!slash)return 91;
  size_t prefix=(size_t)(slash-fixture);
  if(prefix+40>=sizeof(dir))return 92;
  memcpy(dir,fixture,prefix);dir[prefix]='\0';
  strcat(dir,"/credential-access.XXXXXX");if(!mkdtemp(dir))return 93;
  if(snprintf(file,sizeof(file),"%s/owner-file",dir)>=(int)sizeof(file))return 94;
  int fd=open(file,O_CREAT|O_EXCL|O_WRONLY,0600);if(fd<0)return 95;
  if(write(fd,"OWNED-ACCESS-FIXTURE\n",21)!=21){close(fd);return 96;}close(fd);
  if(chown(file,original_uid,(gid_t)-1)||chown(dir,original_uid,(gid_t)-1))return 97;
  for(int mode=0;mode<2;mode++) {
    if(chmod(dir,mode?0755:0700))return 98;
    pid_t child=fork();if(child<0)return 99;
    if(!child) {
      alarm(10);
      if(setgroups(0,NULL)||setgid(private_uid)||setuid(private_uid))_exit(100);
      errno=0;int rfd=open(file,O_RDONLY),read_errno=errno;if(rfd>=0)close(rfd);
      errno=0;int wfd=open(file,O_WRONLY),write_errno=errno;if(wfd>=0)close(wfd);
      printf("{\"probe\":\"private_uid_repository_access_model\",\"owner_directory_mode\":\"%s\",\"private_ruid\":%u,\"private_euid\":%u,\"owner_uid\":%u,\"read_allowed\":%s,\"read_errno\":%d,\"write_allowed\":%s,\"write_errno\":%d,\"fixture_only\":true}\n",mode?"0755":"0700",getuid(),geteuid(),original_uid,rfd>=0?"true":"false",read_errno,wfd>=0?"true":"false",write_errno);fflush(stdout);
      _exit(rfd<0&&wfd<0?0:101);
    }
    int status;await_child(child,&status);if(!WIFEXITED(status)||WEXITSTATUS(status))return 102;
  }
  pid_t child=fork();if(child<0)return 103;
  if(!child) {
    alarm(10);
    if(apply_profile())_exit(108);
    if(setgroups(0,NULL)||setgid(private_uid)||setreuid(private_uid,original_uid))_exit(104);
    uid_t before_ruid=getuid(),before_euid=geteuid();
    errno=0;int rfd=open(file,O_RDONLY),access_errno=errno;if(rfd>=0)close(rfd);
    errno=0;int rc=setreuid(original_uid,(uid_t)-1),migration_errno=errno;
    printf("{\"probe\":\"mixed_private_ruid_original_euid_escape\",\"sandboxed\":true,\"before_ruid\":%u,\"before_euid\":%u,\"owner_file_read_allowed\":%s,\"read_errno\":%d,\"setreuid_rc\":%d,\"setreuid_errno\":%d,\"after_ruid\":%u,\"after_euid\":%u,\"boundary_escape_observed\":%s}\n",before_ruid,before_euid,rfd>=0?"true":"false",access_errno,rc,migration_errno,getuid(),geteuid(),rc==0&&getuid()==original_uid?"true":"false");fflush(stdout);
    _exit(0); /* Negative design observation, never a secure-profile PASS. */
  }
  int status;await_child(child,&status);
  /* These exact paths were created above; no recursive/global deletion. */
  if(unlink(file)||rmdir(dir))return 105;
  return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:106;
}

/* Root caller may only clean the new UID reserved by this exact probe. No
 * fixed account/nobody UID is accepted and no process outside it is signaled. */
static int cleanup_reserved_uid(uid_t uid) {
  if(uid<1000000000u||uid>=1900000000u||!signal_token)return 50;
  pid_t pids[4096];int err=0,total_signals=0,passes=0;
  long long deadline=monotonic_ms()+20000;
  while(monotonic_ms()<deadline) {
    int count=uid_members(uid,pids,4096,&err);passes++;
    if(count<0)return 51;
    if(count==0) {
      printf("{\"probe\":\"kernel_ruid_zero_membership\",\"uid\":%u,\"passes\":%d,\"signals_sent\":%d,\"zero_observed\":true,\"basis\":\"proc_listpids_RUID_filter_inside_kernel_list_lock\"}\n",uid,passes,total_signals);fflush(stdout);
      return 0;
    }
    for(int i=0;i<count;i++) {
      audit_token_t token;
      if(token_for_uid(pids[i],uid,&token))continue;
      int rc=signal_token(&token,SIGKILL);
      if(rc==0)total_signals++;
      else if(rc!=ESRCH) {
        printf("{\"probe\":\"uid_signal_error\",\"uid\":%u,\"pid\":%d,\"errno\":%d}\n",uid,pids[i],rc);fflush(stdout);
        return 52;
      }
    }
    nap_ms(10);
  }
  int count=uid_members(uid,pids,4096,&err);
  printf("{\"probe\":\"kernel_ruid_zero_membership\",\"uid\":%u,\"passes\":%d,\"signals_sent\":%d,\"zero_observed\":false,\"remaining\":%d,\"errno\":%d}\n",uid,passes,total_signals,count,err);fflush(stdout);
  return 53;
}

static int uid_worker(int fd,uid_t uid,const char *mode,mach_port_name_t scrubbed_right,au_asid_t foreign) {
  alarm(30);
  errno=0;int r1=setuid(0),e1=errno;
  errno=0;int r2=seteuid(0),e2=errno;
  errno=0;int r3=setreuid(0,0),e3=errno;
  gid_t g=0;errno=0;int r4=setgroups(1,&g),e4=errno;
  errno=0;au_asid_t joined=audit_session_join(scrubbed_right);int ej=errno;
  printf("{\"probe\":\"sanitized_unprivileged_worker\",\"mode\":\"%s\",\"pid\":%d,\"ruid\":%u,\"euid\":%u,\"uid\":%u,\"setuid_rc\":%d,\"setuid_errno\":%d,\"seteuid_rc\":%d,\"seteuid_errno\":%d,\"setreuid_rc\":%d,\"setreuid_errno\":%d,\"setgroups_rc\":%d,\"setgroups_errno\":%d,\"join_scrubbed_right_errno\":%d,\"join_scrubbed_right_escaped\":%s}\n",mode,getpid(),getuid(),geteuid(),uid,r1,e1,r2,e2,r3,e3,r4,e4,ej,joined==foreign?"true":"false");fflush(stdout);
  struct frame f;fill_frame(&f);
  if(exact_io(fd,&f,sizeof(f),1))return 60;
  if(getuid()!=uid||geteuid()!=uid||r1==0||r2==0||r3==0||r4==0)return 61;
  if(!strcmp(mode,"orphan")) {
    pid_t first=fork();if(first<0)return 62;
    if(!first) {
      pid_t second=fork();if(second<0)_exit(63);
      if(second)_exit(0);
      if(setsid()<0)_exit(64);
      fill_frame(&f);
      if(exact_io(fd,&f,sizeof(f),1))_exit(65);
      close(fd);for(;;)pause();
    }
    int status=0;await_child(first,&status);close(fd);
    return 0; /* real guardian loss; detached second child remains */
  }
  if(strcmp(mode,"fork_race"))return 66;
  close(fd);
  /* A bounded fork race, maximum one new child per 10ms. RLIMIT_NPROC bounds
   * concurrent processes; each child owns a short alarm and exits. */
  for(;;) {
    pid_t p=fork();
    if(!p){alarm(3);if(setsid()<0){}for(;;)pause();}
    while(waitpid(-1,NULL,WNOHANG)>0){}
    nap_ms(10);
  }
}

static int launch_owned_worker(const char *self,uid_t uid,const char *mode,int report_fd,au_asid_t foreign) {
  alarm(30);
  struct rlimit limit={64,64};if(setrlimit(RLIMIT_NPROC,&limit))return 70;
  mach_port_name_t old=MACH_PORT_NULL;
  if(audit_session_port(foreign,&old))return 71;
  /* Demonstrate actual removal before exec, rather than trusting deny
   * system-audit to revoke a previously possessed session capability. */
  if(mach_port_deallocate(mach_task_self(),old)!=KERN_SUCCESS)return 72;
  if(task_set_special_port(mach_task_self(),TASK_BOOTSTRAP_PORT,MACH_PORT_NULL)!=KERN_SUCCESS)return 73;
  if(apply_profile())return 74;
  if(setgroups(0,NULL)||setgid(uid)||setuid(uid))return 75;
  char fdtext[24],uidtext[24],porttext[24],asidtext[24];
  snprintf(fdtext,sizeof(fdtext),"%d",report_fd);snprintf(uidtext,sizeof(uidtext),"%u",uid);
  snprintf(porttext,sizeof(porttext),"%u",old);snprintf(asidtext,sizeof(asidtext),"%u",foreign);
  execl(self,self,"--uid-worker",fdtext,uidtext,mode,porttext,asidtext,(char *)NULL);
  return 76;
}

static int scenario(const char *self,uid_t uid,const char *mode,au_asid_t foreign) {
  int fds[2];if(pipe(fds))return 80;
  pid_t guardian=fork();if(guardian<0)return 81;
  if(!guardian){close(fds[0]);_exit(launch_owned_worker(self,uid,mode,fds[1],foreign));}
  close(fds[1]);struct frame worker,detached;int status=0;
  int rr=exact_io(fds[0],&worker,sizeof(worker),0);
  if(rr||worker.magic!=0x4b415349){close(fds[0]);await_child(guardian,&status);return 82;}
  if(!strcmp(mode,"orphan")) {
    rr=exact_io(fds[0],&detached,sizeof(detached),0);close(fds[0]);await_child(guardian,&status);
    printf("{\"probe\":\"guardian_lost_before_recoverer\",\"uid\":%u,\"guardian_reaped\":true,\"guardian_status\":%d,\"detached_frame\":%s,\"detached_pid\":%d}\n",uid,status,!rr&&detached.magic==0x4b415349?"true":"false",rr?-1:detached.pid);fflush(stdout);
    if(rr)return 83;
  } else {close(fds[0]);nap_ms(350);}
  /* Fresh native recoverer receives UID only: no descendant PID/PPID ledger. */
  pid_t recoverer=fork();if(recoverer<0)return 84;
  if(!recoverer){alarm(25);_exit(cleanup_reserved_uid(uid));}
  /* RUID enumeration includes zombies. Reap our guardian while recovery runs;
   * awaiting the recoverer first would manufacture an unreaped-owned zombie. */
  if(strcmp(mode,"orphan"))await_child(guardian,&status);
  await_child(recoverer,&status);
  int recovery_ok=WIFEXITED(status)&&WEXITSTATUS(status)==0;
  pid_t pids[8];int saved_errno;int after=uid_members(uid,pids,8,&saved_errno);
  printf("{\"probe\":\"uid_scenario_result\",\"mode\":\"%s\",\"uid\":%u,\"recoverer_success\":%s,\"post_cleanup_members\":%d,\"errno\":%d}\n",mode,uid,recovery_ok?"true":"false",after,saved_errno);fflush(stdout);
  if(!recovery_ok||after!=0){cleanup_reserved_uid(uid);return 85;}
  return 0;
}

int main(int argc,char **argv) {
  if(argc==7&&!strcmp(argv[1],"--uid-worker"))return uid_worker(atoi(argv[2]),(uid_t)strtoul(argv[3],NULL,10),argv[4],(mach_port_name_t)strtoul(argv[5],NULL,10),(au_asid_t)strtoul(argv[6],NULL,10));
  if(argc==3&&(!strcmp(argv[1],"--leaf")||!strcmp(argv[1],"--suid-leaf")))return asid_probe1_main(argc,argv);
  setvbuf(stdout,NULL,_IONBF,0);alarm(120);
  if(argc!=3||strcmp(argv[1],"--probe2")){fprintf(stderr,"usage: %s --probe2 ABSOLUTE_ROOT_OWNED_SUID_FIXTURE\n",argv[0]);return 2;}
  if(geteuid()!=0){result("root_ruid_preflight",0,"unavailable before workload");return 0;}
  struct stat fixture_st;
  if(stat(argv[2],&fixture_st)||!S_ISREG(fixture_st.st_mode)||fixture_st.st_uid!=0||!(fixture_st.st_mode&S_ISUID)||(fixture_st.st_mode&0022))return 7;
  void *sym=dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");memcpy(&signal_token,&sym,sizeof(signal_token));
  struct kk_bsduniq own;struct frame ownf;fill_frame(&ownf);
  int abi=bsduniq(getpid(),&own)==0&&own.uniq.pidversion==(int32_t)ownf.token.val[7]&&own.bsd.pbi_ruid==getuid();
  printf("{\"probe\":\"combined_bsd_unique_identity_abi\",\"valid\":%s,\"structure_size\":%zu,\"signal_symbol\":%s}\n",abi?"true":"false",sizeof(own),signal_token?"true":"false");
  if(!abi||!signal_token)return 3;
  pid_t canary[4096];int saved;int count=uid_members(getuid(),canary,4096,&saved);
  result("kernel_ruid_positive_canary",count>0,"nonnull buffer required; NULL only sizes all processes");
  if(count<=0)return 4;
  int kq=kqueue();struct kevent change,event;struct timespec zero={0,0};
  EV_SET(&change,ownf.token.val[6],-11,EV_ADD|EV_RECEIPT,0,0,NULL);errno=0;
  int n=kq<0?-1:kevent(kq,&change,1,&event,1,&zero);int ke=errno;if(kq>=0)close(kq);
  printf("{\"probe\":\"historical_EVFILT_SESSION_minus11\",\"return\":%d,\"errno\":%d,\"event_error\":%lld,\"note\":\"modern Apple event_private.h names this EVFILT_UNUSED_11\"}\n",n,ke,n>0?(long long)event.data:-1);
  uid_t u1=fresh_uid(),u2=fresh_uid();if(!u1||!u2||u1==u2)return 5;
  const char *invoker=getenv("SUDO_UID");char *uid_end=NULL;
  unsigned long original_uid=invoker?strtoul(invoker,&uid_end,10):0;
  int credential_rc=invoker&&uid_end&&!*uid_end&&original_uid>0&&original_uid<1000000000ul
    ?credential_profiles(fresh_uid(),(uid_t)original_uid,argv[2]):107;
  result("credential_profile_transport_code",credential_rc,"mixed original EUID profile is intentionally tested as insecure; no repo ACL changes");
  /* Sentinel is an owned direct child in the original root UID; it must survive
   * both cleanup loops and is torn down only after the observation. */
  pid_t sentinel=fork();if(sentinel<0)return 6;if(!sentinel){alarm(90);for(;;)pause();}
  struct kk_bsduniq sentinel_birth;int sentinel_bound=bsduniq(sentinel,&sentinel_birth)==0;
  int r1=scenario(argv[0],u1,"orphan",ownf.token.val[6]);
  int r2=scenario(argv[0],u2,"fork_race",ownf.token.val[6]);
  struct kk_bsduniq sentinel_after;
  int sentinel_alive=sentinel_bound&&bsduniq(sentinel,&sentinel_after)==0&&sentinel_after.uniq.uniqueid==sentinel_birth.uniq.uniqueid&&sentinel_after.uniq.pidversion==sentinel_birth.uniq.pidversion;
  result("unrelated_owned_sentinel_survived",sentinel_alive,"no outside-UID process may be signaled by recovery");
  kill(sentinel,SIGKILL);int st;await_child(sentinel,&st);
  /* Repeat SUID under the same inherited policy with a fresh task UID. */
  uid_t u3=fresh_uid();int suid_rc=u3?suid_case(argv[2],u3,1):1;
  printf("{\"probe\":\"ruid_probe_summary\",\"orphan_case_code\":%d,\"fork_race_case_code\":%d,\"suid_transport_code\":%d,\"sentinel_alive\":%s,\"product_backend_certified\":false}\n",r1,r2,suid_rc,sentinel_alive?"true":"false");
  return r1||r2||suid_rc||credential_rc||!sentinel_alive?1:0;
}
