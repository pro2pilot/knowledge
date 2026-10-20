/* Audit-only Darwin capability/escape probe. Never a product containment helper.
 * Each signal targets an unreaped child created by this process, using its own
 * TASK_AUDIT_TOKEN. No process-group/global signal or daemon operation exists.
 */
#if !defined(__APPLE__) || !defined(__MACH__)
#error This probe requires native Darwin.
#endif
#define _DARWIN_C_SOURCE 1
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <bsm/audit.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sandbox.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef AU_ASSIGN_ASID
#define AU_ASSIGN_ASID ((au_asid_t)-1)
#endif
#ifndef AU_IPv4
#define AU_IPv4 4
#endif
/* Apple bsm/audit.h hides these prototypes behind __APPLE_API_PRIVATE. */
extern mach_port_name_t audit_session_self(void);
extern au_asid_t audit_session_join(mach_port_name_t port);
extern int audit_session_port(au_asid_t asid, mach_port_name_t *portname);
typedef int (*signal_token_fn)(audit_token_t *, int);
static signal_token_fn signal_token;
static const char *profile =
  "(version 1)\n(allow default)\n(deny system-audit)\n(deny mach-lookup)\n";
static unsigned failures;

struct frame {
  uint32_t magic;
  pid_t pid;
  uid_t ruid, euid;
  int audit_rc, audit_errno, token_rc;
  auditinfo_addr_t aia;
  audit_token_t token;
  struct proc_bsdinfo bsd;
  int bsd_bytes;
  int mutate_rc, mutate_errno;
  au_asid_t after_asid;
};

static void result(const char *name, int observed, const char *meaning) {
  printf("{\"probe\":\"%s\",\"observed\":%d,\"meaning\":\"%s\"}\n", name, observed, meaning);
  fflush(stdout);
}
static int exact_io(int fd, void *buf, size_t n, int writing) {
  size_t done=0;
  while(done<n) {
    ssize_t r=writing?write(fd,(char *)buf+done,n-done):read(fd,(char *)buf+done,n-done);
    if(r<0 && errno==EINTR) continue;
    if(r<=0) return -1;
    done+=(size_t)r;
  }
  return 0;
}
static int current_aia(auditinfo_addr_t *aia) {
  memset(aia,0,sizeof(*aia));
  return getaudit_addr(aia,sizeof(*aia));
}
static int allocate_asid(auditinfo_addr_t *aia) {
  if(current_aia(aia)) return -1;
  aia->ai_asid=AU_ASSIGN_ASID;
  aia->ai_auid=getuid();
  aia->ai_flags=0;
  memset(&aia->ai_termid,0,sizeof(aia->ai_termid));
  aia->ai_termid.at_type=AU_IPv4;
  if(setaudit_addr(aia,sizeof(*aia))) return -1;
  return current_aia(aia);
}
static int lookup_asid(au_asid_t asid, int *saved_errno) {
  auditinfo_addr_t aia;
  memset(&aia,0,sizeof(aia)); aia.ai_asid=asid;
  errno=0;
  int rc=auditon(A_GETSINFO_ADDR,&aia,sizeof(aia));
  *saved_errno=errno;
  return rc;
}
static void fill_frame(struct frame *f) {
  memset(f,0,sizeof(*f)); f->magic=0x4b415349;
  f->pid=getpid(); f->ruid=getuid(); f->euid=geteuid();
  errno=0; f->audit_rc=current_aia(&f->aia); f->audit_errno=errno;
  mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
  f->token_rc=task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)&f->token,&count);
  f->bsd_bytes=proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&f->bsd,sizeof(f->bsd));
  f->after_asid=f->aia.ai_asid;
}
static int apply_profile(void) {
  char *error=NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  int rc=sandbox_init(profile,0,&error);
#pragma clang diagnostic pop
  if(error) { /* Do not trust profile diagnostics as JSON or shell input. */
    fprintf(stderr,"sandbox profile compilation/application: %s\n",error);
    sandbox_free_error(error);
  }
  return rc;
}
static int await_child(pid_t p, int *status) {
  for(;;) {pid_t got=waitpid(p,status,0); if(got==p)return 0; if(got<0&&errno==EINTR)continue;return -1;}
}
static void child_alarm(void) { alarm(20); }

/* Executed image reports through an intentionally inherited owned pipe. */
static int leaf(int fd, int suid_probe) {
  child_alarm();
  struct frame f;
  fill_frame(&f);
  if(suid_probe) {
    auditinfo_addr_t fresh;
    errno=0; f.mutate_rc=allocate_asid(&fresh); f.mutate_errno=errno;
    if(!f.mutate_rc) f.after_asid=fresh.ai_asid;
  }
  if(exact_io(fd,&f,sizeof(f),1)) return 91;
  close(fd);
  if(suid_probe) return 0;
  for(;;) pause();
}

static int inheritance_case(const char *self, au_asid_t original, int asid_write_fd) {
  child_alarm();
  auditinfo_addr_t new_aia;
  errno=0; int rc=allocate_asid(&new_aia), saved=errno;
  printf("{\"probe\":\"root_allocate_asid\",\"rc\":%d,\"errno\":%d,\"asid\":%u,\"original_asid\":%u}\n",rc,saved,(unsigned)new_aia.ai_asid,(unsigned)original);fflush(stdout);
  if(rc || new_aia.ai_asid==original) return 10;
  if(exact_io(asid_write_fd,&new_aia.ai_asid,sizeof(new_aia.ai_asid),1))return 11;
  close(asid_write_fd);
  int lookup_errno=0;
  result("new_asid_positive_lookup",lookup_asid(new_aia.ai_asid,&lookup_errno)==0,"must be a positive kernel session lookup before testing absence");
  int fds[2]; if(pipe(fds))return 12;
  pid_t child=fork();
  if(child<0)return 13;
  if(!child) {
    close(fds[0]);
    if(setsid()<0) _exit(14);
    char fdtext[24];snprintf(fdtext,sizeof(fdtext),"%d",fds[1]);
    execl(self,self,"--leaf",fdtext,(char *)NULL);_exit(15);
  }
  close(fds[1]);
  struct frame f; int read_rc=exact_io(fds[0],&f,sizeof(f),0);close(fds[0]);
  int status=0;
  if(read_rc || f.magic!=0x4b415349) {
    /* Direct child is still unreaped, so its PID cannot be reused. */
    kill(child,SIGKILL);await_child(child,&status);return 16;
  }
  int inherited=f.audit_rc==0 && f.aia.ai_asid==new_aia.ai_asid && f.token.val[6]==(uint32_t)new_aia.ai_asid;
  printf("{\"probe\":\"fork_exec_setsid_inheritance\",\"pid\":%d,\"asid\":%u,\"token_asid\":%u,\"token_pidversion\":%u,\"start_sec\":%llu,\"start_usec\":%llu,\"inherited\":%s}\n",f.pid,(unsigned)f.aia.ai_asid,f.token.val[6],f.token.val[7],(unsigned long long)f.bsd.pbi_start_tvsec,(unsigned long long)f.bsd.pbi_start_tvusec,inherited?"true":"false");fflush(stdout);
  if(!signal_token || f.token_rc!=KERN_SUCCESS) {
    kill(child,SIGKILL);await_child(child,&status);return 17;
  }
  audit_token_t stale=f.token;stale.val[7]^=0x80000000u;
  int stale_rc=signal_token(&stale,SIGKILL);
  int still_live=waitpid(child,&status,WNOHANG)==0;
  printf("{\"probe\":\"stale_audit_token_signal\",\"result_errno\":%d,\"owned_child_alive\":%s}\n",stale_rc,still_live?"true":"false");fflush(stdout);
  if(!still_live)return 18;
  int live_rc=signal_token(&f.token,SIGKILL);
  result("exact_audit_token_sigkill_errno",live_rc,"zero required; no raw-PID fallback accepted for the capability claim");
  if(live_rc)kill(child,SIGKILL); /* owned unreaped-child emergency teardown only */
  await_child(child,&status);
  result("exact_audit_token_sigkill_observed",WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL,"physical waitpid observation of owned leaf");
  return inherited && stale_rc==ESRCH && live_rc==0?0:19;
}

static int join_escape_case(au_asid_t foreign, uid_t unpriv_uid, int sandboxed) {
  child_alarm();
  auditinfo_addr_t own;
  if(allocate_asid(&own))return 30;
  mach_port_name_t old_right=MACH_PORT_NULL,own_right=MACH_PORT_NULL;
  if(audit_session_port(foreign,&old_right) || audit_session_port(own.ai_asid,&own_right))return 31;
  if(sandboxed && apply_profile())return 32;
  if(setgroups(0,NULL) || setgid((gid_t)unpriv_uid) || setuid(unpriv_uid))return 33;
  mach_port_name_t extra=MACH_PORT_NULL;
  errno=0;int foreign_rc=audit_session_port(foreign,&extra), foreign_errno=errno;
  if(extra!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),extra);
  errno=0;au_asid_t joined=audit_session_join(old_right);int join_errno=errno;
  /* This is a vulnerability observation: success is never called secure PASS. */
  printf("{\"probe\":\"foreign_session_right_escape\",\"sandboxed\":%s,\"ruid\":%u,\"euid\":%u,\"foreign_port_rc\":%d,\"foreign_port_errno\":%d,\"join_return_asid\":%u,\"join_errno\":%d,\"foreign_asid\":%u,\"escape_observed\":%s}\n",sandboxed?"true":"false",getuid(),geteuid(),foreign_rc,foreign_errno,(unsigned)joined,join_errno,(unsigned)foreign,joined==foreign?"true":"false");fflush(stdout);
  au_asid_t restored=audit_session_join(own_right);
  result(sandboxed?"sandbox_restore_own_asid":"baseline_restore_own_asid",restored==own.ai_asid,"test-owned process restores before exit; not a production admission mechanism");
  mach_port_deallocate(mach_task_self(),old_right);mach_port_deallocate(mach_task_self(),own_right);
  return 0;
}

static int suid_case(const char *fixture,uid_t unpriv_uid,int sandboxed) {
  int fds[2];if(pipe(fds))return 40;
  pid_t child=fork();if(child<0)return 41;
  if(!child) {
    child_alarm();close(fds[0]);
    auditinfo_addr_t new_aia;if(allocate_asid(&new_aia))_exit(42);
    if(sandboxed && apply_profile())_exit(43);
    if(setgroups(0,NULL)||setgid((gid_t)unpriv_uid)||setuid(unpriv_uid))_exit(44);
    char fdtext[24];snprintf(fdtext,sizeof(fdtext),"%d",fds[1]);
    execl(fixture,fixture,"--suid-leaf",fdtext,(char *)NULL);_exit(45);
  }
  close(fds[1]);struct frame f;int rr=exact_io(fds[0],&f,sizeof(f),0);close(fds[0]);
  int status=0;await_child(child,&status);
  if(rr || f.magic!=0x4b415349) {
    printf("{\"probe\":\"suid_exec\",\"sandboxed\":%s,\"frame_received\":false,\"wait_status\":%d}\n",sandboxed?"true":"false",status);fflush(stdout);return 0;
  }
  printf("{\"probe\":\"suid_exec\",\"sandboxed\":%s,\"frame_received\":true,\"pid\":%d,\"ruid\":%u,\"euid\":%u,\"getaudit_rc\":%d,\"getaudit_errno\":%d,\"token_asid\":%u,\"before_asid\":%u,\"after_asid\":%u,\"setaudit_rc\":%d,\"setaudit_errno\":%d,\"credential_escape_observed\":%s,\"audit_escape_observed\":%s}\n",sandboxed?"true":"false",f.pid,f.ruid,f.euid,f.audit_rc,f.audit_errno,f.token.val[6],(unsigned)f.aia.ai_asid,(unsigned)f.after_asid,f.mutate_rc,f.mutate_errno,f.euid==0?"true":"false",!f.mutate_rc&&f.after_asid!=f.aia.ai_asid?"true":"false");fflush(stdout);
  return 0;
}

int main(int argc,char **argv) {
  setvbuf(stdout,NULL,_IONBF,0);alarm(120);
  if(argc==3 && !strcmp(argv[1],"--leaf"))return leaf(atoi(argv[2]),0);
  if(argc==3 && !strcmp(argv[1],"--suid-leaf"))return leaf(atoi(argv[2]),1);
  if(argc!=4 || strcmp(argv[1],"--probe")) {fprintf(stderr,"usage: %s --probe ABSOLUTE_ROOT_OWNED_SUID_FIXTURE UNPRIVILEGED_UID\n",argv[0]);return 2;}
  char *end=NULL;unsigned long parsed=strtoul(argv[3],&end,10);
  if(!end||*end||parsed<500||parsed>2000000000ul)return 2;
  uid_t unpriv_uid=(uid_t)parsed;
  struct utsname u;uname(&u);
  char boot[128]={0};size_t boot_len=sizeof(boot);errno=0;
  int boot_rc=sysctlbyname("kern.bootsessionuuid",boot,&boot_len,NULL,0),boot_errno=errno;
  boot[sizeof(boot)-1]='\0';
  /* UUID alphabet only; never print a kernel-controlled string as JSON. */
  int valid_boot=boot_rc==0&&boot_len>=36&&strspn(boot,"0123456789abcdefABCDEF-")==36;
  printf("{\"probe\":\"host\",\"darwin_release\":\"%s\",\"architecture\":\"%s\",\"ruid\":%u,\"euid\":%u,\"boot_identity_available\":%s,\"boot_errno\":%d,\"auditinfo_size\":%zu,\"audit_token_size\":%zu}\n",u.release,u.machine,getuid(),geteuid(),valid_boot?"true":"false",boot_errno,sizeof(auditinfo_addr_t),sizeof(audit_token_t));
  void *sym=dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");memcpy(&signal_token,&sym,sizeof(signal_token));
  result("proc_signal_with_audittoken_symbol",signal_token!=NULL,"Apple libproc signature int(audit_token_t *, int); no PID fallback capability");
  if(geteuid()!=0) {result("backend_preflight",0,"root ASID capability unavailable; user workload must not start");return 0;}
  struct stat fixture_st;
  if(stat(argv[2],&fixture_st)||!S_ISREG(fixture_st.st_mode)||fixture_st.st_uid!=0||!(fixture_st.st_mode&S_ISUID)||(fixture_st.st_mode&0022)) {fprintf(stderr,"fixture must be root-owned setuid regular file, no group/world writes\n");return 3;}
  auditinfo_addr_t original;if(current_aia(&original))return 4;
  int err=0;result("original_asid_positive_lookup",lookup_asid(original.ai_asid,&err)==0,"controls A_GETSINFO_ADDR ABI and permission");
  int ids[2];if(pipe(ids))return 5;pid_t p=fork();if(p<0)return 6;
  if(!p){close(ids[0]);_exit(inheritance_case(argv[0],original.ai_asid,ids[1]));}
  close(ids[1]);au_asid_t tested_asid=AU_ASSIGN_ASID;int got_asid=exact_io(ids[0],&tested_asid,sizeof(tested_asid),0)==0;close(ids[0]);
  int status=0;await_child(p,&status);if(!WIFEXITED(status)||WEXITSTATUS(status))failures++;
  result("original_asid_positive_lookup_after_exit",lookup_asid(original.ai_asid,&err)==0,"positive canary again before interpreting target absence");
  int target_errno=0;int target_rc=got_asid?lookup_asid(tested_asid,&target_errno):-2;
  printf("{\"probe\":\"owned_session_after_all_owners_exit\",\"asid_received\":%s,\"asid\":%u,\"lookup_rc\":%d,\"errno\":%d,\"note\":\"absence candidate only; not product cleanup proof\"}\n",got_asid?"true":"false",(unsigned)tested_asid,target_rc,target_errno);
  for(int sandboxed=0;sandboxed<=1;sandboxed++) {
    p=fork();if(p<0)return 7;
    if(!p)_exit(join_escape_case(original.ai_asid,unpriv_uid,sandboxed));
    await_child(p,&status);
    printf("{\"probe\":\"join_case_runner\",\"sandboxed\":%s,\"wait_status\":%d}\n",sandboxed?"true":"false",status);
    if(!WIFEXITED(status)||WEXITSTATUS(status))failures++;
    if(suid_case(argv[2],unpriv_uid,sandboxed))failures++;
  }
  printf("{\"probe\":\"probe_transport_summary\",\"infrastructure_failures\":%u,\"product_backend_certified\":false,\"note\":\"zero infrastructure failures does not mean escape prevention\"}\n",failures);
  return failures?1:0;
}
