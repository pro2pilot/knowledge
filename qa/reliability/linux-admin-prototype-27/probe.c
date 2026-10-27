/* QA ONLY: fixed operations, no arbitrary executable/argv or user-supplied profile. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef PROBE_PROFILE
#error Compile with a unique fixed PROBE_PROFILE and PROBE_EXECUTABLE
#endif
#ifndef PROBE_EXECUTABLE
#error Missing fixed executable
#endif
#define WORKER_PROFILE PROBE_PROFILE "//worker"
#define WORKER_STACK PROBE_PROFILE "//&" WORKER_PROFILE
#define WORKER_STACK_REVERSE WORKER_PROFILE "//&" PROBE_PROFILE
#define STACK_BYTES (1024 * 1024)
struct event { int kind, value; };
struct child_args { int gate[2], events[2], parentfd, depth; uid_t uid; gid_t gid; };
static int created, closed;
static volatile uint64_t guarded_word = UINT64_C(0x4936527027413251);
#define REQUIRED_SECUREBITS (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED)
static int qa_ids(void) {
  uid_t r,e,s;gid_t gr,ge,gs;
  return !getresuid(&r,&e,&s) && !getresgid(&gr,&ge,&gs) &&
    r==1001 && e==1001 && s==1001 && gr==1001 && ge==1001 && gs==1001;
}
static int exact_write(int fd, const void *data, size_t count) {
  const char *p = data;
  while (count) { ssize_t n = write(fd, p, count); if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1; p += n; count -= (size_t)n; }
  return 0;
}
static int exact_read(int fd, void *data, size_t count) {
  char *p = data;
  while (count) { ssize_t n = read(fd, p, count); if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return -1; p += n; count -= (size_t)n; }
  return 0;
}
static int profile_is(const char *expected) {
  char text[256]; int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0; ssize_t n = read(fd, text, sizeof(text)-1); close(fd);
  if (n < 1) return 0; text[n] = 0;
  char wanted[256]; snprintf(wanted, sizeof(wanted), "%s (enforce)", expected);
  text[strcspn(text, "\r\n")] = 0; return !strcmp(text, wanted);
}
static const char *worker_label(void) {
  /* Exact known components only. Authority-only or an unknown extra component
     never counts as a worker. Preserve the actual known order in evidence. */
  if (profile_is(WORKER_STACK)) return WORKER_STACK;
  if (profile_is(WORKER_STACK_REVERSE)) return WORKER_STACK_REVERSE;
  return NULL;
}
static int zero_caps(void) {
  struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct d[2]; memset(d, 0, sizeof(d));
  if (syscall(SYS_capget, &h, d)) return 0;
  if (d[0].effective || d[0].permitted || d[0].inheritable || d[1].effective || d[1].permitted || d[1].inheritable) return 0;
  for (int i = 0; i <= 40; ++i) { int value = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0);
    if (value > 0 || (value < 0 && errno != EINVAL)) return 0; }
  return 1;
}
static int restrict_child(void) {
  struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
  struct __user_cap_data_struct d[2]; memset(d, 0, sizeof(d));
  /* Only called after the child user namespace is mapped; never capset on host. */
  return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
    prctl(PR_SET_SECUREBITS, REQUIRED_SECUREBITS, 0, 0, 0) ||
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) ||
    syscall(SYS_capset, &h, d) || prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) ||
    prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) != REQUIRED_SECUREBITS ||
    prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 1 ||
    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 || !zero_caps() ? -1 : 0;
}
/* Diagnostic refusal, not a defense against a tracer which can rewrite this
   check before it executes. Only kernel exec refusal qualifies that boundary. */
static int tracer_state(void) {
  char text[4096]; int fd=open("/proc/self/status",O_RDONLY|O_CLOEXEC);
  if(fd<0)return -1; ssize_t n=read(fd,text,sizeof(text)-1);close(fd);
  if(n<1)return -1;text[n]=0;char *line=strstr(text,"\nTracerPid:");
  if(!line)return -1;char *end;errno=0;long pid=strtol(line+11,&end,10);
  if(errno || end==line+11 || pid<0 || (*end!='\n' && *end!='\r'))return -1;
  return pid>0;
}
static int profile_command(const char *verb, const char *name) {
  char command[256]; int n = snprintf(command, sizeof(command), "%s %s", verb, name);
  if (n <= 0 || (size_t)n >= sizeof(command)) { errno = EINVAL; return -1; }
  int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC); if (fd < 0) return -1;
  int rc = exact_write(fd, command, (size_t)n), saved = errno; close(fd); errno = saved; return rc;
}
static int host_pid(void) {
  char text[32], *end; ssize_t n = readlink("/proc/self", text, sizeof(text)-1);
  if (n < 1) return -1; text[n] = 0; long value = strtol(text, &end, 10);
  return *end || value < 1 || value > 2147483647 ? -1 : (int)value;
}
static int map_one(int pid, const char *name, const char *value) {
  char file[96]; snprintf(file, sizeof(file), "/proc/%d/%s", pid, name);
  int fd = open(file, O_WRONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return -1;
  int rc = exact_write(fd, value, strlen(value)), saved = errno; close(fd); errno = saved; return rc;
}
static int pidfd_signal(int fd) { return (int)syscall(SYS_pidfd_send_signal, fd, SIGKILL, NULL, 0); }
static int wait_child(pid_t pid, int *status) { pid_t r; do { r = waitpid(pid, status, 0); } while (r < 0 && errno == EINTR); return r == pid; }
static int self_exec(const char *mode, int expected_exit, int must_worker) {
  int channel[2]; if (pipe2(channel, O_CLOEXEC)) return 0;
  pid_t child = fork(); if (child < 0) { close(channel[0]); close(channel[1]); return 0; }
  if (!child) { close(channel[0]); if (dup2(channel[1], STDOUT_FILENO) < 0) _exit(124); close(channel[1]);
    execl(PROBE_EXECUTABLE, PROBE_EXECUTABLE, mode, (char *)NULL); _exit(125); }
  close(channel[1]); char raw[512]; ssize_t n = read(channel[0], raw, sizeof(raw)-1); close(channel[0]);
  int status; if (!wait_child(child, &status) || !WIFEXITED(status) || WEXITSTATUS(status) != expected_exit || n < 1) return 0;
  raw[n] = 0; return !must_worker || strstr(raw, "\"worker_label\":true") != NULL;
}
static int worker_checks(void) {
  /* Explicit restrictive STACK, not replacement or fallback. Under NNP the
     original authority restrictions remain and the worker denies intersect. */
  if (profile_command("stack", WORKER_PROFILE) || !worker_label() || !zero_caps() || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0) != 1) {
    dprintf(1, "{\"event\":\"worker_transition\",\"ok\":false,\"errno\":%d}\n", errno); return 0; }
  pid_t child = fork(); int userns_denied = 0;
  if (!child) { errno = 0; int rc = unshare(CLONE_NEWUSER); _exit(rc < 0 && (errno == EACCES || errno == EPERM) ? 0 : 1); }
  if (child > 0) { int status; userns_denied = wait_child(child,&status) && WIFEXITED(status) && WEXITSTATUS(status)==0; }
  errno = 0; int change = profile_command("changeprofile", PROBE_PROFILE), change_errno = errno;
  int change_denied = change < 0 && (change_errno == EACCES || change_errno == EPERM) && worker_label();
  int identity = self_exec("--identity", 0, 1);
  int direct_denied = self_exec("--suite", 77, 1);
  int ok = userns_denied && change_denied && identity && direct_denied && zero_caps();
  dprintf(1,"{\"event\":\"worker_negatives\",\"ok\":%s,\"worker_label_exact\":\"%s\",\"new_userns_denied\":%s,\"change_back_denied\":%s,\"helper_identity_preserves_worker\":%s,\"direct_authority_refused\":%s}\n",
    ok?"true":"false",worker_label()?worker_label():"unrecognized",userns_denied?"true":"false",change_denied?"true":"false",identity?"true":"false",direct_denied?"true":"false");
  return ok;
}
static int run_chain(int depth);
static int namespace_init(void *pointer) {
  struct child_args *a = pointer; close(a->gate[1]); close(a->events[0]);
  if (prctl(PR_SET_PDEATHSIG,SIGKILL) || getpid()!=1) return 123;
  struct pollfd parent = {a->parentfd,POLLIN,0}; if (poll(&parent,1,0) != 0) return 123; close(a->parentfd);
  struct event born = {1,host_pid()}; if (born.value < 1 || exact_write(a->events[1],&born,sizeof(born))) return 123;
  char gate; if (exact_read(a->gate[0],&gate,1) || gate!='M') return 123; close(a->gate[0]);
  pid_t child = fork(); if (child < 0) return 123;
  if (!child) {
    if (restrict_child() || !qa_ids() || getuid()!=a->uid || getgid()!=a->gid || !profile_is(PROBE_PROFILE)) {
      dprintf(1,"{\"event\":\"post_map_setup_failed\",\"depth\":%d,\"errno\":%d}\n",a->depth,errno);_exit(122);
    }
    dprintf(1,"{\"event\":\"authority_depth\",\"depth\":%d,\"uid\":%u,\"caps_zero\":true,\"nnp\":1,\"securebits\":%d,\"dumpable\":1}\n",a->depth,(unsigned)getuid(),REQUIRED_SECUREBITS);
    int ok = a->depth > 1 ? run_chain(a->depth-1) : worker_checks();
    struct event done = {2,ok}; if (exact_write(a->events[1],&done,sizeof(done))) _exit(121);
    for (;;) pause();
  }
  for (;;) { int status; pid_t reaped=waitpid(-1,&status,0);
    if(reaped==child) { struct event failed={2,0};(void)exact_write(a->events[1],&failed,sizeof(failed)); }
    if(reaped<0 && errno!=EINTR)pause();
  }
}
static int run_chain(int depth) {
  struct child_args a; memset(&a,0,sizeof(a)); a.depth=depth; a.uid=getuid(); a.gid=getgid();
  a.parentfd=(int)syscall(SYS_pidfd_open,getpid(),0);
  if (a.parentfd < 0 || pipe2(a.gate,O_CLOEXEC) || pipe2(a.events,O_CLOEXEC)) return 0;
  char *stack=malloc(STACK_BYTES); if (!stack) return 0;
  pid_t child=clone(namespace_init,stack+STACK_BYTES,CLONE_NEWUSER|CLONE_NEWPID|SIGCHLD,&a);
  if (child<0) { int e=errno; close(a.parentfd);close(a.gate[0]);close(a.gate[1]);close(a.events[0]);close(a.events[1]);free(stack);
    dprintf(1,"{\"event\":\"clone_failed\",\"depth\":%d,\"errno\":%d}\n",depth,e);return 0; }
  ++created; close(a.parentfd); close(a.gate[0]);close(a.events[1]);
  int pidfd=(int)syscall(SYS_pidfd_open,child,0), ok=0; struct event event;
  if (pidfd>=0 && !exact_read(a.events[0],&event,sizeof(event)) && event.kind==1) {
    char map[80]; snprintf(map,sizeof(map),"%u %u 1\n",(unsigned)a.uid,(unsigned)a.uid);
    const char *map_stage="uid_map";
    int maps=map_one(event.value,"uid_map",map);
    if (!maps) {map_stage="setgroups";maps=map_one(event.value,"setgroups","deny\n");}
    snprintf(map,sizeof(map),"%u %u 1\n",(unsigned)a.gid,(unsigned)a.gid);
    if (!maps) {map_stage="gid_map";maps=map_one(event.value,"gid_map",map);}
    if(maps)dprintf(1,"{\"event\":\"mapping_failed\",\"depth\":%d,\"stage\":\"%s\",\"errno\":%d}\n",depth,map_stage,errno);
    if (!maps && !exact_write(a.gate[1],"M",1) && !exact_read(a.events[0],&event,sizeof(event)) && event.kind==2) ok=event.value==1;
  }
  int stopped = pidfd>=0 && !pidfd_signal(pidfd), status=0, reaped=0;
  struct pollfd terminal={pidfd,POLLIN,0};
  if(pidfd>=0 && (stopped || poll(&terminal,1,0)>0))reaped=wait_child(child,&status);
  if(reaped)++closed;else ok=0;
  int killed_reaped=stopped&&reaped&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL;
  if(!killed_reaped)ok=0;
  dprintf(1,"{\"event\":\"scope_closure\",\"depth\":%d,\"init_pidfd_signalled_and_reaped\":%s,\"init_exit_reaped\":%s,\"checks_ok\":%s}\n",depth,killed_reaped?"true":"false",reaped?"true":"false",ok?"true":"false");
  if(pidfd>=0)close(pidfd);close(a.gate[1]);close(a.events[0]);free(stack);return ok;
}
int main(int argc,char **argv) {
  if(argc!=2)return 64;
  int traced=tracer_state();
  if(traced!=0) {
    dprintf(1,"{\"event\":\"pre_authority_tracer_refusal\",\"tracer_present\":%s,\"authority_entered\":false}\n",traced>0?"true":"false");
    return traced>0?79:78;
  }
  if(!strcmp(argv[1],"--loader-check")) {
    int ok=qa_ids() && zero_caps() && profile_is(PROBE_PROFILE);
    dprintf(1,"{\"event\":\"loader_check\",\"authority_label\":%s,\"caps_zero\":%s}\n",ok?"true":"false",zero_caps()?"true":"false");
    return ok?0:78;
  }
  if(!strcmp(argv[1],"--identity")) { const char *worker=worker_label(); dprintf(1,"{\"worker_label\":%s,\"worker_label_exact\":\"%s\",\"caps_zero\":%s}\n",worker?"true":"false",worker?worker:"unrecognized",zero_caps()?"true":"false"); return worker&&zero_caps()?0:78; }
  if(!strcmp(argv[1],"--suite") && worker_label()) {
    dprintf(1,"{\"worker_label\":true,\"authority_refused\":true}\n"); return 77;
  }
  if(strcmp(argv[1],"--suite") || !qa_ids() || !zero_caps() || !profile_is(PROBE_PROFILE)) return 78;
  alarm(25); /* Includes the paused same-UID parent-probe handshake. */
  /* A fixed paused target lets the same-UID unconfined Python parent attempt
     read/trace access. Its only accepted input is the exact GO line. */
  int secret[2];if(pipe2(secret,O_CLOEXEC)||exact_write(secret[1],"fixed-private-probe",19))return 80;
  dprintf(1,"{\"event\":\"parent_probe_ready\",\"pid\":%d,\"address\":\"%llu\",\"probe_fd\":%d,\"fixed_word\":\"%llu\"}\n",getpid(),(unsigned long long)(uintptr_t)&guarded_word,secret[0],(unsigned long long)guarded_word);
  char go[3];if(exact_read(0,go,3)||memcmp(go,"GO\n",3))return 81;close(secret[0]);close(secret[1]);
  if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 82;
  int ok=run_chain(3);
  dprintf(1,"{\"event\":\"result\",\"ok\":%s,\"native_cleanup_confirmed\":%s,\"local_scopes_created\":%d,\"local_scopes_closed\":%d,\"qualification\":false}\n",ok?"true":"false",created==closed?"true":"false",created,closed);
  return ok?0:1;
}
