/* Knowledge Linux PID-namespace keeper. No root service or host mount changes.
 * The only successful tree proof is the final exit of our exact namespace init.
 * This is descendant containment, not a filesystem/network security sandbox.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/securebits.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROTOCOL "knowledge-linux-namespace-helper.v1"
#define STACK_SIZE (1024 * 1024)
#define MAX_TEXT 16384
struct identity { int pid, proc_pid, ns_pid, depth; unsigned long long ticks, ns_dev, ns_ino, exe_dev, exe_ino, born_ms; char state; };
struct event { int kind, pid, value; };
struct child_args { int procfd, keeperfd, commands[2], events[2], gate[2], execerr[2], trusted_authority; char **command; };
static int procfd = -1;
static unsigned long long procdev, observer_dev, observer_ino, btime;
static long hz;
static int observer_depth;
static char boot_id[64];

static long long now_ms(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1; return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000; }
static int pidfd_open_local(int pid) { return (int)syscall(SYS_pidfd_open, pid, 0); }
static int pidfd_kill(int fd) { return (int)syscall(SYS_pidfd_send_signal, fd, SIGKILL, NULL, 0); }
static int exited_fd(int fd) { struct pollfd p = {fd, POLLIN, 0}; int r = poll(&p, 1, 0); return r > 0 && (p.revents & (POLLIN | POLLHUP)); }
static int write_all(int fd, const void *data, size_t length) { const char *p = data; while (length) { ssize_t n = write(fd, p, length); if (n < 0 && errno == EINTR) continue; if (n <= 0) return -1; p += n; length -= (size_t)n; } return 0; }
static int read_text_at(int dir, const char *name, char *out, size_t length) { int f = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (f < 0) return -1; ssize_t n; do { n = read(f, out, length - 1); } while (n < 0 && errno == EINTR); int saved = errno; close(f); errno = saved; if (n <= 0 || (size_t)n == length - 1) return -1; out[n] = 0; return 0; }
static int decimal(const char *s, unsigned long long *n) { if (!s || !*s || *s == '+' || *s == '-') return -1; char *end; errno = 0; *n = strtoull(s, &end, 10); return errno || *end ? -1 : 0; }
static int self_proc_pid(void) { char s[64]; ssize_t n = readlinkat(procfd, "self", s, sizeof(s) - 1); if (n <= 0) return -1; s[n] = 0; unsigned long long p; return decimal(s, &p) || p > INT_MAX ? -1 : (int)p; }
static int process_dir(int pid) { char name[32]; snprintf(name, sizeof(name), "%d", pid); return openat(procfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); }

/* dirfd anchors the task, including between birth validation and pidfd_open.
 * It must not be replaced by two path reads around a PID-based kill. */
static int identity_at(int dir, int proc_pid, struct identity *out) {
  char buf[MAX_TEXT], status[MAX_TEXT]; memset(out, 0, sizeof(*out)); out->proc_pid = proc_pid;
  if (read_text_at(dir, "stat", buf, sizeof(buf)) || read_text_at(dir, "status", status, sizeof(status))) return -1;
  char *tail = strrchr(buf, ')'); if (!tail || tail[1] != ' ') { errno = EINVAL; return -1; }
  char *save = NULL, *token = strtok_r(tail + 2, " ", &save); int field = 3;
  while (token) { if (field == 3) out->state = token[0]; if (field == 22 && decimal(token, &out->ticks)) return -1; if (field++ == 22) break; token = strtok_r(NULL, " ", &save); }
  if (field < 23 || !out->ticks) { errno = EINVAL; return -1; }
  char *p = strstr(status, "\nNSpid:"); if (!p) { errno = ENOTSUP; return -1; } p += 7;
  while (*p == ' ' || *p == '\t') ++p;
  while (*p >= '0' && *p <= '9') { char *end; long n = strtol(p, &end, 10); if (n <= 0 || n > INT_MAX || end == p) return -1; out->depth++; out->ns_pid = (int)n; if (out->depth == observer_depth) out->pid = (int)n; p = end; while (*p == ' ' || *p == '\t') ++p; }
  struct stat ns, exe;
  if (fstatat(dir, "ns/pid", &ns, 0)) {
    if (out->state != 'Z' && out->state != 'X') return -1;
  } else { out->ns_dev = (unsigned long long)ns.st_dev; out->ns_ino = (unsigned long long)ns.st_ino; }
  if (!fstatat(dir, "exe", &exe, 0)) { out->exe_dev = (unsigned long long)exe.st_dev; out->exe_ino = (unsigned long long)exe.st_ino; }
  out->born_ms = btime * 1000 + (out->ticks * 1000) / (unsigned long long)hz;
  return 0;
}
static int identity(int proc_pid, struct identity *out) { int d = process_dir(proc_pid); if (d < 0) return -1; int r = identity_at(d, proc_pid, out), saved = errno; close(d); errno = saved; return r; }
static int read_boot_time(void) {
  int fd = openat(procfd, "stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return -1;
  FILE *input = fdopen(fd, "r"); if (!input) { close(fd); return -1; }
  char line[1024]; int found = 0;
  /* /proc/stat grows with CPU count; a fixed whole-file buffer would reject
   * otherwise supported large hosts. Read bounded lines until btime. */
  while (fgets(line, sizeof(line), input)) if (!strncmp(line, "btime ", 6)) { found = sscanf(line + 6, "%llu", &btime) == 1; break; }
  fclose(input); if (!found) { errno = EINVAL; return -1; } return 0;
}
static int setup_observer(void) {
  procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); if (procfd < 0) return -1;
  struct statfs fs; struct stat st; if (fstatfs(procfd, &fs) || fs.f_type != PROC_SUPER_MAGIC || fstat(procfd, &st)) { errno = ENOTSUP; return -1; } procdev = (unsigned long long)st.st_dev;
  char buf[MAX_TEXT]; if (read_text_at(procfd, "sys/kernel/random/boot_id", boot_id, sizeof(boot_id))) return -1;
  boot_id[strcspn(boot_id, "\r\n")] = 0; if (strlen(boot_id) != 36) { errno = EINVAL; return -1; }
  if (read_boot_time()) return -1;
  hz = sysconf(_SC_CLK_TCK); if (hz <= 0) return -1;
  if (fstatat(procfd, "self/ns/pid", &st, 0)) return -1; observer_dev = (unsigned long long)st.st_dev; observer_ino = (unsigned long long)st.st_ino;
  /* NSpid count of the observer tells which column belongs to this caller. */
  int d = process_dir(self_proc_pid()); if (d < 0) return -1;
  if (read_text_at(d, "status", buf, sizeof(buf))) { close(d); return -1; } close(d);
  char *p = strstr(buf, "\nNSpid:"); if (!p) { errno = ENOTSUP; return -1; } p += 7;
  while (*p == ' ' || *p == '\t') ++p;
  while (*p >= '0' && *p <= '9') { char *end; (void)strtol(p, &end, 10); observer_depth++; p = end; while (*p == ' ' || *p == '\t') ++p; }
  struct identity self; if (!observer_depth || identity(self_proc_pid(), &self) || self.pid != getpid()) { errno = ENOTSUP; return -1; }
  return 0;
}
static void print_identity(int fd, const struct identity *i) {
  time_t sec = (time_t)(i->born_ms / 1000); struct tm t; char iso[40]; gmtime_r(&sec, &t); strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S", &t);
  dprintf(fd, "{\"pid\":%d,\"proc_pid\":%d,\"start_ticks\":\"%llu\",\"os_creation_time\":\"%s.%03lluZ\",\"namespace_pid\":%d,\"pid_namespace\":{\"dev\":\"%llu\",\"ino\":\"%llu\"},\"executable\":{\"dev\":\"%llu\",\"ino\":\"%llu\"}}", i->pid, i->proc_pid, i->ticks, iso, i->born_ms % 1000, i->ns_pid, i->ns_dev, i->ns_ino, i->exe_dev, i->exe_ino);
}
static void print_error(int fd, const char *code) { dprintf(fd, "{\"protocol\":\"%s\",\"status\":\"unconfirmed\",\"code\":\"%s\",\"errno\":%d}\n", PROTOCOL, code, errno); }
static int send_event(int fd, int kind, int pid, int value) { struct event e = {kind, pid, value}; return write_all(fd, &e, sizeof(e)); }
static int close_above_five(void) {
#ifdef SYS_close_range
  if (!syscall(SYS_close_range, 6U, ~0U, 0)) return 0;
  if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
  struct rlimit lim; if (getrlimit(RLIMIT_NOFILE, &lim) || lim.rlim_cur > 1048576) return -1;
  for (int fd = 6; (rlim_t)fd < lim.rlim_cur; fd++) close(fd); return 0;
}
static int restrict_worker(int trusted_authority) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED)) return -1;
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0}; struct __user_cap_data_struct data[2]; memset(data, 0, sizeof(data));
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
  /* Only the pinned authority may create a nested user namespace when its
   * parent UID is 0. Linux >=5.12 requires CAP_SETFCAP for that map. This is
   * namespaced authority, never a host capability or a command-worker grant. */
  unsigned int allowed = trusted_authority ? (1U << CAP_SETFCAP) : 0;
  data[0].permitted = data[0].effective = data[0].inheritable = allowed;
  if (syscall(SYS_capset, &header, data) || prctl(PR_SET_DUMPABLE, 1)) return -1;
  if (trusted_authority && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SETFCAP, 0, 0)) return -1;
  memset(data, 0, sizeof(data)); if (syscall(SYS_capget, &header, data)) return -1;
  if (data[0].permitted != allowed || data[0].effective != allowed || data[0].inheritable != allowed || data[1].permitted || data[1].effective || data[1].inheritable || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) { errno = EPERM; return -1; }
  return 0;
}
static void worker_stub(struct child_args *a) {
  close(a->gate[1]); close(a->execerr[0]);
  if (restrict_worker(a->trusted_authority)) { send_event(a->events[1], 'E', 0, errno); _exit(125); }
  int host_pid = self_proc_pid(); if (host_pid <= 0 || send_event(a->events[1], 'W', host_pid, getpid())) _exit(125);
  if (dup2(a->gate[0], 4) < 0 || dup2(a->execerr[1], 5) < 0 || fcntl(5, F_SETFD, FD_CLOEXEC) < 0 || close_above_five()) _exit(125);
  char c; ssize_t n; do { n = read(4, &c, 1); } while (n < 0 && errno == EINTR); close(4);
  if (n != 1 || c != 'P' || !a->command || !a->command[0]) _exit(125);
  execv(a->command[0], a->command); int saved = errno; (void)write_all(5, &saved, sizeof(saved)); _exit(126);
}
static int init_main(void *value) {
  struct child_args *a = value; close(a->commands[1]); close(a->events[0]); close(a->execerr[0]);
  /* Parent may die before prctl; inherited exact keeper pidfd closes that race.
   * getppid() would be zero here, so it is deliberately not used. */
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || exited_fd(a->keeperfd) || getpid() != 1) return 125;
  int host_pid = self_proc_pid(); if (host_pid <= 0 || send_event(a->events[1], 'H', host_pid, 1)) return 125;
  char c; if (read(a->commands[0], &c, 1) != 1 || c != 'M') return 125;
  /* Retain init capabilities; the worker irrevocably drops all of them. The
   * commoncap ptrace subset rule denies worker access to init's private FDs,
   * while the outside owner can still read native namespace identities. */
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || exited_fd(a->keeperfd) || prctl(PR_SET_DUMPABLE, 1) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 125;
  pid_t worker = fork(); if (worker < 0) { send_event(a->events[1], 'E', 0, errno); return 125; }
  if (!worker) worker_stub(a);
  close(a->gate[0]); close(a->execerr[1]); close(a->keeperfd); close(a->procfd);
  for (int fd = 0; fd <= 4; fd++) close(fd);
  if (send_event(a->events[1], 'R', 0, 0)) return 125;
  int permitted = 0;
  for (;;) {
    int status; pid_t reaped;
    while ((reaped = waitpid(-1, &status, WNOHANG)) > 0) if (reaped == worker && send_event(a->events[1], 'X', worker, status)) return 125;
    struct pollfd p = {a->commands[0], POLLIN, 0}; int r = poll(&p, 1, 100);
    if (r < 0 && errno == EINTR) continue; if (r < 0) return 125;
    if (r && (p.revents & (POLLIN | POLLHUP))) {
      if (read(a->commands[0], &c, 1) != 1) return 125;
      if (c != 'P' || permitted) return 125;
      permitted = 1; if (write_all(a->gate[1], &c, 1)) return 125; close(a->gate[1]);
    }
  }
}
static int write_map(int child, const char *part, const char *value) { int d = process_dir(child); if (d < 0) return -1; int fd = openat(d, part, O_WRONLY | O_CLOEXEC | O_NOFOLLOW); close(d); if (fd < 0) return -1; int r = write_all(fd, value, strlen(value)), saved = errno; close(fd); errno = saved; return r; }
static int parent_proc_pid(void) { char buf[MAX_TEXT]; int d = process_dir(self_proc_pid()); if (d < 0) return -1; int r = read_text_at(d, "status", buf, sizeof(buf)); close(d); if (r) return -1; char *p = strstr(buf, "\nPPid:"); return p ? atoi(p + 6) : -1; }

static int run_keeper(char **command, int lifetime, int probe, int trusted_authority) {
  int out = probe ? 1 : 4; pid_t controller = getppid();
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != controller || setup_observer()) { print_error(out, "namespace_observer_unavailable"); return 1; }
  struct identity keeper_identity, controller_identity;
  if (identity(self_proc_pid(), &keeper_identity) || identity(parent_proc_pid(), &controller_identity)) { print_error(out, "namespace_parent_identity_unavailable"); return 1; }
  struct child_args a; memset(&a, 0, sizeof(a)); a.procfd = procfd; a.command = command; a.trusted_authority = trusted_authority; a.keeperfd = pidfd_open_local(getpid());
  if (a.keeperfd < 0 || pipe2(a.commands, O_CLOEXEC) || pipe2(a.events, O_CLOEXEC) || pipe2(a.gate, O_CLOEXEC) || pipe2(a.execerr, O_CLOEXEC)) { print_error(out, "namespace_pipe_unavailable"); return 1; }
  char *stack = malloc(STACK_SIZE); if (!stack) return 1;
  pid_t init = clone(init_main, stack + STACK_SIZE, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, &a);
  if (init < 0) { print_error(out, "namespace_create_denied"); free(stack); return 1; }
  int initfd = pidfd_open_local(init); close(a.commands[0]); close(a.events[1]); close(a.gate[0]); close(a.gate[1]); close(a.execerr[1]); close(a.keeperfd);
  if (!probe) for (int fd = 0; fd <= 3; fd++) close(fd);
  if (initfd < 0) { (void)kill(init, SIGKILL); print_error(out, "namespace_pidfd_unavailable"); return 1; }
  int host_init = 0, host_worker = 0, ready = 0, emitted = 0, permitted = 0, closing = 0, started = 0, failed = 0;
  long long deadline = now_ms() + lifetime; char input[128]; size_t used = 0;
  struct identity init_identity, worker_identity;
  for (;;) {
    long long remaining = deadline - now_ms();
    if (remaining <= 0) { (void)pidfd_kill(initfd); print_error(out, "namespace_cleanup_timeout"); return 1; }
    if (exited_fd(initfd)) {
      int status; if (waitpid(init, &status, WNOHANG) != init) { print_error(out, "namespace_init_reap_unconfirmed"); return 1; }
      if (closing && !failed) { dprintf(out, "{\"protocol\":\"%s\",\"status\":\"closed\",\"active_processes\":0,\"init_exit_observed\":true,\"init_reaped\":true}\n", PROTOCOL); return 0; }
      print_error(out, "namespace_init_exited_unexpectedly"); return 1;
    }
    struct pollfd p[3] = {{a.events[0], POLLIN, 0}, {probe ? -1 : 4, POLLIN, 0}, {permitted && !started ? a.execerr[0] : -1, POLLIN, 0}};
    int delay = remaining < 100 ? (int)remaining : 100; int polled = poll(p, 3, delay);
    if (polled < 0 && errno == EINTR) continue;
    if (polled < 0) { failed = closing = 1; (void)pidfd_kill(initfd); continue; }
    if (p[0].revents & POLLIN) {
      struct event e; ssize_t n = read(a.events[0], &e, sizeof(e));
      if (n != sizeof(e)) { failed = closing = 1; (void)pidfd_kill(initfd); continue; }
      if (e.kind == 'H' && !host_init) {
        host_init = e.pid; char map[96]; snprintf(map, sizeof(map), "%u %u 1\n", getuid(), getuid());
        if (write_map(host_init, "uid_map", map) || write_map(host_init, "setgroups", "deny\n")) { print_error(out, "namespace_uid_mapping_failed"); failed = closing = 1; (void)pidfd_kill(initfd); continue; }
        snprintf(map, sizeof(map), "%u %u 1\n", getgid(), getgid());
        if (write_map(host_init, "gid_map", map) || write_all(a.commands[1], "M", 1)) { print_error(out, "namespace_gid_mapping_failed"); failed = closing = 1; (void)pidfd_kill(initfd); continue; }
      } else if (e.kind == 'R') ready = 1;
      else if (e.kind == 'W') host_worker = e.pid;
      else if (e.kind == 'X') { if (!closing) dprintf(out, "{\"protocol\":\"%s\",\"status\":\"worker_exit\",\"wait_status\":%d}\n", PROTOCOL, e.value); }
      else { if (e.kind == 'E') errno = e.value; print_error(out, "namespace_child_setup_failed"); failed = closing = 1; (void)pidfd_kill(initfd); }
    }
    if (ready && host_worker && !emitted && !closing) {
      if (identity(host_init, &init_identity) || identity(host_worker, &worker_identity) || init_identity.ns_pid != 1 || init_identity.pid != init || init_identity.ns_ino == observer_ino) { print_error(out, "namespace_birth_identity_failed"); failed = closing = 1; (void)pidfd_kill(initfd); continue; }
      emitted = 1;
      dprintf(out, "{\"protocol\":\"%s\",\"status\":\"ready\",\"boot_id\":\"%s\",\"procfs_dev\":\"%llu\",\"observer_pid_namespace\":{\"dev\":\"%llu\",\"ino\":\"%llu\"},\"procfs_mode\":\"inherited_ancestor_view\",\"capability_profile\":\"%s\",\"no_new_privileges\":true,\"identities\":{\"controller\":", PROTOCOL, boot_id, procdev, observer_dev, observer_ino, trusted_authority ? "authority_setfcap" : "worker_none");
      print_identity(out, &controller_identity); dprintf(out, ",\"keeper\":"); print_identity(out, &keeper_identity); dprintf(out, ",\"init\":"); print_identity(out, &init_identity); dprintf(out, ",\"worker\":"); print_identity(out, &worker_identity); dprintf(out, "}}\n");
      if (probe) { closing = 1; (void)pidfd_kill(initfd); }
    }
    if (p[2].revents & (POLLIN | POLLHUP)) {
      int exec_errno = 0; ssize_t n = read(a.execerr[0], &exec_errno, sizeof(exec_errno)); started = 1; close(a.execerr[0]);
      if (n == 0 && !closing) dprintf(out, "{\"protocol\":\"%s\",\"status\":\"started\"}\n", PROTOCOL);
      else if (!closing) { errno = exec_errno; print_error(out, "namespace_worker_exec_failed"); failed = closing = 1; (void)pidfd_kill(initfd); }
    }
    if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(4, input + used, sizeof(input) - 1 - used);
      if (n <= 0) { closing = 1; (void)pidfd_kill(initfd); continue; }
      used += (size_t)n; input[used] = 0; char *nl;
      while ((nl = strchr(input, '\n'))) {
        *nl = 0;
        if (!strcmp(input, "permit") && emitted && !permitted && !closing) { permitted = 1; if (write_all(a.commands[1], "P", 1)) { failed = closing = 1; (void)pidfd_kill(initfd); } }
        else if (!strncmp(input, "close ", 6)) { unsigned long long ms; if (decimal(input + 6, &ms) || ms > INT_MAX) failed = 1; else { long long end = now_ms() + (long long)ms; if (end < deadline) deadline = end; } closing = 1; (void)pidfd_kill(initfd); }
        else { failed = closing = 1; (void)pidfd_kill(initfd); }
        size_t consumed = (size_t)(nl - input) + 1; memmove(input, input + consumed, used - consumed); used -= consumed; input[used] = 0;
      }
      if (used == sizeof(input) - 1) { failed = closing = 1; (void)pidfd_kill(initfd); }
    }
  }
}

/* Read-only observe and exact-identity stop share this single PID-safe path.
 * Absence is evidence only about this old birth, never a generic tree proof.
 * JS recovery applies the persisted namespace-init lifecycle invariant. */
static int observe(int argc, char **argv, int stop) {
  if (argc != 13 || setup_observer()) { print_error(1, "native_observer_unavailable"); return 1; }
  unsigned long long values[10]; for (int i = 0; i < 10; i++) if (decimal(argv[i + 3], &values[i])) { print_error(1, "native_identity_invalid"); return 1; }
  if (strcmp(argv[2], boot_id) || values[0] != observer_dev || values[1] != observer_ino || values[2] != procdev || values[3] > INT_MAX || values[4] > INT_MAX || values[8] > INT_MAX || values[9] > INT_MAX) { print_error(1, "native_observer_mismatch"); return 1; }
  int pid = (int)values[3], proc_pid = (int)values[4], ns_pid = (int)values[8], timeout = (int)values[9];
  if (pid <= 1 || proc_pid <= 1 || (stop && pid == getpid())) { print_error(1, "native_identity_invalid"); return 1; }
  int d = process_dir(proc_pid);
  if (d < 0) {
    if (errno == ENOENT || errno == ESRCH) {
      /* hidepid/visibility can make procfs lie by omission. PID existence is
       * checked separately in the exact observer namespace, without a signal. */
      int check = pidfd_open_local(pid);
      if (check >= 0) { close(check); errno = EACCES; print_error(1, "native_proc_visibility_unconfirmed"); return 1; }
      if (errno == ESRCH) { dprintf(1, "{\"status\":\"exited\",\"method\":\"linux_boot_birth_absent\",\"process_reaped\":false,\"release_inferred\":true}\n"); return 0; }
    }
    print_error(1, "native_identity_denied"); return 1;
  }
  struct identity first, second;
  if (identity_at(d, proc_pid, &first)) { close(d); print_error(1, "native_identity_unconfirmed"); return 1; }
  if (first.pid != pid || first.ticks != values[5]) { close(d); dprintf(1, "{\"status\":\"exited\",\"method\":\"linux_boot_birth_replaced\",\"process_reaped\":false,\"release_inferred\":true}\n"); return 0; }
  if (((first.state != 'Z' && first.state != 'X') && (first.ns_dev != values[6] || first.ns_ino != values[7])) || first.ns_pid != ns_pid) { close(d); print_error(1, "native_namespace_mismatch"); return 1; }
  int fd = pidfd_open_local(pid); if (fd < 0) { close(d); print_error(1, "native_pidfd_unavailable"); return 1; }
  if (identity_at(d, proc_pid, &second) || second.pid != first.pid || second.ticks != first.ticks || second.ns_ino != first.ns_ino || second.ns_dev != first.ns_dev) { close(d); close(fd); print_error(1, "native_identity_raced"); return 1; } close(d);
  if (!exited_fd(fd) && !stop) { close(fd); dprintf(1, "{\"status\":\"active\"}\n"); return 0; }
  if (!exited_fd(fd) && pidfd_kill(fd) && errno != ESRCH) { close(fd); print_error(1, "native_stop_denied"); return 1; }
  long long deadline = now_ms() + timeout;
  while (!exited_fd(fd)) { long long left = deadline - now_ms(); if (left <= 0) { close(fd); print_error(1, "native_exit_timeout"); return 1; } struct pollfd p = {fd, POLLIN, 0}; int r = poll(&p, 1, left > 100 ? 100 : (int)left); if (r < 0 && errno != EINTR) { close(fd); print_error(1, "native_exit_poll_failed"); return 1; } }
  struct pollfd final = {fd, POLLIN, 0}; (void)poll(&final, 1, 0); close(fd);
  dprintf(1, "{\"status\":\"exited\",\"method\":\"linux_pidfd_exit\",\"process_reaped\":%s}\n", final.revents & POLLHUP ? "true" : "false"); return 0;
}
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc == 2 && !strcmp(argv[1], "--probe")) return run_keeper(NULL, 15000, 1, 0);
  if (argc == 2 && !strcmp(argv[1], "--identity")) {
    if (setup_observer()) { print_error(1, "native_observer_unavailable"); return 1; }
    struct identity i; if (identity(parent_proc_pid(), &i)) { print_error(1, "native_identity_unavailable"); return 1; }
    dprintf(1, "{\"backend\":\"linux_pid_namespace\",\"boot_id\":\"%s\",\"observer_pid_namespace\":{\"dev\":\"%llu\",\"ino\":\"%llu\"},\"procfs_dev\":\"%llu\",\"identity\":", boot_id, observer_dev, observer_ino, procdev); print_identity(1, &i); dprintf(1, "}\n"); return 0;
  }
  if (argc >= 2 && (!strcmp(argv[1], "--observe") || !strcmp(argv[1], "--stop"))) return observe(argc, argv, !strcmp(argv[1], "--stop"));
  unsigned long long lifetime;
  if (argc >= 6 && !strcmp(argv[1], "--run") && !decimal(argv[2], &lifetime) && lifetime > 0 && lifetime <= INT_MAX && (!strcmp(argv[3], "authority") || !strcmp(argv[3], "worker")) && !strcmp(argv[4], "--") && argv[5][0] == '/') return run_keeper(argv + 5, (int)lifetime, 0, !strcmp(argv[3], "authority"));
  errno = EINVAL; print_error(1, "native_arguments_invalid"); return 2;
}
