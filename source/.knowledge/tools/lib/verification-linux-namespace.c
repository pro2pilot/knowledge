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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROTOCOL "knowledge-linux-namespace-helper.v2"
#define PID_NAMESPACE_LINK_PROVIDER "linux_procfs_pid_namespace_link.v1"
#define STACK_SIZE (1024 * 1024)
#define MAX_TEXT 16384
struct identity { int pid, proc_pid, ns_pid, depth, pid_chain[64]; unsigned long long ticks, ns_dev, ns_ino, exe_dev, exe_ino, born_ms; char state; };
struct event { int kind, pid, value; };
struct child_args { int procfd, keeperfd, commands[2], events[2], gate[2], execerr[2], trusted_authority; char **command; };
static int procfd = -1;
static unsigned long long procdev, observer_dev, observer_ino, btime;
static long hz;
static int observer_depth;
static char boot_id[64];
static int observer_stage;
/* Legacy stat observations remain distinct. New run/identity-link commands
 * select this provider explicitly; EACCES never changes provider implicitly. */
static int namespace_link_provider;

/* Native custody must never wait for its controller to drain a report. The
 * controller channel is a pipe/socket, and its nonblocking failure is latched
 * until the owned init has been stopped. Partial JSON is deliberately a failed
 * transcript; retrying it after a deadline must not create a successful one. */
static int report_fd = -1, report_failed;
static int prepare_report(int fd) {
  struct stat state;
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fstat(fd, &state) || (!S_ISFIFO(state.st_mode) && !S_ISSOCK(state.st_mode)) ||
      fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return -1;
  report_fd = fd; report_failed = 0; return 0;
}
static int report_printf(int fd, const char *format, ...) {
  va_list arguments; va_start(arguments, format);
  if (fd != report_fd) { int result = vdprintf(fd, format, arguments); va_end(arguments); return result; }
  if (report_failed) { va_end(arguments); errno = EPIPE; return -1; }
  char text[4096]; int size = vsnprintf(text, sizeof(text), format, arguments); va_end(arguments);
  if (size < 0 || (size_t)size >= sizeof(text)) { report_failed = 1; errno = EOVERFLOW; return -1; }
  size_t sent = 0; unsigned interrupted = 0;
  while (sent < (size_t)size) {
    ssize_t written = write(fd, text + sent, (size_t)size - sent);
    if (written < 0 && errno == EINTR && ++interrupted < 8) continue;
    if (written <= 0) { report_failed = 1; return -1; }
    sent += (size_t)written;
  }
  return size;
}

static long long now_ms(void) {
  static long long previous = -1; struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
  if (t.tv_sec < 0 || t.tv_nsec < 0 || t.tv_nsec >= 1000000000 || (unsigned long long)t.tv_sec > (unsigned long long)(LLONG_MAX / 1000)) { errno = EOVERFLOW; return -1; }
  long long value = (long long)t.tv_sec * 1000, fraction = t.tv_nsec / 1000000;
  if (value > LLONG_MAX - fraction) { errno = EOVERFLOW; return -1; }
  value += fraction;
  if (value < previous) { errno = ERANGE; return -1; }
  previous = value; return value;
}
static int pidfd_open_local(int pid) { return (int)syscall(SYS_pidfd_open, pid, 0); }
static int pidfd_kill(int fd) { return (int)syscall(SYS_pidfd_send_signal, fd, SIGKILL, NULL, 0); }
static int exited_fd(int fd) { struct pollfd p = {fd, POLLIN, 0}; int r = poll(&p, 1, 0); return r > 0 && (p.revents & (POLLIN | POLLHUP)); }
static int write_all(int fd, const void *data, size_t length) { const char *p = data; while (length) { ssize_t n = write(fd, p, length); if (n < 0 && errno == EINTR) continue; if (n <= 0) return -1; p += n; length -= (size_t)n; } return 0; }
static int read_text_at(int dir, const char *name, char *out, size_t length) { int f = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (f < 0) return -1; ssize_t n; do { n = read(f, out, length - 1); } while (n < 0 && errno == EINTR); int saved = errno; close(f); errno = saved; if (n <= 0 || (size_t)n == length - 1) return -1; out[n] = 0; return 0; }
static int decimal(const char *s, unsigned long long *n) { if (!s || !*s || *s == '+' || *s == '-') return -1; char *end; errno = 0; *n = strtoull(s, &end, 10); return errno || *end ? -1 : 0; }
static int self_proc_pid(void) { char s[64]; ssize_t n = readlinkat(procfd, "self", s, sizeof(s) - 1); if (n <= 0) return -1; s[n] = 0; unsigned long long p; return decimal(s, &p) || p > INT_MAX ? -1 : (int)p; }
static int process_dir(int pid) { char name[32]; snprintf(name, sizeof(name), "%d", pid); return openat(procfd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); }

/* An omitted /proc PID is not absence when the mount hides processes. These
 * bounded observations qualify only the inferred-absence path; a native
 * pidfd final-exit observation retains its independent stronger meaning. */
#define MAX_MOUNT_TEXT (1024 * 1024)
struct proc_visibility { unsigned long long dev, ino, mount_id; char row[MAX_TEXT]; };
static int canonical_unsigned(const char *text, unsigned long long *value) {
  if (!text || !*text || strlen(text) > 20 || (text[0] == '0' && text[1])) return -1;
  for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return -1;
  return decimal(text, value);
}
/* A procfs PID namespace link is kernel-generated, after a ptrace read gate.
 * Its number identifies a LIVE namespace in the qualified Linux allocator;
 * it is not a forever-unique ID. Birth + anchored proc directory + pidfd are
 * still required by observe(). No st_dev is inferred from a link string.
 * O_PATH|O_NOFOLLOW holds the procfs symlink itself, never a disconnected
 * nsfs inode whose getattr may legitimately be denied by an LSM profile. */
static int parse_pid_namespace_link(const char *text, size_t length, unsigned long long *ino) {
  if (!text || length < 7 || length > 16 || memchr(text, 0, length) ||
      memcmp(text, "pid:[", 5) || text[length - 1] != ']') { errno = EINVAL; return -1; }
  char number[16]; size_t count = length - 6;
  memcpy(number, text + 5, count); number[count] = 0;
  if (canonical_unsigned(number, ino) || !*ino || *ino > UINT_MAX) { errno = EINVAL; return -1; }
  return 0;
}
static int namespace_at(int directory, const char *name, unsigned long long *dev, unsigned long long *ino) {
  struct stat before, after;
  if (!namespace_link_provider) {
    if (fstatat(directory, name, &before, 0)) return -1;
    *dev = (unsigned long long)before.st_dev; *ino = (unsigned long long)before.st_ino; return 0;
  }
  struct statfs filesystem;
  if (fstatfs(directory, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC) { errno = EINVAL; return -1; }
  int fd = openat(directory, name, O_PATH | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return -1;
  int result = -1, saved = EINVAL; char text[64];
  if (fstatfs(fd, &filesystem)) { saved = errno; goto finished; }
  if (filesystem.f_type != PROC_SUPER_MAGIC) goto finished;
  if (fstat(fd, &before)) { saved = errno; goto finished; }
  if (!S_ISLNK(before.st_mode) || (unsigned long long)before.st_dev != procdev) goto finished;
  ssize_t length = readlinkat(fd, "", text, sizeof(text));
  if (length < 0) { saved = errno; goto finished; }
  if ((size_t)length == sizeof(text) || parse_pid_namespace_link(text, (size_t)length, ino)) goto finished;
  if (fstat(fd, &after)) { saved = errno; goto finished; }
  if (after.st_dev != before.st_dev || after.st_ino != before.st_ino || !S_ISLNK(after.st_mode)) goto finished;
  /* This internal unused slot is never serialized as a device identifier. */
  *dev = 0; result = 0; saved = 0;
finished:
  close(fd); errno = saved; return result;
}
static int own_namespace_matches(void) {
  unsigned long long dev, ino;
  if (namespace_at(procfd, "self/ns/pid", &dev, &ino)) return -1;
  return ino == observer_ino && (namespace_link_provider || dev == observer_dev) ? 0 : -1;
}
static int bounded_kernel_text(int dir, const char *name, char *out, size_t capacity) {
  int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  size_t used = 0; int result = -1, saved = EINVAL;
  while (used < capacity) {
    ssize_t count = read(fd, out + used, capacity - used);
    if (count < 0 && errno == EINTR) continue;
    if (count < 0) { saved = errno; break; }
    if (!count) {
      if (used && used < capacity && !memchr(out, 0, used)) { out[used] = 0; result = 0; }
      break;
    }
    used += (size_t)count;
  }
  close(fd); errno = saved; return result;
}
/* pidfd fdinfo Pid/NSpid are expressed in the PID namespace of the procfs
 * instance that supplied the fdinfo file. Compare the entire freshly read
 * target chain before using the handle. A namespace inum/depth comparison
 * alone is never authority to signal or accept exit of a translated PID. */
static int pidfd_pid_list(const char *start, size_t length, const int *expected, int count) {
  const char *end = start + length; int index = 0;
  while (start < end) {
    while (start < end && (*start == ' ' || *start == '\t')) start++;
    if (start == end) break;
    const char *next = start;
    while (next < end && *next != ' ' && *next != '\t') next++;
    char number[32]; size_t size = (size_t)(next - start); unsigned long long value;
    if (!size || size >= sizeof(number) || index >= count) return -1;
    memcpy(number, start, size); number[size] = 0;
    if (canonical_unsigned(number, &value) || !value || value > INT_MAX || value != (unsigned long long)expected[index++]) return -1;
    start = next;
  }
  return index == count ? 0 : -1;
}
static int parse_pidfd_identity(const char *text, const struct identity *expected) {
  size_t size = strlen(text); int pid_seen = 0, chain_seen = 0;
  if (!size || text[size - 1] != '\n' || expected->depth < 1 || expected->depth > 64 || expected->pid_chain[0] != expected->proc_pid) return -1;
  for (const char *line = text; *line;) {
    const char *end = strchr(line, '\n'); if (!end) return -1;
    size_t length = (size_t)(end - line);
    if (length >= 4 && !strncmp(line, "Pid:", 4)) {
      if (++pid_seen != 1 || pidfd_pid_list(line + 4, length - 4, &expected->proc_pid, 1)) return -1;
    } else if (length >= 6 && !strncmp(line, "NSpid:", 6)) {
      if (++chain_seen != 1 || pidfd_pid_list(line + 6, length - 6, expected->pid_chain, expected->depth)) return -1;
    }
    line = end + 1;
  }
  return pid_seen == 1 && chain_seen == 1 ? 0 : -1;
}
static int pidfd_matches_identity(int fd, const struct identity *expected) {
  char name[64], text[MAX_TEXT];
  snprintf(name, sizeof(name), "self/fdinfo/%d", fd);
  if (bounded_kernel_text(procfd, name, text, sizeof(text))) return -1;
  if (parse_pidfd_identity(text, expected)) { errno = EINVAL; return -1; }
  return 0;
}
static int proc_mount_id(const char *fdinfo, unsigned long long *mount_id) {
  const char *line = fdinfo; int found = 0;
  while (*line) {
    const char *end = strchr(line, '\n'); size_t length = end ? (size_t)(end - line) : strlen(line);
    if (length >= 7 && !strncmp(line, "mnt_id:", 7)) {
      char number[32]; const char *start = line + 7;
      while (start < line + length && (*start == ' ' || *start == '\t')) start++;
      const char *last = line + length;
      while (last > start && (last[-1] == ' ' || last[-1] == '\t')) last--;
      if (++found != 1 || last == start || (size_t)(last - start) >= sizeof(number)) return -1;
      memcpy(number, start, (size_t)(last - start)); number[last - start] = 0;
      if (canonical_unsigned(number, mount_id) || !*mount_id) return -1;
    }
    if (!end) break;
    line = end + 1;
  }
  return found == 1 ? 0 : -1;
}
static int proc_visible_options(char *options, int *hiding_count) {
  if (!*options || options[0] == ',' || options[strlen(options) - 1] == ',' || strstr(options, ",,")) return -1;
  char *save = NULL, *option = strtok_r(options, ",", &save);
  while (option) {
    if (!strcmp(option, "hidepid") || !strncmp(option, "hidepid=", 8)) {
      if (++*hiding_count > 1 || (strcmp(option, "hidepid=0") && strcmp(option, "hidepid=off"))) return -1;
    }
    option = strtok_r(NULL, ",", &save);
  }
  return 0;
}
static int parse_proc_visibility(const char *fdinfo, const char *mountinfo, dev_t device, struct proc_visibility *out) {
  unsigned long long mount_id;
  if (proc_mount_id(fdinfo, &mount_id) || strlen(mountinfo) >= MAX_MOUNT_TEXT) { errno = EINVAL; return -1; }
  char *copy = strdup(mountinfo); if (!copy) return -1;
  int found = 0, result = -1; char *save = NULL, *row = strtok_r(copy, "\n", &save);
  while (row) {
    char *first_space = strchr(row, ' '), number[32]; unsigned long long row_id;
    if (!first_space || (size_t)(first_space - row) >= sizeof(number)) goto invalid;
    memcpy(number, row, (size_t)(first_space - row)); number[first_space - row] = 0;
    if (canonical_unsigned(number, &row_id) || !row_id) goto invalid;
    if (row_id != mount_id) { row = strtok_r(NULL, "\n", &save); continue; }
    if (++found != 1 || strlen(row) >= sizeof(out->row) || strchr(row, '\t') || strstr(row, "  ")) goto invalid;
    strcpy(out->row, row);
    char *separator = strstr(row, " - "); if (!separator || strstr(separator + 3, " - ")) goto invalid;
    *separator = 0;
    char *fields[6], *left_save = NULL;
    fields[0] = strtok_r(row, " ", &left_save);
    for (int i = 1; i < 6; i++) fields[i] = strtok_r(NULL, " ", &left_save);
    if (!fields[5] || strcmp(fields[3], "/") || strcmp(fields[4], "/proc")) goto invalid;
    unsigned long long parent, dev_major, dev_minor;
    if (canonical_unsigned(fields[1], &parent) || !parent) goto invalid;
    char *colon = strchr(fields[2], ':'); if (!colon || strchr(colon + 1, ':')) goto invalid; *colon = 0;
    if (canonical_unsigned(fields[2], &dev_major) || canonical_unsigned(colon + 1, &dev_minor) ||
        dev_major != (unsigned long long)major(device) || dev_minor != (unsigned long long)minor(device)) goto invalid;
    char *right_save = NULL, *filesystem = strtok_r(separator + 3, " ", &right_save);
    char *source = strtok_r(NULL, " ", &right_save), *options = strtok_r(NULL, " ", &right_save);
    if (!filesystem || strcmp(filesystem, "proc") || !source || !options || strtok_r(NULL, " ", &right_save)) goto invalid;
    int hiding_count = 0;
    if (proc_visible_options(fields[5], &hiding_count) || proc_visible_options(options, &hiding_count)) goto invalid;
    out->mount_id = mount_id;
    row = strtok_r(NULL, "\n", &save);
  }
  result = found == 1 ? 0 : -1;
invalid:
  free(copy);
  if (result) errno = EINVAL;
  return result;
}
static int proc_visibility_snapshot(struct proc_visibility *out) {
  struct stat before, after, fixed; struct statfs filesystem;
  if (fstat(procfd, &before) || !S_ISDIR(before.st_mode) || (unsigned long long)before.st_dev != procdev ||
      fstatfs(procfd, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC ||
      fstatat(AT_FDCWD, "/proc", &fixed, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(fixed.st_mode) ||
      fixed.st_dev != before.st_dev || fixed.st_ino != before.st_ino ||
      own_namespace_matches()) return -1;
  char name[64], fdinfo[MAX_TEXT];
  snprintf(name, sizeof(name), "self/fdinfo/%d", procfd);
  if (bounded_kernel_text(procfd, name, fdinfo, sizeof(fdinfo))) return -1;
  char *mountinfo = malloc(MAX_MOUNT_TEXT); if (!mountinfo) return -1;
  int result = bounded_kernel_text(procfd, "self/mountinfo", mountinfo, MAX_MOUNT_TEXT);
  if (!result) result = parse_proc_visibility(fdinfo, mountinfo, before.st_dev, out);
  int saved = errno; free(mountinfo); errno = saved;
  if (result) return -1;
  unsigned long long last_mount_id;
  if (bounded_kernel_text(procfd, name, fdinfo, sizeof(fdinfo)) || proc_mount_id(fdinfo, &last_mount_id) || last_mount_id != out->mount_id ||
      fstat(procfd, &after) || after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
      fstatfs(procfd, &filesystem) || filesystem.f_type != PROC_SUPER_MAGIC ||
      fstatat(AT_FDCWD, "/proc", &fixed, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(fixed.st_mode) ||
      fixed.st_dev != before.st_dev || fixed.st_ino != before.st_ino ||
      own_namespace_matches()) return -1;
  out->dev = (unsigned long long)before.st_dev; out->ino = (unsigned long long)before.st_ino;
  return 0;
}
static int absent_birth_confirmed(int pid, int proc_pid) {
  struct proc_visibility before, after;
  if (proc_visibility_snapshot(&before)) return -1;
  int descriptor = process_dir(proc_pid);
  if (descriptor >= 0) { close(descriptor); errno = EAGAIN; return -1; }
  if (errno != ENOENT && errno != ESRCH) return -1;
  int handle = pidfd_open_local(pid);
  if (handle >= 0) { close(handle); errno = EACCES; return -1; }
  if (errno != ESRCH) return -1;
  descriptor = process_dir(proc_pid);
  if (descriptor >= 0) { close(descriptor); errno = EAGAIN; return -1; }
  if (errno != ENOENT && errno != ESRCH) return -1;
  if (proc_visibility_snapshot(&after) || before.dev != after.dev || before.ino != after.ino ||
      before.mount_id != after.mount_id || strcmp(before.row, after.row)) { errno = EACCES; return -1; }
  return 0;
}

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
  while (*p >= '0' && *p <= '9') { char *end; long n = strtol(p, &end, 10); if (n <= 0 || n > INT_MAX || end == p || out->depth >= 64) return -1; out->pid_chain[out->depth++] = (int)n; out->ns_pid = (int)n; if (out->depth == observer_depth) out->pid = (int)n; p = end; while (*p == ' ' || *p == '\t') ++p; }
  struct stat exe;
  if (namespace_at(dir, "ns/pid", &out->ns_dev, &out->ns_ino)) {
    if (out->state != 'Z' && out->state != 'X') return -1;
  }
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
  observer_stage = 10;
  procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW); if (procfd < 0) return -1;
  observer_stage = 11;
  struct statfs fs; struct stat st; if (fstatfs(procfd, &fs) || fs.f_type != PROC_SUPER_MAGIC || fstat(procfd, &st)) { errno = ENOTSUP; return -1; } procdev = (unsigned long long)st.st_dev;
  observer_stage = 12;
  char buf[MAX_TEXT]; if (read_text_at(procfd, "sys/kernel/random/boot_id", boot_id, sizeof(boot_id))) return -1;
  boot_id[strcspn(boot_id, "\r\n")] = 0; if (strlen(boot_id) != 36) { errno = EINVAL; return -1; }
  observer_stage = 13;
  if (read_boot_time()) return -1;
  observer_stage = 14;
  hz = sysconf(_SC_CLK_TCK); if (hz <= 0) return -1;
  observer_stage = 15;
  if (namespace_at(procfd, "self/ns/pid", &observer_dev, &observer_ino)) return -1;
  /* NSpid count of the observer tells which column belongs to this caller. */
  observer_stage = 16;
  int d = process_dir(self_proc_pid()); if (d < 0) return -1;
  observer_stage = 17;
  if (read_text_at(d, "status", buf, sizeof(buf))) { close(d); return -1; } close(d);
  char *p = strstr(buf, "\nNSpid:"); if (!p) { errno = ENOTSUP; return -1; } p += 7;
  while (*p == ' ' || *p == '\t') ++p;
  while (*p >= '0' && *p <= '9') { char *end; (void)strtol(p, &end, 10); observer_depth++; p = end; while (*p == ' ' || *p == '\t') ++p; }
  observer_stage = 18;
  struct identity self; if (!observer_depth || identity(self_proc_pid(), &self) || self.pid != getpid()) { errno = ENOTSUP; return -1; }
  if (namespace_link_provider) {
    /* Qualify the actual mounted proc view for this new provider, including
     * its mount ID, canonical root and visibility options. */
    struct proc_visibility view; if (proc_visibility_snapshot(&view)) return -1;
  }
  observer_stage = 0;
  return 0;
}
static void print_namespace(int fd, unsigned long long dev, unsigned long long ino) {
  if (namespace_link_provider) report_printf(fd, "{\"provider\":\"%s\",\"ino\":\"%llu\"}", PID_NAMESPACE_LINK_PROVIDER, ino);
  else report_printf(fd, "{\"dev\":\"%llu\",\"ino\":\"%llu\"}", dev, ino);
}
static void print_identity(int fd, const struct identity *i) {
  time_t sec = (time_t)(i->born_ms / 1000); struct tm t; char iso[40]; gmtime_r(&sec, &t); strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S", &t);
  report_printf(fd, "{\"pid\":%d,\"proc_pid\":%d,\"start_ticks\":\"%llu\",\"os_creation_time\":\"%s.%03lluZ\",\"namespace_pid\":%d,\"pid_namespace\":", i->pid, i->proc_pid, i->ticks, iso, i->born_ms % 1000, i->ns_pid);
  print_namespace(fd, i->ns_dev, i->ns_ino);
  report_printf(fd, ",\"executable\":{\"dev\":\"%llu\",\"ino\":\"%llu\"},\"proc_pid_chain\":[", i->exe_dev, i->exe_ino);
  for (int j = 0; j < i->depth; j++) report_printf(fd, "%s%d", j ? "," : "", i->pid_chain[j]);
  report_printf(fd, "]}");
}
static void print_error(int fd, const char *code) { report_printf(fd, "{\"protocol\":\"%s\",\"status\":\"unconfirmed\",\"code\":\"%s\",\"errno\":%d,\"observer_stage\":%d}\n", PROTOCOL, code, errno, observer_stage); }
static int send_event(int fd, int kind, int pid, int value) { struct event e = {kind, pid, value}; return write_all(fd, &e, sizeof(e)); }
static int close_above_five(void) {
#ifdef SYS_close_range
  if (!syscall(SYS_close_range, 6U, ~0U, 0)) return 0;
  if (errno != ENOSYS && errno != EINVAL) return -1;
#endif
  struct rlimit lim; if (getrlimit(RLIMIT_NOFILE, &lim) || lim.rlim_cur > 1048576) return -1;
  for (int fd = 6; (rlim_t)fd < lim.rlim_cur; fd++) close(fd); return 0;
}
static int restrict_worker(int trusted_authority, int *stage) {
  *stage = 1; if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
  *stage = 2; if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED)) return -1;
  struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0}; struct __user_cap_data_struct data[2]; memset(data, 0, sizeof(data));
  *stage = 3; if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return -1;
  /* Only the pinned authority may create a nested user namespace when its
   * parent UID is 0. Linux >=5.12 requires CAP_SETFCAP for that map. This is
   * namespaced authority, never a host capability or a command-worker grant. */
  /* Self maps preserve the caller's numeric UID. A nonzero parent UID does
   * not need SETFCAP; requesting it unnecessarily is also rejected by hosts
   * which allow user namespaces while masking their extra capabilities. */
  unsigned int allowed = trusted_authority && getuid() == 0 ? (1U << CAP_SETFCAP) : 0;
  data[0].permitted = data[0].effective = data[0].inheritable = allowed;
  *stage = 4; if (syscall(SYS_capset, &header, data)) return -1;
  *stage = 5; if (prctl(PR_SET_DUMPABLE, 1)) return -1;
  *stage = 6; if (allowed && prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SETFCAP, 0, 0)) return -1;
  *stage = 7; memset(data, 0, sizeof(data)); if (syscall(SYS_capget, &header, data)) return -1;
  *stage = 8;
  if (data[0].permitted != allowed || data[0].effective != allowed || data[0].inheritable != allowed || data[1].permitted || data[1].effective || data[1].inheritable || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) { errno = EPERM; return -1; }
  return 0;
}
static void worker_stub(struct child_args *a) {
  close(a->gate[1]); close(a->execerr[0]);
  int stage = 0;
  if (restrict_worker(a->trusted_authority, &stage)) { send_event(a->events[1], 'E', stage, errno); _exit(125); }
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
  /* Do not diagnose through an unsupported descriptor: even before custody,
   * that fallback could block on a regular file or a stalled device. */
  if (prepare_report(out)) return 1;
  observer_stage = 1;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL)) { print_error(out, "namespace_observer_unavailable"); return 1; }
  long long began = now_ms();
  if (began < 0 || began > LLONG_MAX - lifetime) { print_error(out, "native_clock_unavailable"); return 1; }
  long long deadline = began + lifetime;
  observer_stage = 2;
  if (getppid() != controller || setup_observer()) { print_error(out, "namespace_observer_unavailable"); return 1; }
  struct identity keeper_identity, controller_identity;
  if (identity(self_proc_pid(), &keeper_identity) || identity(parent_proc_pid(), &controller_identity)) { print_error(out, "namespace_parent_identity_unavailable"); return 1; }
  long long before_clone = now_ms();
  if (before_clone < 0) { print_error(out, "native_clock_unavailable"); return 1; }
  if (before_clone >= deadline) { print_error(out, "namespace_cleanup_timeout"); return 1; }
  struct child_args a; memset(&a, 0, sizeof(a)); a.procfd = procfd; a.command = command; a.trusted_authority = trusted_authority; a.keeperfd = pidfd_open_local(getpid());
  if (a.keeperfd < 0 || pipe2(a.commands, O_CLOEXEC) || pipe2(a.events, O_CLOEXEC) || pipe2(a.gate, O_CLOEXEC) || pipe2(a.execerr, O_CLOEXEC)) { print_error(out, "namespace_pipe_unavailable"); return 1; }
  char *stack = malloc(STACK_SIZE); if (!stack) return 1;
  pid_t init = clone(init_main, stack + STACK_SIZE, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, &a);
  if (init < 0) { print_error(out, "namespace_create_denied"); free(stack); return 1; }
  int initfd = pidfd_open_local(init); close(a.commands[0]); close(a.events[1]); close(a.gate[0]); close(a.gate[1]); close(a.execerr[1]); close(a.keeperfd);
  if (!probe) for (int fd = 0; fd <= 3; fd++) close(fd);
  if (initfd < 0) { (void)kill(init, SIGKILL); print_error(out, "namespace_pidfd_unavailable"); return 1; }
  int host_init = 0, host_worker = 0, ready = 0, emitted = 0, permitted = 0, closing = 0, started = 0, failed = 0;
  char input[128]; size_t used = 0;
  struct identity init_identity, worker_identity;
  for (;;) {
    if (report_failed) { failed = closing = 1; (void)pidfd_kill(initfd); }
    long long current = now_ms();
    if (current < 0) { (void)pidfd_kill(initfd); print_error(out, "native_clock_unavailable"); return 1; }
    long long remaining = deadline - current;
    if (remaining <= 0) { (void)pidfd_kill(initfd); print_error(out, "namespace_cleanup_timeout"); return 1; }
    if (exited_fd(initfd)) {
      int status; if (waitpid(init, &status, WNOHANG) != init) { print_error(out, "namespace_init_reap_unconfirmed"); return 1; }
      long long final_time = now_ms();
      if (final_time < 0) { print_error(out, "native_clock_unavailable"); return 1; }
      if (final_time >= deadline) { print_error(out, "namespace_cleanup_timeout"); return 1; }
      if (closing && !failed) {
        report_printf(out, "{\"protocol\":\"%s\",\"status\":\"closed\",\"active_processes\":0,\"init_exit_observed\":true,\"init_reaped\":true%s}\n",
          PROTOCOL, probe == 2 ? ",\"probe_depth\":2" : "");
        return report_failed ? 1 : 0;
      }
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
      else if (e.kind == 'X') {
        if (probe == 2 && !closing) {
          /* The fixed inner --probe exits zero only after its own exact init
           * final exit and wait. A signal/nonzero exit cannot qualify nesting. */
          if (!WIFEXITED(e.value) || WEXITSTATUS(e.value) != 0) failed = 1;
          closing = 1; (void)pidfd_kill(initfd);
        } else if (!closing) report_printf(out, "{\"protocol\":\"%s\",\"status\":\"worker_exit\",\"wait_status\":%d}\n", PROTOCOL, e.value);
      }
      else {
        if (e.kind == 'E') report_printf(out, "{\"protocol\":\"%s\",\"status\":\"unconfirmed\",\"code\":\"namespace_child_setup_failed\",\"errno\":%d,\"setup_stage\":%d}\n", PROTOCOL, e.value, e.pid);
        else print_error(out, "namespace_child_setup_failed");
        failed = closing = 1; (void)pidfd_kill(initfd);
      }
    }
    if (ready && host_worker && !emitted && !closing) {
      if (identity(host_init, &init_identity) || identity(host_worker, &worker_identity) || init_identity.ns_pid != 1 || init_identity.pid != init || init_identity.ns_ino == observer_ino) { print_error(out, "namespace_birth_identity_failed"); failed = closing = 1; (void)pidfd_kill(initfd); continue; }
      long long before_ready = now_ms();
      if (before_ready < 0) { (void)pidfd_kill(initfd); print_error(out, "native_clock_unavailable"); return 1; }
      if (before_ready >= deadline) { (void)pidfd_kill(initfd); print_error(out, "namespace_cleanup_timeout"); return 1; }
      emitted = 1;
      report_printf(out, "{\"protocol\":\"%s\",\"status\":\"ready\",\"boot_id\":\"%s\",\"procfs_dev\":\"%llu\",\"observer_pid_namespace\":", PROTOCOL, boot_id, procdev);
      print_namespace(out, observer_dev, observer_ino);
      report_printf(out, ",\"namespace_identity_provider\":\"%s\",\"procfs_mode\":\"inherited_ancestor_view\",\"capability_profile\":\"%s\",\"no_new_privileges\":true,\"identities\":{\"controller\":", PID_NAMESPACE_LINK_PROVIDER, trusted_authority ? (getuid() == 0 ? "authority_setfcap" : "authority_none") : "worker_none");
      print_identity(out, &controller_identity); report_printf(out, ",\"keeper\":"); print_identity(out, &keeper_identity); report_printf(out, ",\"init\":"); print_identity(out, &init_identity); report_printf(out, ",\"worker\":"); print_identity(out, &worker_identity); report_printf(out, "}}\n");
      if (probe == 1) { closing = 1; (void)pidfd_kill(initfd); }
      else if (probe == 2) {
        /* Only this fixed native canary is auto-permitted. The outer original
         * deadline encloses inner setup and both drains; it is never renewed. */
        long long before_probe_permit = now_ms();
        if (report_failed || before_probe_permit < 0 || before_probe_permit >= deadline || write_all(a.commands[1], "P", 1)) {
          failed = closing = 1; (void)pidfd_kill(initfd);
        } else permitted = 1;
      }
    }
    if (p[2].revents & (POLLIN | POLLHUP)) {
      int exec_errno = 0; ssize_t n = read(a.execerr[0], &exec_errno, sizeof(exec_errno)); started = 1; close(a.execerr[0]);
      if (n == 0 && !closing) {
        /* The inner probe now owns stdout. Suppress this optional outer event
         * so its multi-write JSON cannot interleave the inner ready receipt. */
        if (probe != 2) report_printf(out, "{\"protocol\":\"%s\",\"status\":\"started\"}\n", PROTOCOL);
      }
      else if (!closing) { errno = exec_errno; print_error(out, "namespace_worker_exec_failed"); failed = closing = 1; (void)pidfd_kill(initfd); }
    }
    /* Keep consuming a caller's close budget even after report failure.
     * closing denies permits; a close command may still shorten cleanup. */
    if (report_failed) { failed = closing = 1; (void)pidfd_kill(initfd); }
    if (p[1].revents & (POLLIN | POLLHUP | POLLERR)) {
      ssize_t n = read(4, input + used, sizeof(input) - 1 - used);
      if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
      if (n <= 0) { closing = 1; (void)pidfd_kill(initfd); continue; }
      used += (size_t)n; input[used] = 0; char *nl;
      while ((nl = strchr(input, '\n'))) {
        *nl = 0;
        if (!strcmp(input, "permit") && emitted && !permitted && !closing) {
          long long before_permit = now_ms();
          if (before_permit < 0) { (void)pidfd_kill(initfd); print_error(out, "native_clock_unavailable"); return 1; }
          if (before_permit >= deadline) { (void)pidfd_kill(initfd); print_error(out, "namespace_cleanup_timeout"); return 1; }
          permitted = 1; if (write_all(a.commands[1], "P", 1)) { failed = closing = 1; (void)pidfd_kill(initfd); }
        }
        else if (!strncmp(input, "close ", 6)) { unsigned long long ms; if (decimal(input + 6, &ms) || ms > INT_MAX) failed = 1; else {
          long long close_time = now_ms();
          if (close_time < 0 || close_time > LLONG_MAX - (long long)ms) { (void)pidfd_kill(initfd); print_error(out, "native_clock_unavailable"); return 1; }
          long long end = close_time + (long long)ms; if (end < deadline) deadline = end;
        } closing = 1; (void)pidfd_kill(initfd); }
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
      /* Both interfaces may be restricted. Never turn hidden proc entries
       * plus a policy-generated pidfd ESRCH into a confirmed old-birth exit. */
      if (!absent_birth_confirmed(pid, proc_pid)) { report_printf(1, "{\"status\":\"exited\",\"method\":\"linux_boot_birth_absent\",\"process_reaped\":false,\"release_inferred\":true}\n"); return 0; }
      print_error(1, "native_proc_visibility_unconfirmed"); return 1;
    }
    print_error(1, "native_identity_denied"); return 1;
  }
  struct identity first, second;
  if (identity_at(d, proc_pid, &first)) { close(d); print_error(1, "native_identity_unconfirmed"); return 1; }
  if (namespace_link_provider && first.ticks == values[5] && first.pid != pid) { close(d); print_error(1, "native_observer_translation_unconfirmed"); return 1; }
  if (first.pid != pid || first.ticks != values[5]) { close(d); report_printf(1, "{\"status\":\"exited\",\"method\":\"linux_boot_birth_replaced\",\"process_reaped\":false,\"release_inferred\":true}\n"); return 0; }
  if (((first.state != 'Z' && first.state != 'X') && (first.ns_dev != values[6] || first.ns_ino != values[7])) || first.ns_pid != ns_pid) { close(d); print_error(1, "native_namespace_mismatch"); return 1; }
  int fd = pidfd_open_local(pid); if (fd < 0) { close(d); print_error(1, "native_pidfd_unavailable"); return 1; }
  if (namespace_link_provider && pidfd_matches_identity(fd, &first)) { close(d); close(fd); print_error(1, "native_pidfd_identity_unconfirmed"); return 1; }
  if (identity_at(d, proc_pid, &second) || second.pid != first.pid || second.ticks != first.ticks || second.ns_ino != first.ns_ino || second.ns_dev != first.ns_dev) { close(d); close(fd); print_error(1, "native_identity_raced"); return 1; } close(d);
  if (!exited_fd(fd) && !stop) { close(fd); report_printf(1, "{\"status\":\"active\"}\n"); return 0; }
  if (!exited_fd(fd) && pidfd_kill(fd) && errno != ESRCH) { close(fd); print_error(1, "native_stop_denied"); return 1; }
  long long began = now_ms();
  if (began < 0 || began > LLONG_MAX - timeout) { close(fd); print_error(1, "native_clock_unavailable"); return 1; }
  long long deadline = began + timeout;
  while (!exited_fd(fd)) {
    long long current = now_ms();
    if (current < 0) { close(fd); print_error(1, "native_clock_unavailable"); return 1; }
    long long left = deadline - current; if (left <= 0) { close(fd); print_error(1, "native_exit_timeout"); return 1; }
    struct pollfd p = {fd, POLLIN, 0}; int r = poll(&p, 1, left > 100 ? 100 : (int)left);
    if (r < 0 && errno != EINTR) { close(fd); print_error(1, "native_exit_poll_failed"); return 1; }
  }
  long long final_time = now_ms();
  if (final_time < 0) { close(fd); print_error(1, "native_clock_unavailable"); return 1; }
  if (final_time >= deadline) { close(fd); print_error(1, "native_exit_timeout"); return 1; }
  struct pollfd final = {fd, POLLIN, 0}; (void)poll(&final, 1, 0); close(fd);
  report_printf(1, "{\"status\":\"exited\",\"method\":\"linux_pidfd_exit\",\"process_reaped\":%s}\n", final.revents & POLLHUP ? "true" : "false"); return 0;
}
/* Versioned link operations do not accept or synthesize a namespace device.
 * The unused zero slots below are an internal adapter to the unchanged exact
 * birth/pidfd observer. They are never part of a serialized descriptor. */
static int observe_link(int argc, char **argv, int stop) {
  if (argc != 11) { errno = EINVAL; print_error(1, "native_identity_invalid"); return 1; }
  unsigned long long observer, target;
  if (canonical_unsigned(argv[3], &observer) || !observer || observer > UINT_MAX ||
      canonical_unsigned(argv[8], &target) || !target || target > UINT_MAX) {
    errno = EINVAL; print_error(1, "native_identity_invalid"); return 1;
  }
  char zero[] = "0";
  char *expanded[] = {argv[0], argv[1], argv[2], zero, argv[3], argv[4], argv[5], argv[6], argv[7], zero, argv[8], argv[9], argv[10], NULL};
  namespace_link_provider = 1;
  return observe(13, expanded, stop);
}
int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  /* Read-only observers may be launched by the responsive control process.
   * Bind its exact still-live parent before any procfs I/O. No observer is
   * allowed to outlive that owner merely because the IPC server disappeared. */
  if (argc >= 4 && !strcmp(argv[1], "--parent")) {
    unsigned long long expected;
    if (decimal(argv[2], &expected) || expected < 1 || expected > INT_MAX || getppid() != (pid_t)expected) { print_error(1, "native_observer_parent_changed"); return 1; }
    int parentfd = pidfd_open_local((pid_t)expected);
    if (parentfd < 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != (pid_t)expected || exited_fd(parentfd)) {
      if (parentfd >= 0) close(parentfd); print_error(1, "native_observer_parent_unconfirmed"); return 1;
    }
    close(parentfd); argc -= 2; argv += 2;
  }
  if (argc == 2 && !strcmp(argv[1], "--probe")) { namespace_link_provider = 1; return run_keeper(NULL, 15000, 1, 0); }
  if (argc == 2 && !strcmp(argv[1], "--probe-nested")) {
    /* Self-exec names the already mapped helper inode, not an updateable path.
     * This fixed native prerequisite probe never runs Node or project code. */
    char *nested[] = {"/proc/self/exe", "--probe-nested-controller", NULL};
    namespace_link_provider = 1; return run_keeper(nested, 15000, 2, 1);
  }
  if (argc == 2 && !strcmp(argv[1], "--probe-nested-controller")) {
    /* Match real authority -> helper ancestry. Self-exec alone would make
     * capability-full namespace init the helper's parent: its identity is
     * intentionally unreadable by the restricted authority. This fixed
     * controller has the same restricted profile as the real Node authority. */
    if (getpid() != 2 || getppid() != 1 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 1;
    pid_t child = fork(); if (child < 0) return 1;
    if (!child) { char *nested[] = {"/proc/self/exe", "--probe", NULL}; execv(nested[0], nested); _exit(126); }
    int status; pid_t reaped;
    do { reaped = waitpid(child, &status, 0); } while (reaped < 0 && errno == EINTR);
    return reaped == child && WIFEXITED(status) ? WEXITSTATUS(status) : 1;
  }
  if (argc == 2 && (!strcmp(argv[1], "--identity") || !strcmp(argv[1], "--identity-link"))) {
    namespace_link_provider = !strcmp(argv[1], "--identity-link");
    if (setup_observer()) { print_error(1, "native_observer_unavailable"); return 1; }
    struct identity i; if (identity(parent_proc_pid(), &i)) { print_error(1, "native_identity_unavailable"); return 1; }
    report_printf(1, "{\"backend\":\"linux_pid_namespace\",\"boot_id\":\"%s\",\"observer_pid_namespace\":", boot_id);
    print_namespace(1, observer_dev, observer_ino);
    if (namespace_link_provider) report_printf(1, ",\"namespace_identity_provider\":\"%s\"", PID_NAMESPACE_LINK_PROVIDER);
    report_printf(1, ",\"procfs_dev\":\"%llu\",\"identity\":", procdev); print_identity(1, &i); report_printf(1, "}\n"); return 0;
  }
  if (argc >= 2 && (!strcmp(argv[1], "--observe") || !strcmp(argv[1], "--stop"))) return observe(argc, argv, !strcmp(argv[1], "--stop"));
  if (argc >= 2 && (!strcmp(argv[1], "--observe-link") || !strcmp(argv[1], "--stop-link"))) return observe_link(argc, argv, !strcmp(argv[1], "--stop-link"));
  unsigned long long lifetime;
  if (argc >= 6 && !strcmp(argv[1], "--run") && !decimal(argv[2], &lifetime) && lifetime > 0 && lifetime <= INT_MAX && (!strcmp(argv[3], "authority") || !strcmp(argv[3], "worker")) && !strcmp(argv[4], "--") && argv[5][0] == '/') {
    namespace_link_provider = 1; return run_keeper(argv + 5, (int)lifetime, 0, !strcmp(argv[3], "authority"));
  }
  errno = EINVAL; print_error(1, "native_arguments_invalid"); return 2;
}
