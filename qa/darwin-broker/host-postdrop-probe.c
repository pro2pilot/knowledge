/* Trace only: own fork child may die on guarded-port destruction; no host-port setter/SIP changes.
 * clang -O2 -Wall -Wextra -Wno-deprecated-declarations host-postdrop-port-trace-probe.c -o PROTECTED_COPY/probe
 * sudo PROTECTED_COPY/probe PRIVATE_UID [ROOT_OWNED_PROFILE_FILE]
 * Optional profile must allow exec of this exact probe inside its own workspace.
 * Parent watchdog 4s, child alarm3. No production qualification claim. */
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/task_special_ports.h>
#include <libproc.h>
#include <grp.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sandbox.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(90);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int self_private(uid_t uid) {
    struct proc_bsdinfo b = {0};
    gid_t groups[2] = {0, 0};
    return proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &b, sizeof b) == sizeof b
        && b.pbi_ruid == uid && b.pbi_uid == uid && b.pbi_svuid == uid
        && b.pbi_rgid == uid && b.pbi_gid == uid && b.pbi_svgid == uid
        && getgroups(2, groups) == 1 && groups[0] == uid;
}
static int fresh_facts(const char *stage, int require_ordinary) {
    /* Never infer safety from an invalid cached mach_host_self numeric name. */
    mach_port_t host = MACH_PORT_NULL;
    kern_return_t get_rc = task_get_special_port(mach_task_self(), TASK_HOST_PORT, &host);
    mach_port_type_t type = 0;
    kern_return_t type_rc = MACH_PORT_VALID(host)
        ? mach_port_type(mach_task_self(), host, &type) : KERN_INVALID_NAME;
    host_basic_info_data_t basic = {0};
    mach_msg_type_number_t n = HOST_BASIC_INFO_COUNT;
    kern_return_t info_rc = MACH_PORT_VALID(host)
        ? host_info(host, HOST_BASIC_INFO, (host_info_t)&basic, &n) : KERN_INVALID_NAME;
    kernel_boot_info_t boot = {0};
    kern_return_t boot_rc = MACH_PORT_VALID(host)
        ? host_get_boot_info(host, boot) : KERN_INVALID_NAME;
    memset(boot, 0, sizeof boot); /* Never print boot payload. */
    int valid = get_rc == KERN_SUCCESS && MACH_PORT_VALID(host)
        && type_rc == KERN_SUCCESS && (type & MACH_PORT_TYPE_SEND)
        && info_rc == KERN_SUCCESS && n == HOST_BASIC_INFO_COUNT;
    int ok = valid && (!require_ordinary || boot_rc != KERN_SUCCESS);
    printf("{\"stage\":\"%s\",\"ruid\":%u,\"euid\":%u,\"fresh_host_rc\":%d,"
           "\"send_type_rc\":%d,\"send_right\":%s,\"host_info_rc\":%d,"
           "\"host_info_count\":%u,\"host_boot_rc\":%d,\"observation_ok\":%s}\n",
           stage, getuid(), geteuid(), get_rc, type_rc,
           (type & MACH_PORT_TYPE_SEND) ? "true" : "false", info_rc, n,
           boot_rc, ok ? "true" : "false");
    fflush(stdout);
    if (MACH_PORT_VALID(host)) mach_port_deallocate(mach_task_self(), host);
    return ok;
}
static int scrub_names(void) {
    /* DIAGNOSTIC ONLY: intentionally trace the previous destroy algorithm.
     * A guard may kill this OWN child. Never use this as a proposed safe scrub. */
    static unsigned round = 0;
    ++round;
    mach_port_t task = mach_task_self(), thread = mach_thread_self();
    mach_port_name_array_t names = NULL;
    mach_port_type_array_t types = NULL;
    mach_msg_type_number_t nn = 0, nt = 0;
    kern_return_t names_rc = mach_port_names(task, &names, &nn, &types, &nt);
    printf("{\"stage\":\"scrub_snapshot\",\"round\":%u,\"names_rc\":%d,"
           "\"count\":%u,\"types_count\":%u,\"self_task\":%u,\"self_thread\":%u}\n",
           round, names_rc, nn, nt, task, thread);
    fflush(stdout);
    if (names_rc != KERN_SUCCESS || nn != nt || nn > 256) return 0;
    int ok = 1;
    for (mach_msg_type_number_t i = 0; i < nn; i++) {
        mach_port_t name = names[i];
        mach_port_urefs_t refs = 0;
        mach_port_status_t status = {0};
        mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
        kern_return_t refs_rc = KERN_INVALID_RIGHT, status_rc = KERN_INVALID_RIGHT;
        printf("{\"stage\":\"port_observe_begin\",\"round\":%u,\"index\":%u,"
               "\"name\":%u,\"type\":%u}\n", round, i, name, types[i]);
        fflush(stdout);
        if (types[i] & MACH_PORT_TYPE_SEND)
            refs_rc = mach_port_get_refs(task, name, MACH_PORT_RIGHT_SEND, &refs);
        if (types[i] & MACH_PORT_TYPE_RECEIVE)
            status_rc = mach_port_get_attributes(task, name, MACH_PORT_RECEIVE_STATUS,
                                                (mach_port_info_t)&status, &count);
        int preserve = name == task || name == thread;
        printf("{\"stage\":\"port_before_action\",\"round\":%u,\"index\":%u,"
               "\"name\":%u,\"type\":%u,\"send_refs_rc\":%d,\"send_refs\":%u,"
               "\"receive_status_rc\":%d,\"receive_flags\":%u,\"queued_messages\":%u,"
               "\"action\":\"%s\"}\n",
               round, i, name, types[i], refs_rc, refs, status_rc, status.mps_flags,
               status.mps_msgcount, preserve ? "preserve_self" : "destroy_old_algorithm");
        fflush(stdout);
        if (!preserve) {
            kern_return_t rc = mach_port_destroy(task, name);
            printf("{\"stage\":\"port_after_destroy\",\"round\":%u,\"index\":%u,"
                   "\"name\":%u,\"rc\":%d}\n", round, i, name, rc);
            fflush(stdout);
            if (rc != KERN_SUCCESS) ok = 0;
        }
    }
    printf("{\"stage\":\"before_snapshot_vm_deallocate\",\"round\":%u}\n", round);
    fflush(stdout);
    kern_return_t names_free = vm_deallocate(task, (vm_address_t)names, nn * sizeof *names);
    kern_return_t types_free = vm_deallocate(task, (vm_address_t)types, nt * sizeof *types);
    mach_port_urefs_t thread_refs = 0;
    kern_return_t thread_refs_rc = mach_port_get_refs(task, thread, MACH_PORT_RIGHT_SEND, &thread_refs);
    printf("{\"stage\":\"before_thread_deallocate\",\"round\":%u,\"name\":%u,"
           "\"send_refs_rc\":%d,\"send_refs\":%u,\"names_free_rc\":%d,\"types_free_rc\":%d}\n",
           round, thread, thread_refs_rc, thread_refs, names_free, types_free);
    fflush(stdout);
    kern_return_t thread_free = mach_port_deallocate(task, thread);
    printf("{\"stage\":\"after_thread_deallocate\",\"round\":%u,\"rc\":%d}\n",
           round, thread_free);
    fflush(stdout);
    return ok && names_free == KERN_SUCCESS && types_free == KERN_SUCCESS
        && thread_free == KERN_SUCCESS;
}
static char *read_profile(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat s;
    if (fd < 0) return NULL;
    if (fstat(fd, &s) || !S_ISREG(s.st_mode) || s.st_uid != 0
        || (s.st_mode & 0022) || s.st_size < 1 || s.st_size > 65536) {
        close(fd); return NULL;
    }
    char *text = calloc((size_t)s.st_size + 1, 1);
    size_t at = 0;
    while (text && at < (size_t)s.st_size) {
        ssize_t n = read(fd, text + at, (size_t)s.st_size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(text); text = NULL; break; }
        at += (size_t)n;
    }
    close(fd);
    if (text && memchr(text, 0, (size_t)s.st_size)) { free(text); text = NULL; }
    return text;
}
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 3 && !strcmp(argv[1], "--leaf")) {
        uid_t uid = (uid_t)strtoul(argv[2], NULL, 10);
        return self_private(uid) && fresh_facts("private_post_exec", 1) ? 0 : 41;
    }
    if (argc < 2 || argc > 3 || getuid() || geteuid() || argv[0][0] != '/') return 64;
    char *end = NULL;
    unsigned long parsed = strtoul(argv[1], &end, 10);
    if (!end || *end || parsed < 1000000000UL || parsed >= 1900000000UL) return 64;
    uid_t uid = (uid_t)parsed;
    pid_t members[4096]; errno = 0;
    int count = proc_listpids(PROC_RUID_ONLY, uid, members, sizeof members);
    if (count != 0 || errno) return 65; /* Explicit fresh test UID only. */
    char *profile = argc == 3 ? read_profile(argv[2]) : NULL;
    if (argc == 3 && !profile) return 66;
    pid_t child = fork();
    if (child < 0) { free(profile); return 71; }
    if (child == 0) {
        alarm(3);
        if (!fresh_facts("root_before_scrub", 0) || !scrub_names()) _exit(30);
        if (profile) {
            char *error = NULL;
            if (sandbox_init(profile, 0, &error)) {
                printf("{\"stage\":\"sandbox\",\"applied\":false,\"errno\":%d}\n", errno);
                if (error) sandbox_free_error(error);
                _exit(31);
            }
        }
        gid_t group = uid;
        if (setgroups(1, &group) || setgid(group) || setuid(uid) || !self_private(uid)) _exit(32);
        if (!fresh_facts("private_post_drop", 1)) _exit(33);
        /* Remove every acquired namespace reference again before exec. */
        if (!scrub_names() || !fresh_facts("private_post_scrub", 1)) _exit(34);
        char uid_text[32]; snprintf(uid_text, sizeof uid_text, "%u", uid);
        char *leaf[] = { argv[0], "--leaf", uid_text, NULL };
        char *environment[] = { "PATH=/usr/bin:/bin", "LANG=C", NULL };
        execve(argv[0], leaf, environment);
        printf("{\"stage\":\"exec\",\"errno\":%d}\n", errno);
        _exit(35);
    }
    free(profile);
    uint64_t deadline = ms() + 4000;
    int status = 0, timeout = 0;
    for (;;) {
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child) break;
        if (got < 0 && errno != EINTR) return 72;
        if (ms() >= deadline) {
            timeout = 1;
            /* Exact non-reaped direct child: its PID cannot have been recycled. */
            kill(child, SIGKILL);
            if (waitpid(child, &status, 0) != child) return 73;
            break;
        }
        usleep(10000);
    }
    int ok = !timeout && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("{\"stage\":\"parent_reaped\",\"timeout\":%s,\"wait_status\":%d,"
           "\"probe_ok\":%s,\"backend_certified\":false}\n",
           timeout ? "true" : "false", status, ok ? "true" : "false");
    return ok ? 0 : 1;
}
