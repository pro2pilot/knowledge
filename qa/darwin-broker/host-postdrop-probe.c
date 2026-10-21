/* Diagnostic only: candidate SEND-only scrub in own tiny C fork child; no host setter/SIP changes.
 * clang -O2 -Wall -Wextra -Wno-deprecated-declarations host-postdrop-rights-candidate-probe.c -o PROTECTED_COPY/probe
 * sudo PROTECTED_COPY/probe PRIVATE_UID [ROOT_OWNED_PROFILE_FILE]
 * Optional profile must allow exec of this exact probe inside its own workspace.
 * Parent watchdog 4s, child alarm3. No production qualification claim. */
#include <mach/mach.h>
#include <dlfcn.h>
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
    int ok = valid && (!require_ordinary || boot_rc == KERN_INVALID_HOST);
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
/* DIAGNOSTIC candidate only. Tiny trusted C image; no Mach message reception,
 * descriptor imports, XPC/dispatch/Objective-C, async RPC or foreign callbacks.
 * A new task IPC space inherits selected SEND slots, not parent RECEIVE rights.
 * Thus local RECEIVE provenance is the reviewed runtime, not arbitrary input.
 * This argument MUST NOT be transplanted into arbitrary Foundation processes. */
static int scrub_names(void) {
    static unsigned round = 0;
    ++round;
    task_t task = mach_task_self();
    thread_t self = mach_thread_self();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t rc = task_threads(task, &threads, &thread_count);
    if (rc != KERN_SUCCESS || thread_count != 1 || threads[0] != self) return 0;
    /* task_threads added exactly one own-thread reference; do not remove the
     * final possibly pinned self reference. We retain mach_thread_self's ref. */
    if (mach_port_deallocate(task, threads[0]) != KERN_SUCCESS
        || vm_deallocate(task, (vm_address_t)threads, sizeof *threads) != KERN_SUCCESS) return 0;
    typedef mach_port_t (*reply_getter)(void);
    reply_getter get_mig = (reply_getter)dlsym(RTLD_DEFAULT, "mig_get_reply_port");
    reply_getter get_special = (reply_getter)dlsym(RTLD_DEFAULT, "thread_get_special_reply_port");
    mach_port_t mig = get_mig ? get_mig() : MACH_PORT_NULL;
    mach_port_t special = get_special ? get_special() : MACH_PORT_NULL;
    /* Metadata only; this private symbol is frequently not exported. Never
     * write this storage or recover a guard context. */
    const mach_port_t *task_reply_address = (const mach_port_t *)dlsym(RTLD_DEFAULT, "_task_reply_port");
    mach_port_t task_reply = task_reply_address ? *task_reply_address : MACH_PORT_NULL;
    printf("{\"stage\":\"candidate_runtime\",\"round\":%u,\"threads\":%u,\"self_task\":%u,\"self_thread\":%u,"
           "\"mig_reply\":%u,\"special_reply\":%u,\"task_reply_symbol\":%s,\"task_reply\":%u}\n",
           round, thread_count, task, self, mig, special,
           task_reply_address ? "true" : "false", task_reply);
    /* Import slots must be dealt with separately from namespace names. This
     * diagnostic keeps inherited TASK_ACCESS policy slot; not certification. */
    if (task_set_special_port(task, TASK_BOOTSTRAP_PORT, MACH_PORT_NULL) != KERN_SUCCESS
        || mach_ports_register(task, NULL, 0) != KERN_SUCCESS
        || task_set_exception_ports(task, EXC_MASK_ALL, MACH_PORT_NULL,
                                    EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS
        || thread_set_exception_ports(self, EXC_MASK_ALL, MACH_PORT_NULL,
                                      EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) return 0;
    /* Two bounded rounds: mutate SEND-only entries, then observe no remnants.
     * SEND coalesced with our own RECEIVE targets that same LOCAL endpoint. */
    for (unsigned pass = 0; pass < 2; ++pass) {
        mach_port_name_array_t names = NULL;
        mach_port_type_array_t types = NULL;
        mach_msg_type_number_t nn = 0, nt = 0;
        rc = mach_port_names(task, &names, &nn, &types, &nt);
        if (rc != KERN_SUCCESS || nn != nt || nn > 256) return 0;
        int ok = 1;
        for (mach_msg_type_number_t i = 0; i < nn; ++i) {
            mach_port_name_t name = names[i];
            mach_port_type_t type = types[i];
            mach_port_status_t status = {0};
            mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
            mach_port_urefs_t refs = 0;
            int own_control = name == task || name == self;
            const char *action = own_control ? "preserve_own_control" : "reject_unknown";
            if (!own_control && (type & MACH_PORT_TYPE_RECEIVE)) {
                rc = mach_port_get_attributes(task, name, MACH_PORT_RECEIVE_STATUS,
                                              (mach_port_info_t)&status, &count);
                if (rc != KERN_SUCCESS || count != MACH_PORT_RECEIVE_STATUS_COUNT
                    || status.mps_msgcount != 0) ok = 0;
                /* mps_sorights is logged, not used as a standalone no-inflight
                 * proof: observing status may use a synchronous reply right. */
                action = "preserve_trusted_local_receive";
            } else if (!own_control && type == MACH_PORT_TYPE_SEND) {
                if (pass == 1) { ok = 0; action = "reject_remaining_send"; }
                else {
                    rc = mach_port_get_refs(task, name, MACH_PORT_RIGHT_SEND, &refs);
                    if (rc != KERN_SUCCESS || refs == 0 || refs > 65535) ok = 0;
                    action = "drop_send_urefs";
                }
            } else if (!own_control && type == MACH_PORT_TYPE_DEAD_NAME) {
                action = "preserve_noncapability_dead_name";
            } else if (!own_control) {
                /* Unknown SEND_ONCE, port-set or mixed type is not ignored. */
                ok = 0;
            }
            printf("{\"stage\":\"candidate_port\",\"round\":%u,\"pass\":%u,\"name\":%u,\"type\":%u,"
                   "\"refs\":%u,\"flags\":%u,\"queue\":%u,\"send_once\":%u,\"action\":\"%s\",\"metadata_ok\":%s}\n",
                   round, pass, name, type, refs, status.mps_flags, status.mps_msgcount,
                   status.mps_sorights, action, ok ? "true" : "false");
            fflush(stdout);
            if (!ok) break;
            if (!own_control && pass == 0 && type == MACH_PORT_TYPE_SEND) {
                /* Right-specific: never destroys RECEIVE or extracts guards.
                 * Unknown pinned send can still fault; candidate is own child
                 * only. An unsupported right must never be caught/ignored. */
                rc = mach_port_mod_refs(task, name, MACH_PORT_RIGHT_SEND,
                                        -(mach_port_delta_t)refs);
                printf("{\"stage\":\"candidate_drop_send\",\"round\":%u,\"name\":%u,\"rc\":%d}\n",
                       round, name, rc);
                fflush(stdout);
                if (rc != KERN_SUCCESS) { ok = 0; break; }
            }
        }
        kern_return_t free_names = vm_deallocate(task, (vm_address_t)names, nn * sizeof *names);
        kern_return_t free_types = vm_deallocate(task, (vm_address_t)types, nt * sizeof *types);
        if (!ok || free_names != KERN_SUCCESS || free_types != KERN_SUCCESS) return 0;
    }
    return 1;
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
    /* Owned foreign SEND canary: parent keeps RECEIVE; child only inherits a
     * registered SEND slot and explicitly acquires its namespace reference. */
    mach_port_t canary = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &canary) != KERN_SUCCESS
        || mach_port_insert_right(mach_task_self(), canary, canary, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS
        || mach_ports_register(mach_task_self(), &canary, 1) != KERN_SUCCESS) return 67;
    pid_t child = fork();
    if (child < 0) { free(profile); return 71; }
    if (child == 0) {
        alarm(3);
        mach_port_array_t inherited = NULL;
        mach_msg_type_number_t inherited_count = 0;
        if (mach_ports_lookup(mach_task_self(), &inherited, &inherited_count) != KERN_SUCCESS
            || inherited_count == 0 || inherited_count > 16 || !MACH_PORT_VALID(inherited[0])) _exit(36);
        mach_port_t foreign_canary = inherited[0];
        if (vm_deallocate(mach_task_self(), (vm_address_t)inherited,
                          inherited_count * sizeof *inherited) != KERN_SUCCESS) _exit(37);
        if (!fresh_facts("root_before_scrub", 0) || !scrub_names()) _exit(30);
        mach_port_type_t after_type = 0;
        kern_return_t after_rc = mach_port_type(mach_task_self(), foreign_canary, &after_type);
        int removed = after_rc == KERN_INVALID_NAME;
        printf("{\"stage\":\"owned_foreign_send_removed\",\"name\":%u,\"type_rc\":%d,\"removed\":%s}\n",
               foreign_canary, after_rc, removed ? "true" : "false");
        if (!removed) _exit(38);
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
