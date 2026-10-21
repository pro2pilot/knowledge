/* Read-only Darwin process-creation-parent diagnostic; never signals a target. */
#if !defined(__APPLE__)
#error "launch-origin-probe requires the macOS SDK and a real Darwin host"
#endif
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <unistd.h>

/* Kept ABI-identical to verification-darwin-broker.m, not a public SDK type. */
struct KUnique {
    uint8_t uuid[16];
    uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion;
    uint32_t reserved;
    uint64_t reserved2, reserved3;
};
struct KIdentity { struct proc_bsdinfo bsd; struct KUnique unique; };
_Static_assert(sizeof(struct KUnique) == 56, "Darwin proc unique ABI changed");

struct Snapshot { struct KIdentity id; char image[PROC_PIDPATHINFO_MAXSIZE]; };
static volatile sig_atomic_t alarm_fired;

static bool fresh_identity(pid_t pid, struct KIdentity *v) {
    memset(v, 0, sizeof(*v));
    return pid > 0 && proc_pidinfo(pid, 18, 0, v, sizeof(*v)) == (int)sizeof(*v) &&
        v->bsd.pbi_pid == (uint32_t)pid && v->unique.uniqueid > 0 && v->unique.pidversion > 0;
}

static bool same_birth(const struct KIdentity *a, const struct KIdentity *b) {
    return a->bsd.pbi_pid == b->bsd.pbi_pid && a->bsd.pbi_ppid == b->bsd.pbi_ppid &&
        a->bsd.pbi_start_tvsec == b->bsd.pbi_start_tvsec &&
        a->bsd.pbi_start_tvusec == b->bsd.pbi_start_tvusec &&
        a->bsd.pbi_ruid == b->bsd.pbi_ruid && a->bsd.pbi_uid == b->bsd.pbi_uid &&
        a->bsd.pbi_svuid == b->bsd.pbi_svuid &&
        a->unique.uniqueid == b->unique.uniqueid &&
        a->unique.parent_uniqueid == b->unique.parent_uniqueid &&
        a->unique.pidversion == b->unique.pidversion;
}

static bool stable_snapshot(pid_t pid, struct Snapshot *out) {
    struct KIdentity first, second;
    char path_first[PROC_PIDPATHINFO_MAXSIZE], path_second[PROC_PIDPATHINFO_MAXSIZE];
    if (!fresh_identity(pid, &first) || !fresh_identity(pid, &second) ||
        !same_birth(&first, &second) || proc_pidpath(pid, path_first, sizeof(path_first)) <= 0 ||
        proc_pidpath(pid, path_second, sizeof(path_second)) <= 0 ||
        strcmp(path_first, path_second) != 0) return false;
    out->id = second;
    strlcpy(out->image, path_second, sizeof(out->image));
    return true;
}

static void json_string(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    putchar('"');
    for (; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static void print_identity(const struct Snapshot *s) {
    const struct KIdentity *v = &s->id;
    printf("{\"pid\":%u,\"ppid\":%u,\"unique_id\":\"%" PRIu64
           "\",\"parent_unique_id\":\"%" PRIu64 "\",\"start_sec\":%" PRIu64
           ",\"start_usec\":%" PRIu64 ",\"ruid\":%u,\"euid\":%u,\"suid\":%u,\"image\":",
           v->bsd.pbi_pid, v->bsd.pbi_ppid, v->unique.uniqueid, v->unique.parent_uniqueid,
           (uint64_t)v->bsd.pbi_start_tvsec, (uint64_t)v->bsd.pbi_start_tvusec,
           v->bsd.pbi_ruid, v->bsd.pbi_uid, v->bsd.pbi_svuid);
    json_string(s->image);
    printf(",\"ruid_is_root\":%s,\"euid_is_root\":%s,\"suid_is_root\":%s}",
           v->bsd.pbi_ruid == 0 ? "true" : "false",
           v->bsd.pbi_uid == 0 ? "true" : "false",
           v->bsd.pbi_svuid == 0 ? "true" : "false");
}

static int report(pid_t pid, const char *mode) {
    struct Snapshot target, init;
    if (!stable_snapshot(pid, &target) || !stable_snapshot(1, &init)) {
        fprintf(stderr, "could not read two stable process identities\n");
        return 2;
    }
    bool pid1_image = strcmp(init.image, "/sbin/launchd") == 0;
    bool parent_matches = target.id.unique.parent_uniqueid == init.id.unique.uniqueid;
    bool is_init = target.id.bsd.pbi_ppid == 1 && parent_matches && pid1_image;
    printf("{\"schema\":\"knowledge-launch-origin.v1\",\"mode\":");
    json_string(mode);
    printf(",\"target_identity_fresh_twice\":true,\"pid1_identity_fresh_twice\":true,\"target\":");
    print_identity(&target);
    printf(",\"pid1_birth\":");
    print_identity(&init);
    printf(",\"proc_pidpath_pid1_is_sbin_launchd\":%s,\"parent_unique_matches_pid1\":%s,\"creation_parent_is_init\":%s}\n",
           pid1_image ? "true" : "false", parent_matches ? "true" : "false",
           is_init ? "true" : "false");
    return 0;
}

static void alarm_handler(int signo) { (void)signo; alarm_fired = 1; }

static int orphan_canary(void) {
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 2; }
    if (child > 0) _exit(0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) != 0) _exit(2);
    alarm(5);
    while (!alarm_fired) {
        struct KIdentity current;
        if (fresh_identity(getpid(), &current) && current.bsd.pbi_ppid == 1)
            return report(getpid(), "orphan-canary");
        (void)poll(NULL, 0, 10);
    }
    puts("{\"schema\":\"knowledge-launch-origin.v1\",\"mode\":\"orphan-canary\",\"status\":\"reparent-timeout\",\"creation_parent_is_init\":false}");
    return 3;
}

static bool parse_pid(const char *s, pid_t *out) {
    if (!s[0]) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    char *end = NULL;
    errno = 0;
    long value = strtol(s, &end, 10);
    if (errno || !s[0] || !end || *end || value <= 0 || value > INT32_MAX) return false;
    *out = (pid_t)value;
    return true;
}

int main(int argc, char **argv) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--self") == 0))
        return report(getpid(), "self");
    if (argc == 2 && strcmp(argv[1], "--orphan-canary") == 0)
        return orphan_canary();
    if (argc == 2 && strncmp(argv[1], "--pid=", 6) == 0) {
        pid_t pid;
        if (parse_pid(argv[1] + 6, &pid)) return report(pid, "pid");
    }
    fprintf(stderr, "usage: %s [--self|--pid=<positive-integer>|--orphan-canary]\n", argv[0]);
    return 64;
}
