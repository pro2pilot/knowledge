/*
 * Test-only regression probe for the product's private_credentials() check.
 * Build with the same SDK used for the Darwin stub, then invoke as root with
 * one unused synthetic UID in [K_UID_FIRST, K_UID_LAST - 1). No exec, config,
 * imports, filesystem writes, account lookups, or foreign-process signals.
 */
#define main knowledge_stub_main
#include "verification-darwin-stub.c"
#undef main

#include <sys/wait.h>

struct ChildFacts {
    int32_t setgroups_ok;
    int32_t setgid_ok;
    int32_t setuid_ok;
    int32_t private_credentials_ok;
    int32_t query_count;
    int32_t read_count;
    int32_t query_errno_zero;
    int32_t read_errno_zero;
    int32_t values_match_expected;
    int32_t counts_match;
    int32_t stderr_suppressed;
};

struct CaseResult {
    struct ChildFacts facts;
    int32_t child_started;
    int32_t result_received;
    int32_t child_exited_zero;
    int32_t child_reaped;
};

static bool decimal_uid(const char *text, uid_t *out) {
    if (!text || !text[0]) return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++)
        if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    unsigned long long max_uid = (unsigned long long)((uid_t)-1);
    if (errno || !end || *end || value > max_uid) return false;
    if (value < K_UID_FIRST || value >= (uint64_t)K_UID_LAST - 1) return false;
    *out = (uid_t)value;
    return true;
}

static bool write_child_facts(int fd, const struct ChildFacts *facts) {
    const unsigned char *bytes = (const unsigned char *)facts;
    size_t remaining = sizeof(*facts);
    while (remaining) {
        ssize_t count = write(fd, bytes, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count;
        remaining -= (size_t)count;
    }
    return true;
}

static void child_case(int output_fd, int null_fd, uid_t uid, unsigned group_count) {
    alarm(5);
    struct ChildFacts facts = {0};
    facts.stderr_suppressed = dup2(null_fd, STDERR_FILENO) == STDERR_FILENO;
    gid_t groups[2] = {uid, (gid_t)(uid + 1)};

    if (facts.stderr_suppressed) {
        facts.setgroups_ok = setgroups(group_count, groups) == 0;
        if (facts.setgroups_ok) {
            facts.setgid_ok = setgid((gid_t)uid) == 0;
            if (facts.setgid_ok) facts.setuid_ok = setuid(uid) == 0;
            if (facts.setuid_ok) {
                facts.private_credentials_ok = private_credentials(uid);
                errno = 0;
                facts.query_count = kernel_getgroups(0, NULL);
                facts.query_errno_zero = errno == 0;
                gid_t observed[2] = {0, 0};
                errno = 0;
                facts.read_count = kernel_getgroups(2, observed);
                facts.read_errno_zero = errno == 0;
                facts.counts_match = facts.query_errno_zero && facts.read_errno_zero
                    && facts.query_count == (int32_t)group_count
                    && facts.read_count == facts.query_count;
                facts.values_match_expected = facts.read_count == (int32_t)group_count
                    && observed[0] == (gid_t)uid
                    && (group_count == 1 || observed[1] == (gid_t)(uid + 1));
            }
        }
    }

    bool written = write_child_facts(output_fd, &facts);
    close(output_fd);
    close(null_fd);
    _exit(written ? 0 : 2);
}

static bool wait_owned_child(pid_t child, int *status) {
    for (unsigned attempt = 0; attempt < 350; attempt++) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child) return true;
        if (result < 0 && errno != EINTR) return false;
        struct timespec pause = {0, 20000000};
        nanosleep(&pause, NULL);
    }
    return false;
}

static bool read_facts(int fd, struct ChildFacts *facts) {
    unsigned char *bytes = (unsigned char *)facts;
    size_t remaining = sizeof(*facts);
    while (remaining) {
        ssize_t count = read(fd, bytes, remaining);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        bytes += count;
        remaining -= (size_t)count;
    }
    unsigned char extra;
    ssize_t tail;
    do { tail = read(fd, &extra, 1); } while (tail < 0 && errno == EINTR);
    return tail == 0;
}

static struct CaseResult run_case(int null_fd, uid_t uid, unsigned group_count) {
    struct CaseResult result = {0};
    int channel[2];
    if (pipe(channel)) return result;
    pid_t child = fork();
    if (child < 0) {
        close(channel[0]); close(channel[1]);
        return result;
    }
    if (child == 0) {
        close(channel[0]);
        child_case(channel[1], null_fd, uid, group_count);
    }

    close(channel[1]);
    result.child_started = 1;
    int status = 0;
    result.child_reaped = wait_owned_child(child, &status);
    if (result.child_reaped) {
        result.child_exited_zero = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        result.result_received = read_facts(channel[0], &result.facts);
    }
    close(channel[0]);
    return result;
}

static bool case_passed(const struct CaseResult *result,
                        bool expected_private_credentials) {
    const struct ChildFacts *f = &result->facts;
    return result->child_started && result->child_reaped && result->child_exited_zero && result->result_received
        && f->stderr_suppressed && f->setgroups_ok && f->setgid_ok && f->setuid_ok
        && f->query_errno_zero && f->read_errno_zero && f->counts_match
        && f->values_match_expected
        && (f->private_credentials_ok != 0) == expected_private_credentials;
}

static void print_case(const char *name, unsigned requested,
                       const struct CaseResult *result,
                       bool expected_private_credentials) {
    const struct ChildFacts *f = &result->facts;
    printf("{\"name\":\"%s\",\"requested_group_count\":%u,"
           "\"setgroups_ok\":%s,\"setgid_ok\":%s,\"setuid_ok\":%s,"
           "\"kernel_getgroups_size0_count\":%d,\"kernel_getgroups_read_count\":%d,"
           "\"errno_clear\":%s,\"counts_match\":%s,\"values_match_expected\":%s,"
           "\"private_credentials\":%s,\"expected_private_credentials\":%s,"
           "\"child_started\":%s,\"child_reaped\":%s,\"result_received\":%s,\"passed\":%s}",
           name, requested, f->setgroups_ok ? "true" : "false",
           f->setgid_ok ? "true" : "false", f->setuid_ok ? "true" : "false",
           f->query_count, f->read_count,
           f->query_errno_zero && f->read_errno_zero ? "true" : "false",
           f->counts_match ? "true" : "false", f->values_match_expected ? "true" : "false",
           f->private_credentials_ok ? "true" : "false",
           expected_private_credentials ? "true" : "false",
           result->child_started ? "true" : "false",
           result->child_reaped ? "true" : "false", result->result_received ? "true" : "false",
           case_passed(result, expected_private_credentials) ? "true" : "false");
}

int main(int argc, char **argv) {
    if (getuid() != 0 || geteuid() != 0) {
        puts("{\"schema\":\"knowledge-kernel-groups-regression.v1\",\"status\":\"NOT_RUN_REQUIRES_ROOT\",\"backend_certified\":false}");
        return 2;
    }
    uid_t uid;
    if (argc != 2 || !decimal_uid(argv[1], &uid)) {
        puts("{\"schema\":\"knowledge-kernel-groups-regression.v1\",\"status\":\"INVALID_TEST_UID\",\"backend_certified\":false}");
        return 2;
    }

    int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (null_fd < 0) {
        puts("{\"schema\":\"knowledge-kernel-groups-regression.v1\",\"status\":\"SETUP_FAILED\",\"backend_certified\":false}");
        return 1;
    }
    struct CaseResult one = run_case(null_fd, uid, 1);
    struct CaseResult two = {0};
    if (one.child_reaped) two = run_case(null_fd, uid, 2);
    close(null_fd);

    bool one_pass = case_passed(&one, true);
    bool two_pass = case_passed(&two, false);
    bool cleanup_confirmed = (!one.child_started || one.child_reaped)
        && (!two.child_started || two.child_reaped);
    bool passed = one_pass && two_pass && cleanup_confirmed;
    printf("{\"schema\":\"knowledge-kernel-groups-regression.v1\",\"status\":\"%s\","
           "\"backend_certified\":false,\"case_count\":2,\"cleanup_confirmed\":%s,\"cases\":[",
           passed ? "PASS" : cleanup_confirmed ? "FAIL" : "UNCONFIRMED",
           cleanup_confirmed ? "true" : "false");
    print_case("single_synthetic_group", 1, &one, true);
    putchar(',');
    print_case("two_synthetic_groups", 2, &two, false);
    puts("]}");
    return passed ? 0 : 1;
}
