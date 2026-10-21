#define _DARWIN_C_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static bool lower_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
static bool suffix_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}
static bool valid_path(const char *path, const char **fixture, const char **leaf) {
    const char *prefix = "/private/tmp/knowledge-launchd-smoke.";
    size_t prefix_len = strlen(prefix);
    if (!path || strncmp(path, prefix, prefix_len) != 0) return false;
    const char *name = path + prefix_len;
    const char *slash = strchr(name, '/');
    if (!slash || slash == name) return false;
    for (const char *p = name; p < slash; p++) if (!suffix_char(*p)) return false;
    if (strncmp(slash, "/registry/", 10) != 0) return false;
    const char *file = slash + 10;
    if (strlen(file) != 64 + strlen(".admission")) return false;
    for (size_t i = 0; i < 64; i++) if (!lower_hex(file[i])) return false;
    if (strcmp(file + 64, ".admission") != 0) return false;
    *fixture = path + strlen("/private/tmp/");
    *leaf = file;
    return true;
}
static bool safe_directory(int fd, bool sticky_tmp) {
    struct stat st;
    if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != 0) return false;
    if ((st.st_mode & 0022) == 0) return true;
    /* Only literal /private/tmp is passed sticky_tmp; allow its standard 01777 mode. */
    return sticky_tmp && (st.st_mode & 07777) == 01777;
}
static int open_dir(int parent, const char *name, bool sticky_tmp) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (!safe_directory(fd, sticky_tmp)) { close(fd); return -1; }
    return fd;
}
static bool pause_until_milliseconds(long milliseconds) {
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return false;
    const long long target = (long long)milliseconds * 1000000LL;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return false;
        long long elapsed = (long long)(now.tv_sec - start.tv_sec) * 1000000000LL +
                            (long long)now.tv_nsec - (long long)start.tv_nsec;
        if (elapsed >= target) return true;
        long long left = target - elapsed;
        struct timespec wait = { (time_t)(left / 1000000000LL), (long)(left % 1000000000LL) };
        if (nanosleep(&wait, NULL) && errno != EINTR) return false;
    }
}
static int fail(const char *reason) {
    printf("{\"ok\":false,\"result\":\"%s\"}\n", reason);
    return 2;
}
int main(int argc, char **argv) {
    bool check = argc == 3 && strcmp(argv[1], "--check") == 0;
    bool hold = argc == 3 && strcmp(argv[1], "--hold=1500") == 0;
    if ((!check && !hold) || geteuid() != 0) return fail("invalid_invocation");
    const char *fixture = NULL, *leaf = NULL;
    if (!valid_path(argv[2], &fixture, &leaf)) return fail("invalid_path");
    int root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0 || !safe_directory(root, false)) return fail("unsafe_root");
    int private_fd = open_dir(root, "private", false);
    int tmp_fd = private_fd >= 0 ? open_dir(private_fd, "tmp", true) : -1;
    char fixture_name[256];
    size_t fixture_len = (size_t)(strchr(fixture, '/') - fixture);
    if (fixture_len == 0 || fixture_len >= sizeof(fixture_name)) return fail("invalid_fixture");
    memcpy(fixture_name, fixture, fixture_len);
    fixture_name[fixture_len] = '\0';
    int fixture_fd = tmp_fd >= 0 ? open_dir(tmp_fd, fixture_name, false) : -1;
    int registry_fd = fixture_fd >= 0 ? open_dir(fixture_fd, "registry", false) : -1;
    if (registry_fd < 0) return fail("unsafe_ancestor");
    int admission = openat(registry_fd, leaf, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (admission < 0 || fstat(admission, &st) || !S_ISREG(st.st_mode) ||
        st.st_uid != 0 || st.st_nlink != 1 || (st.st_mode & 07777) != 0600)
        return fail("unsafe_admission_file");
    if (flock(admission, LOCK_EX | LOCK_NB) != 0) {
        if (check && errno == EWOULDBLOCK) {
            printf("{\"ok\":true,\"result\":\"already_held\"}\n");
            return 0;
        }
        return fail("flock_failed");
    }
    if (check) {
        close(admission);
        return fail("unexpectedly_acquired");
    }
    alarm(6);
    printf("{\"ok\":true,\"result\":\"hold_started\",\"pid\":%ld,\"device\":%" PRIuMAX
           ",\"inode\":%" PRIuMAX "}\n",
           (long)getpid(), (uintmax_t)st.st_dev, (uintmax_t)st.st_ino);
    fflush(stdout);
    bool held = pause_until_milliseconds(1500);
    close(admission);
    close(registry_fd);
    close(fixture_fd);
    close(tmp_fd);
    close(private_fd);
    close(root);
    alarm(0);
    if (!held) return fail("hold_wait_failed");
    printf("{\"ok\":true,\"result\":\"hold_complete\"}\n");
    return 0;
}
