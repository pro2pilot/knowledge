/* QA-only ordinary-owner image membership snapshot. Read-only, no signaling.
 * For quiescent owned fixture housekeeping, not a native cleanup proof or reap. */
#include <libproc.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2 || getuid() == 0 || geteuid() != getuid()) return 64;
    char physical[PATH_MAX]; struct stat st;
    if (argv[1][0] != '/' || !realpath(argv[1], physical) || strcmp(physical, argv[1]) ||
        lstat(physical, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
        st.st_nlink != 1 || (st.st_mode & 07777) != 0555) return 78;
    const int limit = 65536;
    pid_t *pids = calloc((size_t)limit, sizeof(pid_t)); if (!pids) return 71;
    errno = 0;
    int bytes = proc_listpids(PROC_RUID_ONLY, getuid(), pids, limit * (int)sizeof(pid_t));
    int list_error = errno, self_seen = 0, matches = 0, unknown = 0;
    int valid = !list_error && bytes > 0 && bytes < limit * (int)sizeof(pid_t) &&
                bytes % (int)sizeof(pid_t) == 0;
    if (valid) for (int i = 0; i < bytes / (int)sizeof(pid_t); ++i) {
        if (pids[i] <= 0) { unknown++; continue; }
        if (pids[i] == getpid()) self_seen = 1;
        char image[PROC_PIDPATHINFO_MAXSIZE] = {0}; errno = 0;
        int count = proc_pidpath(pids[i], image, sizeof(image));
        int path_error = errno;
        if (count <= 0) { if (path_error != ESRCH) unknown++; continue; }
        if (count >= (int)sizeof(image) || !memchr(image, '\0', sizeof(image))) { unknown++; continue; }
        if (!strcmp(image, physical)) matches++;
    }
    valid = valid && self_seen && !unknown;
    printf("{\"schema\":\"knowledge-qa-helper-image-observation.v1\",\"owner_uid\":%u,"
           "\"observation_valid\":%s,\"self_canary\":%s,\"unknown\":%d,"
           "\"image_members\":%d,\"reaped\":false,\"production_proof\":false}\n",
           (unsigned)getuid(), valid ? "true" : "false", self_seen ? "true" : "false",
           unknown, valid ? matches : -1);
    free(pids);
    return valid ? (matches == 0 ? 0 : 1) : 2;
}
