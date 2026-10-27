/* QA ONLY: bounded credential observation in a disposable original-owner
 * setuid leaf. This is never installed setuid-root and is never a product
 * helper. The controller installs it only in its freshly owned test workspace
 * with owner equal to the ordinary test UID. It neither forks nor changes
 * credentials, opens files, invokes a shell, or performs external actions.
 * The private-RUID executable allowlist must deny its exec before this runs.
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 64;
    printf("{\"schema\":\"knowledge-macos-owner-exec-canary.v1\","
           "\"ruid\":%u,\"euid\":%u,\"rgid\":%u,\"egid\":%u}\n",
           (unsigned)getuid(), (unsigned)geteuid(),
           (unsigned)getgid(), (unsigned)getegid());
    return 0;
}
