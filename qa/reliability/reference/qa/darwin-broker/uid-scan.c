/* Audit-only, read-only private UID membership observation. No signaling. */
#include <libproc.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char **argv) {
  if (argc != 2) return 64;
  char *end = NULL; errno = 0; unsigned long uid = strtoul(argv[1], &end, 10);
  if (errno || !end || *end || uid < 1000000000ul || uid >= 1900000000ul) return 64;
  pid_t *pids = calloc(65536, sizeof(pid_t)); if (!pids) return 71;
  errno = 0;
  int control = proc_listpids(PROC_RUID_ONLY, getuid(), pids, 65536 * sizeof(pid_t));
  int control_errno = errno; errno = 0;
  int bytes = proc_listpids(PROC_RUID_ONLY, (uint32_t)uid, pids, 65536 * sizeof(pid_t));
  int observed_errno = errno;
  int valid = control > 0 && !control_errno && bytes >= 0 && !observed_errno &&
              bytes < 65536 * (int)sizeof(pid_t) && bytes % (int)sizeof(pid_t) == 0;
  printf("{\"uid\":%lu,\"observation_valid\":%s,\"member_count\":%d,\"errno\":%d,\"members\":[",
         uid, valid ? "true" : "false", valid ? bytes / (int)sizeof(pid_t) : -1, observed_errno);
  if (valid) for (int i = 0; i < bytes / (int)sizeof(pid_t); i++) printf("%s%d", i ? "," : "", pids[i]);
  puts("]}"); free(pids);
  return valid ? (bytes == 0 ? 0 : 1) : 2;
}

