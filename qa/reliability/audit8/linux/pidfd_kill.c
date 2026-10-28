#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

/* QA-only fixed native operation. FD0 is the caller's already retained pidfd,
 * preserved as standard input through sudo/timeout. There is no PID lookup,
 * pathname, protocol parser, configurable signal, or product admission hook. */
int main(int argc, char **argv) {
  (void)argv;
  if (argc != 1 || getuid() != 0 || geteuid() != 0) return 2;
  struct pollfd held = { STDIN_FILENO, POLLIN, 0 };
  if (poll(&held, 1, 0) != 0) return 3;
  if (syscall(SYS_pidfd_send_signal, STDIN_FILENO, 0, NULL, 0)) return 4;
  if (syscall(SYS_pidfd_send_signal, STDIN_FILENO, SIGKILL, NULL, 0)) return 5;
  return 0;
}
