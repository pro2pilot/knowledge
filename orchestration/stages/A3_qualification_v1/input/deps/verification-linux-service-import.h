#ifndef KNOWLEDGE_LINUX_SERVICE_IMPORT_H
#define KNOWLEDGE_LINUX_SERVICE_IMPORT_H
#include "verification-linux-uid-history.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define KV_LINUX_IMPORT_DEPENDENCIES 6
/* Administrative installed-byte pins, never caller payload/configuration. */
struct kv_linux_import_pins { unsigned char node[32], dependencies[KV_LINUX_IMPORT_DEPENDENCIES][32]; };
struct kv_linux_import_input {
    int source_fd; /* caller retains ownership; native sealed anonymous fd */
    int peer_pidfd; /* held authenticated peer from actor claim; caller retains */
    kv_linux_uid_reservation reservation;
    uint64_t work_deadline_ns, cleanup_deadline_ns;
};
/* Serialized root-native parent owns these descriptors until process reaping
 * AND receipt EOF. Fields are native observations, not serializable proofs.
 * UID=burned authority UID; primary GID=burned worker GID. This fixed importer
 * role never runs commands or grants authority; a future authority cannot
 * reuse its custody without native drain/readonly-mount proof. */
struct kv_linux_import_process {
    pid_t pid, owner_pid;
    int pidfd, peer_pidfd, receipt_fd, job_directory_fd, source_directory_fd;
    int reaped, receipt_eof, cancelled, failed, exit_code;
    uint64_t work_deadline_ns, cleanup_deadline_ns;
    dev_t source_dev; ino_t source_ino;
    unsigned char receipt[4097]; size_t receipt_bytes;
};
/* Fixed protected Node/entry/dependencies; fixed native-generated destination.
 * Root executes only this C launch path. Child drops all authority before Node.
 * Parent obtains held pidfd before releasing the child's start barrier.
 * Failure never closes UID history, removes output, or resets the reservation. */
int kv_linux_import_start(const struct kv_linux_import_pins *, const struct kv_linux_import_input *, struct kv_linux_import_process *);
/* Private custody keeper only. Creates a new PID+mount namespace init and
 * attaches its held, unreaped birth to the supplied native-owned cgroup before
 * releasing the start barrier. The keeper must already own an isolated user/
 * mount namespace with exact reserved-ID mappings and no supplementary groups.
 * The original native child opens its own PID namespace and transfers exactly
 * one descriptor over a pre-fork private channel; the keeper checks automatic
 * sender credentials against its actual held child birth and validates NSFS,
 * PID namespace type, distinct original namespace and EOF before gate release.
 * Node runs as ordinary PID 1; peer pidfd liveness never requires a visible PID
 * inside that namespace. This does not by itself seal or close the source. */
int kv_linux_import_start_isolated(const struct kv_linux_import_pins *, const struct kv_linux_import_input *,
    int owned_cgroup_directory_fd, int *init_namespace_fd, struct kv_linux_import_process *);
/* Nonblocking. 0 active; 1 reaped+EOF (inspect failed/cancelled/exit_code);
 * -1 native observation failure, retained process still requires cancellation.
 * A successful observation is IMPORTED_BYTES_UNSEALED only, not namespace drain. */
int kv_linux_import_poll(struct kv_linux_import_process *);
int kv_linux_import_cancel(struct kv_linux_import_process *);
/* Refuses EBUSY until reaped+EOF. Never deletes native-owned directories. */
int kv_linux_import_close(struct kv_linux_import_process *);
extern const char *const kv_linux_import_dependency_paths[KV_LINUX_IMPORT_DEPENDENCIES];
#endif
