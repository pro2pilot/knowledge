#ifndef KNOWLEDGE_LINUX_SERVICE_VERIFY_H
#define KNOWLEDGE_LINUX_SERVICE_VERIFY_H
#include "verification-linux-uid-history.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define KV_LINUX_VERIFY_DEPENDENCIES 7
#define KV_LINUX_VERIFY_CONTENT_REPORT_BYTES 256
struct kv_linux_verify_content;
struct kv_linux_verify_pins { unsigned char node[32], dependencies[KV_LINUX_VERIFY_DEPENDENCIES][32]; };
struct kv_linux_verify_expected {
    kv_linux_uid_reservation reservation;
    uint64_t work_deadline_ns, cleanup_deadline_ns;
    uint64_t source_dev, source_ino, time_namespace_dev, time_namespace_ino;
    unsigned char source_sha256[32], manifest_sha256[32], directories_sha256[32];
};
/* Native serialized owner must maintain actual readonly custody, reservation,
 * peer and stop/recovery state. Not a JS callback, caller boolean or receipt.
 * It must outlive this verifier process and never grant authority by itself. */
typedef int (*kv_linux_verify_owner_check)(void *, const struct kv_linux_verify_expected *);
struct kv_linux_verify_input {
    int source_fd, readonly_root_fd, peer_pidfd; /* caller retains these */
    struct kv_linux_verify_expected expected;
    kv_linux_verify_owner_check owner_check;
    void *owner_context;
};
/* DATA observation, never a service/public authority or finality proof. */
struct kv_linux_verify_content_observation {
    uint32_t schema_version; /* 1 */
    struct kv_linux_verify_expected expected;
    unsigned char config_sha256[32], report_sha256[32];
};
struct kv_linux_verify_process {
    pid_t pid, owner_pid;
    int pidfd, peer_pidfd, receipt_fd, job_directory_fd, source_directory_fd;
    int start_fd, preparation_fd, content_report_fd;
    int reaped, receipt_eof, cancelled, failed, exit_code;
    int preparation_received, preparation_eof, preparation_failed;
    /* Known nonce may name a partial artifact even before its FD is admitted.
     * Neither process completion nor close confirms removal of that artifact. */
    int generation_artifact_unconfirmed;
    int content_report_eof, content_report_valid, content_claim_attempted;
    struct kv_linux_verify_content *content_claim;
    unsigned char config_sha256[32];
    unsigned char content_report[KV_LINUX_VERIFY_CONTENT_REPORT_BYTES+1];
    size_t content_report_bytes;
    struct kv_linux_verify_expected expected;
    kv_linux_verify_owner_check owner_check;
    void *owner_context;
    unsigned char receipt[4097];size_t receipt_bytes;
};
/* Root executes fixed C only. Private pinned runtime snapshot precedes a drop
 * to the burned authority UID / worker GID, all caps0 and NNP. The source root
 * must already be a held directory on a readonly tmpfs; no path, chmod, mount
 * or project JSON is interpreted by this launcher. No commands are executed.
 * Runtime path walks/creation/copy occur only in the held child after its
 * abortable start barrier. Parent accepts one credential/birth/nonce-bound
 * generation directory FD; it never reopens the generation by pathname.
 * FD9 is a dedicated fixed binary content-report pipe; JSON FD6 is diagnostic.
 * Caller input/pins are copied before fork. The owner callback/context must
 * remain valid until close. Failure after fork retains process and all three
 * output channels, including failures opening pidfd or releasing the barrier.
 * Pre-fork held-FD/proc/memfd metadata is not an arbitrary kernel-I/O bound.
 * A live polling owner enforces epochs; stopped owners/D-state are unqualified. */
int kv_linux_verify_start(const struct kv_linux_verify_pins *, const struct kv_linux_verify_input *, struct kv_linux_verify_process *);
/* 0 active; 1 reaped+receipt EOF+preparation EOF+content-report EOF;
 * -1 unconfirmed observation.
 * On failure retain/poll
 * custody until actual completion. Exit/receipt observations are not native
 * finality, service activation or a replacement for whole namespace custody. */
int kv_linux_verify_poll(struct kv_linux_verify_process *);
int kv_linux_verify_cancel(struct kv_linux_verify_process *);
/* EBUSY until all three real output/preparation EOFs and reap. Invalidates
 * borrowed content handles. Does not delete artifacts. */
int kv_linux_verify_close(struct kv_linux_verify_process *);
/* 0 success; -1 refusal, output untouched. Pure readiness refusal is retryable;
 * after readiness, one-shot admission is consumed BEFORE any current check.
 * Failure then stays sticky, including transient EMFILE/owner/clock refusal.
 * Handle is borrowed until process close. Provider must retain process, owner
 * context and actual custody/guard throughout use. No native/public activation. */
int kv_linux_verify_claim_content(struct kv_linux_verify_process *,const struct kv_linux_verify_content **);
/* Pure DATA copy. Current liveness is not implied; caller must use the fresh
 * current guard at the actual native use under its serialized owner. */
int kv_linux_verify_content_observe(const struct kv_linux_verify_content *,struct kv_linux_verify_content_observation *);
/* 0 current; -1 permanently invalid. The owner callback must not recursively
 * poll this verifier. This guard never refreshes epochs or revives a failure. */
int kv_linux_verify_content_current(const struct kv_linux_verify_content *);
extern const char *const kv_linux_verify_dependency_paths[KV_LINUX_VERIFY_DEPENDENCIES];
#endif
