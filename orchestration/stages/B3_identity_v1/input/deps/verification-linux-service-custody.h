#ifndef KNOWLEDGE_LINUX_SERVICE_CUSTODY_H
#define KNOWLEDGE_LINUX_SERVICE_CUSTODY_H
#include "verification-linux-service-import.h"

typedef struct kv_linux_source_custody kv_linux_source_custody;
enum kv_linux_source_phase {
    KV_SOURCE_STARTING=1, KV_SOURCE_IMPORTING=2, KV_SOURCE_DRAINING=3,
    KV_SOURCE_READONLY_READY=4, KV_SOURCE_RETAINED_UNCONFIRMED=5
};
struct kv_linux_source_observation {
    enum kv_linux_source_phase phase;
    int cancelled, failed, keeper_reaped, control_eof;
    int init_reaped, receipt_eof, cgroup_empty, superblock_readonly;
    int seal_errno; /* Exact failed whole-superblock remount errno, otherwise 0. */
    uint64_t init_namespace_dev, init_namespace_ino;
    uint64_t cgroup_dev, cgroup_ino, source_dev, source_ino;
    int content_verified_after_drain; /* Always false in this boundary. */
    size_t receipt_bytes;
    unsigned char receipt[4096]; /* Ordinary importer data, not authority proof. */
};
/* One root-native caller lifetime. Inputs/pins are already authenticated native
 * administrative values; no packet selects a path, UID or executable. Caller
 * retains input descriptors. Forked keeper owns fresh private namespaces and a
 * dedicated tmpfs, exact allocated-ID maps and a native-owned child cgroup.
 * No existing daemon/actor API is activated by this separate component.
 * NULL means a pre-fork refusal only. Non-NULL retains the exact child/control
 * lifetime even if setup already failed; callers must poll/observe and close.
 * Protected path admission and nonce mkdir/fsync happen only in that child
 * after its held-pidfd/abortable start barrier. Duplicate nonce refusal is
 * asynchronous. A pre-guard failure cannot persist a nonce here: the caller's
 * durable one-shot actor reservation must remain pending and forbid retries.
 * A live polling owner enforces setup expiry; paused-controller autonomy and
 * interruptibility of arbitrary kernel I/O are not claimed. */
kv_linux_source_custody *kv_linux_source_custody_start(const struct kv_linux_import_pins *,
    const struct kv_linux_import_input *);
/* Nonblocking native observation. Retains unknown/failed custody; never treats
 * keeper death, missing output, direct-child-only exit or timeout as a seal.
 * Caller must keep polling through original work/cleanup deadlines. */
int kv_linux_source_custody_poll(kv_linux_source_custody *, unsigned max_wait_ms);
int kv_linux_source_custody_observe(const kv_linux_source_custody *, struct kv_linux_source_observation *);
void kv_linux_source_custody_cancel(kv_linux_source_custody *);
/* One shot, only after independent init birth/death/reap/EOF and exact cgroup
 * populated-zero observations, whole dedicated tmpfs superblock readonly,
 * source identity, live keeper/peer and fresh ORIGINAL work deadline checks.
 * Returns a CLOEXEC O_RDONLY directory fd, never a writable alias or namespace
 * descriptor. Caller initializes *out=-1 and owns it on success. The ordinary
 * import receipt predates namespace drain; descendants could have changed the
 * tree afterwards. A fixed nonroot verifier MUST compare the entire readonly
 * inventory to the sealed envelope before any authority command. No content
 * authentication is implied by these custody/mount facts. No KVE,
 * authority execution, journal closure, UID reuse or production qualification. */
int kv_linux_source_custody_claim_readonly(kv_linux_source_custody *, int *out);
/* Requests native termination; EBUSY while keeper birth/EOF remain unresolved.
 * Never recursively removes a retained source or closes durable UID history. */
int kv_linux_source_custody_close(kv_linux_source_custody *);
#endif
