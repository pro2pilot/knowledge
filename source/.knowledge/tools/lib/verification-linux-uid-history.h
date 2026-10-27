#ifndef KNOWLEDGE_LINUX_UID_HISTORY_H
#define KNOWLEDGE_LINUX_UID_HISTORY_H
#include <stdint.h>

/* Native root-only persistence primitive; NOT an admitted execution backend.
 * All callers must be a single serialized native broker lifecycle actor.
 * No Node/project code may execute as root. Configuration is administrative,
 * never derived from a public caller's paths, UID, proof or force flag.
 *
 * Existing anchor_dir and journal_dir must have root-owned protected directory
 * chains, be distinct non-overlapping directories with mode0700 and no ACLs.
 * The marker/latest-head and append-only journal are independently anchored.
 * UID/GID range reservation and conflict checks belong to the administrator.
 * This module never creates accounts, resets history, reuses a UID, signals a
 * process, trusts lease age, or attests coherent rollback of all root records.
 *
 * Build with OpenSSL libcrypto (EVP SHA-256); do not substitute weak hashes.
 */
typedef struct kv_linux_uid_history kv_linux_uid_history;
typedef struct {
    const char *anchor_dir;
    const char *journal_dir;
    uint32_t uid_first, uid_last; /* inclusive, fixed reserved native range */
    unsigned char installation_id[16], host_id[16];
} kv_linux_uid_configuration;
typedef struct {
    uint64_t allocation_sequence;
    uint32_t authority_uid, worker_uid;
    unsigned char attempt_nonce[32], boot_id[16];
} kv_linux_uid_reservation;
typedef struct {
    uint64_t record_sequence, allocations;
    int pending_cleanup;
    kv_linux_uid_reservation reservation;
    unsigned char checkpoint_sha256[32];
} kv_linux_uid_snapshot;

/* Explicit administrator initialization: both existing directories must be
 * empty. Any partial failure is retained; initialization never repairs it. */
int kv_linux_uid_initialize(const kv_linux_uid_configuration *configuration,
                            const char **reason);
/* A consistent pending reservation may be opened for exact native recovery,
 * but reserve refuses admission until record_closed succeeds. Missing/corrupt
 * records return NULL and never create files. Lock is retained until close. */
kv_linux_uid_history *kv_linux_uid_open(const kv_linux_uid_configuration *configuration,
                                      const char **reason);
int kv_linux_uid_read(kv_linux_uid_history *history, kv_linux_uid_snapshot *snapshot);
/* Burn and publish journal+head BEFORE returning a reservation. Every prior
 * attempt_nonce remains unique, including terminal attempts. */
int kv_linux_uid_reserve(kv_linux_uid_history *history,
                        const unsigned char attempt_nonce[32],
                        const unsigned char boot_id[16],
                        kv_linux_uid_reservation *reservation);
/* This records an already independently validated native closure, not a caller
 * assertion of cleanup. Broker MUST bind proof to exact pidfds/cgroup/EOF and
 * its immutable reservation, and enforce the original deadline BEFORE and
 * AFTER this call and again before terminal publication. A late fsync can be
 * durable diagnostic history, never an in-budget closure claim. NEVER expose
 * this function as a public socket command. */
int kv_linux_uid_record_closed(kv_linux_uid_history *history,
                              const kv_linux_uid_reservation *reservation,
                              const unsigned char native_proof_sha256[32]);
const char *kv_linux_uid_reason(const kv_linux_uid_history *history);
void kv_linux_uid_close(kv_linux_uid_history *history);
#endif
