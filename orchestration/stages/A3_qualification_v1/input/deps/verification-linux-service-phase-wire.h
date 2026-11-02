#ifndef KNOWLEDGE_LINUX_SERVICE_PHASE_WIRE_H
#define KNOWLEDGE_LINUX_SERVICE_PHASE_WIRE_H
#include <stddef.h>
#include <stdint.h>

/* Private finite DATA codec only. Caller-supplied expected bytes/bindings do
 * not establish a native owner, birth, phase transition or current authority. */
#define KV_LINUX_PHASE_FRAME_BYTES 320
enum kv_linux_phase_kind {KV_LINUX_PHASE_PREPARE=1,KV_LINUX_PHASE_PREPARED=2,
    KV_LINUX_PHASE_COMMIT=3,KV_LINUX_PHASE_ACK=4,KV_LINUX_PHASE_STOP=5};
enum kv_linux_phase_role {KV_LINUX_PHASE_SOURCE=1,KV_LINUX_PHASE_KEY=2,KV_LINUX_PHASE_WORKER=3};
struct kv_linux_phase_binding {
    uint32_t role;
    uint64_t phase_sequence,native_revision,pending_revision;
    uint64_t work_deadline_ns,cleanup_deadline_ns,semantic_sequence,exclusive_sequence;
    unsigned char transition_nonce[32],participant_nonce[32];
    unsigned char pending_sha256[32],result_sha256[32],roster_sha256[32],boot_id[16];
    uint64_t time_namespace_dev,time_namespace_ino;
    uint32_t sender_pid,receiver_pid;
    unsigned char startup_context_sha256[32];
};
/* No allocation, I/O, crypto, callbacks, ownership or phase mutation.
 * Encode stages all bytes and leaves output entirely unchanged on refusal. */
int kv_linux_phase_frame_encode(unsigned char out[KV_LINUX_PHASE_FRAME_BYTES],
    enum kv_linux_phase_kind,const struct kv_linux_phase_binding *);
int kv_linux_phase_frame_validate(const unsigned char *,size_t,
    enum kv_linux_phase_kind,const struct kv_linux_phase_binding *expected);
#endif
