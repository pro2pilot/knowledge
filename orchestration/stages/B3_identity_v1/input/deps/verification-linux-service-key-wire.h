#ifndef KNOWLEDGE_LINUX_SERVICE_KEY_WIRE_H
#define KNOWLEDGE_LINUX_SERVICE_KEY_WIRE_H
#include "verification-linux-service-semantic-report.h"
#include "verification-linux-service-attempt-identity.h"
#include <stddef.h>
#include <stdint.h>

/* Private finite DATA codec. Nothing here authenticates a birth, grants current
 * or constructs a native key/plan capability. Supported launchers alone retain
 * the genuine ownership chain and actual kernel handles. See reviewed v1 ABI. */
#define KV_LINUX_KEY_CONTEXT_BYTES 7296
#define KV_LINUX_KEY_FRAME_BYTES 256
#define KV_LINUX_KEY_PENDING_OFFSET 256
#define KV_LINUX_KEY_REPORT_OFFSET 896
enum kv_linux_key_frame_kind {
    KV_LINUX_KEY_PREP=1, KV_LINUX_KEY_READY=2,
    KV_LINUX_KEY_RELEASE=3, KV_LINUX_KEY_PUBLIC=4
};
struct kv_linux_key_binding {
    uint32_t parent_pid,key_pid,peer_pid;
    uint64_t semantic_sequence,exclusive_sequence,native_revision;
    uint64_t creator_namespace_dev,creator_namespace_ino;
    uint64_t key_namespace_dev,key_namespace_ino;
    unsigned char nonce[32];
};
/* Caller disables ambient configuration before first general crypto use. In the
 * fresh fixed entry this occurs only after credentials/FD/namespace checks and
 * the reviewed strict TSYNC policy. Failure leaves all outputs untouched. */
int kv_linux_key_context_encode(unsigned char out[KV_LINUX_KEY_CONTEXT_BYTES],
    const struct kv_linux_key_binding *,
    const unsigned char pending[KV_LINUX_ATTEMPT_PENDING_BYTES],
    const unsigned char report[KV_LINUX_SEMANTIC_REPORT_BYTES]);
int kv_linux_key_context_validate(const unsigned char *,size_t,
    struct kv_linux_key_binding *out);
/* Exact sealed memfd read only: REG/nlink0/size and four seals; bounded pread,
 * not shared offsets. Does not validate contents or grant native provenance. */
int kv_linux_key_context_read(int fd,unsigned char out[KV_LINUX_KEY_CONTEXT_BYTES]);
int kv_linux_key_frame_encode(unsigned char out[KV_LINUX_KEY_FRAME_BYTES],
    const unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],
    enum kv_linux_key_frame_kind,const unsigned char *public_key_or_null);
int kv_linux_key_frame_validate(const unsigned char *,size_t,
    const unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],
    enum kv_linux_key_frame_kind,unsigned char *public_key_out_or_null);
#endif
