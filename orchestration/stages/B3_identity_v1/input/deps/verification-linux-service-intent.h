#ifndef KNOWLEDGE_LINUX_SERVICE_INTENT_H
#define KNOWLEDGE_LINUX_SERVICE_INTENT_H
#include "verification-linux-uid-history.h"
#include <stdint.h>
#define KV_LINUX_INTENT_HEADER_BYTES 128
#define KV_LINUX_INTENT_MAX_BODY_BYTES 1048576
typedef struct kv_linux_intent_binding kv_linux_intent_binding;
struct kv_linux_intent_expected {
    kv_linux_uid_reservation reservation;
    unsigned char source_sha256[32];
    uint64_t time_namespace_dev, time_namespace_ino;
    uint64_t requested_work_ns, requested_cleanup_ns;
    uint64_t effective_work_ns, effective_cleanup_ns;
};
struct kv_linux_intent_bytes {
    uint64_t total_bytes, body_bytes;
    unsigned char intent_sha256[32], body_sha256[32];
};
/* Internal native owner dependency, never a JS callback or wire proof.
 * Return 1 only while this exact immutable reservation/source/epochs remains
 * current and neither cancellation nor recovery has begun. This callback and
 * its context must outlive the binding; all use is serialized by that owner.
 * A fixture callback does not qualify a production service actor. */
typedef int (*kv_linux_intent_owner_check)(void *, const struct kv_linux_intent_expected *);
/* Caller owns fd. Returns an owned opaque BYTE binding, not semantic JSON,
 * source sealing, authority admission or finality. Expected source digest must
 * be the owner's independent observation of held input, not a wire assertion.
 * Native boot/clock, full seals, exact sizes/identity and SHA are rechecked.
 * Output must initially be NULL. Failure never closes caller's descriptor. */
int kv_linux_intent_bind(int fd, const struct kv_linux_intent_expected *,
    kv_linux_intent_owner_check, void *owner_context, kv_linux_intent_binding **out);
/* Explicit native KVLREQ2/version2 byte binder. Existing bind accepts only
 * KVLINT1/version1. No header autodetection or semantic JSON validation. The
 * shared opaque result/describe/close retain their byte-custody-only meaning. */
int kv_linux_request_bind_v2(int fd,const struct kv_linux_intent_expected *,
    kv_linux_intent_owner_check,void *owner_context,kv_linux_intent_binding **out);
int kv_linux_intent_describe(const kv_linux_intent_binding *, struct kv_linux_intent_bytes *);
/* One shot, burned before dup. Output initially -1. Fresh native owner/clock
 * checks bracket duplication; a failed postcheck closes only the new fd.
 * Even success remains byte custody; separate ordinary authority semantics
 * and native source/runtime admission are mandatory before execution. */
int kv_linux_intent_claim(kv_linux_intent_binding *, int *out_fd);
void kv_linux_intent_close(kv_linux_intent_binding *);
#endif
