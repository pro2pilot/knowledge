#ifndef KNOWLEDGE_LINUX_SERVICE_FINALIZATION_H
#define KNOWLEDGE_LINUX_SERVICE_FINALIZATION_H
#include "verification-linux-service-cleanup-phase.h"
#include "verification-linux-service-result-wire.h"
#include <stdint.h>
typedef struct kv_linux_finalization kv_linux_finalization;
enum kv_linux_finalization_state {
    KV_FINALIZATION_MOVED=1,KV_FINALIZATION_WAIT_PHASE=2,KV_FINALIZATION_SIGNING=3,
    KV_FINALIZATION_DRAINING=4,KV_FINALIZATION_PERSISTING=5,KV_FINALIZATION_PROVISIONAL=6,
    KV_FINALIZATION_CONFIRMED=7,KV_FINALIZATION_FAILED_RETAINED=8,KV_FINALIZATION_CLOSING=9
};
#define KV_LINUX_FINALIZATION_SIGNED_BYTES 576
#define KV_LINUX_FINALIZATION_BUNDLE_MAX_BYTES (KV_LINUX_FINALIZATION_SIGNED_BYTES+KV_LINUX_RESULT_MAX_BYTES)
/* Diagnostic DATA, never an owner, publication right or recovered acceptance. */
struct kv_linux_finalization_observation {
    enum kv_linux_finalization_state state;
    int failed,cancelled,delivery_closed,confirmed,signature_received,persisted;
    uint64_t work_deadline_ns,cleanup_deadline_ns;
};
/* Allocate inert state, move the whole genuine phase, then perform effects.
 * NULL is pre-move refusal only; later failures retain the same allocation. */
kv_linux_finalization *kv_linux_finalization_start(kv_linux_cleanup_phase **owned);
/* Native persistence may block in this original session process. Production
 * needs an actual owned birth and independent outer caller deadline. */
int kv_linux_finalization_poll(kv_linux_finalization *,unsigned max_wait_ms);
int kv_linux_finalization_cancel(kv_linux_finalization *);
int kv_linux_finalization_observe(const kv_linux_finalization *,struct kv_linux_finalization_observation *);
/* Exact signed DATA from a confirmed same-live decision with fresh C checks;
 * not service authentication or timely delivery. Historical lookup needs its
 * own genuine service/read-access counterpart, never a caller boolean. */
int kv_linux_finalization_export(kv_linux_finalization *,unsigned char out[KV_LINUX_FINALIZATION_SIGNED_BYTES]);
/* Disable delivery/lookup before negative cancellation; EBUSY retains owner. */
int kv_linux_finalization_close(kv_linux_finalization **owned);
#endif
