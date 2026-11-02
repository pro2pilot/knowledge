#ifndef KNOWLEDGE_LINUX_SERVICE_CHILD_RUNTIME_H
#define KNOWLEDGE_LINUX_SERVICE_CHILD_RUNTIME_H
#include "verification-linux-service-source-provider.h"
#include "verification-linux-service-request-capability.h"
#include "verification-linux-service-semantic-plan.h"
#include "verification-linux-service-execution.h"
#include "verification-linux-service-finalization.h"
#include <stddef.h>

typedef struct kv_linux_service_child_runtime kv_linux_service_child_runtime;
/* Fixed administrative digest values only. No path, FD, function pointer,
 * arbitrary payload, observation or purported acceptance is a constructor. */
struct kv_linux_service_child_runtime_pins {
    struct kv_linux_import_pins imports;
    struct kv_linux_verify_pins verifies;
    struct kv_linux_semantic_pins semantic;
    struct kv_linux_key_pins key;
    struct kv_linux_worker_pins worker;
};
enum kv_linux_service_child_mode {
    KV_CHILD_WORK=1,KV_CHILD_CLEANUP=2,KV_CHILD_CONFIRMED_READ=3,KV_CHILD_FAILED=4
};
enum kv_linux_service_child_stage {
    KV_CHILD_PROVIDER=1,KV_CHILD_IDENTITY=2,KV_CHILD_SEMANTIC=3,KV_CHILD_KEY=4,
    KV_CHILD_EXECUTION=5,KV_CHILD_RESULT=6,KV_CHILD_PHASE=7,KV_CHILD_FINALIZER=8,
    KV_CHILD_READ=9,KV_CHILD_RETAINED_FAILURE=10
};
/* Routing/diagnostic DATA only, not a transition permit or F constructor.
 * A root child bridge must call read_confirmed on this same retained runtime
 * before a typed read-only transition/query; a cached mode bit grants nothing. */
struct kv_linux_service_child_status {
    enum kv_linux_service_child_mode mode;
    enum kv_linux_service_child_stage stage;
    int failed,cancelled,closing;
};
/* SOURCE DRAFT. Original fixed single-thread root-native session only, after
 * raw birth/descriptor allowlist and the genuine actor INTENT_HELD reply ACK.
 * Actor/connection/admin pins remain caller-owned and stable through close;
 * they are neither moved nor freed here. Pins are copied before provider claim.
 * The provider's actual native actor claim authenticates the reservation; its
 * public DATA tuple cannot construct an input guard or upgrade role mode.
 *
 * Allocate inert state before that sole role-qualified provider invocation.
 * NULL is pre-claim pure argument/allocation refusal only. Once the provider
 * factory is invoked, every later result returns the same retained runtime,
 * including a spent actor claim that returned no provider. Never retry start.
 * That NULL-provider failure still retains actor/connection borrows and drives
 * their real negative actor_abandon_connection path; no fake provider/drain
 * object is created. Actor/guard allocation remains caller-owned until the
 * outer child closes the actual actor after runtime close.
 * Root bridge owns all public reply delivery under front SCM credentials;
 * this runtime never sends public DATA or installs an arbitrary callback. */
kv_linux_service_child_runtime *kv_linux_service_child_runtime_start(
    const struct kv_linux_service_child_runtime_pins *,kv_linux_service_actor *,
    const struct kv_linux_service_connection *,const kv_linux_uid_reservation *);
/* At most one positive owner-stage move per call. Actual component constructors
 * and final persistence may block in this original child; wait is not an I/O
 * deadline. Parent retains the original atomic birth/control and original C.
 * No W/C/setup renewal. After phase fencing, only the genuine phase/F route
 * polls; upstream WORK/current helpers stay dormant until negative close. */
int kv_linux_service_child_runtime_poll(kv_linux_service_child_runtime *,unsigned max_wait_ms);
int kv_linux_service_child_runtime_status(const kv_linux_service_child_runtime *,struct kv_linux_service_child_status *);
/* Exact same-live confirmed signed DATA only, through the root-owned private
 * kv_linux_finalization_read_confirmed counterpart. It rechecks actual F/read
 * access, without C/W renewal, signing, persistence, a new decision or recovery.
 * Output untouched on refusal. Public op6/authenticated service routing belongs
 * to the fixed root bridge, not to a caller boolean or this status structure. */
int kv_linux_service_child_runtime_read_confirmed(kv_linux_service_child_runtime *,unsigned char out[KV_LINUX_FINALIZATION_SIGNED_BYTES]);
/* Same live F's signed DATA followed by its canonical historical result
 * transcript. The root-owned F getter rechecks actual read access/drain and
 * binds transcript SHA to signed message192..223. No observation/record is an
 * input constructor. No upstream WORK/current poll, signing, persist or CAS.
 * Output and *used stay untouched on refusal; EMSGSIZE is a buffer refusal.
 * The fixed root bridge alone owns op7 delivery and its unchanged read bound. */
int kv_linux_service_child_runtime_read_bundle(kv_linux_service_child_runtime *,unsigned char *out,size_t capacity,size_t *used);
int kv_linux_service_child_runtime_cancel(kv_linux_service_child_runtime *);
/* Disable read/work first. Deepest actual owner closes before semantic parser,
 * identity and provider; all upstream allocations remain retained through F
 * close/unlink. EBUSY retains the same runtime. Never closes actor/connection,
 * records CLOSED by assertion, deletes arbitrary paths or recycles any UID. */
int kv_linux_service_child_runtime_close(kv_linux_service_child_runtime **owned);
#endif
