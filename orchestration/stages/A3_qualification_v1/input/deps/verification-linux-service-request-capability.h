#ifndef KNOWLEDGE_LINUX_SERVICE_REQUEST_CAPABILITY_H
#define KNOWLEDGE_LINUX_SERVICE_REQUEST_CAPABILITY_H
#include "verification-linux-service-admission.h"
#include "verification-linux-service-input-hash.h"
#include "verification-linux-service-verify.h"

struct kv_linux_source_provider;
typedef struct kv_linux_request_identity_cap kv_linux_request_identity_cap;
/* Native DATA, not a capability constructor. The hashes.intent_* fields name
 * the complete KVLREQ2 request envelope here; body SHA authenticates opaque
 * bytes only. Semantic JSON/commands/keys/terminal acceptance are absent. */
struct kv_linux_request_identity_data {
    uint32_t request_version; /* Exactly 2, from the private native entry. */
    struct kv_linux_service_input_binding binding;
    struct kv_linux_input_hash_result hashes;
    struct kv_linux_verify_content_observation content;
    uint64_t body_bytes;
    unsigned char installation_id[16],host_id[16];
};
/* Only an explicit request-v2 provider after actual CONTENT_READY can publish
 * this sole owned reference. Caller initializes *out=NULL. One mint opportunity
 * is burned before current-dependent admission; failure cannot renew it.
 * Provider close cancels/invalidates but remains EBUSY while this lease exists.
 * No input FD, public constructor, deserializer or reference-acquire exists.
 * The explicit role-qualified variant retains its private role state through
 * this same capability; DATA fields never construct or upgrade qualification. */
int kv_linux_source_provider_claim_request_v2_identity(struct kv_linux_source_provider *,kv_linux_request_identity_cap **out);
/* All APIs: 0 success, -1 refusal. ECHILD is a pure inherited-owner refusal;
 * EALREADY denotes repeated consumption. A genuine owned consume burns before
 * any current observation; subsequent failure is sticky ECANCELED and leaves
 * DATA untouched. Native identity consumes this once before RNG/assembly. */
int kv_linux_request_identity_cap_consume(kv_linux_request_identity_cap *,struct kv_linux_request_identity_data *out);
/* Fresh source-provider/actor/custody/content check at actual use. Failure is
 * permanent. These calls are serialized in the original native owner process. */
int kv_linux_request_identity_cap_current(kv_linux_request_identity_cap *);
/* Sole owned reference, release only after identity and every dependent native
 * consumer drains. Clears *cap; does not free provider, close durable history
 * or attest removal. Inherited-owner refusal leaves *cap unchanged. */
int kv_linux_request_identity_cap_release(kv_linux_request_identity_cap **cap);
#endif
