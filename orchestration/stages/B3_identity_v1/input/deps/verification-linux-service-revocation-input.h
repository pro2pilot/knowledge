#ifndef KNOWLEDGE_LINUX_SERVICE_REVOCATION_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_REVOCATION_INPUT_H
#include "verification-linux-service-admission.h"

/* Fixed linked native composition only. No descriptor/cursor/receipt factory.
 * The actual guard owns its endpoint; transport owns the authenticated anchor.
 * Matching is pure and never recursively calls current. */
typedef struct kv_linux_service_control_anchor kv_linux_service_control_anchor;
typedef struct kv_linux_service_revocation_endpoint kv_linux_service_revocation_endpoint;
int kv_linux_service_revocation_claim(const struct kv_linux_service_connection *,
    kv_linux_service_input_guard *,kv_linux_service_revocation_endpoint **out_null);
int kv_linux_service_revocation_poll(kv_linux_service_revocation_endpoint *,kv_linux_service_input_guard *);
int kv_linux_service_revocation_close(kv_linux_service_revocation_endpoint **owned,kv_linux_service_input_guard *);
int kv_linux_service_input_guard_revocation_matches(const kv_linux_service_input_guard *,
    const kv_linux_service_revocation_endpoint *);
int kv_linux_service_transport_consume_event(struct kv_linux_service_connection *,
    const struct kv_linux_service_event *);
/* Private birth DATA from the same genuine WORK guard, with current/STOP drain
 * on both sides. No caller revision, reset, phase capability or FD factory. */
int kv_linux_service_input_revision_v3(kv_linux_service_input_guard *,
    const struct kv_linux_service_input_binding *,uint64_t *out);

/* Transport primitives used only by the fixed admission implementations above.
 * They accept genuine owned connection/anchor objects, never raw descriptors.
 * Their event outputs are negative control DATA, not an authority receipt. */
int kv_linux_service_control_anchor_hold(const struct kv_linux_service_connection *,kv_linux_service_control_anchor **out_null);
int kv_linux_service_control_anchor_release(kv_linux_service_control_anchor **owned);
/* Pure original native connection/session identity after exclusive handoff.
 * Mutable cursor/state belongs to the private endpoint; no pidfd inode test. */
int kv_linux_service_control_connection_matches(const struct kv_linux_service_connection *,const kv_linux_service_control_anchor *);
/* Duplicate watches from the retained native anchor. Public pidfd mirrors are
 * never a descriptor lineage or birth identity. Outputs publish only together. */
int kv_linux_service_control_watch(const struct kv_linux_service_connection *,int *peer_out_negative,
    struct kv_linux_service_clock_identity *clock_out_negative_or_null);
int kv_linux_service_control_claim(const struct kv_linux_service_connection *,kv_linux_service_control_anchor *,
    const kv_linux_service_input_guard *,kv_linux_service_revocation_endpoint **out_null);
int kv_linux_service_control_matches(const kv_linux_service_revocation_endpoint *,
    const kv_linux_service_input_guard *,const kv_linux_service_control_anchor *);
int kv_linux_service_control_receive(kv_linux_service_revocation_endpoint *,const kv_linux_service_input_guard *,
    struct kv_linux_service_event *);
int kv_linux_service_control_reply(kv_linux_service_revocation_endpoint *,const kv_linux_service_input_guard *,const unsigned char bytes[128]);
int kv_linux_service_control_empty(kv_linux_service_revocation_endpoint *,const kv_linux_service_input_guard *);
int kv_linux_service_control_close(kv_linux_service_revocation_endpoint **owned,const kv_linux_service_input_guard *);
#endif
