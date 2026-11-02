#ifndef KNOWLEDGE_LINUX_SERVICE_RUNTIME_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_RUNTIME_INPUT_H
#include "verification-linux-service-revocation-input.h"
#include "verification-linux-service-runtime-channel-native.h"
/* PRIVATE fixed original-child seam. No public raw descriptor, callback or
 * copied completion observation constructs a route or read authority. Channel
 * storage is initialized only in the new runtime front's actual raw child and
 * outlives every anchor/guard endpoint; binding is reciprocal and one-shot. */
int kv_linux_service_runtime_route_bind(struct kv_linux_service_connection *,struct kv_linux_runtime_channel *);
int kv_linux_service_runtime_defer_read(kv_linux_service_revocation_endpoint *,const kv_linux_service_input_guard *,
    const struct kv_linux_service_event *);
/* 1 actual pending validated request,0 none,-1 refusal. This is request DATA,
 * never a finalization/read authorization. Output untouched on refusal. */
int kv_linux_service_runtime_take_read(const struct kv_linux_service_connection *,struct kv_linux_service_event *);
int kv_linux_service_runtime_reply(const struct kv_linux_service_connection *,const unsigned char *,unsigned size,
    uint64_t ordinal,uint64_t read_deadline_ns);
#endif
