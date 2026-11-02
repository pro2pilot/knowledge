#ifndef KNOWLEDGE_LINUX_SERVICE_CHILD_RUNTIME_INPUT_H
#define KNOWLEDGE_LINUX_SERVICE_CHILD_RUNTIME_INPUT_H
#include "verification-linux-service-child-runtime.h"
/* PRIVATE structural counterpart, Boolean1/0, no effects/current/clock/FD
 * probes. Matches the original runtime/actor/connection and actual retained
 * nonNULL provider returned only after its real native actor claim succeeded.
 * A failed-but-retained provider still proves that construction relation for
 * negative cleanup. NULL-provider runtime/status/DATA cannot substitute it.
 * The fixed outer bridge may use this only in live original ADMISSION before
 * CLAIMED send/ACK. It is not a new WORK permit, epoch or read constructor. */
/* Historical read_bundle adds no matching alternative: both getters still
 * require the same actual F. Transcript/status/public bytes never satisfy this
 * construction predicate or authorize a child/epoch re-adoption. */
int kv_linux_service_child_runtime_claim_matches(const kv_linux_service_child_runtime *,
    const kv_linux_service_actor *,const struct kv_linux_service_connection *);
#endif
