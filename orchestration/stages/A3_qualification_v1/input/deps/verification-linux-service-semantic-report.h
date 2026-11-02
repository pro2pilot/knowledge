#ifndef KNOWLEDGE_LINUX_SERVICE_SEMANTIC_REPORT_H
#define KNOWLEDGE_LINUX_SERVICE_SEMANTIC_REPORT_H
#include <stddef.h>
#include <stdint.h>

#define KV_LINUX_SEMANTIC_REPORT_BYTES 6400
#define KV_LINUX_SEMANTIC_REPORT_HEADER_BYTES 256
#define KV_LINUX_SEMANTIC_COMMAND_BYTES 48
#define KV_LINUX_SEMANTIC_MAX_COMMANDS 128
struct kv_linux_semantic_command_data {
    uint32_t ordinal,type; /* Exactly 1=node_script or 2=node_test. */
    uint64_t deadline_ns;
    unsigned char command_sha256[32];
};
/* Finite DATA observation. No serialized record constructs a native permit,
 * authenticates a child or proves current identity, drain, execution or ACK. */
struct kv_linux_semantic_report_data {
    uint32_t schema_version,command_count;
    unsigned char identity_record_sha256[32],envelope_sha256[32],request_sha256[32];
    unsigned char plan_sha256[32],source_sha256[32],manifest_sha256[32],directories_sha256[32],report_sha256[32];
    struct kv_linux_semantic_command_data commands[KV_LINUX_SEMANTIC_MAX_COMMANDS];
};
/* Snapshots exact 6400 report and exact 640 expected identity bytes before
 * validating either. Expected identity uses the real pending-record structural
 * validator, which itself grants no native provenance. No JSON/argv is parsed.
 * Output remains untouched on every refusal. Plan/command hashes are bounded
 * semantic-producer DATA, not recomputed JSON semantics in this native parser.
 * Future owner must independently require exact held child + bounded channel,
 * actual reap/EOF and fresh genuine opaque identity before using any result.
 * Serialized native owner must disable ambient crypto config before first
 * crypto use. A later NO_LOAD_CONFIG cannot undo earlier initialization. */
int kv_linux_semantic_report_validate(const unsigned char *report,size_t report_bytes,
    const unsigned char *expected_identity,size_t identity_bytes,struct kv_linux_semantic_report_data *out);

/* Separate strict timed3 DATA. Legacy report2 types/parser above stay intact. */
#define KV_LINUX_SEMANTIC_MAX_TIMEOUT_MS UINT64_C(600000)
#define KV_LINUX_SEMANTIC_MAX_TIMEOUT_NS (KV_LINUX_SEMANTIC_MAX_TIMEOUT_MS*UINT64_C(1000000))
struct kv_linux_semantic_timed_command_data {
    uint32_t ordinal,type;
    uint64_t timeout_ns; /* Immutable requested duration, never a deadline. */
    unsigned char command_sha256[32];
};
struct kv_linux_semantic_timed_report_data {
    uint32_t schema_version,command_count;
    uint64_t requested_session_started_ns; /* DATA lower bound only. */
    unsigned char identity_record_sha256[32],envelope_sha256[32],request_sha256[32];
    unsigned char plan_sha256[32],source_sha256[32],manifest_sha256[32],directories_sha256[32],report_sha256[32];
    struct kv_linux_semantic_timed_command_data commands[KV_LINUX_SEMANTIC_MAX_COMMANDS];
};
int kv_linux_semantic_timed_report_validate(const unsigned char *report,size_t report_bytes,
    const unsigned char *expected_identity,size_t identity_bytes,struct kv_linux_semantic_timed_report_data *out);
#endif
