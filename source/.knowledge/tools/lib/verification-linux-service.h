#ifndef KNOWLEDGE_LINUX_SERVICE_H
#define KNOWLEDGE_LINUX_SERVICE_H
#include <stdint.h>

/* Fixed native transport. Integers are little endian on supported x64/ARM64
 * Linux. No privileged actor parses the opaque source/authority JSON body.
 * An installed, ordinary-UID client owns one live connection until terminal.
 */
#define KLS_MAGIC UINT32_C(0x4b4c5331)
#define KLS_OUTPUT_MAGIC UINT32_C(0x4b4c4f31)
#define KLS_COMMAND_MAGIC UINT32_C(0x4b4c4331)
#define KLS_REPLY_MAGIC UINT32_C(0x4b4c5231)
#define KLS_VERSION 1U
#define KLS_MAX_INPUT (64U * 1024U * 1024U)
#define KLS_MAX_RESULT (32U * 1024U * 1024U)
#define KLS_MAX_STREAM (16U * 1024U * 1024U)
#define KLS_MAX_COMMAND 65536U
#define KLS_MAX_COMMANDS 64U
#define KLS_MAX_ARGS 32U
#define KLS_MAX_CLEANUP_MS UINT64_C(3600000)
#define KLS_MAX_WORK_MS UINT64_C(60000000000)
enum kls_operation { KLS_HELLO=1, KLS_REGISTER_WRITER=2, KLS_OPEN=3,
  KLS_STOP=4, KLS_OBSERVE=5, KLS_PERMIT=6 };
enum kls_output { KLS_CONTROL_JSON=1, KLS_AUTHORITY_JSON=2 };
enum kls_command_operation { KLS_AUTHORITY_READY=1, KLS_RUN=2 };

#pragma pack(push,1)
struct kls_request {
  uint32_t magic, version, op, ordinal, payload_len, pid;
  uint64_t work_deadline_ns, cleanup_ms;
  unsigned char nonce[32];
  uint64_t reserved;
};
struct kls_output_header { uint32_t magic,version,type,payload_len; };
struct kls_command {
  uint32_t magic,version,op,ordinal,flags,argc,cwd_len,body_len;
  uint64_t deadline_ns;
};
struct kls_ready {
  unsigned char manifest_sha256[32],directories_sha256[32];
  uint64_t files,bytes,directories;
};
struct kls_reply {
  uint32_t magic,version,ordinal;
  int32_t status;
  uint32_t signal,stdout_len,stderr_len,reserved;
};
#pragma pack(pop)
_Static_assert(sizeof(struct kls_request)==80,"native request ABI");
_Static_assert(sizeof(struct kls_output_header)==16,"native output ABI");
_Static_assert(sizeof(struct kls_command)==40,"native command ABI");
_Static_assert(sizeof(struct kls_ready)==88,"authority readback ABI");
_Static_assert(sizeof(struct kls_reply)==32,"native command reply ABI");
#endif
