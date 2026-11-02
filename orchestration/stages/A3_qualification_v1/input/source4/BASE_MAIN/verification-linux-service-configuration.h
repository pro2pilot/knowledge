#ifndef KNOWLEDGE_LINUX_SERVICE_CONFIGURATION_H
#define KNOWLEDGE_LINUX_SERVICE_CONFIGURATION_H
/* Fixed native administrative DATA, not a public owner/FD/path factory.
 * Source prototype: build/install/runtime qualification remain separate. */
#include "verification-linux-service-runtime-front.h"
#include <sys/stat.h>
#include <sys/types.h>
#define KV_LINUX_SERVICE_CONFIGURATION_PATH "/etc/knowledge/verification-linux-service.config"
#define KV_LINUX_SERVICE_CONFIGURATION_NAME "verification-linux-service.config"
#define KV_LINUX_SERVICE_STATE_PATH "/var/lib/knowledge-linux-service"
#define KV_LINUX_SERVICE_ANCHOR_PATH KV_LINUX_SERVICE_STATE_PATH "/anchor"
#define KV_LINUX_SERVICE_JOURNAL_PATH KV_LINUX_SERVICE_STATE_PATH "/journal"
#define KV_LINUX_SERVICE_SINGLETON_NAME "service.singleton"
#define KV_LINUX_SERVICE_CONFIGURATION_HEADER_BYTES 128
#define KV_LINUX_SERVICE_CONFIGURATION_PIN_BYTES 1024
#define KV_LINUX_SERVICE_CONFIGURATION_BYTES 1152
#define KV_LINUX_SERVICE_CONFIGURATION_ABI 1
struct kv_linux_service_configuration {
    kv_linux_uid_configuration history;
    struct kv_linux_daemon_policy policy;
    struct kv_linux_service_child_runtime_pins pins;
};
enum kv_linux_service_fixed_directory {
    KV_SERVICE_CONFIG_DIRECTORY,KV_SERVICE_STATE_DIRECTORY,KV_SERVICE_ANCHOR_DIRECTORY,
    KV_SERVICE_JOURNAL_DIRECTORY,KV_SERVICE_RUNTIME_DIRECTORY,KV_SERVICE_IMPORT_DIRECTORY,
    KV_SERVICE_CUSTODY_DIRECTORY,KV_SERVICE_SEMANTIC_DIRECTORY,KV_SERVICE_VERIFY_DIRECTORY,
    KV_SERVICE_WORKER_DIRECTORY
};
/* Only a finite compiled directory enum; never a supplied pathname or mode.
 * Existing directories only, no mkdir/repair/reset. Returns owned CLOEXEC FD. */
int kv_linux_service_configuration_directory(enum kv_linux_service_fixed_directory);
int kv_linux_service_configuration_load(struct kv_linux_service_configuration *);
/* Metadata helpers used only by this fixed native entry. These checks are
 * DATA checks, never authentication, an opaque native owner or finality. */
int kv_linux_service_configuration_no_attributes(int);
int kv_linux_service_configuration_regular(int,mode_t,off_t,struct stat *);
int kv_linux_service_configuration_same(const struct stat *,const struct stat *);
#endif
