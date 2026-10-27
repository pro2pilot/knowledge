#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/* Experimental root-only native persistence, NOT a qualified containment backend.
 * Single-owner API: caller serializes every call on its lifecycle actor.
 * No account creation, process signaling, registry writes, automatic repair,
 * filesystem permission changes, rollback-proof or OS-attestation claim.
 *
 * Required configuration keys (all NSString): marker_path, head_path,
 * journal_path, lock_path, registry_path, workspace_root, host_id (lower UUID).
 * Paths are lexical absolute, pre-existing root-protected directory chains.
 * Journal/lock share a root0700 parent; registry has a separate root0700 parent;
 * workspace root is root0711. Marker/head parents must be outside those trees.
 * Broker MUST enforce canonical production paths/service and an administratively
 * reserved UID/GID range. Explicit arbitrary paths are for root-owned CI fixtures.
 *
 * External registry protocol: persist a root0600 regular/nlink1 JSON dictionary
 * using NSJSONWritingSortedKeys|NSJSONWritingWithoutEscapingSlashes (same exact
 * codec as broker jsonData), containing "uid_history_checkpoint": history.checkpoint. Caller
 * must F_FULLFSYNC its data, rename/fsync its parent and read back before confirm.
 * This module independently flushes and rereads the actual protected registry
 * inode before accepting the checkpoint. This cannot attest storage honesty
 * or detect coherent rollback of every root record.
 */
@interface KVDarwinUIDHistory : NSObject
@property(nonatomic, readonly) BOOL healthy;
@property(nonatomic, readonly) NSString *reason;
@property(nonatomic, readonly, nullable) NSString *installationID;
@property(nonatomic, readonly, nullable) NSDictionary *checkpoint;

/* Never creates files or resets history. Returns a quarantined object on a
 * history mismatch, retaining the singleton lock when acquired. Unsafe paths,
 * non-root caller or unavailable lock return nil. error contains a code only.
 * The caller can keep independent validated entry-store status/exact cleanup
 * available when this allocator is unhealthy; NEVER derive UID-wide kill
 * authority from an unhealthy object or caller-supplied UID/checkpoint.
 */
+ (nullable instancetype)openWithConfiguration:(NSDictionary<NSString *,NSString *> *)configuration
                                         error:(NSError * _Nullable * _Nullable)error;
/* Additive startup notification after the protected singleton lock is held,
 * before history/registry replay. callback may only signal transport readiness;
 * it receives no history object and does not imply healthy allocation state.
 * Existing API above preserves its synchronous behavior. */
+ (nullable instancetype)openWithConfiguration:(NSDictionary<NSString *,NSString *> *)configuration
                              didAcquireLock:(void (* _Nullable)(void * _Nullable))callback
                                     context:(void * _Nullable)context
                                       error:(NSError * _Nullable * _Nullable)error;

/* Explicit root-admin operation ONLY. Requires empty existing allocator,
 * registry and workspace dirs; refuses any existing marker/head/history/lock.
 * Creates initializing marker first, then genesis/lock/head. No rollback or
 * cleanup of partial initialization on error. Caller persists checkpoint in
 * registry, then explicitly finalizes. Never expose as a user socket request.
 */
+ (nullable instancetype)beginInitializationWithConfiguration:(NSDictionary<NSString *,NSString *> *)configuration
                                                        error:(NSError * _Nullable * _Nullable)error;
- (BOOL)finalizeInitializationWithError:(NSError * _Nullable * _Nullable)error;

/* Success returns {uid, attempt_id, seq, sha256, installation_id}. Journal then
 * independent head are durable before returning. healthy becomes NO with
 * REGISTRY_CHECKPOINT_PENDING. UID is burned even if caller crashes/fails.
 * Caller MUST persist returned current checkpoint and confirm BEFORE inspecting
 * the candidate, consuming another UID or creating private objects/spawning.
 */
- (nullable NSDictionary *)consumeUIDForPlannedAttempt:(NSString *)attemptID
                                                 boot:(NSString *)bootID
                                                error:(NSError * _Nullable * _Nullable)error;
- (BOOL)confirmRegistryCheckpointWithError:(NSError * _Nullable * _Nullable)error;
/* Disk refresh of an already healthy ready instance. A quarantined instance is
 * never healed automatically. healthy alone is cached state, not a fresh read. */
- (BOOL)refreshCurrentCheckpointWithError:(NSError * _Nullable * _Nullable)error;

/* Verifies this exact consumed tuple under currently matching J/head/registry.
 * Does NOT prove account absence, immutable credentials or process finality.
 * Refuses when allocator unhealthy. Numbers seq and SHA are canonical strings.
 */
- (BOOL)validReservationForUID:(uint32_t)uid
                       attempt:(NSString *)attemptID
                      sequence:(NSString *)sequence
                        sha256:(NSString *)sha256
                         error:(NSError * _Nullable * _Nullable)error;
- (void)close;
@end

NS_ASSUME_NONNULL_END
