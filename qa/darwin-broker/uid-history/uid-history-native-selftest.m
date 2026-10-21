/* Own-fixture diagnostic only. Never touches production canonical paths.
 * Compile with -I<WT>/.knowledge/tools/lib and the paired implementation.
 * Run as root with ONE explicitly test-owned, EMPTY, protected directory0755.
 * Leaves all evidence/files in that directory for caller inspection/cleanup. */
#import <Foundation/Foundation.h>
#import "verification-darwin-uid-history.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>
static unsigned checks;
static void check(BOOL ok,const char *name){printf("{\"test\":\"%s\",\"pass\":%s}\n",name,ok?"true":"false");fflush(stdout);if(!ok)exit(1);checks++;}
static BOOL writeJSONOptions(NSString *path,NSDictionary *object,NSJSONWritingOptions options){NSData *data=[NSJSONSerialization dataWithJSONObject:object options:options error:NULL];
    NSString *temp=[path stringByAppendingString:@".test-new"];int fd=open(temp.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return NO;size_t at=0;BOOL ok=YES;while(at<data.length){ssize_t n=write(fd,(const char *)data.bytes+at,data.length-at);if(n<=0){ok=NO;break;}at+=(size_t)n;}
    ok=ok&&fsync(fd)==0&&fcntl(fd,F_FULLFSYNC)==0;if(close(fd))ok=NO;
    if(ok)ok=rename(temp.fileSystemRepresentation,path.fileSystemRepresentation)==0;
    int dir=open(path.stringByDeletingLastPathComponent.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    ok=ok&&dir>=0&&fsync(dir)==0;if(dir>=0)close(dir);return ok;
}
static BOOL writeJSON(NSString *path,NSDictionary *object){return writeJSONOptions(path,object,NSJSONWritingSortedKeys|NSJSONWritingWithoutEscapingSlashes);}
int main(int argc,char **argv){@autoreleasepool{
    if(argc!=2||getuid()||geteuid())return 64;NSString *base=@(argv[1]);
    if(![base hasPrefix:@"/"]||[base isEqual:@"/"])return 64;
    NSError *error=nil;NSArray *existing=[[NSFileManager defaultManager]contentsOfDirectoryAtPath:base error:&error];
    check(existing&&existing.count==0,"explicit_empty_fixture");
    for(NSString *name in @[@"anchors",@"allocator",@"registry",@"workspaces"]){NSString *path=[base stringByAppendingFormat:@"/%@",name];
        mode_t mode=[name isEqual:@"anchors"]?0755:[name isEqual:@"workspaces"]?0711:0700;
        check(mkdir(path.fileSystemRepresentation,mode)==0&&chmod(path.fileSystemRepresentation,mode)==0,"create_own_directory");}
    uuid_t host;struct timespec timeout={2,0};check(gethostuuid(host,&timeout)==0,"actual_host");uuid_string_t text;uuid_unparse_lower(host,text);
    NSDictionary *c=@{@"marker_path":[base stringByAppendingString:@"/anchors/install.json"],@"head_path":[base stringByAppendingString:@"/anchors/head.json"],
        @"journal_path":[base stringByAppendingString:@"/allocator/consumed.journal"],@"lock_path":[base stringByAppendingString:@"/allocator/daemon.lock"],
        @"registry_path":[base stringByAppendingString:@"/registry/registry.json"],@"workspace_root":[base stringByAppendingString:@"/workspaces"],@"host_id":@(text)};
    KVDarwinUIDHistory *h=[KVDarwinUIDHistory beginInitializationWithConfiguration:c error:&error];
    check(h&&!h.healthy&&[h.reason isEqual:@"INITIALIZATION_PENDING"]&&[h.checkpoint[@"seq"] isEqual:@"0"],"explicit_init_pending");
    check(writeJSON(c[@"registry_path"],@{@"uid_history_checkpoint":h.checkpoint,@"fixture_path":base}),"persist_genesis_registry_with_actual_path");
    check([h finalizeInitializationWithError:&error]&&h.healthy,"explicit_finalize");
    KVDarwinUIDHistory *other=[KVDarwinUIDHistory openWithConfiguration:c error:&error];check(!other,"second_singleton_refused");
    NSString *attempt=[@"a" stringByPaddingToLength:64 withString:@"a" startingAtIndex:0];NSString *boot=NSUUID.UUID.UUIDString.lowercaseString;
    NSDictionary *r=[h consumeUIDForPlannedAttempt:attempt boot:boot error:&error];
    check(r&&[r[@"uid"] unsignedIntValue]==1000000000u&&!h.healthy,"consume_burns_pending");
    check(![h validReservationForUID:1000000000u attempt:attempt sequence:r[@"seq"] sha256:r[@"sha256"] error:&error],"pending_not_usable");
    check(writeJSON(c[@"registry_path"],@{@"uid_history_checkpoint":h.checkpoint,@"fixture_path":base})&&[h confirmRegistryCheckpointWithError:&error],"registry_confirm_with_actual_path");
    check([h validReservationForUID:1000000000u attempt:attempt sequence:r[@"seq"] sha256:r[@"sha256"] error:&error],"exact_reservation");
    check(![h validReservationForUID:1000000001u attempt:attempt sequence:r[@"seq"] sha256:r[@"sha256"] error:&error],"wrong_uid_refused");
    NSDictionary *first=h.checkpoint;NSString *installation=h.installationID;[h close];
    h=[KVDarwinUIDHistory openWithConfiguration:c error:&error];check(h.healthy&&[h.checkpoint isEqual:first]&&[h.installationID isEqual:installation],"restart_preserves_checkpoint");
    r=[h consumeUIDForPlannedAttempt:attempt boot:boot error:&error];check(r&&[r[@"uid"] unsignedIntValue]==1000000001u,"restart_never_reuses_uid");
    check(writeJSON(c[@"registry_path"],@{@"uid_history_checkpoint":h.checkpoint,@"fixture_path":base})&&[h confirmRegistryCheckpointWithError:&error],"second_registry_confirm_with_actual_path");NSDictionary *second=h.checkpoint;
    NSDictionary *registry=@{@"uid_history_checkpoint":second,@"fixture_path":base};
    NSData *canonical=[NSData dataWithContentsOfFile:c[@"registry_path"]];
    check(writeJSONOptions(c[@"registry_path"],registry,NSJSONWritingSortedKeys)
        &&![[NSData dataWithContentsOfFile:c[@"registry_path"]] isEqual:canonical],"own_legacy_slash_format_differs");
    check(![h validReservationForUID:1000000001u attempt:attempt sequence:r[@"seq"] sha256:r[@"sha256"] error:&error]
        &&!h.healthy&&[h.reason isEqual:@"REGISTRY_CHECKPOINT_MISMATCH"],"nonmatching_whole_registry_codec_rejected");[h close];
    check(writeJSON(c[@"registry_path"],registry),"restore_own_canonical_registry");
    h=[KVDarwinUIDHistory openWithConfiguration:c error:&error];check(h.healthy,"canonical_registry_path_roundtrip");
    NSDictionary *marker=[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:c[@"marker_path"]] options:0 error:NULL];
    NSMutableDictionary *foreign=[marker mutableCopy];foreign[@"installation_id"]=[@"b" stringByPaddingToLength:64 withString:@"b" startingAtIndex:0];
    check(writeJSON(c[@"marker_path"],foreign),"own_foreign_marker_fixture");
    check(![h validReservationForUID:1000000001u attempt:attempt sequence:r[@"seq"] sha256:r[@"sha256"] error:&error]
        &&!h.healthy&&[h.reason isEqual:@"INSTALL_MARKER_CHANGED"]&&[h.installationID isEqual:installation]
        &&[h.checkpoint isEqual:second],"foreign_marker_preserves_last_trusted_cache");[h close];
    check(writeJSON(c[@"marker_path"],marker),"restore_own_original_marker");
    NSData *journal=[NSData dataWithContentsOfFile:c[@"journal_path"]];check(writeJSON(c[@"head_path"],first),"own_head_rollback_fixture");
    h=[KVDarwinUIDHistory openWithConfiguration:c error:&error];check(h&&!h.healthy&&[h.reason isEqual:@"HEAD_JOURNAL_MISMATCH"],"partial_rollback_quarantines");
    check(![h consumeUIDForPlannedAttempt:attempt boot:boot error:&error]&&[[NSData dataWithContentsOfFile:c[@"journal_path"]] isEqual:journal],"quarantine_never_appends");[h close];
    check(![KVDarwinUIDHistory beginInitializationWithConfiguration:c error:&error],"existing_history_not_reinitialized");
    check(writeJSON(c[@"head_path"],second),"restore_own_head_for_isolated_registry_case");
    check(unlink([c[@"registry_path"] fileSystemRepresentation])==0,"own_registry_loss_fixture");
    h=[KVDarwinUIDHistory openWithConfiguration:c error:&error];check(h&&!h.healthy&&[h.reason isEqual:@"REGISTRY_CHECKPOINT_MISMATCH"]
        &&access([c[@"registry_path"] fileSystemRepresentation],F_OK)!=0,"serve_does_not_create_registry");[h close];
    printf("{\"checks\":%u,\"capability_qualified\":false}\n",checks);return 0;
}}
