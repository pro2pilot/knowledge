#!/usr/bin/env python3
"""Run actual broker decision functions on inert Foundation data on Darwin.

All kernel observations, state writes, time and transports are inert substitutes.
This is deliberately NOT a native broker qualification or privileged test.
On other platforms it generates the exact source harness and records NOT_RUN.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess

PRELUDE = r'''
#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define K_SCHEMA @"knowledge-darwin-broker.v1"
#define K_UID_FIRST 1000000000u
#define K_UID_LAST 1900000000u
#define K_MAX_WORK_MS (600000ull * 100000ull)
#define K_MAX_CLEANUP_MS 3600000ull
#define K_PID_CAP 65536u
#define K_ACCOUNT_POLICY @"admin_reserved_interval_no_runtime_nss.v1"
#define KNOWLEDGE_BROKER_SOURCE_SHA "fixture-source"
#define KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA "fixture-transport-header"
#define KNOWLEDGE_DARWIN_STUB_SOURCE_SHA "fixture-stub-source"
#define KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA "fixture-history-header"
#define KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA "fixture-history-source"
static const bool kCapabilityQualified=false;
struct KIdentity {struct {unsigned pbi_ruid,pbi_pid;} bsd;struct {int pidversion;} unique;};
struct KPeer {uid_t owner;struct KIdentity parent;};
typedef struct {unsigned val[8];} audit_token_t;
static unsigned scenario,consumes,saves,commits,status_reads,close_calls,observations;
static unsigned member_calls,path_child_calls,unexpected_fs_calls,uid_burn_count;
static uid_t next_candidate_uid;
static uint64_t clockValue=10;
static NSMutableDictionary *gRegistry,*gClosing,*storedProofs;
static NSDictionary *gAccountPolicy,*gRuntimePins,*delivered;
static NSString *gWorkspaceRoot,*gHost,*gBoot,*gBinarySHA,*gStubBinarySHA,*gCleanupAttempt,*gAccountPolicySHA;
static int gRegistryFD=-1,gWorkspaceFD=-1,gCleanupBarrier=-1,gCloseWaiter=-1;
static bool gQualificationMode=true,gEntryStoreLoaded=true,gPoisoned=false,gLaunchdCreationParent=false,gDrainOnly=false,gStopping=false;
static bool ownersGone;
static uint64_t gCloseDeadline;
static struct {pid_t pid;} gRun;
@interface InertHistory:NSObject
@property BOOL healthy;
@property NSDictionary *checkpoint;
- (NSDictionary *)consumeUIDForPlannedAttempt:(NSString *)attempt boot:(NSString *)boot error:(NSError **)error;
- (BOOL)confirmRegistryCheckpointWithError:(NSError **)error;
@end
@implementation InertHistory
- (NSDictionary *)consumeUIDForPlannedAttempt:(NSString *)attempt boot:(NSString *)boot error:(NSError **)error {
    (void)attempt;(void)boot;(void)error;consumes++;uid_burn_count++;
    self.checkpoint=@{@"burn_count":@(uid_burn_count),@"last_uid":@(next_candidate_uid),@"next_uid":@(next_candidate_uid+1)};
    uid_t candidate=next_candidate_uid++;
    if(scenario==16){gStopping=true;return nil;}
    if(scenario==17)return @{@"uid":@(candidate),@"installation_id":@"fixture-installation",@"seq":@"1",@"sha256":@"fixture-allocation-sha"};
    return nil;
}
- (BOOL)confirmRegistryCheckpointWithError:(NSError **)error {(void)error;return YES;}
@end
static InertHistory *gUIDHistory;
static uint64_t nowMS(void){return clockValue;}
static bool refreshAccountPolicy(void){if(scenario==14)gStopping=true;return true;}
static bool refreshUIDHistory(void){if(scenario==15)gStopping=true;return true;}
static NSString *randomHex(void){return [@"f" stringByPaddingToLength:64 withString:@"f" startingAtIndex:0];}
static NSString *pathChild(NSString *parent,NSString *leaf){path_child_calls++;return [parent stringByAppendingFormat:@"/%@",leaf];}
static int members(uid_t uid,pid_t *pids){(void)uid;(void)pids;member_calls++;return scenario==17?-1:0;}
static NSString *sandboxProfile(NSString *workspace){(void)workspace;return @"inert";}
static NSDictionary *identityJSON(struct KIdentity *v){(void)v;return @{};}
static bool validUIDAllocation(NSMutableDictionary *entry){(void)entry;return true;}
static bool closeAdmission(NSMutableDictionary *e,NSString *reason,uint64_t budget){(void)reason;(void)budget;
    close_calls++;gDrainOnly=false;gClosing=e;e[@"state"]=@"closing";return false;}
static bool ownerReadACL(int fd,uid_t owner,bool directory){(void)fd;(void)owner;(void)directory;return false;}
static int acquireCleanupBarrier(NSMutableDictionary *e){(void)e;return 100;}
static int observeExact(NSDictionary *saved,struct KIdentity *v){(void)saved;memset(v,0,sizeof(*v));
    observations++;if(scenario==11&&observations>=3)clockValue=600;return scenario>=8&&!ownersGone?1:0;}
static bool signalExact(NSDictionary *saved,uid_t uid){(void)saved;(void)uid;return true;}
static bool freshIdentity(pid_t pid,struct KIdentity *v){(void)pid;memset(v,0,sizeof(*v));return false;}
static int fakeSignal(const audit_token_t *token,int signal){(void)token;(void)signal;return 0;}
static int (*gSignalToken)(const audit_token_t *,int)=fakeSignal;
static bool saveJSON(NSString *name,NSDictionary *record){
    saves++;if(scenario==1||scenario==2||scenario==5)clockValue=600;
    if(scenario==2&&saves==2){gPoisoned=true;return false;}
    if(scenario==5&&saves==2)return false;
    storedProofs[name]=[record copy];return true;
}
static bool persist(void){commits++;if(scenario==3)clockValue=600;if(scenario==17)gStopping=true;return !gPoisoned;}
static NSDictionary *statusReply(NSMutableDictionary *e){status_reads++;if(scenario==4||scenario==9)clockValue=600;if(scenario==7)gPoisoned=true;
    if(scenario==12)ownersGone=true;
    return @{ @"ok":@YES,@"proof":e[@"proof"]?:@{},@"state":e[@"state"],
              @"allocation_tuple_verified_current":@((bool)(scenario!=6&&scenario!=10)),@"registry_healthy":@((bool)!gPoisoned),
              @"cleanup_budget_exceeded":e[@"cleanup_budget_exceeded"]?:@NO };
}
static bool sendJSON(int fd,NSDictionary *reply){(void)fd;delivered=reply;return true;}
static void finishTransport(int fd){(void)fd;}
static int inertClose(int fd){(void)fd;return 0;}
static int inertOpenAt(int fd,const char *path,int flags,...){(void)fd;(void)path;(void)flags;unexpected_fs_calls++;errno=EIO;return -1;}
static int inertMkdirAt(int fd,const char *path,mode_t mode){(void)fd;(void)path;(void)mode;unexpected_fs_calls++;errno=EIO;return -1;}
static int inertFstat(int fd,struct stat *st){(void)fd;(void)st;unexpected_fs_calls++;errno=EIO;return -1;}
static int inertFsync(int fd){(void)fd;unexpected_fs_calls++;errno=EIO;return -1;}
static int inertFchown(int fd,uid_t owner,gid_t group){(void)fd;(void)owner;(void)group;unexpected_fs_calls++;errno=EIO;return -1;}
static int inertFchmod(int fd,mode_t mode){(void)fd;(void)mode;unexpected_fs_calls++;errno=EIO;return -1;}
#define openat inertOpenAt
#define mkdirat inertMkdirAt
#define fstat inertFstat
#define fsync inertFsync
#define fchown inertFchown
#define fchmod inertFchmod
#define close inertClose
'''

MAIN = r'''
static NSString *hex(NSString *s){return [s stringByPaddingToLength:64 withString:s startingAtIndex:0];}
static NSMutableDictionary *record(NSString *attempt,NSString *nonce,uid_t owner) {
    NSDictionary *d=@{@"boundary_id":attempt,@"attempt_id":attempt,@"attempt_nonce":nonce,@"backend":@"darwin_private_ruid",
        @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,
        @"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
        @"stub_binary_sha256":gStubBinarySHA,@"stub_wire_version":@"KVS1",@"installation_id":hex(@"a"),
        @"account_policy_id":K_ACCOUNT_POLICY,@"account_policy_sha256":hex(@"c"),@"allocation_sha256":hex(@"d"),@"allocation_seq":@"1",
        @"uid_history_header_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA,@"uid_history_source_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA,
        @"workspace_path":pathChild(gWorkspaceRoot,attempt),@"task_ruid":@(K_UID_FIRST),@"task_gid":@(K_UID_FIRST),@"owner_uid":@(owner),
        @"work_budget_ms":@120000,@"cleanup_budget_ms":@30000,@"work_started_monotonic_ms":@0,@"work_deadline_ms":@120000};
    NSDictionary *identity=@{@"pid":@101,@"start_sec":@100,@"start_usec":@1,@"ruid":@(owner),@"pidversion":@1,@"unique_id":@"123"};
    return [@{@"descriptor":d,@"descriptor_sha256":sha(jsonData(d)),@"owner_uid":@(owner),@"controller":identity,
        @"work_budget_ms":@120000,@"cleanup_budget_ms":@30000,@"work_started_monotonic_ms":@0,@"work_deadline_ms":@120000,
        @"admission_closed":@YES,@"spawn_intent":@NO,@"authority_spawn_intent":@NO,@"state":@"closed",
        @"cleanup_started_monotonic_ms":@1,@"cleanup_deadline_ms":@500,@"cleanup_budget_exceeded":@NO} mutableCopy];
}
static void reset(void){
    clockValue=10;consumes=saves=commits=status_reads=close_calls=observations=0;
    member_calls=path_child_calls=unexpected_fs_calls=uid_burn_count=0;next_candidate_uid=K_UID_FIRST;
    gStopping=(scenario==13);gPoisoned=false;gEntryStoreLoaded=true;gRun.pid=0;ownersGone=false;
    gWorkspaceRoot=@"/unopened/workspace";gHost=@"fixture-host";gBoot=@"fixture-boot";gBinarySHA=hex(@"e");gStubBinarySHA=hex(@"b");
    gAccountPolicy=@{@"owners":@{@"501":@"owner"}};gRuntimePins=@{};gUIDHistory=[InertHistory new];gUIDHistory.healthy=YES;
    gRegistry=[@{@"attempts":[NSMutableDictionary dictionary],@"active_attempt":@"",@"installation_id":hex(@"a")} mutableCopy];
    storedProofs=[NSMutableDictionary dictionary];delivered=nil;gClosing=nil;gCloseWaiter=100;gCleanupBarrier=100;gDrainOnly=false;
}
static void check(NSMutableArray *rows,NSString *name,BOOL pass,NSDictionary *details){
    [rows addObject:@{@"name":name,@"pass":@(pass),@"details":details?:@{}}];
}
int main(void){@autoreleasepool {
    NSMutableArray *rows=[NSMutableArray array];scenario=0;reset();NSString *id=hex(@"1"),*nonce=hex(@"2");
    NSMutableDictionary *old=record(id,nonce,501);entries()[id]=old;struct KPeer peer={.owner=501};
    NSDictionary *q=@{@"attempt_nonce":nonce,@"mode":@"isolated_copy",@"work_budget_ms":@120000,@"cleanup_budget_ms":@30000};
    NSDictionary *reply=prepare(q,&peer);
    check(rows,@"closed_nonce_never_allocates_again",[reply[@"error"] isEqual:@"ATTEMPT_ALREADY_RESERVED"]&&consumes==0,
        @{@"error":reply[@"error"]?:@"",@"UID_consume_calls":@(consumes)});
#if HAS_NONCE_HELPER
    bool ambiguous=false;NSMutableDictionary *found=reservationForNonce(501,nonce,&ambiguous);
    check(rows,@"closed_nonce_lookup_is_unique",found==old&&!ambiguous,nil);
    entries()[hex(@"3")]=record(hex(@"3"),nonce,501);
    check(rows,@"duplicate_nonce_is_ambiguous",reservationForNonce(501,nonce,&ambiguous)==nil&&ambiguous,nil);
    [entries() removeObjectForKey:hex(@"3")];old[@"descriptor_sha256"]=hex(@"f");
    check(rows,@"invalid_matching_record_is_not_reallocated",reservationForNonce(501,nonce,&ambiguous)==nil&&ambiguous,nil);
    check(rows,@"other_owner_history_is_not_disclosed",reservationForNonce(502,nonce,&ambiguous)==nil&&!ambiguous,nil);
    [old removeObjectForKey:@"owner_uid"];
    check(rows,@"malformed_owner_cannot_reallocate_nonce",reservationForNonce(501,nonce,&ambiguous)==nil&&ambiguous,nil);
#endif
    for(scenario=0;scenario<8;scenario++){
        reset();NSMutableDictionary *e=record(id,nonce,501);entries()[id]=e;gRegistry[@"active_attempt"]=id;
        e[@"admission_closed"]=@YES;e[@"state"]=@"closing";e[@"cleanup_started_monotonic_ms"]=@1;
        e[@"cleanup_deadline_ms"]=@500;e[@"cleanup_budget_exceeded"]=@NO;gCloseDeadline=500;gClosing=e;
        advanceCleanup();NSDictionary *proof=e[@"proof"];BOOL pass;
        if(scenario==0)pass=[e[@"state"] isEqual:@"closed"]&&![proof[@"cleanup_budget_exceeded"] boolValue]&&saves==1;
        else if(scenario==2||scenario>=5)pass=[e[@"state"] isEqual:@"cleanup_unconfirmed"]&&[gRegistry[@"active_attempt"] isEqual:id]
            &&![e objectForKey:@"receipt_sha256"]&&![proof[@"native_cleanup_facts_confirmed"] boolValue];
        else pass=[e[@"state"] isEqual:@"closed"]&&[proof[@"cleanup_budget_exceeded"] boolValue]&&saves==2
            &&[proof isEqual:storedProofs[e[@"receipt_name"]]]&&[e[@"receipt_sha256"] isEqual:sha(jsonData(proof))];
        NSArray *names=@[@"healthy_terminal_receipt",@"slow_receipt_gets_expired_revision",@"failed_expired_revision_keeps_claim",
            @"slow_index_gets_expired_revision",@"slow_status_readback_gets_expired_revision",
            @"failed_expired_open_without_poison_keeps_claim",@"late_status_allocation_loss_keeps_claim",
            @"late_status_registry_poison_keeps_claim"];
        check(rows,names[scenario],pass,@{@"state":e[@"state"],@"saves":@(saves),@"expired":proof[@"cleanup_budget_exceeded"]?:@NO,
            @"active_claim":gRegistry[@"active_attempt"],@"native_facts":proof[@"native_cleanup_facts_confirmed"]?:@NO});
    }
    for(scenario=8;scenario<13;scenario++){
        reset();NSMutableDictionary *e=record(id,nonce,501);entries()[id]=e;gRegistry[@"active_attempt"]=id;
        e[@"authority"]=e[@"controller"];e[@"state"]=@"closing";gCloseDeadline=500;gClosing=e;gDrainOnly=true;
        advanceCleanup();BOOL pass=scenario==8?
            ([e[@"state"] isEqual:@"commands_drained"]&&delivered!=nil&&gClosing==nil&&close_calls==0):
            ([e[@"state"] isEqual:@"closing"]&&delivered==nil&&gClosing==e&&close_calls==1);
        NSArray *names=@[@"healthy_drain_returns_current_phase",@"slow_drain_status_cannot_publish_positive_phase",
            @"late_drain_policy_loss_cannot_publish_positive_phase",@"slow_exact_owner_check_cannot_publish_positive_phase",
            @"owner_loss_during_status_cannot_publish_positive_phase"];
        check(rows,names[scenario-8],pass,@{@"state":e[@"state"],@"close_calls":@(close_calls),
            @"reply_delivered":@(delivered!=nil),@"expired":e[@"cleanup_budget_exceeded"]?:@NO});
    }
    /* Stop-admission regressions invoke the extracted prepare() body. Mocked
     * callbacks flip the real global stop flag; no producer logic is copied here. */
    NSArray *stopNames=@[@"stopping_at_prepare_entry",@"stop_during_account_policy_refresh",
        @"stop_during_uid_history_refresh",@"stop_during_uid_consumption",@"stop_during_checkpoint_persist"];
    for(scenario=13;scenario<18;scenario++){
        reset();gStopping=(scenario==13);
        struct KPeer stopPeer={.owner=501};
        NSDictionary *stopQuery=@{@"attempt_nonce":hex(@"7"),@"mode":@"isolated_copy",
            @"work_budget_ms":@120000,@"cleanup_budget_ms":@30000};
        NSDictionary *stopReply=prepare(stopQuery,&stopPeer);
        BOOL isConsumeStop=(scenario==16),isPersistStop=(scenario==17);
        BOOL stopped=[stopReply[@"error"] isEqual:@"DAEMON_STOPPING"];
        BOOL noPositiveReply=![stopReply[@"ok"] boolValue]&&![stopReply[@"publish_ok"] boolValue]
            &&![stopReply[@"admission_open"] boolValue];
        BOOL noReservation=(entries().count==0&&[gRegistry[@"active_attempt"] length]==0
            &&path_child_calls==0&&member_calls==0&&unexpected_fs_calls==0);
        BOOL burnRetained=isConsumeStop?
            (uid_burn_count==1&&[gUIDHistory.checkpoint[@"burn_count"] unsignedIntValue]==1
             &&[gUIDHistory.checkpoint[@"next_uid"] unsignedIntValue]==K_UID_FIRST+1
             &&next_candidate_uid==K_UID_FIRST+1&&commits==0):
            isPersistStop?(uid_burn_count==1&&[gUIDHistory.checkpoint[@"burn_count"] unsignedIntValue]==1
             &&[gRegistry[@"uid_history_checkpoint"][@"burn_count"] unsignedIntValue]==1
             &&[gUIDHistory.checkpoint[@"next_uid"] unsignedIntValue]==K_UID_FIRST+1
             &&next_candidate_uid==K_UID_FIRST+1&&commits==1):
            (uid_burn_count==0&&consumes==0);
        BOOL pass=stopped&&noPositiveReply&&noReservation&&burnRetained;
        check(rows,stopNames[scenario-13],pass,@{@"error":stopReply[@"error"]?:@"",
            @"active_attempt":gRegistry[@"active_attempt"]?:@"",@"entry_count":@(entries().count),
            @"publish_ok":@( [stopReply[@"publish_ok"] boolValue] ),@"admission_open":@( [stopReply[@"admission_open"] boolValue] ),
            @"admission_or_workspace_path_touched":@(path_child_calls!=0),@"members_calls":@(member_calls),
            @"unexpected_filesystem_calls":@(unexpected_fs_calls),@"consumes":@(consumes),
            @"burn_count":@(uid_burn_count),@"checkpoint":gUIDHistory.checkpoint?:@{}});
    }
    NSData *data=jsonData(rows);fwrite(data.bytes,1,data.length,stdout);fputc('\n',stdout);
    for(NSDictionary *row in rows)if(![row[@"pass"] boolValue])return 1;return 0;
}}
'''

REQUIRED_CASES = [
    'closed_nonce_never_allocates_again',
    'closed_nonce_lookup_is_unique',
    'duplicate_nonce_is_ambiguous',
    'invalid_matching_record_is_not_reallocated',
    'other_owner_history_is_not_disclosed',
    'malformed_owner_cannot_reallocate_nonce',
    'healthy_terminal_receipt',
    'slow_receipt_gets_expired_revision',
    'failed_expired_revision_keeps_claim',
    'slow_index_gets_expired_revision',
    'slow_status_readback_gets_expired_revision',
    'failed_expired_open_without_poison_keeps_claim',
    'late_status_allocation_loss_keeps_claim',
    'late_status_registry_poison_keeps_claim',
    'healthy_drain_returns_current_phase',
    'slow_drain_status_cannot_publish_positive_phase',
    'late_drain_policy_loss_cannot_publish_positive_phase',
    'slow_exact_owner_check_cannot_publish_positive_phase',
    'owner_loss_during_status_cannot_publish_positive_phase',
    'stopping_at_prepare_entry',
    'stop_during_account_policy_refresh',
    'stop_during_uid_history_refresh',
    'stop_during_uid_consumption',
    'stop_during_checkpoint_persist',
]


def function(source, name):
    pattern = r'^static [^\n]*\b' + re.escape(name) + r'\([^\n]*'
    match = re.search(pattern, source, re.M)
    if not match:
        return None
    start = match.start()
    opening = source.index('{', start)
    depth = 0
    in_string = False
    escape = False
    quote = ''
    in_line = in_block = False
    i = opening
    while i < len(source):
        c = source[i]
        following = source[i:i+2]
        if in_line:
            if c == '\n': in_line = False
        elif in_block:
            if following == '*/': in_block=False; i+=1
        elif in_string:
            if escape: escape=False
            elif c == '\\': escape=True
            elif c == quote: in_string=False
        elif following == '//': in_line=True; i+=1
        elif following == '/*': in_block=True; i+=1
        elif c in ('"', "'"): in_string=True; quote=c
        elif c == '{': depth+=1
        elif c == '}':
            depth-=1
            if depth == 0: return source[start:i+1]
        i+=1
    raise ValueError('unclosed function: '+name)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();args.output_dir.mkdir(parents=True,exist_ok=False)
    raw=args.source.read_bytes();source=raw.decode()
    names=['jsonData','sha','isString','hex64','decimal64','numericField','validDuration','booleanField',
           'failure','entries','entryFor','activeID','validRecordedIdentity','validRecordedEntry','reservationForNonce','prepare','advanceCleanup']
    functions={name:function(source,name) for name in names}
    assert all(value is not None for name,value in functions.items() if name!='reservationForNonce')
    target=args.output_dir/'actual-broker-logic-inert.m'
    target.write_text(PRELUDE+'\n'+'\n'.join(value for value in functions.values() if value)+'\n'
                      +f'#define HAS_NONCE_HELPER {int(functions["reservationForNonce"] is not None)}\n'+MAIN)
    report={'scope':'actual Objective-C producer functions; inert I/O, kernel, transport and clock; NOT native qualification',
            'platform':platform.system(),'source_sha256':hashlib.sha256(raw).hexdigest(),
            'function_sha256':{k:hashlib.sha256(v.encode()).hexdigest() for k,v in functions.items() if v},
            'generated_source_sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
    if platform.system()!='Darwin':
        report['status']='NOT_RUN_DARWIN_FOUNDATION_REQUIRED'
    else:
        binary=args.output_dir/'actual-broker-logic-inert'
        command=['clang','-fobjc-arc','-Wall','-Wextra','-Wno-deprecated-declarations','-Wno-unused-function',
                 '-framework','Foundation',str(target),'-o',str(binary)]
        build=subprocess.run(command,capture_output=True,text=True,timeout=120)
        (args.output_dir/'compile.stdout').write_text(build.stdout);(args.output_dir/'compile.stderr').write_text(build.stderr)
        report.update(compile_command=command,compile_exit=build.returncode,status='COMPILE_FAILED')
        if build.returncode==0:
            run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
            (args.output_dir/'run.stdout').write_text(run.stdout);(args.output_dir/'run.stderr').write_text(run.stderr)
            cases=json.loads(run.stdout)
            actual_names=[row.get('name') for row in cases if isinstance(row,dict)]
            coverage={'expected_count':len(REQUIRED_CASES),'actual_count':len(cases),
                      'missing':[name for name in REQUIRED_CASES if name not in actual_names],
                      'unexpected':[name for name in actual_names if name not in REQUIRED_CASES],
                      'ordered_names_match':actual_names==REQUIRED_CASES}
            coverage_ok=(len(cases)==24 and actual_names==REQUIRED_CASES
                         and all(row.get('pass') is True for row in cases if isinstance(row,dict)))
            report.update(exit_code=run.returncode,cases=cases,case_coverage=coverage,
                          status='PASS' if run.returncode==0 and coverage_ok else 'FAIL')
    (args.output_dir/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status'] in ('PASS','NOT_RUN_DARWIN_FOUNDATION_REQUIRED') else 1


if __name__=='__main__': raise SystemExit(main())
