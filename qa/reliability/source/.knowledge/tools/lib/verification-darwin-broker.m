/*
 * Explicitly installed macOS isolated-copy verification broker.
 *
 * Build: clang -fobjc-arc -Wall -Wextra -Wno-deprecated-declarations -framework Foundation
 *   -DKNOWLEDGE_BROKER_SOURCE_SHA='"<sha256 of this source>"'
 *   -DKNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA='"<header sha256>"'
 *   -DKNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA='"<implementation sha256>"'
 *   -DKNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA='"<transport header sha256>"'
 *   this.m verification-darwin-uid-history.m -o broker
 *
 * This source is NOT a qualified containment backend. The production gate is
 * deliberately closed. --qualification-mode is a root administrator's explicit
 * diagnostic switch; neither its receipts nor a zero UID scan certify closure.
 * No JavaScript is evaluated by the privileged daemon or native launch stub.
 */
#if !defined(__APPLE__)
#error "verification-darwin-broker requires the macOS SDK and a real Darwin host"
#endif
#import <Foundation/Foundation.h>
#import "verification-darwin-uid-history.h"
#include "verification-darwin-transport.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <bsm/audit.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/task_special_ports.h>
#include <membership.h>
#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sandbox.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
#include <launch.h>
#if !defined(KNOWLEDGE_DARWIN_QA_SOCKET_PATH) || !defined(KNOWLEDGE_DARWIN_QA_BUILD_ID)
#error "QA persistence gate requires explicit protected socket and build identity"
#endif
static bool gQAServing;
void KVDarwinQAPersistenceGate(const char *point);
void KVDarwinQAPersistenceGateComplete(const char *point,bool ok,int savedErrno);
#endif

#ifndef KNOWLEDGE_BROKER_SOURCE_SHA
#define KNOWLEDGE_BROKER_SOURCE_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_DARWIN_STUB_SOURCE_SHA
#define KNOWLEDGE_DARWIN_STUB_SOURCE_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA
#define KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA
#define KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA
#define KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA "UNPINNED"
#endif
#define K_SCHEMA @"knowledge-darwin-broker.v1"
#define K_MAX_JSON (12u * 1024u * 1024u)
#define K_MAX_FRAME (1024u * 1024u)
#define K_MAX_FILES 50000u
#define K_MAX_COPY (2ull * 1024ull * 1024ull * 1024ull)
#define K_UID_FIRST 1000000000u
#define K_UID_LAST 1900000000u
#define K_ACCOUNT_POLICY @"admin_reserved_interval_no_runtime_nss.v1"
#define K_MAX_OWNERS 64u
/* Actor refresh cadence, not semantic progress or a stop SLA. Disk I/O may
 * stall this actor; reactor/observer remain independent. Never catch up missed
 * ticks in a burst. Fresh transition guards remain mandatory independently. */
#define K_ACTIVE_STATE_REFRESH_MS 5000ull
#define K_PID_CAP 65536u
/* Match verification-policy.js. Valid caller budgets are never silently
 * shortened to the earlier one-hour work / one-minute cleanup prototype caps. */
#define K_MAX_WORK_MS (600000ull * 100000ull)
#define K_MAX_CLEANUP_MS 3600000ull
/* The candidate implements the production contract. This is an implementation
 * admission flag, not a claim that the release/platform qualification matrix
 * has passed. Diagnostic lineage and compile-time QA instrumentation can only
 * disable it. It is selected once after argv parsing and before any worker,
 * listener or admission; no request or environment variable can change it. */
static const bool kCapabilityImplemented = true;
static bool gCapabilityQualified;
static bool capabilityForMode(bool qualificationMode) {
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    (void)qualificationMode;return false;
#else
    return kCapabilityImplemented&&!qualificationMode;
#endif
}

/* Apple private combined ABI: one proc reference yields credentials + unique
 * birth + PID signal version. Fail closed when the kernel/SDK ABI differs. */
struct KUnique { uint8_t uuid[16]; uint64_t uniqueid, parent_uniqueid;
    int32_t pidversion; uint32_t reserved; uint64_t reserved2, reserved3; };
struct KIdentity { struct proc_bsdinfo bsd; struct KUnique unique; };
_Static_assert(sizeof(struct KUnique) == 56, "Darwin proc unique ABI");
typedef int (*KSignalToken)(const audit_token_t *, int);
static KSignalToken gSignalToken;
static NSString *gExecutable, *gBinarySHA, *gStubPath, *gStubBinarySHA, *gRegistryPath, *gSocketPath, *gWorkspaceRoot;
static NSString *gPrintWorkspace;
static NSString *gAllocatorPath,*gAnchorPath;
static NSString *gAccountPolicyArgument,*gAccountPolicySHA,*gAccountPolicyReason;
static NSMutableArray<NSString *> *gAllowedOwners;
static NSDictionary *gAccountPolicy;
static NSDictionary<NSString *,NSData *> *gOwnerUUIDs;
static NSData *gAccountPolicyBytes;
static bool gAccountPolicyHealthy,gAccountPolicyFailed;
static KVDarwinUIDHistory *gUIDHistory;
static bool gUIDRefreshAttempted,gEntryStoreLoaded,gUIDRangeConfirmed;
static uint64_t gUIDLastRefreshMS;
static NSString *gBoot, *gHost, *gDaemonEpoch;
static NSArray<NSString *> *gRuntimes;
static NSDictionary<NSString *,NSString *> *gRuntimePins;
static NSMutableDictionary *gRegistry;
static NSData *gRegistryDurableBytes;
static int gRegistryFD = -1, gWorkspaceFD = -1, gListen = -1;
static bool gQualificationMode, gPoisoned, gLaunchdCreationParent;
static NSString *gQuarantineReason;
static const char *gSetupStage="initial";
/* Lock-free atomic access is required by both the signal handler and observer.
 * sig_atomic_t alone does not synchronize C threads. */
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"stop latch must be signal-safe lock-free");
static _Atomic sig_atomic_t gStopping;
static _Atomic bool gActorDone,gWriterPending,gHistoryLockReady;
static _Atomic int gActorExitStatus;
static _Atomic uint64_t gStopGeneration;
static void publishState(void);
static uint64_t gTransportTimeoutMS=KVT_DEFAULT_TRANSPORT_MS;
static uint64_t gLifecycleTimeoutMS=KVT_DEFAULT_LIFECYCLE_MS;
static bool gTransportTimeoutExplicit,gLifecycleTimeoutExplicit;

static _Atomic bool gClockFailed;
static uint64_t nowMS(void) {
    /* Per-thread monotonicity avoids treating ordinary cross-thread scheduling
     * as a backwards clock. Unknown time closes admission globally. */
    static _Thread_local uint64_t last;struct timespec t={0};
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000
        ||(uint64_t)t.tv_sec>(UINT64_MAX-K_MAX_WORK_MS-K_MAX_CLEANUP_MS-999)/1000){
        atomic_store(&gClockFailed,true);gStopping=1;return last;}
    uint64_t now=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
    if(now<last){atomic_store(&gClockFailed,true);gStopping=1;return last;}
    last=now;return now;
}
static bool exactIO(int fd, void *p, size_t n, bool writing) {
    unsigned char *b = p; while (n) { ssize_t r = writing ? write(fd,b,n) : read(fd,b,n);
        if (r < 0 && errno == EINTR) continue; if (r <= 0) return false;
        b += r; n -= (size_t)r; } return true;
}
static NSData *jsonData(id value) { return [NSJSONSerialization dataWithJSONObject:value
    options:NSJSONWritingSortedKeys|NSJSONWritingWithoutEscapingSlashes error:NULL]; }
static NSDictionary *parseJSON(NSData *data) { if (!data || data.length > K_MAX_JSON) return nil;
    id v = [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:NULL];
    return [v isKindOfClass:NSDictionary.class] ? v : nil; }
static NSString *sha(NSData *d) { unsigned char h[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(d.bytes,(CC_LONG)d.length,h); char s[65];
    for (unsigned i=0;i<32;i++) snprintf(s+2*i,3,"%02x",h[i]); return @(s); }
static NSString *randomHex(void) { unsigned char b[32]; arc4random_buf(b,sizeof(b));
    char s[65]; for(unsigned i=0;i<32;i++) snprintf(s+2*i,3,"%02x",b[i]); return @(s); }
static bool isString(id v, NSUInteger max) { return [v isKindOfClass:NSString.class]
    && [v length] > 0 && [v length] <= max
    && [v rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0,1)]].location==NSNotFound; }
static bool hex64(id v) { if (!isString(v,64) || [v length]!=64) return false;
    return [v rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:
        @"0123456789abcdef"] invertedSet]].location==NSNotFound; }
static bool decimal64(id value,uint64_t *out) {
    if(!isString(value,20))return false;uint64_t result=0;
    for(NSUInteger i=0;i<[value length];i++){
        unichar c=[value characterAtIndex:i];if(c<'0'||c>'9')return false;
        unsigned digit=(unsigned)(c-'0');if(result>(UINT64_MAX-digit)/10)return false;
        result=result*10+digit;
    }
    if([value length]>1&&[value characterAtIndex:0]=='0')return false;
    *out=result;return true;
}
static bool nativeUInt64Field(id value) {
    uint64_t number=0;return [value isKindOfClass:NSNumber.class]
        &&CFGetTypeID((__bridge CFTypeRef)value)!=CFBooleanGetTypeID()
        &&decimal64([value stringValue],&number);
}
static bool equalSecret(NSString *a, NSString *b) {
    NSData *x=[a dataUsingEncoding:NSUTF8StringEncoding], *y=[b dataUsingEncoding:NSUTF8StringEncoding];
    if (!x || x.length!=y.length) return false; const uint8_t *p=x.bytes,*q=y.bytes; uint8_t v=0;
    for(NSUInteger i=0;i<x.length;i++) v|=p[i]^q[i]; return v==0;
}
static bool safeText(id v,NSUInteger max) { return [v isKindOfClass:NSString.class]&&[v length]<=max
    &&[v rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0,1)]].location==NSNotFound; }
static bool canonicalAbsolute(NSString *path) {
    if(!isString(path,4096)||![path hasPrefix:@"/"]||[path hasSuffix:@"/"]
        ||[path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)return false;
    NSArray *parts=[path componentsSeparatedByString:@"/"];
    for(NSUInteger i=1;i<parts.count;i++)if(![parts[i] length]||[parts[i] isEqual:@"."]||[parts[i] isEqual:@".."])return false;
    return true;
}
/* Keep physical spelling. Foundation path utilities may rewrite /private/tmp
 * into the /tmp symlink, which nofollow trust checks must never follow. */
static NSString *pathChild(NSString *parent,NSString *leaf) {
    return [parent isEqual:@"/"]?[@"/" stringByAppendingString:leaf]:[parent stringByAppendingFormat:@"/%@",leaf];
}
static NSString *pathParent(NSString *path) {
    NSRange slash=[path rangeOfString:@"/" options:NSBackwardsSearch];
    return slash.location==0?@"/":[path substringToIndex:slash.location];
}
static bool numericField(id value) { if(![value isKindOfClass:NSNumber.class]
    ||CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID())return false;
    double d=[value doubleValue];return isfinite(d)&&d>=0&&d<=9007199254740991.0&&floor(d)==d; }
static bool validDuration(id value,uint64_t maximum) {
    return numericField(value)&&[value unsignedLongLongValue]>=1&&[value unsignedLongLongValue]<=maximum;
}
static bool booleanField(id value) {
    return value&&CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID();
}
static bool requestTypes(NSDictionary *q) {
    for(NSString *key in @[@"work_budget_ms",@"cleanup_budget_ms",@"timeout_ms",@"mode",@"bytes",@"offset"]){
        if([key isEqual:@"mode"]&&[q[key] isKindOfClass:NSString.class])continue;
        if(q[key]&&!numericField(q[key]))return false;}
    return true;
}
static NSDictionary *failure(NSString *code) { return @{ @"ok":@NO,@"schema":K_SCHEMA,
    @"error":code,@"capability_qualified":@(gCapabilityQualified),@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA }; }
static bool freshIdentity(pid_t pid, struct KIdentity *v) {
    memset(v,0,sizeof(*v)); return pid>0 && proc_pidinfo(pid,18,0,v,sizeof(*v))==(int)sizeof(*v)
        && v->bsd.pbi_pid==(uint32_t)pid && v->unique.uniqueid>0 && v->unique.pidversion>0;
}
static NSDictionary *identityJSON(struct KIdentity *v) { return @{ @"pid":@(v->bsd.pbi_pid),
    @"unique_id":[NSString stringWithFormat:@"%llu",v->unique.uniqueid],
    @"parent_unique_id":[NSString stringWithFormat:@"%llu",v->unique.parent_uniqueid],
    @"start_sec":@(v->bsd.pbi_start_tvsec),@"start_usec":@(v->bsd.pbi_start_tvusec),
    @"ruid":@(v->bsd.pbi_ruid),@"pidversion":@(v->unique.pidversion) }; }
static bool sameBirth(NSDictionary *saved, struct KIdentity *v) {
    uint64_t unique=0;
    return decimal64(saved[@"unique_id"],&unique)&&[saved[@"pid"] unsignedIntValue]==v->bsd.pbi_pid
        && unique==v->unique.uniqueid
        && [saved[@"start_sec"] unsignedLongLongValue]==v->bsd.pbi_start_tvsec
        && [saved[@"start_usec"] unsignedLongLongValue]==v->bsd.pbi_start_tvusec;
}
/* A disappearance is accepted only for ESRCH; an unsupported API/permission
 * failure is not evidence of process exit. A fresh different birth proves that
 * exact former identity exited, without signaling the recycled PID. */
static int observeExact(NSDictionary *saved, struct KIdentity *v) {
    errno=0; if(freshIdentity([saved[@"pid"] intValue],v)) return sameBirth(saved,v)?1:0;
    return errno==ESRCH?0:-1;
}
static bool signalExact(NSDictionary *saved, uid_t uid) {
    struct KIdentity v; int observed=observeExact(saved,&v); if(observed==0)return true;
    if(observed<0 || v.bsd.pbi_ruid!=uid || !gSignalToken)return false;
    audit_token_t t={{0}}; t.val[5]=v.bsd.pbi_pid; t.val[7]=(uint32_t)v.unique.pidversion;
    int rc=gSignalToken(&t,SIGKILL); return rc==0 || rc==ESRCH;
}
static int members(uid_t uid, pid_t *pids) {
    errno=0; int n=proc_listpids(PROC_RUID_ONLY,uid,pids,(int)(K_PID_CAP*sizeof(pid_t)));
    if(n<0 || (n==0&&errno!=0) || n%(int)sizeof(pid_t) || n>=(int)(K_PID_CAP*sizeof(pid_t)))return -1;
    return n/(int)sizeof(pid_t);
}

/* Root trust is checked on every ancestor without following symlinks. Only
 * the literal /private/tmp sticky ancestor is accepted for explicit CI roots.
 * Its child must already be root-owned and non-writable by group/other. */
static bool safeRootACL(NSString *path) {
    /* acl_get_file conflates a missing FILESEC_ACL property with ENOENT.
     * Query metadata explicitly so a missing object is never accepted as an
     * empty ACL. lstatx also avoids following a replaced final component. */
    filesec_t metadata=filesec_init();if(!metadata)return false;
    struct stat observed;int present=0;acl_t acl=NULL;
    bool fetched=lstatx_np(path.fileSystemRepresentation,&observed,metadata)==0
        &&!S_ISLNK(observed.st_mode)&&observed.st_uid==0
        &&filesec_query_property(metadata,FILESEC_ACL,&present)==0;
    if(fetched&&present)fetched=filesec_get_property(metadata,FILESEC_ACL,&acl)==0&&acl!=NULL;
    filesec_free(metadata);
    if(!fetched)return false;
    if(!present)return true;
    acl_entry_t entry;int next=ACL_FIRST_ENTRY;bool safe=true;
    while(acl_get_entry(acl,next,&entry)==0){next=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t permissions;
        if(acl_get_tag_type(entry,&tag)||acl_get_permset(entry,&permissions)){safe=false;break;}
        if(tag!=ACL_EXTENDED_ALLOW)continue;
        acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,
            ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
        for(unsigned i=0;i<sizeof(writes)/sizeof(writes[0]);i++)if(acl_get_perm_np(permissions,writes[i])!=0){safe=false;break;}
        if(!safe)break;
    }
    acl_free(acl);return safe;
}
static bool protectedPath(NSString *path, bool regular, bool allowTmp) {
    /* Foundation standardization can rewrite /private/tmp to /tmp. Validate
     * syntax lexically, then lstat every component without following links. */
    if(!canonicalAbsolute(path))return false;
    NSString *p=@"/"; NSArray *parts=[path componentsSeparatedByString:@"/"];
    for(NSUInteger i=1;i<parts.count;i++) { p=pathChild(p,parts[i]);
        struct stat s; if(lstat(p.fileSystemRepresentation,&s) || s.st_uid!=0 || S_ISLNK(s.st_mode))return false;
        bool leaf=i==parts.count-1;
        bool tmpException=allowTmp && [p isEqual:@"/private/tmp"] && S_ISDIR(s.st_mode) && (s.st_mode&S_ISVTX);
        if((s.st_mode&0022) && !tmpException)return false;
        if(!tmpException&&!safeRootACL(p))return false;
        if(!leaf && !S_ISDIR(s.st_mode))return false;
        if(leaf && (regular ? (!S_ISREG(s.st_mode)||s.st_nlink!=1||(s.st_mode&(S_ISUID|S_ISGID))) : !S_ISDIR(s.st_mode)))return false;
    } return true;
}
static bool sameFileSnapshot(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size
        &&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec
        &&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static NSData *readFD(int fd, size_t max) { struct stat s;
    if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_size<0||(uint64_t)s.st_size>max)return nil;
    NSMutableData *d=[NSMutableData dataWithLength:(NSUInteger)s.st_size];size_t at=0;
    while(at<d.length){ssize_t n=pread(fd,(unsigned char *)d.mutableBytes+at,d.length-at,(off_t)at);
        if(n<0&&errno==EINTR)continue;if(n<=0)return nil;at+=(size_t)n;}
    /* Prefix equality is insufficient: reject appended data and same-size
     * changes before publishing any hash or registry-health observation. */
    unsigned char extra;ssize_t n;do{n=pread(fd,&extra,1,(off_t)d.length);}while(n<0&&errno==EINTR);
    struct stat after;return n==0&&fstat(fd,&after)==0&&sameFileSnapshot(&s,&after)?d:nil;
}
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
/* Test build only. This gates a persistence syscall boundary; it is NOT proof
 * of a kernel I/O stall. Root QA driver owns the independent watchdog/release.
 * Only lifecycle actor uses these objects/Fds. No environment/public RPC hook. */
static int gQAListener=-2,gQAPeer=-1;
static bool gQAUsed;
static NSDictionary *gQAArm;
static NSString *gQAEnteredPoint;
static bool qaWrite(NSDictionary *record) {
    NSData *bytes=jsonData(record);if(!bytes||bytes.length>512)return false;
    uint32_t length=htonl((uint32_t)bytes.length);
    return exactIO(gQAPeer,&length,4,true)&&exactIO(gQAPeer,(void *)bytes.bytes,bytes.length,true);
}
static NSDictionary *qaRead(void) {
    uint32_t length=0;if(!exactIO(gQAPeer,&length,4,false))return nil;length=ntohl(length);
    if(length<2||length>512)return nil;NSMutableData *bytes=[NSMutableData dataWithLength:length];
    return exactIO(gQAPeer,bytes.mutableBytes,length,false)?parseJSON(bytes):nil;
}
static void qaFail(void) {
    gStopping=1;gQAUsed=true;gQAArm=nil;gQAEnteredPoint=nil;
    if(gQAPeer>=0){close(gQAPeer);gQAPeer=-1;}
}
static bool qaListener(void) {
    if(gQAListener!=-2)return gQAListener>=0;
    gQAListener=-1;NSString *path=@KNOWLEDGE_DARWIN_QA_SOCKET_PATH;struct stat parent,named;
    if(!hex64(@KNOWLEDGE_DARWIN_QA_BUILD_ID)||!canonicalAbsolute(path)
        ||!protectedPath(pathParent(path),false,true)||lstat(pathParent(path).fileSystemRepresentation,&parent)
        ||(parent.st_mode&07777)!=0700||lstat(path.fileSystemRepresentation,&named)
        ||!S_ISSOCK(named.st_mode)||named.st_uid!=0||(named.st_mode&07777)!=0600)return false;
    int *fds=NULL;size_t count=0;
    if(launch_activate_socket("KnowledgeQAPersistenceGate",&fds,&count)||count!=1){
        for(size_t i=0;i<count;i++)close(fds[i]);free(fds);return false;}
    int fd=fds[0];free(fds);struct sockaddr_un address={0};socklen_t length=sizeof(address);int type=0;socklen_t typeLength=sizeof(type);
    if(getsockname(fd,(struct sockaddr *)&address,&length)||address.sun_family!=AF_UNIX
        ||strnlen(address.sun_path,sizeof(address.sun_path))>=sizeof(address.sun_path)
        ||strcmp(address.sun_path,path.fileSystemRepresentation)||getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&typeLength)
        ||type!=SOCK_STREAM||!kvtNonblocking(fd)||fcntl(fd,F_SETFD,FD_CLOEXEC)<0){close(fd);return false;}
    gQAListener=fd;return true;
}
void KVDarwinQAPersistenceGate(const char *point) {
    if(!gQAServing||gQAUsed)return;
    if(!atomic_load_explicit(&gHistoryLockReady,memory_order_acquire)||!qaListener()){qaFail();return;}
    if(gQAPeer<0){
        gQAPeer=accept(gQAListener,NULL,NULL);if(gQAPeer<0){if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)qaFail();return;}
        uid_t uid;gid_t gid;int flags=fcntl(gQAPeer,F_GETFL);
        if(getpeereid(gQAPeer,&uid,&gid)||uid!=0||flags<0||fcntl(gQAPeer,F_SETFL,flags&~O_NONBLOCK)<0
            ||fcntl(gQAPeer,F_SETFD,FD_CLOEXEC)<0){qaFail();return;}
        NSDictionary *arm=qaRead();NSString *selected=arm[@"point"];
        if(arm.count!=5||![arm[@"schema"] isEqual:@"knowledge-darwin-qa-persistence-gate.v1"]
            ||![arm[@"op"] isEqual:@"arm"]||!hex64(arm[@"run_id"])||!numericField(arm[@"occurrence"])
            ||[arm[@"occurrence"] unsignedLongLongValue]!=1
            ||![@[@"history_journal_read",@"registry_file_fsync",@"registry_fullfsync",@"guardian_birth_registered"] containsObject:selected]){qaFail();return;}
        gQAArm=[arm copy];
    }
    if(![gQAArm[@"point"] isEqual:@(point)])return;
    gQAEnteredPoint=@(point);
    if(!qaWrite(@{@"schema":@"knowledge-darwin-qa-persistence-gate.v1",@"op":@"entered",
        @"run_id":gQAArm[@"run_id"],@"point":gQAEnteredPoint,@"ordinal":@1,@"broker_pid":@(getpid()),
        @"qa_build_id":@KNOWLEDGE_DARWIN_QA_BUILD_ID,@"persistence_gate":@YES})){qaFail();return;}
    NSDictionary *release=qaRead();
    if(release.count!=5||![release[@"schema"] isEqual:@"knowledge-darwin-qa-persistence-gate.v1"]
        ||![release[@"op"] isEqual:@"release"]||![release[@"run_id"] isEqual:gQAArm[@"run_id"]]
        ||![release[@"point"] isEqual:gQAEnteredPoint]||!numericField(release[@"ordinal"])
        ||[release[@"ordinal"] unsignedLongLongValue]!=1)qaFail();
}
void KVDarwinQAPersistenceGateComplete(const char *point,bool ok,int savedErrno) {
    if(!gQAEnteredPoint||![gQAEnteredPoint isEqual:@(point)])return;
    if(!qaWrite(@{@"schema":@"knowledge-darwin-qa-persistence-gate.v1",@"op":@"completed",
        @"run_id":gQAArm[@"run_id"],@"point":gQAEnteredPoint,@"ordinal":@1,@"result_ok":@(ok),
        @"errno":@(ok?0:savedErrno)})){qaFail();return;}
    gQAUsed=true;gQAArm=nil;gQAEnteredPoint=nil;close(gQAPeer);gQAPeer=-1;
}
#endif
static NSString *protectedFileSHA(NSString *path) {
    struct stat named,opened,after;
    if(lstat(path.fileSystemRepresentation,&named)||!S_ISREG(named.st_mode))return nil;
    /* Bind the snapshot before checking pathname trust, so an intervening
     * replacement cannot borrow the preceding object's protectedPath check. */
    if(!protectedPath(path,true,true))return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC); if(fd<0)return nil;
    NSData *d=fstat(fd,&opened)==0&&sameFileSnapshot(&named,&opened)?readFD(fd,256u*1024u*1024u):nil;
    if(d&&(lstat(path.fileSystemRepresentation,&after)||!sameFileSnapshot(&opened,&after)))d=nil;
    if(close(fd))d=nil;return d?sha(d):nil;
}
static bool rootCredentials(const struct KIdentity *v) {
    return v->bsd.pbi_ruid==0&&v->bsd.pbi_uid==0&&v->bsd.pbi_svuid==0;
}
static bool sameKernelBirth(const struct KIdentity *a,const struct KIdentity *b) {
    return a->bsd.pbi_pid==b->bsd.pbi_pid&&a->unique.uniqueid==b->unique.uniqueid
        &&a->unique.pidversion==b->unique.pidversion&&a->unique.parent_uniqueid==b->unique.parent_uniqueid
        &&a->bsd.pbi_ppid==b->bsd.pbi_ppid&&a->bsd.pbi_start_tvsec==b->bsd.pbi_start_tvsec
        &&a->bsd.pbi_start_tvusec==b->bsd.pbi_start_tvusec;
}
/* This is a kernel creation-lineage check, NOT attestation of an installed
 * system-domain plist. Protected administrator installation and the OS TCB
 * remain prerequisites. In particular an orphan with current ppid1 fails. */
static bool launchdRootBirth(pid_t pid) {
    struct KIdentity candidate,init,again,initAgain;char image[PROC_PIDPATHINFO_MAXSIZE];
    if(!freshIdentity(pid,&candidate)||!freshIdentity(1,&init)||!rootCredentials(&candidate)||!rootCredentials(&init)
        ||candidate.bsd.pbi_ppid!=1||candidate.unique.parent_uniqueid!=init.unique.uniqueid
        ||proc_pidpath(1,image,sizeof(image))<=0||strcmp(image,"/sbin/launchd")
        ||!protectedPath(@"/sbin/launchd",true,false))return false;
    return freshIdentity(pid,&again)&&freshIdentity(1,&initAgain)
        &&rootCredentials(&again)&&rootCredentials(&initAgain)
        &&sameKernelBirth(&candidate,&again)&&sameKernelBirth(&init,&initAgain);
}
/* The singleton serializes this daemon; root maintenance must be quiescent.
 * These bounded fresh guards also preserve an externally lost/changed registry
 * instead of repairing it from a cached dictionary. They are not filesystem CAS. */
static bool registryMatches(NSData *expected,bool initialCreation) {
    struct stat named;if(initialCreation){errno=0;
        return fstatat(gRegistryFD,"registry.json",&named,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;}
    if(!expected||!gEntryStoreLoaded)return false;
    int fd=openat(gRegistryFD,"registry.json",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;
    struct stat opened;NSString *path=pathChild(gRegistryPath,@"registry.json");NSData *bytes=nil;
    bool safe=fstat(fd,&opened)==0&&S_ISREG(opened.st_mode)&&opened.st_uid==0&&opened.st_nlink==1
        &&(opened.st_mode&07777)==0600&&fstatat(gRegistryFD,"registry.json",&named,AT_SYMLINK_NOFOLLOW)==0
        &&opened.st_dev==named.st_dev&&opened.st_ino==named.st_ino&&protectedPath(path,true,true);
    if(safe)bytes=readFD(fd,K_MAX_JSON);if(close(fd))safe=false;
    return safe&&bytes&&[bytes isEqual:expected];
}
static bool poisonEntryStore(void) {
    gPoisoned=true;gQuarantineReason=@"REGISTRY_CHANGED_OR_MISSING_NOT_OVERWRITTEN";return false;
}
static bool refreshEntryStore(void) {
    if(gPoisoned||!gEntryStoreLoaded)return false;
    return registryMatches(gRegistryDurableBytes,false)?true:poisonEntryStore();
}
static bool saveJSONExpected(NSString *name,NSDictionary *record,NSData *expectedRegistry,bool initialCreation) {
    bool registry=[name isEqual:@"registry.json"];
    if(registry&&((!initialCreation&&gPoisoned)||!registryMatches(expectedRegistry,initialCreation)))return poisonEntryStore();
    NSData *d=jsonData(record); if(!d || d.length>K_MAX_JSON)return false;
    NSString *temp=[NSString stringWithFormat:@".%@.%@",name,randomHex()];
    int fd=openat(gRegistryFD,temp.UTF8String,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false; bool ok=exactIO(fd,(void *)d.bytes,d.length,true);
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    if(ok&&registry)KVDarwinQAPersistenceGate("registry_file_fsync");
#endif
    if(ok){int result=fsync(fd),savedErrno=errno;ok=result==0;
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
        if(registry)KVDarwinQAPersistenceGateComplete("registry_file_fsync",ok,savedErrno);
#else
        (void)savedErrno;
#endif
    }
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    if(ok&&registry)KVDarwinQAPersistenceGate("registry_fullfsync");
#endif
    if(ok){int result=fcntl(fd,F_FULLFSYNC),savedErrno=errno;ok=result==0;
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
        if(registry)KVDarwinQAPersistenceGateComplete("registry_fullfsync",ok,savedErrno);
#else
        (void)savedErrno;
#endif
    }
    if(close(fd))ok=false;
    if(ok&&registry&&!registryMatches(expectedRegistry,initialCreation)){poisonEntryStore();ok=false;}
    if(ok)ok=renameat(gRegistryFD,temp.UTF8String,gRegistryFD,name.UTF8String)==0&&fsync(gRegistryFD)==0;
    if(!ok){unlinkat(gRegistryFD,temp.UTF8String,0);gPoisoned=true;return false;}
    fd=openat(gRegistryFD,name.UTF8String,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    struct stat s; NSData *back=nil;
    if(fd>=0&&!fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==0&&s.st_nlink==1&&(s.st_mode&07777)==0600
        &&protectedPath(pathChild(gRegistryPath,name),true,true))back=readFD(fd,K_MAX_JSON);
    if(fd>=0)close(fd); ok=back && [back isEqual:d]; if(!ok)gPoisoned=true;
    if(ok&&registry){gRegistryDurableBytes=[d copy];gEntryStoreLoaded=true;}return ok;
}
static bool saveJSON(NSString *name,NSDictionary *record) {
    return saveJSONExpected(name,record,gRegistryDurableBytes,false);
}
/* This single explicit call site may create registry.json. No ambient init
 * flag or serve fallback can recreate missing bytes later in the process. */
static bool initializeRegistry(void) {
    if(gPoisoned||gEntryStoreLoaded||gRegistryDurableBytes)return false;
    return saveJSONExpected(@"registry.json",gRegistry,nil,true);
}
static bool persist(void) {
    publishState(); /* identities/intent become observable BEFORE a disk wait */
    if(gPoisoned||!gEntryStoreLoaded)return false;
    bool ok=saveJSON(@"registry.json",gRegistry);
    if(!ok)gPoisoned=true;
    return ok;
}
/* Account-directory access is confined to explicit quiescent admin init below.
 * Serving only parses protected bytes and uses numeric UUID ACL qualifiers. */
static bool canonicalUUID(id value) {
    if(!isString(value,36)||[value length]!=36)return false;
    uuid_t uuid;uuid_string_t text;
    if(uuid_parse([value UTF8String],uuid)||uuid_is_null(uuid))return false;
    uuid_unparse_lower(uuid,text);return [value isEqual:@(text)];
}
static bool ownerNumber(NSString *text,uid_t *uid) {
    uint64_t n=0;if(!decimal64(text,&n)||n==0||n>=K_UID_FIRST)return false;
    *uid=(uid_t)n;return true;
}
static NSData *readAccountPolicy(void) {
    NSString *path=pathChild(gAnchorPath,@"account-policy.json");
    if(!protectedPath(path,true,true))return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return nil;
    struct stat s,n;NSData *bytes=nil;
    if(!fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==0&&s.st_nlink==1&&(s.st_mode&07777)==0600
        &&!lstat(path.fileSystemRepresentation,&n)&&s.st_dev==n.st_dev&&s.st_ino==n.st_ino)bytes=readFD(fd,32768);
    if(close(fd))return nil;return bytes;
}
static bool policyFailure(NSString *reason) {
    gAccountPolicyHealthy=false;gAccountPolicyFailed=true;gAccountPolicyReason=reason;return false;
}
static bool refreshAccountPolicy(void) {
    if(gAccountPolicyFailed)return false;
    NSDictionary *binding=gRegistry[@"account_policy"];NSData *bytes=readAccountPolicy();
    NSDictionary *p=parseJSON(bytes);NSDictionary *owners=p[@"owners"];
    if(![binding isKindOfClass:NSDictionary.class]||binding.count!=2||![binding[@"id"] isEqual:K_ACCOUNT_POLICY]
        ||!hex64(binding[@"sha256"])||!bytes||![sha(bytes) isEqual:binding[@"sha256"]]
        ||![jsonData(p) isEqual:bytes]||p.count!=7||![p[@"schema"] isEqual:@"knowledge-darwin-account-policy.v1"]
        ||![p[@"id"] isEqual:K_ACCOUNT_POLICY]||!hex64(p[@"installation_id"])
        ||![p[@"installation_id"] isEqual:gRegistry[@"installation_id"]]
        ||!numericField(p[@"uid_first"])||[p[@"uid_first"] unsignedLongLongValue]!=K_UID_FIRST
        ||!numericField(p[@"uid_last_exclusive"])||[p[@"uid_last_exclusive"] unsignedLongLongValue]!=K_UID_LAST
        ||!booleanField(p[@"range_admin_asserted"])||![p[@"range_admin_asserted"] boolValue]
        ||![owners isKindOfClass:NSDictionary.class]||!owners.count||owners.count>K_MAX_OWNERS)
        return policyFailure(@"ACCOUNT_POLICY_MISSING_INVALID_OR_UNBOUND");
    NSMutableSet *qualifiers=[NSMutableSet set];NSMutableDictionary *uuidBytes=[NSMutableDictionary dictionary];
    for(NSString *key in owners){uid_t uid;if(!ownerNumber(key,&uid)||!canonicalUUID(owners[key])||[qualifiers containsObject:owners[key]])
        return policyFailure(@"ACCOUNT_POLICY_OWNER_INVALID");[qualifiers addObject:owners[key]];
        uuid_t uuid;if(uuid_parse([owners[key] UTF8String],uuid))return policyFailure(@"ACCOUNT_POLICY_OWNER_INVALID");
        uuidBytes[key]=[NSData dataWithBytes:uuid length:sizeof(uuid)];}
    if(gAccountPolicyBytes&&![gAccountPolicyBytes isEqual:bytes])return policyFailure(@"ACCOUNT_POLICY_CHANGED");
    gAccountPolicy=p;gOwnerUUIDs=[uuidBytes copy];gAccountPolicyBytes=[bytes copy];gAccountPolicySHA=binding[@"sha256"];
    gAccountPolicyHealthy=true;gAccountPolicyReason=@"HEALTHY";return true;
}
static NSDictionary *accountPolicyStatus(void) {
    return @{@"id":K_ACCOUNT_POLICY,@"healthy":@(gAccountPolicyHealthy),
        @"reason":gAccountPolicyReason?:@"NOT_VALIDATED",@"sha256":gAccountPolicySHA?:NSNull.null,
        @"configured_owner_count":@([gAccountPolicy[@"owners"] count]),@"runtime_directory_lookups":@NO};
}
static bool writeInitialAccountPolicy(NSDictionary *owners) {
    NSDictionary *p=@{@"schema":@"knowledge-darwin-account-policy.v1",@"id":K_ACCOUNT_POLICY,
        @"installation_id":gUIDHistory.installationID,@"uid_first":@(K_UID_FIRST),@"uid_last_exclusive":@(K_UID_LAST),
        @"range_admin_asserted":@YES,@"owners":owners};
    NSData *bytes=jsonData(p);if(!bytes||bytes.length>32768)return false;
    if(!protectedPath(gAnchorPath,false,true))return false;
    int dir=open(gAnchorPath.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dir<0)return false;
    int fd=openat(dir,"account-policy.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    bool ok=fd>=0&&exactIO(fd,(void *)bytes.bytes,bytes.length,true)&&fsync(fd)==0&&fcntl(fd,F_FULLFSYNC)==0;
    if(fd>=0&&close(fd))ok=false;if(ok)ok=fsync(dir)==0;if(close(dir))ok=false;
    NSData *back=ok?readAccountPolicy():nil;if(!back||![back isEqual:bytes])return false;
    gAccountPolicy=p;gAccountPolicyBytes=[bytes copy];gAccountPolicySHA=sha(bytes);return true;
}
static NSMutableDictionary *entries(void) { return gRegistry[@"attempts"]; }
static NSMutableDictionary *entryFor(NSString *attempt) { id e=entries()[attempt];
    return [e isKindOfClass:NSMutableDictionary.class]?e:nil; }
static NSString *activeID(void) { return gRegistry[@"active_attempt"]; }
static bool validRecordedIdentity(id identity) {
    if(![identity isKindOfClass:NSDictionary.class])return false;
    for(NSString *key in @[@"pid",@"start_sec",@"start_usec",@"ruid",@"pidversion"])
        if(!numericField(identity[key]))return false;
    uint64_t unique=0;
    return [identity[@"pid"] unsignedLongLongValue]>1&&[identity[@"pid"] unsignedLongLongValue]<=INT_MAX
        &&decimal64(identity[@"unique_id"],&unique)&&unique>0;
}
static NSString *sysctlString(const char *name);
static bool validBootID(id value) {
    uuid_t parsed;return isString(value,36)&&[value length]==36&&uuid_parse([value UTF8String],parsed)==0&&!uuid_is_null(parsed);
}
static bool sameBootID(id a,id b) {
    return validBootID(a)&&validBootID(b)&&[a caseInsensitiveCompare:b]==NSOrderedSame;
}
static bool kernelBootCurrent(void) {
    return sameBootID(sysctlString("kern.bootsessionuuid"),gBoot);
}
/* Original work/cleanup clocks are historical after reboot. A separate record
 * owns the new cleanup-only clock; a daemon restart within this boot must reuse
 * that clock. Neither this record nor a reboot can make old work executable. */
static bool validRebootCleanup(NSMutableDictionary *e) {
    NSDictionary *r=e[@"reboot_cleanup"],*d=e[@"descriptor"];
    if(!r)return true;
    return [r isKindOfClass:NSDictionary.class]&&[r[@"schema"] isEqual:@"knowledge-darwin-reboot-cleanup.v1"]
        &&hex64(r[@"recovery_epoch"])&&hex64(r[@"daemon_epoch"])
        &&sameBootID(r[@"origin_boot_id"],d[@"boot_id"])&&validBootID(r[@"boot_id"])
        &&!sameBootID(r[@"boot_id"],d[@"boot_id"])&&[r[@"host_id"] isEqual:d[@"host_id"]]
        &&[r[@"descriptor_sha256"] isEqual:e[@"descriptor_sha256"]]
        &&[r[@"installation_id"] isEqual:d[@"installation_id"]]
        &&validDuration(r[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS)
        &&[r[@"cleanup_budget_ms"] unsignedLongLongValue]<=[e[@"cleanup_budget_ms"] unsignedLongLongValue]
        &&numericField(r[@"cleanup_started_monotonic_ms"])&&numericField(r[@"cleanup_deadline_monotonic_ms"])
        &&[r[@"cleanup_deadline_monotonic_ms"] unsignedLongLongValue]>[r[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]
        &&[r[@"cleanup_deadline_monotonic_ms"] unsignedLongLongValue]-[r[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]
            ==[r[@"cleanup_budget_ms"] unsignedLongLongValue]
        &&booleanField(r[@"admission_closed"])&&[r[@"admission_closed"] boolValue]
        &&booleanField(r[@"original_work_revoked"])&&[r[@"original_work_revoked"] boolValue]
        &&booleanField(r[@"cleanup_only"])&&[r[@"cleanup_only"] boolValue]
        &&booleanField(r[@"proof_current"])&&![r[@"proof_current"] boolValue]
        &&[@[@"pending",@"closed",@"unconfirmed"] containsObject:r[@"state"]]
        &&(![r[@"state"] isEqual:@"closed"]||(numericField(r[@"observed_monotonic_ms"])
            &&[r[@"observed_monotonic_ms"] unsignedLongLongValue]>=[r[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]
            &&[r[@"observed_monotonic_ms"] unsignedLongLongValue]<[r[@"cleanup_deadline_monotonic_ms"] unsignedLongLongValue]
            &&booleanField(r[@"native_cleanup_facts_confirmed"])&&[r[@"native_cleanup_facts_confirmed"] boolValue]));
}
static bool currentRebootCleanup(NSMutableDictionary *e) {
    return e[@"reboot_cleanup"]&&validRebootCleanup(e)&&sameBootID(e[@"reboot_cleanup"][@"boot_id"],gBoot)
        &&[e[@"descriptor"][@"host_id"] isEqual:gHost];
}
static bool validRecordedEntry(NSMutableDictionary *e,NSString *id) {
    NSDictionary *d=e[@"descriptor"];uint64_t allocationSequence=0;if(![d isKindOfClass:NSDictionary.class])return false;
    return validBootID(d[@"boot_id"])&&canonicalUUID(d[@"host_id"])&&validRebootCleanup(e)
        &&(!e[@"abort_latched"]||booleanField(e[@"abort_latched"]))
        &&(!e[@"recovery_only"]||booleanField(e[@"recovery_only"]))
        &&(!e[@"planned_terminal"]||booleanField(e[@"planned_terminal"]))
        &&hex64(id)&&[d[@"boundary_id"] isEqual:id]&&[d[@"attempt_id"] isEqual:id]
        &&[d[@"backend"] isEqual:@"darwin_private_ruid"]&&hex64(d[@"source_sha256"])
        &&hex64(d[@"transport_header_sha256"])&&hex64(d[@"stub_source_sha256"])&&hex64(d[@"stub_binary_sha256"])
        &&(([d[@"schema"] isEqual:@"knowledge-darwin-private-ruid-descriptor.v1"]&&[d[@"stub_wire_version"] isEqual:@"KVS1"])
            ||([d[@"schema"] isEqual:@"knowledge-darwin-private-ruid-descriptor.v2"]&&[d[@"stub_wire_version"] isEqual:@"KVS2"]
                &&[d[@"guardian_protocol"] isEqual:@"KVR2"]&&hex64(d[@"daemon_epoch"])))
        &&hex64(d[@"installation_id"])&&[d[@"installation_id"] isEqual:gRegistry[@"installation_id"]]
        &&[d[@"account_policy_id"] isEqual:K_ACCOUNT_POLICY]&&hex64(d[@"account_policy_sha256"])
        &&hex64(d[@"allocation_sha256"])&&isString(d[@"allocation_seq"],20)
        &&hex64(d[@"uid_history_header_sha256"])&&hex64(d[@"uid_history_source_sha256"])
        &&[d[@"workspace_path"] isEqual:pathChild(gWorkspaceRoot,id)]
        &&numericField(d[@"task_ruid"])&&[d[@"task_ruid"] unsignedLongLongValue]>=K_UID_FIRST
        &&[d[@"task_ruid"] unsignedLongLongValue]<K_UID_LAST&&[d[@"task_gid"] isEqual:d[@"task_ruid"]]
        &&decimal64(d[@"allocation_seq"],&allocationSequence)&&allocationSequence>0
        &&allocationSequence==[d[@"task_ruid"] unsignedLongLongValue]-K_UID_FIRST+1
        &&numericField(e[@"owner_uid"])&&[e[@"owner_uid"] unsignedLongLongValue]>0
        &&[e[@"owner_uid"] unsignedLongLongValue]<K_UID_FIRST&&[d[@"owner_uid"] isEqual:e[@"owner_uid"]]
        &&hex64(e[@"descriptor_sha256"])&&[e[@"descriptor_sha256"] isEqual:sha(jsonData(d))]
        &&validDuration(e[@"work_budget_ms"],K_MAX_WORK_MS)&&validDuration(e[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS)
        &&[d[@"work_budget_ms"] isEqual:e[@"work_budget_ms"]]&&[d[@"cleanup_budget_ms"] isEqual:e[@"cleanup_budget_ms"]]
        &&[d[@"work_started_monotonic_ms"] isEqual:e[@"work_started_monotonic_ms"]]&&[d[@"work_deadline_ms"] isEqual:e[@"work_deadline_ms"]]
        &&numericField(e[@"work_started_monotonic_ms"])&&numericField(e[@"work_deadline_ms"])
        &&[e[@"work_deadline_ms"] unsignedLongLongValue]==[e[@"work_started_monotonic_ms"] unsignedLongLongValue]+[e[@"work_budget_ms"] unsignedLongLongValue]
        &&booleanField(e[@"admission_closed"])&&booleanField(e[@"spawn_intent"])&&booleanField(e[@"authority_spawn_intent"])
        &&(![e[@"admission_closed"] boolValue]||(numericField(e[@"cleanup_started_monotonic_ms"])
            &&numericField(e[@"cleanup_deadline_ms"])&&booleanField(e[@"cleanup_budget_exceeded"])
            &&[e[@"cleanup_deadline_ms"] unsignedLongLongValue]>[e[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]
            &&[e[@"cleanup_deadline_ms"] unsignedLongLongValue]-[e[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]
                <=[e[@"cleanup_budget_ms"] unsignedLongLongValue]))
        &&validRecordedIdentity(e[@"controller"])&&(!e[@"authority"]||validRecordedIdentity(e[@"authority"]))
        &&(!e[@"launch_stub"]||validRecordedIdentity(e[@"launch_stub"]))
        &&(!e[@"root_child"]||(validRecordedIdentity(e[@"root_child"])&&[e[@"root_child"][@"ruid"] unsignedIntValue]==0))
        &&(!e[@"command_identity"]||(validRecordedIdentity(e[@"command_identity"])
            &&[e[@"command_identity"][@"ruid"] isEqual:d[@"task_ruid"]]));
}
/* Old valid descriptors are cleanup authority only. Their UID reservation is
 * revalidated against the durable never-reuse history before UID-wide recovery.
 * They never admit a command or turn a historical receipt into current PASS. */
static bool currentEntry(NSMutableDictionary *e) {
    NSDictionary *d=e[@"descriptor"];
    return sameBootID(d[@"boot_id"],gBoot)&&[d[@"host_id"] isEqual:gHost]&&!e[@"reboot_cleanup"]
        &&[d[@"schema"] isEqual:@"knowledge-darwin-private-ruid-descriptor.v2"]
        &&[d[@"daemon_epoch"] isEqual:gDaemonEpoch]&&[d[@"stub_wire_version"] isEqual:@"KVS2"]
        &&[d[@"scratch_policy"] isEqual:@"private_uid_sibling.v1"]
        &&[d[@"scratch_path"] isEqual:[d[@"workspace_path"] stringByAppendingString:@".scratch"]]
        &&[d[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA]
        &&[d[@"stub_source_sha256"] isEqual:@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA]
        &&[d[@"stub_binary_sha256"] isEqual:gStubBinarySHA]
        &&[d[@"transport_header_sha256"] isEqual:@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA]
        &&[d[@"uid_history_header_sha256"] isEqual:@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA]
        &&[d[@"uid_history_source_sha256"] isEqual:@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA];
}
/* A reservation nonce is an owner-scoped durable idempotency key, including
 * after terminal cleanup. A lost prepare reply must not burn another UID or
 * make lookup depend on NSDictionary enumeration order. Never guess between
 * duplicate or malformed matching historical entries. */
static NSMutableDictionary *reservationForNonce(uid_t owner,NSString *nonce,bool *ambiguous) {
    *ambiguous=false;NSMutableDictionary *found=nil;
    for(NSString *id in entries()){
        NSMutableDictionary *e=entryFor(id);NSDictionary *d=e[@"descriptor"];
        if(![d isKindOfClass:NSDictionary.class]||![d[@"attempt_nonce"] isEqual:nonce])continue;
        /* A malformed owner cannot make an existing nonce look unused. No
         * descriptor is disclosed when ownership cannot be established. */
        if(!numericField(e[@"owner_uid"])||!numericField(d[@"owner_uid"])
            ||![e[@"owner_uid"] isEqual:d[@"owner_uid"]]){*ambiguous=true;return nil;}
        if([e[@"owner_uid"] unsignedLongLongValue]!=(uint64_t)owner)continue;
        if(found||!validRecordedEntry(e,id)){*ambiguous=true;return nil;}
        found=e;
    }
    return found;
}
/* Entry syntax/ownership above deliberately does not depend on allocator health:
 * known exact identities remain usable for targeted stop when history fails. */
static bool refreshUIDHistory(void) {
    refreshEntryStore();
    gUIDRefreshAttempted=gUIDHistory.healthy;
    if(!gUIDRefreshAttempted)return false;
    gUIDLastRefreshMS=nowMS();return [gUIDHistory refreshCurrentCheckpointWithError:NULL];
}
static NSDictionary *uidHistoryStatus(bool refresh) {
    if(refresh)refreshUIDHistory();
    return @{@"healthy_cached":@(gUIDHistory.healthy),@"reason":gUIDHistory.reason?:@"UNAVAILABLE",
        @"health_source":gUIDRefreshAttempted?@"disk_refresh_attempt":gUIDHistory.healthy?@"cached_unchecked":@"cached_quarantine",
        @"last_refresh_attempt_started_monotonic_ms":gUIDLastRefreshMS?@(gUIDLastRefreshMS):(id)NSNull.null,
        @"installation_id_cached":gUIDHistory.installationID?:NSNull.null,
        @"checkpoint_cached":gUIDHistory.checkpoint?:NSNull.null,
        @"header_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA,
        @"source_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA};
}
static bool validUIDAllocation(NSMutableDictionary *e) {
    NSDictionary *d=e[@"descriptor"];gUIDRefreshAttempted=false;
    if(!refreshEntryStore()||!refreshAccountPolicy()||![d[@"account_policy_id"] isEqual:K_ACCOUNT_POLICY]
        ||![d[@"account_policy_sha256"] isEqual:gAccountPolicySHA]
        ||!gUIDHistory.healthy||![d[@"installation_id"] isEqual:gUIDHistory.installationID])return false;
    gUIDRefreshAttempted=true;
    gUIDLastRefreshMS=nowMS();return [gUIDHistory validReservationForUID:[d[@"task_ruid"] unsignedIntValue]
        attempt:d[@"attempt_id"] sequence:d[@"allocation_seq"] sha256:d[@"allocation_sha256"] error:NULL];
}
static bool validRelative(NSString *path) {
    if(!isString(path,4096)||[path isAbsolutePath])return false;
    for(NSString *s in [path componentsSeparatedByString:@"/"])
        if(!s.length||[s isEqual:@"."]||[s isEqual:@".."]||[s containsString:@"\\"])return false;
    return true;
}
/* A newly created inode receives only the original owner's read ACL. No source
 * ACL, xattrs, hardlinks, special files, ownership, or privileged mode survives.
 * The original project is never opened by root and is never chmod/chown'd. */
static bool ownerReadACL(int fd, uid_t owner, bool directory) {
    NSString *key=[NSString stringWithFormat:@"%u",owner];uuid_t uuid;
    if(!refreshAccountPolicy())return false;NSData *qualifier=gOwnerUUIDs[key];
    if(qualifier.length!=sizeof(uuid))return false;memcpy(uuid,qualifier.bytes,sizeof(uuid));
    acl_t a=acl_init(1); if(!a)return false; acl_entry_t e; acl_permset_t p;
    bool ok=acl_create_entry(&a,&e)==0 && acl_set_tag_type(e,ACL_EXTENDED_ALLOW)==0
        && acl_set_qualifier(e,uuid)==0 && acl_get_permset(e,&p)==0 && acl_clear_perms(p)==0;
    acl_perm_t rights[]={ACL_READ_DATA,ACL_READ_ATTRIBUTES,ACL_READ_EXTATTRIBUTES,ACL_READ_SECURITY};
    for(unsigned i=0;ok && i<sizeof(rights)/sizeof(rights[0]);i++)ok=acl_add_perm(p,rights[i])==0;
    if(ok && directory)ok=acl_add_perm(p,ACL_SEARCH)==0;
    if(ok)ok=acl_set_permset(e,p)==0 && acl_set_fd_np(fd,a,ACL_TYPE_EXTENDED)==0;
    acl_free(a); return ok;
}
static int openWorkspace(NSMutableDictionary *e) {
    NSString *id=e[@"descriptor"][@"boundary_id"]; if(!hex64(id))return -1;
    int fd=openat(gWorkspaceFD,id.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st; if(fd<0)return -1;
    NSDictionary *saved=e[@"workspace_inode"];
    if(![saved isKindOfClass:NSDictionary.class]||!nativeUInt64Field(saved[@"device"])||!nativeUInt64Field(saved[@"inode"])
        ||fstat(fd,&st)||st.st_uid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue] || !S_ISDIR(st.st_mode)
        ||[saved[@"device"] unsignedLongLongValue]!=(uint64_t)st.st_dev||[saved[@"inode"] unsignedLongLongValue]!=(uint64_t)st.st_ino){
        close(fd);return -1; } return fd;
}
static int openScratch(NSMutableDictionary *e) {
    NSDictionary *d=e[@"descriptor"];NSString *id=d[@"boundary_id"];
    if(!hex64(id)||![d[@"scratch_policy"] isEqual:@"private_uid_sibling.v1"]
        ||![d[@"scratch_path"] isEqual:[d[@"workspace_path"] stringByAppendingString:@".scratch"]])return -1;
    NSString *name=[id stringByAppendingString:@".scratch"];
    int fd=openat(gWorkspaceFD,name.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return -1;struct stat st;NSDictionary *saved=e[@"scratch_inode"];
    bool ok=[saved isKindOfClass:NSDictionary.class]&&nativeUInt64Field(saved[@"device"])&&nativeUInt64Field(saved[@"inode"])
        &&fstat(fd,&st)==0&&S_ISDIR(st.st_mode)&&(st.st_mode&0777)==0700
        &&st.st_uid==[d[@"task_ruid"] unsignedIntValue]&&st.st_gid==[d[@"task_gid"] unsignedIntValue]
        &&[saved[@"device"] unsignedLongLongValue]==(uint64_t)st.st_dev&&[saved[@"inode"] unsignedLongLongValue]==(uint64_t)st.st_ino;
    if(!ok){close(fd);return -1;}return fd;
}
static int copyDirectory(NSMutableDictionary *e,NSArray *parts) {
    int dir=openWorkspace(e);if(dir<0)return -1;bool ok=true;
    uid_t uid=[e[@"descriptor"][@"task_ruid"] unsignedIntValue],owner=[e[@"owner_uid"] unsignedIntValue];
    for(NSUInteger i=0;ok && i<parts.count;i++) {
        bool created=mkdirat(dir,[parts[i] UTF8String],0700)==0;
        if(!created && errno!=EEXIST){ok=false;break;}
        int next=openat(dir,[parts[i] UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        struct stat st; if(next<0 || fstat(next,&st) || !S_ISDIR(st.st_mode))ok=false;
        if(ok && created)ok=fchown(next,uid,uid)==0 && fchmod(next,0700)==0 && ownerReadACL(next,owner,true) && fsync(next)==0;
        if(ok && !created)ok=st.st_uid==uid && !(st.st_mode&0077);
        if(ok)ok=fsync(dir)==0;
        close(dir);dir=next;
    }
    if(!ok){if(dir>=0)close(dir);return -1;}return dir;
}
static int newCopyFile(NSMutableDictionary *e,NSString *path,mode_t mode) {
    if(!validRelative(path)||(mode!=0644&&mode!=0755))return -1;
    NSArray *parts=[path componentsSeparatedByString:@"/"];
    int dir=copyDirectory(e,[parts subarrayWithRange:NSMakeRange(0,parts.count-1)]);if(dir<0)return -1;
    int fd=openat(dir,[parts.lastObject UTF8String],O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    uid_t uid=[e[@"descriptor"][@"task_ruid"] unsignedIntValue],owner=[e[@"owner_uid"] unsignedIntValue];
    struct stat st;bool ok=fd>=0&&!fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_nlink==1
        &&fchown(fd,uid,uid)==0&&fchmod(fd,mode&0700)==0&&ownerReadACL(fd,owner,false)&&fsync(fd)==0&&fsync(dir)==0;
    close(dir);if(!ok){if(fd>=0)close(fd);return -1;}return fd;
}
static int gPendingFD=-1;
static CC_SHA256_CTX gPendingHash;
static bool beginCopy(NSMutableDictionary *e,NSDictionary *q) {
    uint64_t bytes=[q[@"bytes"] unsignedLongLongValue];mode_t mode=(mode_t)[q[@"mode"] unsignedIntValue];
    if(gPendingFD>=0||e[@"pending_copy"]||!hex64(q[@"sha256"])||bytes>256u*1024u*1024u
        ||[e[@"files"] unsignedLongLongValue]>=K_MAX_FILES||[e[@"bytes"] unsignedLongLongValue]+bytes>K_MAX_COPY)return false;
    int fd=newCopyFile(e,q[@"path"],mode);if(fd<0)return false;
    e[@"pending_copy"]=[@{@"path":q[@"path"],@"mode":@(mode),@"bytes":@(bytes),@"sha256":q[@"sha256"],@"offset":@0} mutableCopy];
    gPendingFD=fd;CC_SHA256_Init(&gPendingHash);return persist();
}
static bool chunkCopy(NSMutableDictionary *e,NSDictionary *q) {
    NSMutableDictionary *pending=e[@"pending_copy"];NSString *base64=q[@"data"];
    if(gPendingFD<0||!pending||![pending[@"path"] isEqual:q[@"path"]]||!isString(base64,87384)
        ||[q[@"offset"] unsignedLongLongValue]!=[pending[@"offset"] unsignedLongLongValue])return false;
    NSData *data=[[NSData alloc] initWithBase64EncodedString:base64 options:0];
    uint64_t offset=[pending[@"offset"] unsignedLongLongValue];
    if(!data||!data.length||data.length>65536||offset+data.length>[pending[@"bytes"] unsignedLongLongValue])return false;
    if(!exactIO(gPendingFD,(void *)data.bytes,data.length,true)||fsync(gPendingFD))return false;
    CC_SHA256_Update(&gPendingHash,data.bytes,(CC_LONG)data.length);pending[@"offset"]=@(offset+data.length);return persist();
}
static bool commitCopy(NSMutableDictionary *e,NSDictionary *q) {
    NSMutableDictionary *p=e[@"pending_copy"];
    if(gPendingFD<0||!p||![p[@"path"] isEqual:q[@"path"]]||![p[@"sha256"] isEqual:q[@"sha256"]]
        ||[p[@"offset"] unsignedLongLongValue]!=[p[@"bytes"] unsignedLongLongValue])return false;
    unsigned char hash[32];CC_SHA256_Final(hash,&gPendingHash);char text[65];
    for(unsigned i=0;i<32;i++)snprintf(text+2*i,3,"%02x",hash[i]);
    bool ok=[@(text) isEqual:p[@"sha256"]]&&fsync(gPendingFD)==0;
    /* Read back the exact new inode, not a caller-controlled path. */
    if(ok){ok=lseek(gPendingFD,0,SEEK_SET)==0;CC_SHA256_CTX verify;CC_SHA256_Init(&verify);unsigned char b[65536];ssize_t n=0;
        while(ok&&(n=read(gPendingFD,b,sizeof(b)))>0)CC_SHA256_Update(&verify,b,(CC_LONG)n);
        if(ok&&n<0)ok=false;CC_SHA256_Final(hash,&verify);for(unsigned i=0;i<32;i++)snprintf(text+2*i,3,"%02x",hash[i]);
        if(ok)ok=[@(text) isEqual:p[@"sha256"]];
    }
    if(close(gPendingFD))ok=false;gPendingFD=-1;
    if(!ok)return false;
    e[@"manifest"][p[@"path"]]=@{@"path":p[@"path"],@"mode":p[@"mode"],@"bytes":p[@"bytes"],@"sha256":p[@"sha256"]};
    e[@"files"]=@([e[@"files"] unsignedLongLongValue]+1);e[@"bytes"]=@([e[@"bytes"] unsignedLongLongValue]+[p[@"bytes"] unsignedLongLongValue]);
    [e removeObjectForKey:@"pending_copy"];return persist();
}
static NSArray *utf8Sorted(NSArray<NSString *> *paths) {
    return [paths sortedArrayUsingComparator:^NSComparisonResult(NSString *a,NSString *b){
        int c=strcmp(a.UTF8String,b.UTF8String);return c<0?NSOrderedAscending:c>0?NSOrderedDescending:NSOrderedSame;
    }];
}
static bool sealCopy(NSMutableDictionary *e,NSDictionary *q) {
    if(gPendingFD>=0||e[@"pending_copy"]||!hex64(q[@"manifest_sha256"])||!hex64(q[@"directories_sha256"]))return false;
    NSMutableArray *manifest=[NSMutableArray array];
    for(NSString *path in utf8Sorted([e[@"manifest"] allKeys]))[manifest addObject:e[@"manifest"][path]];
    NSArray *dirs=utf8Sorted([e[@"directories"] allKeys]);
    if(![sha(jsonData(manifest)) isEqual:q[@"manifest_sha256"]]||![sha(jsonData(dirs)) isEqual:q[@"directories_sha256"]])return false;
    e[@"manifest_sha256"]=q[@"manifest_sha256"];e[@"directories_sha256"]=q[@"directories_sha256"];e[@"state"]=@"sealed";return persist();
}

struct KPeer { uid_t owner; struct KIdentity native, parent; };
/* Registry/history/policy/run state belongs exclusively to the lifecycle actor.
 * Queue objects contain immutable requests and copied kernel peer identities.
 * No queue/publication lock is held while doing filesystem I/O. */
@interface KWork : NSObject {
@public
    NSDictionary *request;
    struct KPeer peer;
    int client;
    _Atomic bool cancelled;
}
@end
@implementation KWork
@end
static pthread_mutex_t gQueueMutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gObservationMutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gCacheMutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gTransportMutex;
static NSMutableArray<KWork *> *gWorkQueue;
static NSMutableDictionary<NSNumber *,KWork *> *gWorkByClient;
static KWork *gCurrentWork; /* actor only */
static NSDictionary *gCachedEntry,*gCachedStatus;
struct KExactBirth { struct KIdentity identity; bool present; };
struct KObservation {
    uint64_t generation,work_deadline,command_deadline,cleanup_deadline,cleanup_budget,stop_started,stop_deadline;
    char attempt[65]; uid_t owner,private_uid;
    struct KExactBirth controller,authority,stub,root_child,command;
    bool valid,admission_closed,drain_only,planned_terminal,abort_latched;
    bool uid_ticket_armed,guardian_protocol,root_registered,guardian_registered;
};
static struct KObservation gObservation;
static uint64_t gObservationGeneration; /* actor only */
static bool exactFromJSON(NSDictionary *saved,struct KExactBirth *out) {
    uint64_t unique=0;memset(out,0,sizeof(*out));
    if(!validRecordedIdentity(saved)||!decimal64(saved[@"unique_id"],&unique))return false;
    out->identity.bsd.pbi_pid=[saved[@"pid"] unsignedIntValue];
    out->identity.bsd.pbi_start_tvsec=[saved[@"start_sec"] unsignedLongLongValue];
    out->identity.bsd.pbi_start_tvusec=[saved[@"start_usec"] unsignedLongLongValue];
    out->identity.unique.uniqueid=unique;out->identity.unique.pidversion=[saved[@"pidversion"] intValue];
    out->present=true;return true;
}
static bool sameObservedBirth(const struct KIdentity *saved,const struct KIdentity *fresh) {
    return saved->bsd.pbi_pid==fresh->bsd.pbi_pid&&saved->unique.uniqueid==fresh->unique.uniqueid
        &&saved->bsd.pbi_start_tvsec==fresh->bsd.pbi_start_tvsec&&saved->bsd.pbi_start_tvusec==fresh->bsd.pbi_start_tvusec;
}
static int observeBirth(struct KExactBirth saved,struct KIdentity *fresh) {
    if(!saved.present)return 0;errno=0;
    if(freshIdentity((pid_t)saved.identity.bsd.pbi_pid,fresh))return sameObservedBirth(&saved.identity,fresh)?1:0;
    return errno==ESRCH?0:-1;
}
static bool latchGenerationMode(uint64_t generation,uint64_t budget,bool planned,bool authorityExitOnly) {
    uint64_t started=nowMS();bool matched=false;
    pthread_mutex_lock(&gObservationMutex);
    if(gObservation.valid&&gObservation.generation==generation){
        /* A kernel observation may precede a newly queued planned close. Decide
         * exact authority absence using the latest same-generation intent. */
        if(authorityExitOnly&&gObservation.planned_terminal&&!gObservation.abort_latched){
            pthread_mutex_unlock(&gObservationMutex);return false;
        }
        matched=true;
        if(planned)gObservation.planned_terminal=true;else gObservation.abort_latched=true;
        atomic_store_explicit(&gStopGeneration,generation,memory_order_release);
        if(!gObservation.stop_started)gObservation.stop_started=started;
        uint64_t bounded=MAX(1ull,MIN(MIN(budget,K_MAX_CLEANUP_MS),gObservation.cleanup_budget));
        uint64_t deadline=gObservation.stop_started+bounded;
        if(gObservation.cleanup_deadline)deadline=MIN(deadline,gObservation.cleanup_deadline);
        if(!gObservation.stop_deadline||deadline<gObservation.stop_deadline)gObservation.stop_deadline=deadline;
    }
    pthread_mutex_unlock(&gObservationMutex);return matched;
}
static bool latchGeneration(uint64_t generation,uint64_t budget) {
    return latchGenerationMode(generation,budget,false,false);
}
static struct KObservation observationCopy(void) {
    pthread_mutex_lock(&gObservationMutex);struct KObservation v=gObservation;
    pthread_mutex_unlock(&gObservationMutex);return v;
}
static bool stoppedAttempt(NSMutableDictionary *e) {
    struct KObservation v=observationCopy();NSString *attempt=e[@"descriptor"][@"attempt_id"];
    return v.valid&&attempt&&[attempt isEqual:@(v.attempt)]
        &&atomic_load_explicit(&gStopGeneration,memory_order_acquire)==v.generation;
}
static bool abortedAttempt(NSMutableDictionary *e) {
    struct KObservation v=observationCopy();NSString *attempt=e[@"descriptor"][@"attempt_id"];
    return gStopping||[e[@"abort_latched"] boolValue]
        ||(attempt&&[attempt isEqual:@(v.attempt)]&&v.abort_latched);
}
static bool plannedAttempt(NSMutableDictionary *e) {
    struct KObservation v=observationCopy();NSString *attempt=e[@"descriptor"][@"attempt_id"];
    return !abortedAttempt(e)&&([e[@"planned_terminal"] boolValue]
        ||(v.valid&&attempt&&[attempt isEqual:@(v.attempt)]&&v.planned_terminal));
}
static bool currentPeerAlive(void) {
    if(!gCurrentWork)return true;struct KIdentity native,parent;
    return freshIdentity((pid_t)gCurrentWork->peer.native.bsd.pbi_pid,&native)
        &&freshIdentity((pid_t)gCurrentWork->peer.parent.bsd.pbi_pid,&parent)
        &&sameKernelBirth(&native,&gCurrentWork->peer.native)&&sameKernelBirth(&parent,&gCurrentWork->peer.parent)
        &&native.bsd.pbi_ruid==gCurrentWork->peer.owner&&native.bsd.pbi_uid==gCurrentWork->peer.owner
        &&native.unique.parent_uniqueid==parent.unique.uniqueid;
}
static bool workStopped(NSMutableDictionary *e) {
    bool cancelled=gCurrentWork&&atomic_load_explicit(&gCurrentWork->cancelled,memory_order_acquire);
    bool alreadyStopped=gStopping||cancelled||atomic_load_explicit(&gClockFailed,memory_order_acquire);
    bool observationsCurrent=true;uint64_t observed=0;
    if(!alreadyStopped){
        observationsCurrent=currentPeerAlive()&&(!e||(currentEntry(e)&&!stoppedAttempt(e)));
        /* Native owner observations can take time or expose cancellation.
         * Sample after them, then read every flag the sample may latch. */
        observed=nowMS();
    }
    cancelled=gCurrentWork&&atomic_load_explicit(&gCurrentWork->cancelled,memory_order_acquire);
    bool stop=alreadyStopped||!observationsCurrent||gStopping||cancelled
        ||atomic_load_explicit(&gClockFailed,memory_order_acquire)
        ||(e&&observed>=[e[@"work_deadline_ms"] unsignedLongLongValue]);
    if(stop&&e){struct KObservation v=observationCopy();
        if(v.valid&&[e[@"descriptor"][@"attempt_id"] isEqual:@(v.attempt)])
            latchGeneration(v.generation,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    return stop;
}
static bool revalidateWorkPeer(KWork *work) {
    struct KIdentity native,parent;char image[PROC_PIDPATHINFO_MAXSIZE];
    return freshIdentity((pid_t)work->peer.native.bsd.pbi_pid,&native)&&freshIdentity((pid_t)work->peer.parent.bsd.pbi_pid,&parent)
        &&sameKernelBirth(&native,&work->peer.native)&&sameKernelBirth(&parent,&work->peer.parent)
        &&native.bsd.pbi_ruid==work->peer.owner&&native.bsd.pbi_uid==work->peer.owner
        &&parent.bsd.pbi_ruid==work->peer.owner&&native.unique.parent_uniqueid==parent.unique.uniqueid
        &&proc_pidpath((pid_t)native.bsd.pbi_pid,image,sizeof(image))>0&&[gExecutable isEqual:@(image)]
        &&[protectedFileSHA(gExecutable) isEqual:gBinarySHA];
}
static bool queueWork(int token,struct KPeer peer,NSDictionary *request) {
    KWork *work=[KWork new];work->client=token;work->peer=peer;work->request=request;
    atomic_init(&work->cancelled,false);
    pthread_mutex_lock(&gQueueMutex);bool room=gWorkQueue.count<16;
    if(room){[gWorkQueue addObject:work];gWorkByClient[@(token)]=work;}
    pthread_mutex_unlock(&gQueueMutex);return room;
}
static void cancelWork(int token) {
    pthread_mutex_lock(&gQueueMutex);KWork *work=gWorkByClient[@(token)];
    if(work)atomic_store_explicit(&work->cancelled,true,memory_order_release);
    pthread_mutex_unlock(&gQueueMutex);
    if(!work||[@[@"probe",@"status",@"lookup",@"close",@"recover"] containsObject:work->request[@"op"]])return;
    pthread_mutex_lock(&gCacheMutex);NSDictionary *entry=gCachedEntry,*cached=gCachedStatus;pthread_mutex_unlock(&gCacheMutex);
    bool owner=entry&&work->peer.owner==[entry[@"owner_uid"] unsignedIntValue];
    bool role=owner&&(sameBirth(entry[@"controller"],&work->peer.parent)
        ||([entry[@"authority"] isKindOfClass:NSDictionary.class]&&sameBirth(entry[@"authority"],&work->peer.parent)));
    bool capability=owner&&hex64(work->request[@"token"])&&equalSecret(entry[@"token_sha256"],sha([work->request[@"token"] dataUsingEncoding:NSUTF8StringEncoding]));
    bool attempt=[work->request[@"attempt_id"] isEqual:entry[@"attempt_id"]];
    bool preparation=role&&[work->request[@"op"] isEqual:@"prepare"]
        &&[work->request[@"attempt_nonce"] isEqual:cached[@"descriptor"][@"attempt_nonce"]];
    if((attempt&&(role||capability))||preparation){struct KObservation v=observationCopy();
        if(v.valid&&[entry[@"attempt_id"] isEqual:@(v.attempt)])latchGeneration(v.generation,K_MAX_CLEANUP_MS);}
}
static KWork *takeWork(void) {
    pthread_mutex_lock(&gQueueMutex);KWork *work=gWorkQueue.firstObject;
    if(work)[gWorkQueue removeObjectAtIndex:0];pthread_mutex_unlock(&gQueueMutex);return work;
}
static void retireWork(KWork *work) {
    pthread_mutex_lock(&gQueueMutex);if(gWorkByClient[@(work->client)]==work)[gWorkByClient removeObjectForKey:@(work->client)];
    pthread_mutex_unlock(&gQueueMutex);
}
/* One request per authenticated connection. Reads/writes make bounded progress
 * and return to the owner/deadline loop; slow consumers receive backpressure.
 * Transport completion is not process exit or a native cleanup proof. */
#define K_MAX_CLIENTS 16u
struct KClient {
    int fd,token; struct KPeer peer; struct KVTReader rx; struct KVTBuffer tx;
    uint64_t started_ms, tx_progress_ms, lifecycle_budget_ms; bool dispatched, finishing;
    char run_attempt[65];
};
static struct KClient gClients[K_MAX_CLIENTS];
static unsigned gNextClient;
static int gNextTransportToken=1;
static void transportLost(int fd);
static struct KClient *transportClient(int fd) {
    for(unsigned i=0;i<K_MAX_CLIENTS;i++)if(gClients[i].fd>=0&&gClients[i].token==fd)return &gClients[i];
    return NULL;
}
static void dropTransport(int fd,bool lost) {
    pthread_mutex_lock(&gTransportMutex);struct KClient *c=transportClient(fd);
    if(!c){pthread_mutex_unlock(&gTransportMutex);return;}
    if(lost){cancelWork(fd);transportLost(fd);}
    close(c->fd);kvtReaderClear(&c->rx);kvtBufferClear(&c->tx);memset(c,0,sizeof(*c));c->fd=-1;
    pthread_mutex_unlock(&gTransportMutex);
}
static void finishTransport(int fd) {
    pthread_mutex_lock(&gTransportMutex);struct KClient *c=transportClient(fd);
    if(!c){pthread_mutex_unlock(&gTransportMutex);return;}
    c->finishing=true;if(!c->tx.length)dropTransport(fd,false);
    pthread_mutex_unlock(&gTransportMutex);
}
static bool transportRoom(int fd,size_t bytes) {
    pthread_mutex_lock(&gTransportMutex);
    struct KClient *c=transportClient(fd);
    bool room=c&&!c->finishing&&bytes<=KVT_QUEUE_LIMIT&&c->tx.length<=KVT_QUEUE_LIMIT-bytes;
    pthread_mutex_unlock(&gTransportMutex);return room;
}
static bool sendFrame(int fd,char type,NSData *body) {
    pthread_mutex_lock(&gTransportMutex);struct KClient *c=transportClient(fd);bool ok=false;
    if(c&&!c->finishing&&body){bool empty=!c->tx.length;
        ok=kvtQueueFrame(&c->tx,(unsigned char)type,body.bytes,body.length,true);
        if(ok&&empty)c->tx_progress_ms=nowMS();}
    pthread_mutex_unlock(&gTransportMutex);return ok;
}
static bool sendJSON(int fd,NSDictionary *value) { return sendFrame(fd,'J',jsonData(value)); }
static bool authenticate(int fd, struct KPeer *p) {
    gid_t gid;pid_t pid=0;socklen_t length=sizeof(pid);uid_t uid;
    if(getpeereid(fd,&uid,&gid)||getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&length)||length!=sizeof(pid)
        ||!freshIdentity(pid,&p->native)||p->native.bsd.pbi_ruid!=uid||p->native.bsd.pbi_uid!=uid
        ||!freshIdentity((pid_t)p->native.bsd.pbi_ppid,&p->parent)||p->parent.bsd.pbi_ruid!=uid
        ||p->native.unique.parent_uniqueid!=p->parent.unique.uniqueid)return false;
    char path[PROC_PIDPATHINFO_MAXSIZE];if(proc_pidpath(pid,path,sizeof(path))<=0)return false;
    /* The reactor never hashes a filesystem image. The actor repeats the
     * protected binary pin before effects; fast stop additionally requires an
     * immutable attempt capability or exact registered controller/authority. */
    if(![gExecutable isEqual:@(path)])return false;
    p->owner=uid;return true;
}
static bool authenticatedEntry(NSMutableDictionary *e, NSDictionary *q, struct KPeer *p, bool secret) {
    if(!e || !validRecordedEntry(e,q[@"attempt_id"]) || [e[@"owner_uid"] unsignedIntValue]!=p->owner
        || (secret&&!sameBootID(e[@"descriptor"][@"boot_id"],gBoot)) || ![e[@"descriptor"][@"host_id"] isEqual:gHost])return false;
    if(secret){if(!hex64(q[@"token"]))return false;
        return equalSecret(e[@"token_sha256"],sha([q[@"token"] dataUsingEncoding:NSUTF8StringEncoding]));}
    return hex64(q[@"descriptor_sha256"]) && equalSecret(e[@"descriptor_sha256"],q[@"descriptor_sha256"]);
}
static bool isController(NSMutableDictionary *e,struct KPeer *p) { return sameBirth(e[@"controller"],&p->parent); }
static bool isAuthority(NSMutableDictionary *e,struct KPeer *p) { return e[@"authority"] && sameBirth(e[@"authority"],&p->parent); }

struct KRun { pid_t pid,command_pid;int client,out,err,ready,gate,config;uint64_t deadline,ordinal;
    bool exited,birth_seen,birth_permit_pending,birth_permitted,ready_seen,permit_pending,permitted;int status;size_t ready_used;unsigned char ready_bytes[89]; };
static struct KRun gRun={.pid=0,.client=-1,.out=-1,.err=-1,.ready=-1,.gate=-1,.config=-1};
static NSData *gRunConfig;
static NSString *gRunCommandSHA;
static size_t gRunConfigOffset;
static NSMutableDictionary *gClosing;
static uint64_t gCloseDeadline;
static int gCloseWaiter=-1;
static bool gDrainOnly;
static int gCleanupBarrier=-1;
static NSString *gCleanupAttempt;
static NSMutableDictionary *gRebootClosing;
static NSDictionary *statusReply(NSMutableDictionary *e);
static void publishState(void) {
    /* Only actor calls this. Deep freezing occurs before pointer publication;
     * readers retain immutable objects, never gRegistry or a mutable child. */
    NSString *active=activeID();NSMutableDictionary *e=active.length?entryFor(active):gClosing;
    bool known=e&&validRecordedEntry(e,e[@"descriptor"][@"attempt_id"])
        &&[e[@"descriptor"][@"boot_id"] isEqual:gBoot]&&[e[@"descriptor"][@"host_id"] isEqual:gHost];
    struct KObservation next={0},prior=observationCopy();
    next.generation=prior.generation;strlcpy(next.attempt,prior.attempt,sizeof(next.attempt));
    next.stop_started=prior.stop_started;next.stop_deadline=prior.stop_deadline;
    next.planned_terminal=prior.planned_terminal;next.abort_latched=prior.abort_latched;
    if(known&&(active.length||gClosing==e)){
        const char *attempt=[e[@"descriptor"][@"attempt_id"] UTF8String];
        next.generation=prior.generation&&!strcmp(prior.attempt,attempt)?prior.generation:++gObservationGeneration;
        if(next.generation!=prior.generation){next.stop_started=0;next.stop_deadline=0;next.planned_terminal=false;next.abort_latched=false;}
        strlcpy(next.attempt,attempt,sizeof(next.attempt));next.valid=true;
        next.owner=[e[@"owner_uid"] unsignedIntValue];next.private_uid=[e[@"descriptor"][@"task_ruid"] unsignedIntValue];
        next.work_deadline=[e[@"work_deadline_ms"] unsignedLongLongValue];
        next.command_deadline=gRun.pid?gRun.deadline:0;
        next.cleanup_deadline=[e[@"cleanup_deadline_ms"] unsignedLongLongValue];
        next.cleanup_budget=[e[@"cleanup_budget_ms"] unsignedLongLongValue];
        next.planned_terminal=next.planned_terminal||[e[@"planned_terminal"] boolValue];
        next.abort_latched=next.abort_latched||[e[@"abort_latched"] boolValue];
        next.admission_closed=[e[@"admission_closed"] boolValue];next.drain_only=gDrainOnly||[e[@"state"] isEqual:@"commands_drained"];
        next.guardian_protocol=[e[@"descriptor"][@"stub_wire_version"] isEqual:@"KVS2"];
        exactFromJSON(e[@"controller"],&next.controller);exactFromJSON(e[@"authority"],&next.authority);
        exactFromJSON(e[@"launch_stub"],&next.stub);exactFromJSON(e[@"root_child"],&next.root_child);exactFromJSON(e[@"command_identity"],&next.command);
        if(prior.valid&&prior.generation==next.generation){next.stop_started=prior.stop_started;next.stop_deadline=prior.stop_deadline;}
    }
    pthread_mutex_lock(&gObservationMutex);
    /* A reactor/observer may have latched while the actor built this copy. */
    if(next.valid&&gObservation.valid&&next.generation==gObservation.generation){
        next.stop_started=gObservation.stop_started;next.stop_deadline=gObservation.stop_deadline;
        next.planned_terminal=next.planned_terminal||gObservation.planned_terminal;
        next.abort_latched=next.abort_latched||gObservation.abort_latched;
        next.uid_ticket_armed=gObservation.uid_ticket_armed&&next.private_uid==gObservation.private_uid;
        next.root_registered=gObservation.root_registered&&next.stub.present&&next.root_child.present
            &&gObservation.stub.present&&gObservation.root_child.present
            &&sameObservedBirth(&next.stub.identity,&gObservation.stub.identity)
            &&sameObservedBirth(&next.root_child.identity,&gObservation.root_child.identity);
        next.guardian_registered=gObservation.guardian_registered&&next.stub.present&&next.command.present
            &&gObservation.stub.present&&gObservation.command.present
            &&sameObservedBirth(&next.stub.identity,&gObservation.stub.identity)
            &&sameObservedBirth(&next.command.identity,&gObservation.command.identity);}
    gObservation=next;pthread_mutex_unlock(&gObservationMutex);
    NSDictionary *entry=nil,*status=nil;
    if(known){
        entry=@{@"owner_uid":e[@"owner_uid"],@"descriptor_sha256":e[@"descriptor_sha256"],
            @"token_sha256":e[@"token_sha256"]?:@"",@"controller":e[@"controller"],
            @"authority":e[@"authority"]?:NSNull.null,@"attempt_id":e[@"descriptor"][@"attempt_id"]};
        status=@{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":e[@"descriptor"][@"attempt_id"],
            @"descriptor":e[@"descriptor"],@"descriptor_sha256":e[@"descriptor_sha256"],@"state":e[@"state"],
            @"admission_closed":e[@"admission_closed"],@"spawn_intent":e[@"spawn_intent"],
            @"authority_spawn_intent":e[@"authority_spawn_intent"],@"observation_cached":@YES,
            @"allocation_tuple_verified_current":@NO,@"registry_healthy":@NO,@"registry_health_cached":@((bool)!gPoisoned),
            @"cleanup_confirmed":@NO,@"resources_free":@NO,@"capability_qualified":@(gCapabilityQualified),
            @"work_deadline_monotonic_ms":e[@"work_deadline_ms"],
            @"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"]?:NSNull.null,
            @"writer_generation":@(next.generation?:prior.generation),@"proof_current":@NO};
        entry=[NSJSONSerialization JSONObjectWithData:jsonData(entry) options:0 error:NULL];
        status=[NSJSONSerialization JSONObjectWithData:jsonData(status) options:0 error:NULL];
    }
    pthread_mutex_lock(&gCacheMutex);gCachedEntry=entry;gCachedStatus=status;pthread_mutex_unlock(&gCacheMutex);
}
/* Arm only after durable reservation publication AND current history check.
 * Cached authority can stop this never-reused allocation; it cannot prove a
 * positive completion or authorize any subsequent launch. */
static bool armUIDStopTicket(NSMutableDictionary *e) {
    const char *attempt=[e[@"descriptor"][@"attempt_id"] UTF8String];
    uid_t privateUID=[e[@"descriptor"][@"task_ruid"] unsignedIntValue];
    bool armed=false;pthread_mutex_lock(&gObservationMutex);
    if(gObservation.valid&&attempt&&!strcmp(attempt,gObservation.attempt)
        &&gObservation.private_uid==privateUID){
        gObservation.uid_ticket_armed=true;armed=true;}
    pthread_mutex_unlock(&gObservationMutex);return armed;
}
static void signalObservedBirth(struct KExactBirth birth,uid_t expected,uid_t alternate,int signalNumber) {
    struct KIdentity v;int seen=observeBirth(birth,&v);
    if(seen!=1||(v.bsd.pbi_ruid!=expected&&v.bsd.pbi_ruid!=alternate))return;
    audit_token_t token={{0}};token.val[5]=v.bsd.pbi_pid;token.val[7]=(uint32_t)v.unique.pidversion;
    if(gSignalToken)gSignalToken(&token,signalNumber);
}
static int stopAllocatedUID(struct KObservation v,pid_t *pids) {
    if(!v.uid_ticket_armed||!pids)return -1;
    int count=members(v.private_uid,pids);if(count<0)return -1;
    for(int i=0;i<count;i++){if(pids[i]<=0)continue;struct KIdentity member;errno=0;
        if(!freshIdentity(pids[i],&member)){if(errno==ESRCH)continue;return -1;}
        if(member.bsd.pbi_ruid!=v.private_uid)continue;
        audit_token_t token={{0}};token.val[5]=member.bsd.pbi_pid;token.val[7]=(uint32_t)member.unique.pidversion;
        int rc=gSignalToken?gSignalToken(&token,SIGKILL):-1;if(rc!=0&&rc!=ESRCH)return -1;
    }return count;
}
static void *stopObserver(void *unused) {
    (void)unused;pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));
    if(!pids)gStopping=1;
    while(!atomic_load_explicit(&gActorDone,memory_order_acquire)){
        struct KObservation v=observationCopy();
        if(v.valid){struct KIdentity identity,guardian,rootChild,command;uint64_t now=nowMS();
            bool latched=atomic_load_explicit(&gStopGeneration,memory_order_acquire)==v.generation;
            int controllerSeen=observeBirth(v.controller,&identity),authoritySeen=v.authority.present?observeBirth(v.authority,&identity):1;
            int guardianSeen=v.stub.present?observeBirth(v.stub,&guardian):0;
            int rootSeen=v.root_child.present?observeBirth(v.root_child,&rootChild):0;
            int commandSeen=v.command.present?observeBirth(v.command,&command):0;
            bool expired=(!v.admission_closed&&now>=v.work_deadline)
                ||(v.command_deadline&&now>=v.command_deadline)
                ||(v.admission_closed&&v.cleanup_deadline&&now>=v.cleanup_deadline);
            if(gStopping||controllerSeen!=1||authoritySeen!=1||expired){
                bool authorityExitOnly=!gStopping&&controllerSeen==1&&authoritySeen==0&&!expired;
                latched=latchGenerationMode(v.generation,K_MAX_CLEANUP_MS,false,authorityExitOnly)||latched;
            }
            if(v.guardian_protocol&&v.command_deadline&&v.stub.present&&guardianSeen!=1){
                /* Guardian death must not strand detached children while the
                 * actor is blocked on disk. A normal guardian exits only
                 * after its direct child was reaped and its UID scan was zero. */
                int count=stopAllocatedUID(v,pids);
                if(guardianSeen<0||rootSeen!=0||commandSeen!=0||count!=0)
                    latched=latchGeneration(v.generation,K_MAX_CLEANUP_MS)||latched;
            }
            if(v.guardian_protocol&&v.uid_ticket_armed&&guardianSeen==1&&rootCredentials(&guardian)
                &&rootSeen==1&&(rootCredentials(&rootChild)||rootChild.bsd.pbi_ruid==v.private_uid)
                &&rootChild.bsd.pbi_ppid==guardian.bsd.pbi_pid&&rootChild.unique.parent_uniqueid==guardian.unique.uniqueid){
                pthread_mutex_lock(&gObservationMutex);
                if(gObservation.valid&&gObservation.generation==v.generation&&gObservation.stub.present
                    &&gObservation.root_child.present&&sameObservedBirth(&guardian,&gObservation.stub.identity)
                    &&sameObservedBirth(&rootChild,&gObservation.root_child.identity))gObservation.root_registered=true;
                pthread_mutex_unlock(&gObservationMutex);
            }
            if(v.guardian_protocol&&v.uid_ticket_armed&&guardianSeen==1&&rootCredentials(&guardian)
                &&commandSeen==1&&command.bsd.pbi_ruid==v.private_uid
                &&command.bsd.pbi_ppid==guardian.bsd.pbi_pid&&command.unique.parent_uniqueid==guardian.unique.uniqueid){
                pthread_mutex_lock(&gObservationMutex);
                if(gObservation.valid&&gObservation.generation==v.generation&&gObservation.stub.present
                    &&gObservation.command.present&&sameObservedBirth(&guardian,&gObservation.stub.identity)
                    &&sameObservedBirth(&command,&gObservation.command.identity))gObservation.guardian_registered=true;
                pthread_mutex_unlock(&gObservationMutex);
            }
            if(latched||(v.admission_closed&&v.drain_only)){
                /* The enforcer receives TERM and survives until drain. It is
                 * not killed before its owned descendants are observed gone. */
                signalObservedBirth(v.stub,0,v.private_uid,v.guardian_protocol?SIGTERM:SIGKILL);
                if(v.guardian_protocol)signalObservedBirth(v.stub,0,0,SIGCONT);
                signalObservedBirth(v.root_child,0,v.private_uid,SIGKILL);
                signalObservedBirth(v.command,v.private_uid,v.private_uid,SIGKILL);
                if(v.uid_ticket_armed)stopAllocatedUID(v,pids);
                if(latched)signalObservedBirth(v.authority,v.owner,v.owner,SIGKILL);
            }
        }
        struct timespec pause={0,20000000};nanosleep(&pause,NULL);
    }
    free(pids);return NULL;
}
static void stopSignal(int sig) {(void)sig;gStopping=1;}
static bool closeAdmission(NSMutableDictionary *e,NSString *reason,uint64_t budget) {
    gDrainOnly=[reason isEqual:@"commands_complete"];
    /* Restart can reach this before any active snapshot has been published.
     * Establish that generation before latching, then publish closed state
     * before persistence so stalled restart closure still has exact stop. */
    publishState();
    if(!gDrainOnly){struct KObservation v=observationCopy();
        if(v.valid&&[e[@"descriptor"][@"attempt_id"] isEqual:@(v.attempt)])
            latchGenerationMode(v.generation,budget,[reason isEqual:@"close_requested"]&&plannedAttempt(e),false);
    }
    if(abortedAttempt(e))e[@"abort_latched"]=@YES;
    if(plannedAttempt(e))e[@"planned_terminal"]=@YES;
    bool durable=!gPoisoned;
    /* Disk failure poisons positive proof, never the ability to stop work. */
    if(gPendingFD>=0){close(gPendingFD);gPendingFD=-1;}
    if(gRun.config>=0){close(gRun.config);gRun.config=-1;gRunConfig=nil;}
    if(gRun.gate>=0){close(gRun.gate);gRun.gate=-1;}
    /* Only validated request or persisted policy values reach this internal
     * stop path. An invalid stored value cannot grant an unbounded wait. */
    uint64_t profile=[e[@"cleanup_budget_ms"] unsignedLongLongValue];
    uint64_t bounded=budget>=1&&budget<=K_MAX_CLEANUP_MS&&profile>=1&&profile<=K_MAX_CLEANUP_MS?MIN(budget,profile):1;
    uint64_t started=nowMS();
    struct KObservation stop=observationCopy();
    if(stop.valid&&[e[@"descriptor"][@"attempt_id"] isEqual:@(stop.attempt)]&&stop.stop_deadline){
        started=MIN(started,stop.stop_started);}
    if(e[@"cleanup_started_monotonic_ms"])started=MIN(started,[e[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]);
    uint64_t deadline=started+bounded;
    if(stop.valid&&[e[@"descriptor"][@"attempt_id"] isEqual:@(stop.attempt)]&&stop.stop_deadline)deadline=MIN(deadline,stop.stop_deadline);
    if(e[@"cleanup_deadline_ms"])deadline=MIN(deadline,[e[@"cleanup_deadline_ms"] unsignedLongLongValue]);
    if(!e[@"cleanup_started_monotonic_ms"]){e[@"cleanup_started_monotonic_ms"]=@(started);e[@"cleanup_budget_exceeded"]=@NO;}
    e[@"cleanup_deadline_ms"]=@(deadline);
    if(![e[@"admission_closed"] boolValue]){e[@"stop_reason"]=reason;e[@"closed_monotonic_ms"]=@(started);}
    else if([reason isEqual:@"close_requested"]&&[e[@"stop_reason"] isEqual:@"commands_complete"]
        &&[e[@"state"] isEqual:@"commands_drained"]&&plannedAttempt(e)&&!abortedAttempt(e)){
        /* Normal command drain and terminal close are distinct phases. Keep
         * the original closed time/cleanup epoch, but expose the planned
         * terminal cause required by the production acceptance contract. */
        e[@"stop_reason"]=reason;
    }
    else if(![reason isEqual:@"close_requested"]&&![reason isEqual:@"recovery_requested"])e[@"stop_reason"]=reason;
    e[@"admission_closed"]=@YES;e[@"state"]=@"closing";
    gCloseDeadline=deadline;gClosing=e;publishState();
    durable=persist()&&durable;return durable;
}
static void transportLost(int fd) {
    struct KClient *client=transportClient(fd);
    struct KObservation v=observationCopy();
    if(client&&client->run_attempt[0]&&v.valid&&!strcmp(client->run_attempt,v.attempt))
        latchGeneration(v.generation,K_MAX_CLEANUP_MS);
}
static int admissionFD(NSMutableDictionary *e) {
    NSString *name=[NSString stringWithFormat:@"%@.admission",e[@"descriptor"][@"boundary_id"]];
    int fd=openat(gRegistryFD,name.UTF8String,O_RDWR|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    NSDictionary *saved=e[@"admission_inode"];
    if(fd<0)return -1;if(![saved isKindOfClass:NSDictionary.class]||!nativeUInt64Field(saved[@"device"])||!nativeUInt64Field(saved[@"inode"])
        ||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||st.st_nlink!=1||(st.st_mode&0077)
        ||[saved[@"device"] unsignedLongLongValue]!=(uint64_t)st.st_dev||[saved[@"inode"] unsignedLongLongValue]!=(uint64_t)st.st_ino){
        close(fd);return -1;}return fd;
}
static int acquireCleanupBarrier(NSMutableDictionary *e) {
    NSString *attempt=e[@"descriptor"][@"attempt_id"];
    int fresh=admissionFD(e);if(fresh<0)return -1;
    if(gCleanupBarrier>=0){struct stat old,current;
        bool same=[gCleanupAttempt isEqual:attempt]&&fstat(gCleanupBarrier,&old)==0&&fstat(fresh,&current)==0
            &&old.st_dev==current.st_dev&&old.st_ino==current.st_ino;
        close(fresh);return same?fcntl(gCleanupBarrier,F_DUPFD_CLOEXEC,32):-1;
    }
    if(flock(fresh,LOCK_EX|LOCK_NB)){close(fresh);return -1;}
    gCleanupBarrier=fcntl(fresh,F_DUPFD_CLOEXEC,32);
    if(gCleanupBarrier<0){close(fresh);return -1;}gCleanupAttempt=attempt;return fresh;
}
/* New boot recovery never interprets an old PID, old unique-id or old monotonic
 * deadline in the current kernel. The durable non-reuse allocation and policy
 * remain mandatory. An occupied reserved UID is quarantined, never signalled. */
static bool beginRebootCleanup(NSMutableDictionary *e,uint64_t requested) {
    NSDictionary *d=e[@"descriptor"];
    if(!validRecordedEntry(e,d[@"attempt_id"])||sameBootID(d[@"boot_id"],gBoot)
        ||![d[@"host_id"] isEqual:gHost]||!kernelBootCurrent()||atomic_load(&gClockFailed)
        ||gRun.pid||gClosing||(activeID().length&&![activeID() isEqual:d[@"attempt_id"]]))return false;
    if(!validUIDAllocation(e))return false;
    NSDictionary *old=e[@"reboot_cleanup"];
    if(old&&sameBootID(old[@"boot_id"],gBoot)){
        /* A same-boot restart/retry retains the original recovery epoch. */
        gRebootClosing=e;return true;
    }
    uint64_t started=nowMS(),budget=MIN(requested,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    if(atomic_load(&gClockFailed)||budget<1||budget>K_MAX_CLEANUP_MS||!kernelBootCurrent())return false;
    if(old){NSArray *history=e[@"reboot_cleanup_history"]?:@[];
        if(![history isKindOfClass:NSArray.class]||history.count>=64)return false;
        NSMutableArray *kept=[history mutableCopy];[kept addObject:old];e[@"reboot_cleanup_history"]=kept;}
    e[@"reboot_cleanup"]=[@{@"schema":@"knowledge-darwin-reboot-cleanup.v1",
        @"recovery_epoch":randomHex(),@"daemon_epoch":gDaemonEpoch,@"origin_boot_id":d[@"boot_id"],@"boot_id":gBoot,
        @"host_id":gHost,@"installation_id":d[@"installation_id"],@"descriptor_sha256":e[@"descriptor_sha256"],
        @"cleanup_started_monotonic_ms":@(started),@"cleanup_deadline_monotonic_ms":@(started+budget),@"cleanup_budget_ms":@(budget),
        @"admission_closed":@YES,@"original_work_revoked":@YES,@"cleanup_only":@YES,@"proof_current":@NO,
        @"state":@"pending",@"native_cleanup_facts_confirmed":@NO} mutableCopy];
    /* Preserve every original work/cleanup timestamp, intent and birth. Only
     * the new named recovery record owns new-clock state. */
    e[@"recovery_only"]=@YES;e[@"abort_latched"]=@YES;e[@"planned_terminal"]=@NO;e[@"state"]=@"reboot_cleanup_pending";
    gRegistry[@"active_attempt"]=d[@"attempt_id"];
    if(!persist())return false;
    gRebootClosing=e;return true;
}
static void advanceRebootCleanup(void) {
    if(!gRebootClosing)return;NSMutableDictionary *e=gRebootClosing,*r=e[@"reboot_cleanup"];
    NSString *attempt=e[@"descriptor"][@"attempt_id"];uint64_t deadline=[r[@"cleanup_deadline_monotonic_ms"] unsignedLongLongValue];
    bool trusted=currentRebootCleanup(e)&&validUIDAllocation(e)&&kernelBootCurrent();
    uint64_t observed=nowMS();bool inBudget=!atomic_load(&gClockFailed)&&observed>=
        [r[@"cleanup_started_monotonic_ms"] unsignedLongLongValue]&&observed<deadline;
    int barrier=-1;bool excluded=false;
    if(trusted&&inBudget){
        if(e[@"admission_inode"]){barrier=admissionFD(e);excluded=barrier>=0&&flock(barrier,LOCK_EX|LOCK_NB)==0;}
        else{struct stat absent;NSString *name=[attempt stringByAppendingString:@".admission"];errno=0;
            /* Crash before first admission publication: absence is accepted
             * only after a new boot, with the original durable no-spawn state. */
            excluded=![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue]
                &&!e[@"launch_stub"]&&!e[@"authority"]&&fstatat(gRegistryFD,name.UTF8String,&absent,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;}
    }
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));int count=trusted&&excluded&&pids?
        members([e[@"descriptor"][@"task_ruid"] unsignedIntValue],pids):-1;free(pids);
    /* A new kernel boot proves old-birth absence without interpreting a
     * potentially reused PID from that other boot. Current members still
     * require an actual kernel scan, and no old signal authority is imported. */
    observed=nowMS();inBudget=inBudget&&!atomic_load(&gClockFailed)&&observed<deadline&&kernelBootCurrent();
    bool closed=trusted&&excluded&&count==0&&inBudget&&!gPoisoned;
    r[@"state"]=closed?@"closed":@"unconfirmed";r[@"native_cleanup_facts_confirmed"]=@(closed);
    r[@"kernel_membership_zero"]=@(count==0);r[@"spawn_exclusion_acquired"]=@(excluded);
    r[@"old_births_absent_by_new_boot"]=@(trusted);r[@"observed_monotonic_ms"]=@(observed);
    r[@"cleanup_budget_exceeded"]=@((bool)!inBudget);
    r[@"reason"]=closed?@"NEW_BOOT_CLEANUP_CONFIRMED":count>0?@"NEW_BOOT_RESERVED_UID_OCCUPIED_QUARANTINED":
        !inBudget?@"NEW_BOOT_CLEANUP_BUDGET_EXCEEDED":@"NEW_BOOT_CLEANUP_UNCONFIRMED";
    e[@"state"]=closed?@"closed":@"reboot_cleanup_unconfirmed";
    if(closed)gRegistry[@"active_attempt"]=@"";
    bool durable=persist();
    if(!durable||!closed){gRegistry[@"active_attempt"]=attempt;r[@"state"]=@"unconfirmed";
        r[@"native_cleanup_facts_confirmed"]=@NO;e[@"state"]=@"reboot_cleanup_unconfirmed";}
    if(durable&&closed&&(!validUIDAllocation(e)||!kernelBootCurrent()||atomic_load(&gClockFailed)||nowMS()>=deadline)){
        /* Never release a late callback as bounded recovery success. If the
         * process crashes earlier, the stored record is history; readonly
         * closure must independently reobserve this permanently revoked UID. */
        closed=false;gRegistry[@"active_attempt"]=attempt;r[@"state"]=@"unconfirmed";r[@"native_cleanup_facts_confirmed"]=@NO;
        r[@"cleanup_budget_exceeded"]=@(nowMS()>=deadline);e[@"state"]=@"reboot_cleanup_unconfirmed";durable=persist();
    }
    if(gCloseWaiter>=0){sendJSON(gCloseWaiter,durable?statusReply(e):failure(@"REBOOT_CLEANUP_DURABILITY_UNCONFIRMED"));
        finishTransport(gCloseWaiter);gCloseWaiter=-1;}
    if(barrier>=0)close(barrier);gRebootClosing=nil;
}
static bool sameFileObservation(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size
        &&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec
        &&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static bool copyReadACLMatches(int fd,uid_t owner,bool directory) {
    NSData *expected=gOwnerUUIDs[[NSString stringWithFormat:@"%u",owner]];
    if(expected.length!=sizeof(uuid_t))return false;
    acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);if(!acl)return false;
    acl_entry_t entry;bool ok=acl_get_entry(acl,ACL_FIRST_ENTRY,&entry)==0;acl_tag_t tag;
    acl_permset_t permissions;acl_flagset_t flags;void *qualifier=NULL;
    if(ok)ok=acl_get_tag_type(entry,&tag)==0&&tag==ACL_EXTENDED_ALLOW
        &&acl_get_permset(entry,&permissions)==0&&acl_get_flagset_np(entry,&flags)==0;
    if(ok){qualifier=acl_get_qualifier(entry);ok=qualifier&&memcmp(qualifier,expected.bytes,sizeof(uuid_t))==0;}
    if(qualifier)acl_free(qualifier);
    acl_perm_t all[]={ACL_READ_DATA,ACL_WRITE_DATA,ACL_EXECUTE,ACL_DELETE,ACL_APPEND_DATA,ACL_DELETE_CHILD,
        ACL_READ_ATTRIBUTES,ACL_WRITE_ATTRIBUTES,ACL_READ_EXTATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,
        ACL_READ_SECURITY,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER,ACL_SYNCHRONIZE};
    for(unsigned i=0;ok&&i<sizeof(all)/sizeof(all[0]);i++){
        bool allowed=all[i]==ACL_READ_DATA||all[i]==ACL_READ_ATTRIBUTES||all[i]==ACL_READ_EXTATTRIBUTES
            ||all[i]==ACL_READ_SECURITY||(directory&&all[i]==ACL_SEARCH);
        ok=acl_get_perm_np(permissions,all[i])==(allowed?1:0);
    }
    acl_flag_t inherited[]={ACL_ENTRY_INHERITED,ACL_ENTRY_FILE_INHERIT,ACL_ENTRY_DIRECTORY_INHERIT,
        ACL_ENTRY_LIMIT_INHERIT,ACL_ENTRY_ONLY_INHERIT};
    for(unsigned i=0;ok&&i<sizeof(inherited)/sizeof(inherited[0]);i++)ok=acl_get_flag_np(flags,inherited[i])==0;
    if(ok)ok=acl_get_entry(acl,ACL_NEXT_ENTRY,&entry)!=0;
    acl_free(acl);return ok;
}
static bool walkCopy(int directory,NSString *prefix,NSMutableDictionary *e,NSMutableSet *seenFiles,
                     NSMutableSet *seenDirectories,uint64_t *total,unsigned depth) {
    if(depth>256||seenFiles.count+seenDirectories.count>2*K_MAX_FILES)return false;
    int copy=fcntl(directory,F_DUPFD_CLOEXEC,32);if(copy<0)return false;
    DIR *stream=fdopendir(copy);if(!stream){close(copy);return false;}
    uid_t uid=[e[@"descriptor"][@"task_ruid"] unsignedIntValue];bool ok=true;struct dirent *item;
    errno=0;
    while(ok&&(item=readdir(stream))){
        if(!strcmp(item->d_name,".")||!strcmp(item->d_name,".."))continue;
        NSString *leaf=[[NSString alloc] initWithBytes:item->d_name length:strlen(item->d_name) encoding:NSUTF8StringEncoding];
        NSString *path=prefix.length?[prefix stringByAppendingFormat:@"/%@",leaf]:leaf;
        struct stat named,opened,after;
        if(!leaf||!validRelative(path)||fstatat(directory,item->d_name,&named,AT_SYMLINK_NOFOLLOW)
            ||named.st_uid!=uid||named.st_gid!=uid){ok=false;break;}
        bool dir=S_ISDIR(named.st_mode),file=S_ISREG(named.st_mode);
        NSDictionary *expected=e[@"manifest"][path];
        if((!dir&&!file)||(dir&&(!e[@"directories"][path]||(named.st_mode&07777)!=0700))
            ||(file&&(!expected||named.st_nlink!=1||named.st_size<0||(uint64_t)named.st_size!=[expected[@"bytes"] unsignedLongLongValue]
                ||(named.st_mode&07777)!=([expected[@"mode"] unsignedIntValue]&0700)))){ok=false;break;}
        int fd=openat(directory,item->d_name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(dir?O_DIRECTORY:0));
        if(fd<0||fstat(fd,&opened)||!sameFileObservation(&named,&opened)
            ||!copyReadACLMatches(fd,[e[@"owner_uid"] unsignedIntValue],dir)){if(fd>=0)close(fd);ok=false;break;}
        if(dir){[seenDirectories addObject:path];ok=walkCopy(fd,path,e,seenFiles,seenDirectories,total,depth+1);}
        else{
            [seenFiles addObject:path];CC_SHA256_CTX digest;CC_SHA256_Init(&digest);unsigned char buffer[65536],hash[32];
            uint64_t bytes=0;ssize_t n=0;
            while(ok&&(n=read(fd,buffer,sizeof(buffer)))!=0){
                if(n<0){if(errno==EINTR)continue;ok=false;break;}
                bytes+=(uint64_t)n;if(bytes>[expected[@"bytes"] unsignedLongLongValue]||*total+(uint64_t)n>K_MAX_COPY){ok=false;break;}
                *total+=(uint64_t)n;CC_SHA256_Update(&digest,buffer,(CC_LONG)n);
            }
            CC_SHA256_Final(hash,&digest);char hex[65];for(unsigned i=0;i<32;i++)snprintf(hex+2*i,3,"%02x",hash[i]);
            ok=ok&&bytes==[expected[@"bytes"] unsignedLongLongValue]&&[@(hex) isEqual:expected[@"sha256"]];
        }
        if(fstat(fd,&after)||!sameFileObservation(&opened,&after))ok=false;
        struct stat stillNamed;if(fstatat(directory,item->d_name,&stillNamed,AT_SYMLINK_NOFOLLOW)||!sameFileObservation(&after,&stillNamed))ok=false;
        if(close(fd))ok=false;errno=0;
    }
    if(errno)ok=false;if(closedir(stream))ok=false;return ok;
}
static NSDictionary *readbackCopy(NSMutableDictionary *e,struct KPeer *peer) {
    NSString *phase=e[@"state"];bool sealed=[phase isEqual:@"sealed"],drained=[phase isEqual:@"commands_drained"],closed=[phase isEqual:@"closed"];
    if(abortedAttempt(e)||(!sealed&&!drained&&!closed)||(!isController(e,peer)&&!isAuthority(e,peer))||gPendingFD>=0||e[@"pending_copy"])
        return failure(@"COPY_READBACK_INVALID_PHASE_OR_ROLE");
    if(![e[@"manifest"] isKindOfClass:NSDictionary.class]||![e[@"directories"] isKindOfClass:NSDictionary.class]
        ||[e[@"manifest"] count]>K_MAX_FILES||[e[@"directories"] count]>K_MAX_FILES
        ||!numericField(e[@"files"])||[e[@"files"] unsignedLongLongValue]!=[e[@"manifest"] count]
        ||!numericField(e[@"bytes"])||[e[@"bytes"] unsignedLongLongValue]>K_MAX_COPY
        ||!hex64(e[@"manifest_sha256"])||!hex64(e[@"directories_sha256"]))return failure(@"COPY_READBACK_LEDGER_INVALID");
    NSMutableArray *manifest=[NSMutableArray array];
    for(NSString *path in utf8Sorted([e[@"manifest"] allKeys])){
        NSDictionary *item=e[@"manifest"][path];
        if(!validRelative(path)||![item isKindOfClass:NSDictionary.class]||item.count!=4||![item[@"path"] isEqual:path]
            ||!numericField(item[@"mode"])||([item[@"mode"] unsignedLongLongValue]!=0644&&[item[@"mode"] unsignedLongLongValue]!=0755)
            ||!numericField(item[@"bytes"])||[item[@"bytes"] unsignedLongLongValue]>256u*1024u*1024u||!hex64(item[@"sha256"]))
            return failure(@"COPY_READBACK_LEDGER_INVALID");
        [manifest addObject:item];
    }
    for(NSString *path in e[@"directories"])if(!validRelative(path)||!booleanField(e[@"directories"][path])
        ||![e[@"directories"][path] boolValue])return failure(@"COPY_READBACK_LEDGER_INVALID");
    if(![sha(jsonData(manifest)) isEqual:e[@"manifest_sha256"]]
        ||![sha(jsonData(utf8Sorted([e[@"directories"] allKeys]))) isEqual:e[@"directories_sha256"]])return failure(@"COPY_READBACK_LEDGER_DIGEST_MISMATCH");
    if(!validUIDAllocation(e)||gPoisoned)return failure(@"COPY_READBACK_ALLOCATION_UNCONFIRMED");
    int barrier=drained?acquireCleanupBarrier(e):admissionFD(e);
    if(barrier<0)return failure(@"COPY_READBACK_EXCLUSION_UNCONFIRMED");
    bool ok=drained||flock(barrier,LOCK_EX|LOCK_NB)==0;
    int workspace=ok?openWorkspace(e):-1;struct stat before,after;
    ok=ok&&workspace>=0&&fstat(workspace,&before)==0&&(before.st_mode&07777)==0700
        &&copyReadACLMatches(workspace,[e[@"owner_uid"] unsignedIntValue],true);
    NSMutableSet *files=[NSMutableSet set],*directories=[NSMutableSet set];uint64_t bytes=0;
    if(ok)ok=walkCopy(workspace,@"",e,files,directories,&bytes,0);
    if(ok)ok=fstat(workspace,&after)==0&&sameFileObservation(&before,&after)
        &&files.count==[e[@"manifest"] count]&&directories.count==[e[@"directories"] count]
        &&bytes==[e[@"bytes"] unsignedLongLongValue];
    int current=ok?openWorkspace(e):-1;struct stat named;
    if(ok)ok=current>=0&&fstat(current,&named)==0&&sameFileObservation(&after,&named);
    if(current>=0)close(current);if(workspace>=0)close(workspace);
    /* Fresh allocation and clock/owner guards AFTER the last potentially slow
     * read. The OFD stays held across this final check and reply construction. */
    if(ok)ok=validUIDAllocation(e)&&!gPoisoned&&!abortedAttempt(e)&&currentPeerAlive()
        &&(!gCurrentWork||!atomic_load_explicit(&gCurrentWork->cancelled,memory_order_acquire));
    if(ok&&sealed)ok=!workStopped(e)&&![e[@"admission_closed"] boolValue];
    if(ok&&drained){struct KIdentity identity;
        ok=observeExact(e[@"controller"],&identity)==1&&observeExact(e[@"authority"],&identity)==1;}
    if(ok&&closed)ok=[e[@"proof"][@"native_cleanup_facts_confirmed"] boolValue]&&[e[@"admission_closed"] boolValue];
    uint64_t readbackObserved=0;
    if(ok){
        bool phaseCurrent=closed||!stoppedAttempt(e);
        bool abortClear=!abortedAttempt(e);
        readbackObserved=nowMS();
        ok=phaseCurrent&&abortClear&&!gStopping&&!atomic_load_explicit(&gClockFailed,memory_order_acquire)
            &&(!gCurrentWork||!atomic_load_explicit(&gCurrentWork->cancelled,memory_order_acquire))
            &&(sealed?(readbackObserved<[e[@"work_deadline_ms"] unsignedLongLongValue]):
                readbackObserved<[e[@"cleanup_deadline_ms"] unsignedLongLongValue]);
    }
    NSDictionary *reply=failure(@"COPY_READBACK_UNCONFIRMED");
    if(ok){NSDictionary *body=@{@"schema":@"knowledge-darwin-copy-readback.v1",@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor_sha256":e[@"descriptor_sha256"],@"phase":phase,@"manifest_sha256":e[@"manifest_sha256"],
        @"directories_sha256":e[@"directories_sha256"],@"workspace_identity":@{
            @"device":[NSString stringWithFormat:@"%llu",[e[@"workspace_inode"][@"device"] unsignedLongLongValue]],
            @"inode":[NSString stringWithFormat:@"%llu",[e[@"workspace_inode"][@"inode"] unsignedLongLongValue]]},
        @"files":@(files.count),@"directories":@(directories.count),@"bytes":@(bytes),
        @"verified_current":@YES,@"allocation_tuple_verified_current":@YES,
        @"observed_monotonic_ms":@(readbackObserved),@"capability_qualified":@(gCapabilityQualified)};
        NSMutableDictionary *result=[body mutableCopy];result[@"ok"]=@YES;result[@"readback_sha256"]=sha(jsonData(body));reply=result;}
    close(barrier);return reply;
}
static NSString *sbplString(NSString *text) {
    NSString *array=[[NSString alloc] initWithData:jsonData(@[text]) encoding:NSUTF8StringEncoding];
    return [array substringWithRange:NSMakeRange(1,array.length-2)];
}
static NSString *sandboxProfile(NSString *workspace) {
    NSMutableString *p=[NSMutableString stringWithString:@"(version 1) (deny default) (allow file-read*) (allow process-fork) "];
    /* JSON quoting is compatible with these SBPL string literals. Newlines and
     * control bytes in administrator runtime/workspace paths are rejected. */
    NSMutableArray *rules=[NSMutableArray array];
    for(NSString *runtime in utf8Sorted(gRuntimes))
        [rules addObject:[NSString stringWithFormat:@"(literal %@)",sbplString(runtime)]];
    [p appendFormat:@"(allow process-exec %@ (subpath %@)) ",[rules componentsJoinedByString:@" "],sbplString(workspace)];
    /* Node opens /dev/null read/write for ignored child stdio. This grants only
     * data writes to the actual character device, never a replaced regular file
     * or an arbitrary path outside the command workspace. */
    [p appendString:@"(allow file-write-data (require-all (literal \"/dev/null\") (vnode-type CHARACTER-DEVICE))) "];
    /* The copied program cannot modify and restore its sources between two
     * observations. All temporary output is confined to the sibling scratch. */
    [p appendFormat:@"(allow file-write* (subpath %@)) (deny file-link) (allow sysctl-read) (allow process-info* (target self))",
        sbplString([workspace stringByAppendingString:@".scratch"])];
    return p;
}
static bool runtimeAllowed(NSString *path) { return isString(path,4096) && gRuntimePins[path]
    && [protectedFileSHA(path) isEqual:gRuntimePins[path]]; }
/* Fixed endian KVS2, never a dump of an ABI-dependent C structure. The C-only
 * peer repeats all structural validation before using any field. */
static void wire32(NSMutableData *data,uint32_t value) { value=htonl(value);[data appendBytes:&value length:4]; }
static void wire64(NSMutableData *data,uint64_t value) { wire32(data,(uint32_t)(value>>32));wire32(data,(uint32_t)value); }
static bool wireOwnerBirth(NSMutableData *data,NSDictionary *saved,uid_t owner) {
    uint64_t unique=0;
    if(!validRecordedIdentity(saved)||!decimal64(saved[@"unique_id"],&unique)||!unique
        ||[saved[@"ruid"] unsignedIntValue]!=owner||![saved[@"start_sec"] unsignedLongLongValue]
        ||[saved[@"start_usec"] unsignedLongLongValue]>=1000000)return false;
    wire32(data,[saved[@"pid"] unsignedIntValue]);wire32(data,owner);wire64(data,unique);
    wire64(data,[saved[@"start_sec"] unsignedLongLongValue]);wire64(data,[saved[@"start_usec"] unsignedLongLongValue]);return true;
}
static bool wireString(NSMutableData *data,NSString *value,NSUInteger maximum,bool empty) {
    if(![value isKindOfClass:NSString.class])return false;
    NSData *bytes=[value dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    if(!bytes||(!empty&&!bytes.length)||bytes.length>maximum||memchr(bytes.bytes,0,bytes.length)
        ||data.length>K_MAX_FRAME-4||bytes.length>K_MAX_FRAME-4-data.length)return false;
    wire32(data,(uint32_t)bytes.length);[data appendData:bytes];return true;
}
static bool environmentKey(NSString *key) {
    if(!isString(key,256))return false;
    for(NSUInteger i=0;i<key.length;i++){unichar c=[key characterAtIndex:i];
        if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||c=='_'||(i&&c>='0'&&c<='9')))return false;}
    return true;
}
static NSData *stubConfiguration(NSMutableDictionary *e,NSArray *argv,NSDictionary *env,NSString *cwd,
    uint64_t deadline,int lock,int workspace,int scratch) {
    struct stat admission,directory,temporary;
    if(fstat(lock,&admission)||fstat(workspace,&directory)||fstat(scratch,&temporary)||env.count>256)return nil;
    NSMutableData *data=[NSMutableData data];wire32(data,0x4b565332u);
    wire32(data,[e[@"descriptor"][@"task_ruid"] unsignedIntValue]);wire32(data,(uint32_t)argv.count);wire32(data,(uint32_t)env.count);
    wire64(data,deadline);wire64(data,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    wire64(data,[e[@"descriptor"][@"allocation_seq"] longLongValue]);wire64(data,(uint64_t)admission.st_dev);wire64(data,(uint64_t)admission.st_ino);
    wire64(data,(uint64_t)directory.st_dev);wire64(data,(uint64_t)directory.st_ino);
    wire64(data,(uint64_t)temporary.st_dev);wire64(data,(uint64_t)temporary.st_ino);
    if(!wireOwnerBirth(data,e[@"controller"],[e[@"owner_uid"] unsignedIntValue])
        ||!wireOwnerBirth(data,e[@"authority"],[e[@"owner_uid"] unsignedIntValue]))return nil;
    if(!wireString(data,e[@"descriptor"][@"attempt_id"],64,false)||!wireString(data,gRuntimePins[argv[0]],64,false)
        ||!wireString(data,gDaemonEpoch,64,false)||!wireString(data,e[@"descriptor"][@"installation_id"],64,false)
        ||!wireString(data,e[@"descriptor"][@"allocation_sha256"],64,false)
        ||!wireString(data,cwd,4096,false)||!wireString(data,sandboxProfile(e[@"descriptor"][@"workspace_path"]),131072,false))return nil;
    for(NSString *arg in argv)if(!wireString(data,arg,131072,true))return nil;
    for(NSString *key in utf8Sorted(env.allKeys))
        if(!wireString(data,[NSString stringWithFormat:@"%@=%@",key,env[key]],131329,false))return nil;
    return data;
}
static bool launchRun(NSMutableDictionary *e,NSDictionary *q,int client) {
    uint64_t commandStarted=nowMS();
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return false;}
    if(!validUIDAllocation(e)||!armUIDStopTicket(e)){closeAdmission(e,@"uid_allocation_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return false;}
    NSArray *argv=q[@"argv"];NSDictionary *env=q[@"env"]?:@{};NSString *cwd=q[@"cwd"]?:@".";
    if(![argv isKindOfClass:NSArray.class]||argv.count<1||argv.count>256||![env isKindOfClass:NSDictionary.class]
        ||env.count>256||!runtimeAllowed(argv[0])||(![cwd isEqual:@"."]&&!validRelative(cwd))
        ||!validDuration(q[@"timeout_ms"],K_MAX_WORK_MS))return false;
    uint64_t commandDeadline=MIN([e[@"work_deadline_ms"] unsignedLongLongValue],commandStarted+[q[@"timeout_ms"] unsignedLongLongValue]);
    if(nowMS()>=commandDeadline){closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return false;}
    for(id arg in argv)if(!safeText(arg,32768))return false;
    NSMutableDictionary *clean=[NSMutableDictionary dictionaryWithDictionary:@{@"PATH":@"/usr/bin:/bin",@"LANG":@"C",@"LC_ALL":@"C"}];
    NSSet *forbidden=[NSSet setWithArray:@[@"DYLD_INSERT_LIBRARIES",@"DYLD_LIBRARY_PATH",@"DYLD_FRAMEWORK_PATH",@"NODE_OPTIONS",@"BASH_ENV",@"ENV"]];
    for(id key in env){if(!environmentKey(key)||!safeText(env[key],32768)||[forbidden containsObject:key]
        ||[key hasPrefix:@"DYLD_"])return false;clean[key]=env[key];}
    NSString *workspace=e[@"descriptor"][@"workspace_path"];
    NSString *scratch=e[@"descriptor"][@"scratch_path"];
    if(![scratch isEqual:[workspace stringByAppendingString:@".scratch"]])return false;
    clean[@"HOME"]=scratch;clean[@"TMPDIR"]=scratch;clean[@"TMP"]=scratch;clean[@"TEMP"]=scratch;
    int lock=admissionFD(e),workspaceFD=openWorkspace(e),scratchFD=openScratch(e),cfg[2]={-1,-1},ready[2]={-1,-1},gate[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1};
    bool ok=lock>=0&&workspaceFD>=0&&scratchFD>=0&&flock(lock,LOCK_EX|LOCK_NB)==0;
    NSData *data=ok?stubConfiguration(e,argv,clean,cwd,commandDeadline,lock,workspaceFD,scratchFD):nil;
    ok=ok&&data&&[protectedFileSHA(gStubPath) isEqual:gStubBinarySHA];
    if(ok)ok=pipe(cfg)==0&&pipe(ready)==0&&pipe(gate)==0&&pipe(out)==0&&pipe(err)==0;
    if(ok&&(workStopped(e)||nowMS()>=commandDeadline)){closeAdmission(e,workStopped(e)?@"daemon_stopping":@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);ok=false;}
    if(ok){
        /* A prior command's dead stub cannot resolve this new launch intent. */
        [e removeObjectForKey:@"launch_stub"];[e removeObjectForKey:@"root_child"];[e removeObjectForKey:@"command_identity"];
        e[@"spawn_intent"]=@YES;e[@"command_ordinal"]=@([e[@"command_ordinal"] unsignedLongLongValue]+1);ok=persist();
    }
    if(ok&&workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);ok=false;}
    posix_spawn_file_actions_t fa;posix_spawnattr_t attr;bool initialized=false;pid_t pid=0;
    if(ok){ok=posix_spawn_file_actions_init(&fa)==0&&posix_spawnattr_init(&attr)==0;initialized=ok;}
    if(ok){int null=open("/dev/null",O_RDONLY|O_CLOEXEC);ok=null>=0;
        int originals[]={null,out[1],err[1],cfg[0],ready[1],gate[0],lock,workspaceFD,scratchFD};
        int targets[]={0,1,2,10,11,12,13,14,15},sources[9];for(unsigned i=0;i<9;i++)sources[i]=-1;
        /* Duplicate sources above EVERY target before adding file actions.
         * Pipe allocation can otherwise collide with another dup2 target. */
        for(unsigned i=0;ok&&i<9;i++){sources[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,32);ok=sources[i]>=0;}
        for(unsigned i=0;ok&&i<9;i++)ok=posix_spawn_file_actions_adddup2(&fa,sources[i],targets[i])==0;
        if(ok)ok=posix_spawnattr_setflags(&attr,POSIX_SPAWN_CLOEXEC_DEFAULT)==0;
        char *args[]={(char *)gStubPath.fileSystemRepresentation,"--internal-child",NULL};
        char *environment[]={"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",NULL};
        if(ok&&(workStopped(e)||nowMS()>=commandDeadline)){closeAdmission(e,workStopped(e)?@"daemon_stopping":@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);ok=false;}
        if(ok)ok=posix_spawn(&pid,gStubPath.fileSystemRepresentation,&fa,&attr,args,environment)==0;
        for(unsigned i=0;i<9;i++)if(sources[i]>=0)close(sources[i]);
        if(null>=0)close(null);
    }
    if(initialized){posix_spawn_file_actions_destroy(&fa);posix_spawnattr_destroy(&attr);}
    /* Close, never LOCK_UN: the spawned stub holds the SAME open description
     * until its all-private credentials are kernel-visible or it exits. */
    if(lock>=0)close(lock);
    if(workspaceFD>=0)close(workspaceFD);
    if(scratchFD>=0)close(scratchFD);
    if(ok){close(cfg[0]);cfg[0]=-1;close(ready[1]);ready[1]=-1;close(gate[0]);gate[0]=-1;
        close(out[1]);out[1]=-1;close(err[1]);err[1]=-1;
        struct KIdentity identity;
        if(freshIdentity(pid,&identity)){e[@"launch_stub"]=identityJSON(&identity);}
        else ok=false;
        uint32_t n=htonl((uint32_t)data.length);NSMutableData *message=[NSMutableData dataWithBytes:&n length:4];[message appendData:data];
        gRunConfig=message;gRunConfigOffset=0;
        gRun=(struct KRun){.pid=pid,.client=client,.out=out[0],.err=err[0],.ready=ready[0],.gate=gate[1],.config=cfg[1],
            .deadline=commandDeadline,.ordinal=[e[@"command_ordinal"] unsignedLongLongValue]};
        gRunCommandSHA=sha(jsonData(@{@"argv":argv,@"env":env,@"cwd":cwd,@"timeout_ms":q[@"timeout_ms"]}));
        int *nonblocking[]={&gRun.out,&gRun.err,&gRun.ready,&gRun.config,&gRun.gate};
        for(unsigned i=0;i<5;i++){
            int flags=fcntl(*nonblocking[i],F_GETFL);
            if(flags<0||fcntl(*nonblocking[i],F_SETFL,flags|O_NONBLOCK)<0){
                close(*nonblocking[i]);*nonblocking[i]=-1;ok=false;
            }
        }
        /* Publish the gated exact birth and live run FDs before ANY durable
         * operation. Stop observer continues across the spawn/publication race.
         * Missing birth retains unresolved intent; never substitute PID kill. */
        publishState();
        if(ok)ok=persist();
        /* A stop after spawn must retain the exact child and gate bookkeeping.
         * Never take the no-child false tail after posix_spawn succeeded. */
        if(!ok||workStopped(e))closeAdmission(e,workStopped(e)?@"daemon_stopping":@"launch_publication_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return true; /* accepted transport, even when launch must be stopped */
    }
    int *fds[]={cfg,ready,gate,out,err};for(unsigned i=0;i<5;i++)for(unsigned j=0;j<2;j++)if(fds[i][j]>=0)close(fds[i][j]);
    /* Only this still-live daemon knows no process was spawned on a failed
     * posix_spawn. A restart never guesses that from a missing child ledger. */
    e[@"spawn_intent"]=@NO;persist();return false;
}

static NSDictionary *prepare(NSDictionary *q,struct KPeer *peer) {
    uint64_t started=nowMS();
    if(workStopped(nil))return failure(@"DAEMON_STOPPING");
    if(!gCapabilityQualified&&!gQualificationMode)return failure(@"CAPABILITY_UNQUALIFIED");
    if(!gEntryStoreLoaded||gPoisoned)return failure(@"REGISTRY_DURABILITY_UNCONFIRMED");
    if(peer->owner==0||peer->owner>=K_UID_FIRST)return failure(@"ORDINARY_OWNER_REQUIRED");
    if(!refreshAccountPolicy())return failure(@"ACCOUNT_POLICY_UNCONFIRMED");
    if(workStopped(nil))return failure(@"DAEMON_STOPPING");
    if(!gAccountPolicy[@"owners"][[NSString stringWithFormat:@"%u",peer->owner]])return failure(@"OWNER_NOT_CONFIGURED");
    if(![q[@"mode"] isEqual:@"isolated_copy"]||!hex64(q[@"attempt_nonce"]))return failure(@"INVALID_PREPARE");
    if(!validDuration(q[@"work_budget_ms"],K_MAX_WORK_MS))return failure(@"INVALID_WORK_BUDGET");
    if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))return failure(@"INVALID_CLEANUP_BUDGET");
    uint64_t budget=[q[@"work_budget_ms"] unsignedLongLongValue],deadline=started+budget;
    if(!refreshUIDHistory())return failure(@"UID_HISTORY_UNHEALTHY");
    if(workStopped(nil))return failure(@"DAEMON_STOPPING");
    if(nowMS()>=deadline)return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");
    bool ambiguous=false;NSMutableDictionary *prior=reservationForNonce(peer->owner,q[@"attempt_nonce"],&ambiguous);
    if(ambiguous)return failure(@"ATTEMPT_NONCE_AMBIGUOUS");
    if(prior)return @{ @"ok":@NO,@"schema":K_SCHEMA,@"error":@"ATTEMPT_ALREADY_RESERVED",
        @"attempt_id":prior[@"descriptor"][@"attempt_id"],@"descriptor":prior[@"descriptor"],
        @"descriptor_sha256":prior[@"descriptor_sha256"],@"state":prior[@"state"] };
    NSString *active=activeID();if(active.length)return failure(@"ATTEMPT_ACTIVE");
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));if(!pids)return failure(@"ALLOCATION_FAILED");
    uid_t uid=0;NSString *id=randomHex();NSDictionary *allocation=nil;
    for(unsigned i=0;i<1000&&nowMS()<deadline;i++){
        if(workStopped(nil))break;
        NSDictionary *candidate=[gUIDHistory consumeUIDForPlannedAttempt:id boot:gBoot.lowercaseString error:NULL];
        if(!candidate)break;
        /* Burn journal -> independent head -> actual registry, then confirm
         * before even inspecting this candidate. Never reuse failed candidates. */
        gRegistry[@"uid_history_checkpoint"]=gUIDHistory.checkpoint;
        if(!persist()||![gUIDHistory confirmRegistryCheckpointWithError:NULL]||workStopped(nil)||nowMS()>=deadline)break;
        uid_t next=[candidate[@"uid"] unsignedIntValue];int count=members(next,pids);
        if(count<0)break;if(count>0)continue;if(nowMS()>=deadline)break;
        /* Explicit install policy supplies account-range exclusion. Runtime
         * NSS absence never reserved this UID; kernel membership still must. */
        if(nowMS()>=deadline)break;uid=next;allocation=candidate;break;}
    free(pids);
    /* Consumed UID history remains burned even if stop interrupts prepare.
     * No new reservation/private inode is published from that stopped work. */
    if(workStopped(nil))return failure(@"DAEMON_STOPPING");
    if(nowMS()>=deadline)return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");
    if(!uid||gPoisoned||!gUIDHistory.healthy||!allocation)return failure(@"UID_RESERVATION_UNAVAILABLE");
    NSString *token=randomHex();
    NSString *workspacePath=pathChild(gWorkspaceRoot,id);
    NSDictionary *descriptor=@{@"schema":@"knowledge-darwin-private-ruid-descriptor.v2",@"backend":@"darwin_private_ruid",@"daemon_epoch":gDaemonEpoch,@"guardian_protocol":@"KVR2",
        @"boundary_id":id,@"attempt_id":id,@"attempt_nonce":q[@"attempt_nonce"],@"task_ruid":@(uid),@"task_gid":@(uid),
        @"owner_uid":@(peer->owner),@"host_id":gHost,@"boot_id":gBoot,@"mode":@"isolated_copy",
        @"installation_id":allocation[@"installation_id"],@"allocation_seq":allocation[@"seq"],@"allocation_sha256":allocation[@"sha256"],
        @"account_policy_id":K_ACCOUNT_POLICY,@"account_policy_sha256":gAccountPolicySHA,
        @"uid_history_header_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA,
        @"uid_history_source_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA,
        @"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
        @"work_budget_ms":@(budget),@"cleanup_budget_ms":q[@"cleanup_budget_ms"],
        @"work_started_monotonic_ms":@(started),@"work_deadline_ms":@(deadline),
        @"workspace_path":workspacePath,@"scratch_path":[workspacePath stringByAppendingString:@".scratch"],
        @"scratch_policy":@"private_uid_sibling.v1",@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"broker_binary_sha256":gBinarySHA,@"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,
        @"stub_binary_sha256":gStubBinarySHA,@"stub_wire_version":@"KVS2",
        @"allowed_runtimes":gRuntimePins,@"profile_sha256":sha([sandboxProfile(workspacePath) dataUsingEncoding:NSUTF8StringEncoding]),
        @"broker_creation_parent_is_launchd":@(gLaunchdCreationParent),
        @"capability_qualified":@(gCapabilityQualified),@"qualification_mode":@(gQualificationMode),
        @"scope":@"never_reused_private_ruid_with_root_guardian_and_exact_authority;controller_and_daemon_excluded"};
    NSMutableDictionary *e=[@{@"descriptor":descriptor,@"descriptor_sha256":sha(jsonData(descriptor)),@"owner_uid":@(peer->owner),
        @"token_sha256":sha([token dataUsingEncoding:NSUTF8StringEncoding]),@"controller":identityJSON(&peer->parent),@"state":@"reserved",
        @"admission_closed":@NO,@"abort_latched":@NO,@"planned_terminal":@NO,
        @"spawn_intent":@NO,@"authority_spawn_intent":@NO,@"files":@0,@"bytes":@0,
        @"manifest":[NSMutableDictionary dictionary],@"directories":[NSMutableDictionary dictionary],
        @"work_started_monotonic_ms":@(started),@"work_budget_ms":@(budget),
        @"work_deadline_ms":@(deadline),@"cleanup_budget_ms":q[@"cleanup_budget_ms"]} mutableCopy];
    if(workStopped(nil))return failure(@"DAEMON_STOPPING");
    entries()[id]=e;gRegistry[@"active_attempt"]=id;
    /* Reservation and immutable descriptor are fsync/readback BEFORE any
     * private-owned inode, admission lock, stub, or command can exist. */
    if(!persist())return failure(@"RESERVATION_DURABILITY_FAILED");
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    if(!validUIDAllocation(e)||!armUIDStopTicket(e)||nowMS()>=deadline){closeAdmission(e,@"reservation_history_or_budget_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return failure(@"RESERVATION_HISTORY_OR_BUDGET_UNCONFIRMED");}
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    NSString *lockName=[id stringByAppendingString:@".admission"];
    int lock=openat(gRegistryFD,lockName.UTF8String,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat admission;bool ok=lock>=0&&fstat(lock,&admission)==0&&fsync(lock)==0&&fsync(gRegistryFD)==0;
    if(ok){e[@"admission_inode"]=@{@"device":@((uint64_t)admission.st_dev),@"inode":@((uint64_t)admission.st_ino)};ok=persist();}
    if(lock>=0)close(lock);
    /* Preserve already-created inode identity and close local FDs before
     * stopping. An incomplete admission boundary stays unconfirmed. */
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    /* Admission sync/readback consumes the original work clock too. Never
     * create a private inode after that slow I/O has exhausted the lease. */
    if(nowMS()>=deadline){closeAdmission(e,@"work_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");}
    if(ok)ok=mkdirat(gWorkspaceFD,id.UTF8String,0700)==0;
    int workspace=ok?openat(gWorkspaceFD,id.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):-1;
    if(workspace<0)ok=false;
    struct stat workspaceStat;
    if(ok)ok=fchown(workspace,uid,uid)==0&&fchmod(workspace,0700)==0&&ownerReadACL(workspace,peer->owner,true)
        &&fstat(workspace,&workspaceStat)==0&&fsync(workspace)==0&&fsync(gWorkspaceFD)==0;
    if(ok){e[@"workspace_inode"]=@{@"device":@((uint64_t)workspaceStat.st_dev),@"inode":@((uint64_t)workspaceStat.st_ino)};ok=persist();}
    if(workspace>=0)close(workspace);
    /* Temporary output is a different private inode, never part of the sealed
     * source manifest. Create it before any permit and bind its FD in the stub.
     * Cleanup proves process closure independently of later disk removal. */
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    if(nowMS()>=deadline){closeAdmission(e,@"work_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");}
    NSString *scratchName=[id stringByAppendingString:@".scratch"];
    if(ok)ok=mkdirat(gWorkspaceFD,scratchName.UTF8String,0700)==0;
    int scratch=ok?openat(gWorkspaceFD,scratchName.UTF8String,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):-1;
    if(scratch<0)ok=false;struct stat scratchStat;acl_t privateACL=ok?acl_init(0):NULL;
    if(ok)ok=privateACL&&acl_set_fd_np(scratch,privateACL,ACL_TYPE_EXTENDED)==0
        &&fchown(scratch,uid,uid)==0&&fchmod(scratch,0700)==0&&fstat(scratch,&scratchStat)==0
        &&fsync(scratch)==0&&fsync(gWorkspaceFD)==0;
    if(privateACL)acl_free(privateACL);
    if(ok){e[@"scratch_inode"]=@{@"device":@((uint64_t)scratchStat.st_dev),@"inode":@((uint64_t)scratchStat.st_ino)};ok=persist();}
    if(scratch>=0)close(scratch);
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    if(!ok){closeAdmission(e,@"workspace_preparation_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"WORKSPACE_PREPARATION_FAILED");}
    e[@"state"]=@"copying";if(!persist())return failure(@"PREPARATION_DURABILITY_FAILED");
    if(workStopped(e)){closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"DAEMON_STOPPING");}
    if(nowMS()>=deadline){closeAdmission(e,@"work_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");}
    return @{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":id,@"descriptor":descriptor,@"descriptor_sha256":e[@"descriptor_sha256"],
        @"workspace_path":descriptor[@"workspace_path"],@"token":token,@"capability":gCapabilityQualified?@"qualified":@"unqualified"};
}

static bool terminalBeforeCurrentBoot(NSMutableDictionary *e) {
    if(![e[@"state"] isEqual:@"closed"]||sameBootID(e[@"descriptor"][@"boot_id"],gBoot))return false;
    NSDictionary *r=e[@"reboot_cleanup"],*p=e[@"proof"],*d=e[@"descriptor"];
    if(r)return validRebootCleanup(e)&&[r[@"state"] isEqual:@"closed"]&&!sameBootID(r[@"boot_id"],gBoot);
    return [e[@"admission_closed"] boolValue]&&![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue]
        &&[p isKindOfClass:NSDictionary.class]&&[p[@"schema"] isEqual:@"knowledge-darwin-private-ruid-proof.v1"]
        &&[p[@"descriptor_sha256"] isEqual:e[@"descriptor_sha256"]]&&[p[@"attempt_id"] isEqual:d[@"attempt_id"]]
        &&[p[@"installation_id"] isEqual:d[@"installation_id"]]&&[p[@"allocation_sha256"] isEqual:d[@"allocation_sha256"]]
        &&[p[@"host_id"] isEqual:d[@"host_id"]]&&sameBootID(p[@"boot_id"],d[@"boot_id"])
        &&[e[@"receipt_sha256"] isEqual:sha(jsonData(p))]
        &&booleanField(p[@"native_cleanup_facts_confirmed"])&&[p[@"native_cleanup_facts_confirmed"] boolValue]
        &&booleanField(p[@"admission_closed"])&&[p[@"admission_closed"] boolValue]
        &&booleanField(p[@"spawn_intents_resolved"])&&[p[@"spawn_intents_resolved"] boolValue];
}
static NSDictionary *observeScope(NSMutableDictionary *e,NSDictionary *q) {
    if(!hex64(q[@"observation_nonce"]))return failure(@"INVALID_SCOPE_OBSERVATION_NONCE");
    NSDictionary *d=e[@"descriptor"],*recovery=e[@"reboot_cleanup"];
    bool reboot=currentRebootCleanup(e)&&[recovery[@"state"] isEqual:@"closed"];
    bool priorClosed=terminalBeforeCurrentBoot(e),newBoot=reboot||priorClosed;
    bool sameBoot=sameBootID(d[@"boot_id"],gBoot),scope=(sameBoot||newBoot)&&[d[@"host_id"] isEqual:gHost];
    bool tuple=scope&&validUIDAllocation(e),bootCurrent=kernelBootCurrent();
    bool closed=[e[@"state"] isEqual:@"closed"]&&([e[@"admission_closed"] boolValue]||newBoot);
    bool active=[activeID() isEqual:d[@"attempt_id"]]||gClosing==e||gRebootClosing==e;
    bool intents=newBoot||(![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue]);
    bool guardianGone=newBoot||!e[@"launch_stub"],childGone=newBoot||!e[@"root_child"],authorityGone=newBoot||!e[@"authority"];
    bool identitiesKnown=true;struct KIdentity observedIdentity;
    if(sameBoot){
        if(e[@"launch_stub"]){int rc=observeExact(e[@"launch_stub"],&observedIdentity);guardianGone=rc==0;identitiesKnown=identitiesKnown&&rc>=0;}
        if(e[@"root_child"]){int rc=observeExact(e[@"root_child"],&observedIdentity);childGone=rc==0;identitiesKnown=identitiesKnown&&rc>=0;}
        if(e[@"authority"]){int rc=observeExact(e[@"authority"],&observedIdentity);authorityGone=rc==0;identitiesKnown=identitiesKnown&&rc>=0;}
    }else if(!newBoot)identitiesKnown=false;
    int lock=-1;bool excluded=false;
    if(tuple&&closed&&!active){
        if(e[@"admission_inode"]){lock=admissionFD(e);excluded=lock>=0&&flock(lock,LOCK_EX|LOCK_NB)==0;}
        else if(newBoot){struct stat absent;NSString *name=[d[@"attempt_id"] stringByAppendingString:@".admission"];errno=0;
            excluded=![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue]
                &&!e[@"launch_stub"]&&!e[@"authority"]&&fstatat(gRegistryFD,name.UTF8String,&absent,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;}
    }
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));int count=tuple&&pids?members([d[@"task_ruid"] unsignedIntValue],pids):-1;free(pids);
    uint64_t observed=nowMS();bool clockHealthy=!atomic_load(&gClockFailed);
    bool complete=scope&&tuple&&bootCurrent&&closed&&!active&&intents&&excluded&&count==0
        &&identitiesKnown&&guardianGone&&childGone&&authorityGone&&!gPoisoned&&clockHealthy;
    NSString *status=complete?@"completed":scope&&tuple&&(active||count>0||!guardianGone||!childGone||!authorityGone)?@"active":@"unconfirmed";
    NSDictionary *result=@{@"ok":@YES,@"schema":@"knowledge-darwin-scope-observation.v1",
        @"status":status,@"observation_nonce":q[@"observation_nonce"],@"attempt_id":d[@"attempt_id"],@"descriptor_sha256":e[@"descriptor_sha256"],
        @"host_id":gHost,@"boot_id":gBoot,@"daemon_epoch":gDaemonEpoch,
        @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"binary_sha256":gBinarySHA,
        @"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,@"stub_binary_sha256":gStubBinarySHA,
        @"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
        @"uid_history_header_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA,@"uid_history_source_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA,
        @"installation_id":d[@"installation_id"],@"allocation_seq":d[@"allocation_seq"],@"allocation_sha256":d[@"allocation_sha256"],
        @"account_policy_id":d[@"account_policy_id"],@"account_policy_sha256":d[@"account_policy_sha256"],@"task_ruid":d[@"task_ruid"],
        @"state":closed?@"closed":e[@"state"],@"active_attempt":@(active),@"admission_closed":@((bool)([e[@"admission_closed"] boolValue]||newBoot)),
        @"spawn_exclusion_acquired":@(excluded),@"spawn_intents_resolved":@(intents),@"kernel_membership_zero":@(count==0),
        @"guardian_exit_confirmed":@(guardianGone),@"root_child_exit_confirmed":@(childGone),@"registered_authority_exited":@(authorityGone),
        @"authority_identity":e[@"authority"]?:NSNull.null,
        @"native_scope_closed":@(complete),@"registry_healthy":@((bool)!gPoisoned),@"allocation_tuple_verified_current":@(tuple),
        @"cleanup_observation_current":@((bool)(scope&&tuple&&bootCurrent)),@"observation_cached":@NO,
        @"cleanup_only":@YES,@"proof_current":@NO,@"clock_healthy":@(clockHealthy),@"observed_monotonic_ms":@(observed),
        @"lifecycle_basis":reboot?@"reboot_cleanup_epoch":priorClosed?@"historical_terminal_precedes_new_boot":@"same_boot_terminal",
        @"historical_terminal_before_new_boot":@(priorClosed),
        @"reboot_recovery_confirmed":@(reboot),@"recovery_epoch":reboot?recovery[@"recovery_epoch"]:NSNull.null,
        @"recovery_started_monotonic_ms":reboot?recovery[@"cleanup_started_monotonic_ms"]:NSNull.null,
        @"recovery_deadline_monotonic_ms":reboot?recovery[@"cleanup_deadline_monotonic_ms"]:NSNull.null,
        @"recovery_observed_monotonic_ms":reboot?recovery[@"observed_monotonic_ms"]:NSNull.null,
        @"capability_qualified":@(gCapabilityQualified),@"qualification_mode":@(gQualificationMode),
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
        @"qa_persistence_gate":@YES
#else
        @"qa_persistence_gate":@NO
#endif
    };
    if(lock>=0)close(lock);return result;
}
static NSDictionary *statusReply(NSMutableDictionary *e) {
    refreshAccountPolicy();
    bool currentScope=(sameBootID(e[@"descriptor"][@"boot_id"],gBoot)||currentRebootCleanup(e))&&[e[@"descriptor"][@"host_id"] isEqual:gHost];
    struct KObservation observation=observationCopy();
    bool currentProof=currentScope&&currentEntry(e)&&observation.valid
        &&[e[@"descriptor"][@"attempt_id"] isEqual:@(observation.attempt)]
        &&([activeID() isEqual:e[@"descriptor"][@"attempt_id"]]||gClosing==e);
    bool allocationVerified=currentScope&&validUIDAllocation(e);
    NSMutableDictionary *r=[@{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor":e[@"descriptor"],@"descriptor_sha256":e[@"descriptor_sha256"],@"state":e[@"state"],
        @"admission_closed":e[@"admission_closed"],@"spawn_intent":e[@"spawn_intent"],
        @"authority_spawn_intent":e[@"authority_spawn_intent"],@"capability_qualified":@(gCapabilityQualified),
        @"work_budget_ms":e[@"work_budget_ms"]?:NSNull.null,@"cleanup_budget_ms":e[@"cleanup_budget_ms"],
        @"work_started_monotonic_ms":e[@"work_started_monotonic_ms"]?:NSNull.null,
        @"work_deadline_monotonic_ms":e[@"work_deadline_ms"],
        @"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"]?:NSNull.null,
        @"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"]?:NSNull.null,
        @"cleanup_budget_exceeded":e[@"cleanup_budget_exceeded"]?:@NO,
        @"stop_reason":e[@"stop_reason"]?:NSNull.null,@"abort_latched":@((bool)abortedAttempt(e)),
        @"planned_terminal":@((bool)plannedAttempt(e)),@"registry_healthy":@((bool)!gPoisoned),
        @"registry_quarantine_reason":gQuarantineReason?:NSNull.null,
        @"entry_store_loaded":@(gEntryStoreLoaded),@"uid_history":uidHistoryStatus(false),@"account_policy":accountPolicyStatus(),
        @"allocation_tuple_verified_current":@(allocationVerified),@"stop_latched":@((bool)(gStopping||stoppedAttempt(e))),
        @"daemon_epoch":gDaemonEpoch,@"writer_generation":@(observation.generation),@"proof_current":@(currentProof),
        @"cleanup_only":@((bool)(!currentEntry(e)||[e[@"recovery_only"] boolValue])),
        @"cleanup_observation_current":@((bool)(currentScope&&allocationVerified&&gClosing==e&&observation.valid
            &&[e[@"descriptor"][@"attempt_id"] isEqual:@(observation.attempt)])),
        @"sandbox_profile":sandboxProfile(e[@"descriptor"][@"workspace_path"])} mutableCopy];
    if(e[@"proof"]){r[@"proof"]=e[@"proof"];if(e[@"receipt_sha256"])r[@"proof_sha256"]=e[@"receipt_sha256"];}
    if(e[@"command_drain_proof"]&&!abortedAttempt(e)&&!stoppedAttempt(e)){
        r[@"command_drain_proof"]=e[@"command_drain_proof"];
        if(e[@"command_drain_sha256"])r[@"command_drain_sha256"]=e[@"command_drain_sha256"];}
    if(!currentProof){r[@"observation_current_scope"]=@NO;r[@"proof_current"]=@NO;
        r[@"planned_terminal"]=@NO;
        if(![r[@"cleanup_observation_current"] boolValue])[r removeObjectForKey:@"proof_sha256"];
        [r removeObjectForKey:@"command_drain_sha256"];}
    if(e[@"reboot_cleanup"]){r[@"reboot_cleanup"]=e[@"reboot_cleanup"];r[@"cleanup_only"]=@YES;r[@"proof_current"]=@NO;
        r[@"planned_terminal"]=@NO;r[@"admission_closed"]=@YES;r[@"original_work_revoked"]=@YES;
        r[@"cleanup_observation_current"]=@((bool)(currentRebootCleanup(e)&&allocationVerified));
        [r removeObjectForKey:@"proof_sha256"];[r removeObjectForKey:@"command_drain_sha256"];}
    return r;
}
static void latchQueuedClose(struct KPeer peer,NSDictionary *q) {
    if(![@[@"close",@"recover"] containsObject:q[@"op"]]||!requestTypes(q)
        ||![q[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA]
        ||!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))return;
    pthread_mutex_lock(&gCacheMutex);NSDictionary *entry=gCachedEntry,*cached=gCachedStatus;pthread_mutex_unlock(&gCacheMutex);
    bool bound=entry&&peer.owner==[entry[@"owner_uid"] unsignedIntValue]
        &&[q[@"attempt_id"] isEqual:entry[@"attempt_id"]]&&hex64(q[@"descriptor_sha256"])
        &&equalSecret(q[@"descriptor_sha256"],entry[@"descriptor_sha256"]);
    bool role=bound&&(sameBirth(entry[@"controller"],&peer.parent)
        ||([entry[@"authority"] isKindOfClass:NSDictionary.class]&&sameBirth(entry[@"authority"],&peer.parent)));
    if(role){struct KObservation v=observationCopy();
        if(v.valid&&[entry[@"attempt_id"] isEqual:@(v.attempt)]&&v.generation==[cached[@"writer_generation"] unsignedLongLongValue]){
            struct KIdentity authority;
            bool planned=[q[@"op"] isEqual:@"close"]&&sameBirth(entry[@"controller"],&peer.parent)
                &&[cached[@"state"] isEqual:@"commands_drained"]&&v.authority.present
                &&observeBirth(v.authority,&authority)==1;
            latchGenerationMode(v.generation,[q[@"cleanup_budget_ms"] unsignedLongLongValue],planned,false);
        }}
}
static bool fastRequest(int token,struct KPeer peer,NSDictionary *q) {
    NSString *op=q[@"op"];if(![op isEqual:@"observe"]&&![op isEqual:@"stop"])return false;
    NSDictionary *reply=nil;
    if(!requestTypes(q)||![q[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA])reply=failure(@"PROTOCOL_OR_SOURCE_PIN_MISMATCH");
    else{
        pthread_mutex_lock(&gCacheMutex);NSDictionary *entry=gCachedEntry,*cached=gCachedStatus;pthread_mutex_unlock(&gCacheMutex);
        struct KObservation v=observationCopy();
        bool bound=entry&&hex64(q[@"attempt_id"])&&[q[@"attempt_id"] isEqual:entry[@"attempt_id"]]
            &&peer.owner==[entry[@"owner_uid"] unsignedIntValue]&&hex64(q[@"descriptor_sha256"])
            &&equalSecret(q[@"descriptor_sha256"],entry[@"descriptor_sha256"]);
        if([op isEqual:@"observe"]&&!q[@"attempt_id"]){
            reply=@{@"ok":@YES,@"schema":K_SCHEMA,@"state":cached?@"active_cached":@"initializing_or_idle",
                @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"observation_cached":@YES,
                @"durability_pending":@(atomic_load_explicit(&gWriterPending,memory_order_acquire)),
                @"allocation_tuple_verified_current":@NO,@"cleanup_confirmed":@NO,@"resources_free":@NO,
                @"capability_qualified":@(gCapabilityQualified)};
        }else if(!bound)reply=failure(@"OBSERVATION_UNAVAILABLE_OR_ATTEMPT_AUTHENTICATION_FAILED");
        else{
            NSMutableDictionary *r=[cached mutableCopy];
            r[@"durability_pending"]=@(atomic_load_explicit(&gWriterPending,memory_order_acquire));
            r[@"abort_latched"]=@((bool)(gStopping||v.abort_latched));
            r[@"planned_terminal"]=@((bool)(v.planned_terminal&&!v.abort_latched&&!gStopping));
            r[@"stop_latched"]=@((bool)(v.valid&&[q[@"attempt_id"] isEqual:@(v.attempt)]
                &&atomic_load_explicit(&gStopGeneration,memory_order_acquire)==v.generation));
            if([op isEqual:@"stop"]){
                bool role=sameBirth(entry[@"controller"],&peer.parent)
                    ||([entry[@"authority"] isKindOfClass:NSDictionary.class]&&sameBirth(entry[@"authority"],&peer.parent));
                bool capability=hex64(q[@"token"])&&equalSecret(entry[@"token_sha256"],sha([q[@"token"] dataUsingEncoding:NSUTF8StringEncoding]));
                bool generation=v.valid&&[q[@"attempt_id"] isEqual:@(v.attempt)]
                    &&[cached[@"writer_generation"] unsignedLongLongValue]==v.generation;
                if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))reply=failure(@"INVALID_CLEANUP_BUDGET");
                else if(!role&&!capability)reply=failure(@"STOP_ROLE_OR_CAPABILITY_AUTHENTICATION_FAILED");
                else if(!generation||!latchGeneration(v.generation,[q[@"cleanup_budget_ms"] unsignedLongLongValue]))reply=failure(@"STOP_GENERATION_NOT_CURRENT");
                else{r[@"stop_latched"]=@YES;r[@"abort_latched"]=@YES;r[@"planned_terminal"]=@NO;r[@"state"]=@"cleanup_pending";r[@"admission_closed"]=@YES;
                    r[@"terminal_cleanup"]=@NO;r[@"writer_pending"]=r[@"durability_pending"];reply=r;}
            }else reply=r;
        }
    }
    sendJSON(token,reply);finishTransport(token);return true;
}
static NSDictionary *identityObservation(struct KPeer peer,NSDictionary *q) {
    if(!hex64(q[@"observation_nonce"])||!kernelBootCurrent())return failure(@"IDENTITY_OBSERVATION_UNCONFIRMED");
    NSMutableDictionary *reply=[@{@"ok":@YES,@"schema":@"knowledge-darwin-identity-observation.v1",
        @"observation_nonce":q[@"observation_nonce"],@"host_id":gHost,@"boot_id":gBoot,@"daemon_epoch":gDaemonEpoch,
        @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"binary_sha256":gBinarySHA,
        @"capability_qualified":@(gCapabilityQualified),@"qualification_mode":@(gQualificationMode),
        @"proof_current":@NO,@"cleanup_only":@YES,@"observed_monotonic_ms":@(nowMS()),
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
        @"qa_persistence_gate":@YES
#else
        @"qa_persistence_gate":@NO
#endif
    } mutableCopy];
    if([q[@"op"] isEqual:@"peer_identity"]){
        struct KIdentity current;
        if(observeExact(identityJSON(&peer.parent),&current)!=1||current.bsd.pbi_ruid!=peer.owner
            ||current.bsd.pbi_uid!=peer.owner||current.bsd.pbi_svuid!=peer.owner)return failure(@"PEER_PARENT_IDENTITY_UNCONFIRMED");
        reply[@"identity"]=@{@"schema":@"knowledge-darwin-process-identity.v1",@"host_id":gHost,@"boot_id":gBoot,
            @"owner_uid":@(peer.owner),@"birth":identityJSON(&current)};reply[@"status"]=@"active";
    }else{
        NSDictionary *identity=q[@"identity"];
        if(![identity isKindOfClass:NSDictionary.class])return failure(@"IDENTITY_BINDING_INVALID");
        NSDictionary *birth=identity[@"birth"];
        if(identity.count!=5||![identity[@"schema"] isEqual:@"knowledge-darwin-process-identity.v1"]
            ||![identity[@"host_id"] isEqual:gHost]||!validBootID(identity[@"boot_id"])
            ||!numericField(identity[@"owner_uid"])||[identity[@"owner_uid"] unsignedIntValue]!=peer.owner
            ||!validRecordedIdentity(birth)||[birth[@"ruid"] unsignedIntValue]!=peer.owner
            ||[birth[@"start_usec"] unsignedLongLongValue]>=1000000||[birth[@"pidversion"] unsignedLongLongValue]==0)
            return failure(@"IDENTITY_BINDING_INVALID");
        int state=-1;NSString *basis=@"kernel_observation_unconfirmed";
        if(!sameBootID(identity[@"boot_id"],gBoot)){state=0;basis=@"new_kernel_boot";}
        else{struct KIdentity live;state=observeExact(birth,&live);
            basis=state==0?@"exact_birth_absent_or_replaced":state==1?@"same_kernel_birth":basis;}
        reply[@"identity_sha256"]=sha(jsonData(identity));reply[@"status"]=state==0?@"exited":state==1?@"active":@"unconfirmed";
        reply[@"observation_basis"]=basis;
    }
    if(atomic_load(&gClockFailed)||!kernelBootCurrent())return failure(@"IDENTITY_OBSERVATION_UNCONFIRMED");
    return reply;
}
static void handleClient(int fd,struct KPeer peer,NSDictionary *q) {
    NSString *op=q[@"op"];NSDictionary *reply=nil;
    bool stopOrReadOperation=isString(op,64)&&[@[@"probe",@"status",@"lookup",@"close",@"recover",@"observe_scope",@"peer_identity",@"observe_identity"] containsObject:op];
    if(!q||!isString(op,64)||!requestTypes(q)||![q[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA])reply=failure(@"PROTOCOL_OR_SOURCE_PIN_MISMATCH");
    else if(gStopping&&!stopOrReadOperation)reply=failure(@"DAEMON_STOPPING");
    else if([op isEqual:@"peer_identity"]||[op isEqual:@"observe_identity"])reply=identityObservation(peer,q);
    else if([op isEqual:@"probe"]){
        /* Refresh before constructing literals: cached registry/history health
         * must describe the same observation as the policy status. */
        NSDictionary *history=uidHistoryStatus(true);refreshAccountPolicy();
        reply=@{@"ok":@YES,@"schema":K_SCHEMA,@"capability_qualified":@(gCapabilityQualified),
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
        @"qa_persistence_gate":@YES,@"qa_build_id":@KNOWLEDGE_DARWIN_QA_BUILD_ID,
#else
        @"qa_persistence_gate":@NO,@"qa_build_id":NSNull.null,
#endif
        @"qualification_mode":@(gQualificationMode),@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"binary_sha256":gBinarySHA,
        @"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
        @"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,@"stub_binary_sha256":gStubBinarySHA,@"stub_wire_version":@"KVS2",
        @"host_id":gHost,@"boot_id":gBoot,@"daemon_epoch":gDaemonEpoch,@"guardian_protocol":@"KVR2",
        @"allowed_runtimes":gRuntimePins,@"registry_healthy":@((bool)!gPoisoned),
        @"registry_quarantine_reason":gQuarantineReason?:NSNull.null,
        @"entry_store_loaded":@(gEntryStoreLoaded),@"uid_history":history,@"account_policy":accountPolicyStatus()};}
    /* A failed write forbids new work, not an authenticated best-effort stop
     * of a known owned reservation or read-only status. Unknown ownership
     * remains quarantined and never gains signal authority through recovery. */
    else if(gPoisoned&&![@[@"status",@"lookup",@"close",@"recover",@"observe_scope"] containsObject:op])reply=failure(gQuarantineReason?:@"REGISTRY_DURABILITY_UNCONFIRMED");
    else if(![@[@"prepare",@"status",@"lookup",@"close",@"recover",@"observe_scope"] containsObject:op]&&!gUIDHistory.healthy)reply=failure(@"UID_HISTORY_UNHEALTHY");
    else if([op isEqual:@"prepare"])reply=prepare(q,&peer);
    else if([op isEqual:@"lookup"]){bool ambiguous=false;NSMutableDictionary *found=nil;
        if(hex64(q[@"attempt_nonce"]))found=reservationForNonce(peer.owner,q[@"attempt_nonce"],&ambiguous);
        reply=ambiguous?failure(@"ATTEMPT_NONCE_AMBIGUOUS"):found?statusReply(found):failure(@"RESERVATION_UNKNOWN");
    }else{NSMutableDictionary *e=hex64(q[@"attempt_id"])?entryFor(q[@"attempt_id"]):nil;
        bool publicOperation=[@[@"status",@"close",@"recover",@"observe_scope"] containsObject:op];
        if(!authenticatedEntry(e,q,&peer,!publicOperation))reply=failure(@"ATTEMPT_AUTHENTICATION_FAILED");
        else if(publicOperation){
            if([op isEqual:@"observe_scope"])reply=observeScope(e,q);
            else if([op isEqual:@"status"]||([e[@"state"] isEqual:@"closed"]&&![op isEqual:@"recover"]))reply=statusReply(e);
            else if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))reply=failure(@"INVALID_CLEANUP_BUDGET");
            else if(!sameBootID(e[@"descriptor"][@"boot_id"],gBoot)){
                if(gCloseWaiter>=0)reply=failure(@"CLEANUP_BUSY");
                else if(currentRebootCleanup(e)&&[e[@"reboot_cleanup"][@"state"] isEqual:@"closed"])reply=statusReply(e);
                else if(beginRebootCleanup(e,[q[@"cleanup_budget_ms"] unsignedLongLongValue])){gCloseWaiter=fd;return;}
                else reply=failure(@"REBOOT_RECOVERY_UNCONFIRMED");
            }
            else if([op isEqual:@"recover"]&&[e[@"state"] isEqual:@"closed"]){
                /* A stored receipt is history after restart/retirement. An
                 * explicit recovery reobserves the original boundary, keeping
                 * its original stop deadline and never admitting work. */
                if(activeID().length&&![activeID() isEqual:q[@"attempt_id"]])reply=failure(@"RECOVERY_OTHER_ATTEMPT_ACTIVE");
                else{e[@"recovery_only"]=@YES;e[@"abort_latched"]=@YES;e[@"planned_terminal"]=@NO;
                    gRegistry[@"active_attempt"]=q[@"attempt_id"];publishState();
                    if(validUIDAllocation(e))armUIDStopTicket(e);
                    if(closeAdmission(e,@"recovery_requested",[q[@"cleanup_budget_ms"] unsignedLongLongValue])){gCloseWaiter=fd;return;}
                    else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");}
            }
            else if(gCloseWaiter>=0&&gDrainOnly){
                /* A waiting drain reply cannot block explicit terminal stop.
                 * Reject that phase's waiter, then bind the bounded terminal
                 * reply to this caller. No second waiter list or new epoch. */
                int interrupted=gCloseWaiter;gCloseWaiter=-1;
                bool durable=closeAdmission(e,[op isEqual:@"recover"]?@"recovery_during_command_drain":@"terminal_stop_during_command_drain",
                    [q[@"cleanup_budget_ms"] unsignedLongLongValue]);
                sendJSON(interrupted,failure(@"COMMAND_DRAIN_INTERRUPTED_BY_TERMINAL_STOP"));finishTransport(interrupted);
                if(durable){gCloseWaiter=fd;return;}else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
            }else if(gCloseWaiter>=0)reply=failure(@"CLEANUP_BUSY");
            else if(closeAdmission(e,[op isEqual:@"recover"]?@"recovery_requested":@"close_requested",[q[@"cleanup_budget_ms"] unsignedLongLongValue])){
                gCloseWaiter=fd;return;
            }else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
        }else if([op isEqual:@"readback_copy"]){
            reply=readbackCopy(e,&peer);
        }else if(![op isEqual:@"run"]&&!validUIDAllocation(e)){
            closeAdmission(e,@"uid_allocation_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);reply=failure(@"UID_HISTORY_OR_ALLOCATION_UNCONFIRMED");
        }else if(workStopped(e)){
            closeAdmission(e,@"daemon_stopping",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);reply=failure(@"DAEMON_STOPPING");
        }else if([e[@"admission_closed"] boolValue])reply=failure(@"ADMISSION_CLOSED");
        else if(nowMS()>=[e[@"work_deadline_ms"] unsignedLongLongValue]){
            closeAdmission(e,@"work_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            reply=failure(@"WORK_BUDGET_EXCEEDED");
        }
        else if(!isController(e,&peer)&&!isAuthority(e,&peer)){
            if([op isEqual:@"register_authority"]&&[e[@"authority_spawn_intent"] boolValue]){
                struct KIdentity controller;int observed=observeExact(e[@"controller"],&controller);
                if(observed==1&&peer.parent.bsd.pbi_ppid==controller.bsd.pbi_pid&&peer.parent.unique.parent_uniqueid==controller.unique.uniqueid
                    &&peer.parent.bsd.pbi_ruid==peer.owner&&!e[@"authority"]){
                    e[@"authority"]=identityJSON(&peer.parent);e[@"authority_spawn_intent"]=@NO;
                    reply=persist()?@{@"ok":@YES,@"authority":e[@"authority"]}:failure(@"ROLE_DURABILITY_FAILED");
                }else reply=failure(@"AUTHORITY_PARENT_MISMATCH");
            }else reply=failure(@"ROLE_AUTHENTICATION_FAILED");
        }else if([op isEqual:@"mkdir"]&&isController(e,&peer)&&[e[@"state"] isEqual:@"copying"]){
            bool ok=validRelative(q[@"path"])&&[e[@"directories"] count]<K_MAX_FILES;int dir=ok?copyDirectory(e,[q[@"path"] componentsSeparatedByString:@"/"]):-1;
            if(dir>=0){close(dir);e[@"directories"][q[@"path"]]=@YES;ok=persist();}else ok=false;
            reply=ok?@{@"ok":@YES}:failure(@"COPY_DIRECTORY_REJECTED");
        }else if([@[@"put_begin",@"put_chunk",@"put_commit"] containsObject:op]&&isController(e,&peer)&&[e[@"state"] isEqual:@"copying"]){
            bool ok=[op isEqual:@"put_begin"]?beginCopy(e,q):[op isEqual:@"put_chunk"]?chunkCopy(e,q):commitCopy(e,q);
            reply=ok?@{@"ok":@YES}:failure(@"COPY_FILE_REJECTED");
        }else if([op isEqual:@"seal"]&&isController(e,&peer)&&[e[@"state"] isEqual:@"copying"]){
            reply=sealCopy(e,q)?@{@"ok":@YES}:failure(@"SEAL_DIGEST_OR_DURABILITY_FAILED");
        }else if([op isEqual:@"expect_authority"]&&isController(e,&peer)&&[e[@"state"] isEqual:@"sealed"]&&!e[@"authority"]){
            e[@"authority_spawn_intent"]=@YES;reply=persist()?@{@"ok":@YES}:failure(@"ROLE_INTENT_DURABILITY_FAILED");
        }else if([op isEqual:@"permit"]&&isController(e,&peer)&&[e[@"state"] isEqual:@"sealed"]
            &&e[@"authority"]&&![e[@"authority_spawn_intent"] boolValue]){
            e[@"state"]=@"permitted";reply=persist()?@{@"ok":@YES}:failure(@"PERMIT_DURABILITY_FAILED");
        }else if([op isEqual:@"drain_commands"]&&isAuthority(e,&peer)&&[e[@"state"] isEqual:@"permitted"]){
            if(gCloseWaiter>=0)reply=failure(@"CLEANUP_BUSY");
            else if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))reply=failure(@"INVALID_CLEANUP_BUDGET");
            else if(closeAdmission(e,@"commands_complete",[q[@"cleanup_budget_ms"] unsignedLongLongValue])){
                gDrainOnly=true;e[@"state"]=@"draining_commands";
                if(persist()){gCloseWaiter=fd;return;}else reply=failure(@"COMMAND_DRAIN_DURABILITY_FAILED");
            }else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
        }else if([op isEqual:@"run"]&&isAuthority(e,&peer)&&[e[@"state"] isEqual:@"permitted"]){
            if(gRun.pid)reply=failure(@"COMMAND_BUSY");else if(launchRun(e,q,fd)){
                pthread_mutex_lock(&gTransportMutex);struct KClient *client=transportClient(fd);
                if(client){strlcpy(client->run_attempt,[activeID() UTF8String],sizeof(client->run_attempt));
                    /* A healthy silent long command is bounded by its own
                     * admitted absolute deadline, not a short probe timeout. */
                    uint64_t work=gRun.deadline>client->started_ms?gRun.deadline-client->started_ms:0;
                    client->lifecycle_budget_ms=kvtDeadline(work,[e[@"cleanup_budget_ms"] unsignedLongLongValue]+gTransportTimeoutMS);}
                pthread_mutex_unlock(&gTransportMutex);
                return;
            }else reply=failure(@"COMMAND_REJECTED");
        }else reply=failure(@"INVALID_TRANSITION");
    }
    /* State I/O may have observed a stop after the dispatch check. Do not
     * publish a new positive work reply from that stopped transition. */
    if([op isEqual:@"readback_copy"]&&[reply[@"ok"] boolValue]&&abortedAttempt(entryFor(q[@"attempt_id"])))reply=failure(@"COPY_READBACK_ABORTED");
    if(!stopOrReadOperation&&![op isEqual:@"readback_copy"]&&[reply[@"ok"] boolValue]){
        NSMutableDictionary *current=activeID().length?entryFor(activeID()):nil;
        if(workStopped(current)){if(current)closeAdmission(current,@"stopped_during_transition",[current[@"cleanup_budget_ms"] unsignedLongLongValue]);
            reply=failure(@"WORK_STOPPED_OR_EXPIRED");}
    }
    sendJSON(fd,reply?:failure(@"INVALID_REQUEST"));finishTransport(fd);
}

static bool acceptTransport(int fd) {
    struct KPeer peer;if(!authenticate(fd,&peer)||!kvtNonblocking(fd)){close(fd);return false;}
    pthread_mutex_lock(&gTransportMutex);
    if(gNextTransportToken==INT_MAX){pthread_mutex_unlock(&gTransportMutex);close(fd);return false;}
    for(unsigned i=0;i<K_MAX_CLIENTS;i++)if(gClients[i].fd<0){
        struct KClient *c=&gClients[i];memset(c,0,sizeof(*c));c->fd=fd;c->token=gNextTransportToken++;c->peer=peer;
        c->started_ms=c->rx.last_progress_ms=c->tx_progress_ms=nowMS();c->lifecycle_budget_ms=gLifecycleTimeoutMS;
        pthread_mutex_unlock(&gTransportMutex);return true;
    }
    pthread_mutex_unlock(&gTransportMutex);close(fd);return false;
}
static bool pumpTransports(void) {
    pthread_mutex_lock(&gTransportMutex);
    bool progress=false,dispatched=false;unsigned begin=gNextClient;
    for(unsigned step=0;step<K_MAX_CLIENTS;step++){
        unsigned i=(begin+step)%K_MAX_CLIENTS;struct KClient *c=&gClients[i];if(c->fd<0)continue;
        uint64_t now=nowMS();
        if(c->tx.length){size_t old=c->tx.length;
            int sent=kvtFlush(c->fd,&c->tx,KVT_TURN_BYTES,true,now,&c->tx_progress_ms);
            if(sent<0||kvtExpired(now,c->tx_progress_ms,gTransportTimeoutMS)){dropTransport(c->token,true);continue;}
            if(old!=c->tx.length)progress=true;
        }
        if(c->finishing){if(!c->tx.length)dropTransport(c->token,false);continue;}
        if(c->dispatched){
            char extra;ssize_t pending=recv(c->fd,&extra,1,MSG_PEEK|MSG_DONTWAIT);
            if(pending==0||(pending<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)){dropTransport(c->token,true);continue;}
            if(kvtExpired(now,c->started_ms,c->lifecycle_budget_ms)){
                cancelWork(c->token);transportLost(c->token);
                sendJSON(c->token,failure(@"DURABLE_IO_PENDING_UNCONFIRMED"));finishTransport(c->token);}
            continue;
        }
        if(kvtExpired(now,c->started_ms,gLifecycleTimeoutMS)||kvtExpired(now,c->rx.last_progress_ms,gTransportTimeoutMS)){
            dropTransport(c->token,true);continue;
        }
        size_t before=c->rx.header_used+c->rx.body_used;
        int read=kvtRead(c->fd,&c->rx,false,KVT_TURN_BYTES,now);
        if(read<0){dropTransport(c->token,true);continue;}
        if(before!=c->rx.header_used+c->rx.body_used)progress=true;
        if(read==KVT_READY&&!dispatched){
            /* Authenticate again after a slow upload. The captured helper and
             * parent may not be replaced or silently reparented during it. */
            struct KPeer current;bool same=authenticate(c->fd,&current)
                &&current.owner==c->peer.owner&&current.native.unique.uniqueid==c->peer.native.unique.uniqueid
                &&current.native.unique.pidversion==c->peer.native.unique.pidversion
                &&current.parent.unique.uniqueid==c->peer.parent.unique.uniqueid;
            id parsed=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:c->rx.body length:c->rx.body_length] options:0 error:NULL];
            NSDictionary *request=[parsed isKindOfClass:NSDictionary.class]?parsed:nil;
            kvtReaderClear(&c->rx);c->dispatched=true;dispatched=true;progress=true;gNextClient=(i+1)%K_MAX_CLIENTS;
            if(!same){sendJSON(c->token,failure(@"PEER_AUTHENTICATION_FAILED"));finishTransport(c->token);}
            else{latchQueuedClose(current,request);
                if(!fastRequest(c->token,current,request)&&!queueWork(c->token,current,request)){
                    sendJSON(c->token,failure(@"LIFECYCLE_QUEUE_BUSY_UNCONFIRMED"));finishTransport(c->token);}}
        }
    }
    pthread_mutex_unlock(&gTransportMutex);return progress;
}

static void drainOutput(int *fd,char type) {
    if(*fd<0)return;unsigned char b[32768];
    for(unsigned i=0;i<8;i++){
        if(gRun.client>=0&&!transportRoom(gRun.client,sizeof(b)+5))break;
        ssize_t n=read(*fd,b,sizeof(b));
        if(n>0){if(gRun.client>=0&&!sendFrame(gRun.client,type,[NSData dataWithBytes:b length:(NSUInteger)n])){
                dropTransport(gRun.client,true);}continue;}
        if(n==0){close(*fd);*fd=-1;}else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){close(*fd);*fd=-1;}break;
    }
}
static void advanceRun(void) {
    if(!gRun.pid)return;NSMutableDictionary *e=entryFor(activeID());
    if(workStopped(e)&&![e[@"admission_closed"] boolValue])closeAdmission(e,@"work_stop_latched",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    if(gRun.config>=0){
        /* Nonblocking actor transfer; reactor and stop observer are independent. */
        const unsigned char *bytes=gRunConfig.bytes;
        size_t left=gRunConfig.length-gRunConfigOffset;
        ssize_t n=write(gRun.config,bytes+gRunConfigOffset,MIN(left,(size_t)16384));
        if(n>0)gRunConfigOffset+=(size_t)n;
        else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)
            closeAdmission(e,@"configuration_pipe_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        if(gRun.config>=0&&gRunConfigOffset==gRunConfig.length){close(gRun.config);gRun.config=-1;gRunConfig=nil;}
    }
    if(!gRun.ready_seen&&gRun.ready>=0&&!gRun.birth_permit_pending){
        ssize_t n=read(gRun.ready,gRun.ready_bytes+gRun.ready_used,sizeof(gRun.ready_bytes)-gRun.ready_used);
        if(n>0){gRun.ready_used+=(size_t)n;if(gRun.ready_used>88)
            closeAdmission(e,@"guardian_registration_oversized",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
        bool bornPacket=!gRun.birth_seen&&gRun.ready_used==88;
        bool readyPacket=gRun.birth_seen&&n==0;
        if(bornPacket||readyPacket){
            uint32_t fields[4]={0};uint64_t seq=0;bool valid=gRun.ready_used==88;
            if(valid){for(unsigned i=0;i<4;i++){memcpy(&fields[i],gRun.ready_bytes+i*4,4);fields[i]=ntohl(fields[i]);}
                uint32_t hi,lo;memcpy(&hi,gRun.ready_bytes+16,4);memcpy(&lo,gRun.ready_bytes+20,4);seq=((uint64_t)ntohl(hi)<<32)|ntohl(lo);
                valid=fields[0]==(bornPacket?0x4b564232u:0x4b565232u)&&fields[1]==(uint32_t)gRun.pid&&fields[2]>1&&fields[2]<=INT_MAX
                    &&fields[3]==[e[@"descriptor"][@"task_ruid"] unsignedIntValue]
                    &&seq==[e[@"descriptor"][@"allocation_seq"] longLongValue]
                    &&memcmp(gRun.ready_bytes+24,gDaemonEpoch.UTF8String,64)==0;}
            struct KIdentity guardian,child;
            if(valid)valid=freshIdentity(gRun.pid,&guardian)&&sameBirth(e[@"launch_stub"],&guardian)&&rootCredentials(&guardian)
                &&freshIdentity((pid_t)fields[2],&child)&&child.bsd.pbi_ppid==(uint32_t)gRun.pid
                &&child.unique.parent_uniqueid==guardian.unique.uniqueid;
            if(valid&&bornPacket)valid=rootCredentials(&child);
            if(valid&&readyPacket)valid=gRun.birth_permitted&&sameBirth(e[@"root_child"],&child)
                &&child.bsd.pbi_ruid==fields[3]&&child.bsd.pbi_uid==fields[3]&&child.bsd.pbi_svuid==fields[3]
                &&child.bsd.pbi_rgid==fields[3]&&child.bsd.pbi_gid==fields[3]&&child.bsd.pbi_svgid==fields[3];
            if(bornPacket){gRun.birth_seen=true;gRun.ready_used=0;
                if(valid){e[@"root_child"]=identityJSON(&child);publishState();valid=persist();}
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
                /* An explicit test barrier after durable birth registration,
                 * before setup B. It is not a claim of a blocked disk syscall. */
                if(valid){KVDarwinQAPersistenceGate("guardian_birth_registered");
                    KVDarwinQAPersistenceGateComplete("guardian_birth_registered",true,0);}
#endif
                if(valid)gRun.birth_permit_pending=true;
            }else{gRun.ready_seen=true;close(gRun.ready);gRun.ready=-1;
                if(valid){gRun.command_pid=(pid_t)fields[2];e[@"command_identity"]=identityJSON(&child);e[@"spawn_intent"]=@NO;
                    publishState();valid=persist();}
                if(valid)valid=validUIDAllocation(e)&&armUIDStopTicket(e);
                if(valid)gRun.permit_pending=true;
            }
            if(!valid)closeAdmission(e,@"guardian_registration_or_publication_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        }else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))
            closeAdmission(e,@"guardian_registration_read_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    }
    if((gRun.birth_permit_pending||gRun.permit_pending)&&gRun.gate>=0){
        bool failed=false,permitted=false,birth=gRun.birth_permit_pending;
        const char *attempt=[e[@"descriptor"][@"attempt_id"] UTF8String];
        /* Both setup B and final G are linearized with the fast-stop latch.
         * No filesystem calls, allocation, transport or blocking FD here. */
        pthread_mutex_lock(&gObservationMutex);
        bool current=gObservation.valid&&attempt&&!strcmp(attempt,gObservation.attempt);
        // Read the clock BEFORE the stop flags: nowMS itself can latch failure.
        uint64_t permitNow=nowMS();
        bool stopped=gStopping||atomic_load(&gClockFailed)||!current||gObservation.abort_latched||gObservation.admission_closed
            ||atomic_load_explicit(&gStopGeneration,memory_order_acquire)==gObservation.generation
            ||permitNow>=gRun.deadline;
        if(stopped)failed=true;
        else if((birth?gObservation.root_registered:gObservation.guardian_registered)&&gObservation.uid_ticket_armed){
            char go=birth?'B':'G';ssize_t n=write(gRun.gate,&go,1);permitted=n==1;failed=!permitted;}
        pthread_mutex_unlock(&gObservationMutex);
        if(permitted&&birth){gRun.birth_permit_pending=false;gRun.birth_permitted=true;}
        if(failed||(permitted&&!birth)){close(gRun.gate);gRun.gate=-1;gRun.permit_pending=false;gRun.permitted=permitted;}
        if(failed)closeAdmission(e,@"child_permit_stopped_or_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    }
    if(gRun.client>=0){pthread_mutex_lock(&gTransportMutex);bool alive=transportClient(gRun.client)!=NULL;
        pthread_mutex_unlock(&gTransportMutex);
        if(!alive){gRun.client=-1;closeAdmission(e,@"run_transport_lost",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}}
    if(nowMS()>=gRun.deadline&&![e[@"admission_closed"] boolValue])closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    if(!gRun.exited){pid_t p=waitpid(gRun.pid,&gRun.status,WNOHANG);if(p==gRun.pid)gRun.exited=true;
        else if(p<0&&errno!=EINTR)closeAdmission(e,@"command_wait_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    drainOutput(&gRun.out,'O');drainOutput(&gRun.err,'E');
    if(gRun.exited&&gRun.out<0&&gRun.err<0){
        if(nowMS()>=gRun.deadline&&![e[@"admission_closed"] boolValue])
            closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        if(gRun.client>=0&&!transportRoom(gRun.client,65536))return;
        if(gRun.client>=0){sendJSON(gRun.client,@{@"ok":@YES,@"schema":@"knowledge-darwin-command-result.v1",
            @"attempt_id":e[@"descriptor"][@"attempt_id"],@"descriptor_sha256":e[@"descriptor_sha256"],
            @"command_ordinal":@(gRun.ordinal),@"command_sha256":gRunCommandSHA,
            @"daemon_epoch":gDaemonEpoch,@"writer_generation":@(observationCopy().generation),@"proof_current":@(currentEntry(e)),
            @"guardian_reaped":@(gRun.exited),@"guardian_protocol":@"KVR2",@"permit_observed":@(gRun.permitted),
            @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
            @"installation_id":e[@"descriptor"][@"installation_id"],@"allocation_seq":e[@"descriptor"][@"allocation_seq"],
            @"allocation_sha256":e[@"descriptor"][@"allocation_sha256"],@"host_id":gHost,@"boot_id":gBoot,
            @"timed_out":@((bool)(nowMS()>=gRun.deadline)),@"stop_latched":@((bool)(gStopping||stoppedAttempt(e))),
            @"exit_code":WIFEXITED(gRun.status)?@(WEXITSTATUS(gRun.status)):(id)NSNull.null,
            @"signal":WIFSIGNALED(gRun.status)?@(WTERMSIG(gRun.status)):(id)NSNull.null,
            @"admission_closed":e[@"admission_closed"],@"capability_qualified":@(gCapabilityQualified)});finishTransport(gRun.client);}
        if(gRun.ready>=0)close(gRun.ready);if(gRun.gate>=0)close(gRun.gate);if(gRun.config>=0)close(gRun.config);
        gRunConfig=nil;gRunCommandSHA=nil;
        gRun=(struct KRun){.client=-1,.out=-1,.err=-1,.ready=-1,.gate=-1,.config=-1};
        /* Retire the completed command deadline before any queued disk I/O. */
        publishState();}
}
/* Linearize terminal retirement against acknowledged stop requests. There is
 * no filesystem I/O under this mutex. After retirement fast stop cannot ACK
 * this generation. A detected late change retains the claim instead. */
static bool retireTerminalObservation(NSMutableDictionary *e,NSDictionary *proof) {
    const char *attempt=[e[@"descriptor"][@"attempt_id"] UTF8String];
    bool entryAborted=[e[@"abort_latched"] boolValue],proofAborted=[proof[@"abort_latched"] boolValue];
    bool proofExpired=[proof[@"cleanup_budget_exceeded"] boolValue];
    bool retired=false;pthread_mutex_lock(&gObservationMutex);
    uint64_t observed=nowMS();
    bool current=gObservation.valid&&attempt&&!strcmp(attempt,gObservation.attempt)&&!atomic_load(&gClockFailed);
    bool abort=gStopping||gObservation.abort_latched||entryAborted;
    bool recorded=abort==proofAborted&&abort==entryAborted;
    bool timeRecorded=observed<gCloseDeadline||proofExpired;
    if(current&&recorded&&timeRecorded){gObservation.valid=false;retired=true;}
    pthread_mutex_unlock(&gObservationMutex);return retired;
}
static bool retainAbortedClaim(NSMutableDictionary *e,NSString *priorActive) {
    e[@"abort_latched"]=@YES;e[@"planned_terminal"]=@NO;e[@"state"]=@"cleanup_unconfirmed";
    if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
    NSMutableDictionary *historical=[e[@"proof"] mutableCopy];
    if(historical){historical[@"abort_latched"]=@YES;historical[@"planned_terminal"]=@NO;
        historical[@"state"]=@"cleanup_unconfirmed";historical[@"native_cleanup_facts_confirmed"]=@NO;
        historical[@"cleanup_confirmed"]=@NO;historical[@"uid_history_tuple_verified"]=@NO;e[@"proof"]=historical;}
    [e removeObjectForKey:@"receipt_sha256"];[e removeObjectForKey:@"receipt_name"];
    if(priorActive.length)gRegistry[@"active_attempt"]=priorActive;
    return persist();
}
static void advanceCleanup(void) {
    if(!gClosing)return;NSMutableDictionary *e=gClosing;int lock=acquireCleanupBarrier(e);bool excluded=lock>=0;
    /* Every UID-wide signal and positive boundary proof requires current disk
     * history plus this exact tuple. Cached healthy never grants that scope. */
    bool uidExclusive=validUIDAllocation(e);
    /* A captured, exact owned launch stub may still hold the barrier before
     * credential drop. Never infer its exit from a private-UID zero scan. */
    bool stubObserved=true,guardianGone=true;
    bool guardianProtocol=[e[@"descriptor"][@"stub_wire_version"] isEqual:@"KVS2"];
    if(e[@"launch_stub"]){struct KIdentity stub;int rc=observeExact(e[@"launch_stub"],&stub);
        guardianGone=rc==0;
        if(rc==0&&[e[@"spawn_intent"] boolValue]){e[@"spawn_intent"]=@NO;persist();}
        else if(rc<0)stubObserved=false;
        else if(rc==1&&stub.bsd.pbi_ruid==0){
            audit_token_t token={{0}};token.val[5]=stub.bsd.pbi_pid;token.val[7]=(uint32_t)stub.unique.pidversion;
            int result=gSignalToken(&token,guardianProtocol?SIGTERM:SIGKILL);if(result!=0&&result!=ESRCH)stubObserved=false;
            if(guardianProtocol){result=gSignalToken(&token,SIGCONT);if(result!=0&&result!=ESRCH)stubObserved=false;}}
        else if(rc==1&&stub.bsd.pbi_ruid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue])stubObserved=false;
        else if(rc==1&&!uidExclusive&&!signalExact(e[@"launch_stub"],stub.bsd.pbi_ruid))stubObserved=false;
    }
    bool rootChildGone=true;
    if(e[@"root_child"]){struct KIdentity child;int rc=observeExact(e[@"root_child"],&child);rootChildGone=rc==0;
        if(rc<0)stubObserved=false;
        else if(rc==1&&(rootCredentials(&child)||child.bsd.pbi_ruid==[e[@"descriptor"][@"task_ruid"] unsignedIntValue])){
            audit_token_t token={{0}};token.val[5]=child.bsd.pbi_pid;token.val[7]=(uint32_t)child.unique.pidversion;
            int result=gSignalToken(&token,SIGKILL);if(result!=0&&result!=ESRCH)stubObserved=false;
        }else if(rc==1)stubObserved=false;
    }
    bool zero=false,authorityExited=!e[@"authority"],observed=stubObserved;
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));int count=-1;
    if(excluded&&pids){count=members([e[@"descriptor"][@"task_ruid"] unsignedIntValue],pids);zero=count==0;
        if(uidExclusive&&count>0)for(int i=0;i<count;i++){struct KIdentity v;
            if(!freshIdentity(pids[i],&v))continue;
            if(v.bsd.pbi_ruid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue])continue;
            audit_token_t t={{0}};t.val[5]=v.bsd.pbi_pid;t.val[7]=(uint32_t)v.unique.pidversion;
            int rc=gSignalToken(&t,SIGKILL);if(rc!=0&&rc!=ESRCH)observed=false;}}
    free(pids);
    if(!uidExclusive&&e[@"command_identity"]){struct KIdentity command;int rc=observeExact(e[@"command_identity"],&command);
        if(rc<0)observed=false;
        if(rc==1&&!signalExact(e[@"command_identity"],[e[@"descriptor"][@"task_ruid"] unsignedIntValue]))observed=false;}
    int authorityObserved=e[@"authority"]?-1:0;
    if(e[@"authority"]){struct KIdentity v;int rc=observeExact(e[@"authority"],&v);authorityObserved=rc;
        authorityExited=rc==0;if(rc<0)observed=false;
        if(!gDrainOnly&&rc==1&&!signalExact(e[@"authority"],[e[@"owner_uid"] unsignedIntValue]))observed=false;}
    bool intents=![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue];
    if(gDrainOnly){struct KIdentity controller;int controllerObserved=observeExact(e[@"controller"],&controller);
        bool ownerAlive=controllerObserved==1&&authorityObserved==1;
        bool drainFacts=uidExclusive&&excluded&&zero&&observed&&intents&&!gRun.pid&&guardianGone&&rootChildGone&&ownerAlive&&!gPoisoned&&!atomic_load(&gClockFailed);
        uint64_t drainNow=nowMS();
        if(!ownerAlive||gStopping||atomic_load(&gClockFailed)||stoppedAttempt(e)||gPoisoned||!uidExclusive||drainNow>=gCloseDeadline){
            NSString *reason=(gStopping||stoppedAttempt(e))?(plannedAttempt(e)?@"close_requested":@"daemon_stopping"):gPoisoned?@"registry_durability_unconfirmed":
                !uidExclusive?@"uid_history_or_allocation_unconfirmed":!ownerAlive?@"drain_owner_exit_or_observation_unconfirmed":@"cleanup_budget_exceeded";
            if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
            closeAdmission(e,reason,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            /* Full cleanup in the next scheduler turn, with the SAME epoch. */
            if(lock>=0)close(lock);return;
        }
        if(!drainFacts){if(lock>=0)close(lock);return;}
        NSDictionary *proof=@{@"schema":@"knowledge-darwin-command-drain-proof.v1",@"phase":@"commands_drained",
            @"attempt_id":e[@"descriptor"][@"attempt_id"],@"descriptor_sha256":e[@"descriptor_sha256"],
            @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
            @"host_id":gHost,@"boot_id":gBoot,@"daemon_epoch":gDaemonEpoch,
            @"writer_generation":@(observationCopy().generation),@"guardian_exit_confirmed":@(guardianGone),@"root_child_exit_confirmed":@(rootChildGone),
            @"proof_current":@(currentEntry(e)),
            @"installation_id":e[@"descriptor"][@"installation_id"],@"allocation_seq":e[@"descriptor"][@"allocation_seq"],
            @"account_policy_id":e[@"descriptor"][@"account_policy_id"],@"account_policy_sha256":e[@"descriptor"][@"account_policy_sha256"],
            @"allocation_sha256":e[@"descriptor"][@"allocation_sha256"],@"uid_history_tuple_verified":@YES,
            @"task_ruid":e[@"descriptor"][@"task_ruid"],@"admission_closed":@YES,
            @"spawn_exclusion_acquired":@YES,@"spawn_exclusion_held_until_terminal":@YES,
            @"spawn_intents_resolved":@YES,@"kernel_membership_zero":@YES,@"registered_authority_alive":@YES,
            @"authority_identity":e[@"authority"],@"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"],
            @"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"],@"observed_monotonic_ms":@(nowMS()),
            @"native_command_drain_facts_confirmed":@YES,@"abort_latched":@((bool)abortedAttempt(e)),
            @"planned_terminal":@((bool)plannedAttempt(e)),@"capability_qualified":@(gCapabilityQualified),
            @"command_drain_confirmed":@(gCapabilityQualified),@"terminal_cleanup":@NO,
            @"receipt_kind":@"root_registry_not_os_signed_attestation"};
        NSData *bytes=jsonData(proof);NSString *digest=sha(bytes);
        NSString *receipt=[NSString stringWithFormat:@"%@.%@.command-drain.json",e[@"descriptor"][@"attempt_id"],digest];
        bool durable=bytes.length<=65536&&saveJSON(receipt,proof);
        if(durable){e[@"command_drain_proof"]=proof;e[@"command_drain_sha256"]=digest;
            e[@"command_drain_receipt_name"]=receipt;e[@"state"]=@"commands_drained";durable=persist();}
        if(!durable){closeAdmission(e,@"command_drain_durability_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            if(lock>=0)close(lock);return;}
        /* Slow receipt I/O cannot turn an expired epoch or owner loss into a
         * positive current phase. Retain the old receipt only as history. */
        struct KIdentity currentOwner;
        bool historyStillConfirmed=validUIDAllocation(e);
        NSDictionary *drainReply=statusReply(e);
        bool ownersStillAlive=observeExact(e[@"controller"],&currentOwner)==1
            &&observeExact(e[@"authority"],&currentOwner)==1;
        /* Status performs another disk readback. Check time AFTER it and
         * after the exact-owner observations, not before another slow call. */
        uint64_t drainCompletionNow=nowMS();
        if(gStopping||atomic_load(&gClockFailed)||stoppedAttempt(e)||!historyStillConfirmed||!ownersStillAlive||![drainReply[@"allocation_tuple_verified_current"] boolValue]
            ||![drainReply[@"registry_healthy"] boolValue]||drainCompletionNow>=gCloseDeadline){
            if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
            closeAdmission(e,@"drain_completion_expired_or_owner_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            if(lock>=0)close(lock);return;
        }
        if(gCloseWaiter>=0){sendJSON(gCloseWaiter,drainReply);finishTransport(gCloseWaiter);gCloseWaiter=-1;}
        /* Keep the shared OFD in gCleanupBarrier, and keep active_attempt. */
        if(lock>=0)close(lock);gClosing=nil;gDrainOnly=false;return;
    }
    bool facts=uidExclusive&&excluded&&zero&&authorityExited&&observed&&intents&&!gRun.pid&&guardianGone&&rootChildGone;
    if(!facts&&nowMS()<gCloseDeadline){if(lock>=0)close(lock);return;}
    if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
    bool confirmed=facts&&!gPoisoned&&!atomic_load(&gClockFailed)&&validUIDAllocation(e);NSString *state=confirmed?@"closed":@"cleanup_unconfirmed";
    /* The current-history check can itself perform slow durable I/O. */
    if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
    NSDictionary *proof=@{@"schema":@"knowledge-darwin-private-ruid-proof.v1",@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor_sha256":e[@"descriptor_sha256"],@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"transport_header_sha256":@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA,
        @"host_id":gHost,@"boot_id":gBoot,@"task_ruid":e[@"descriptor"][@"task_ruid"],
        @"daemon_epoch":gDaemonEpoch,@"writer_generation":@(observationCopy().generation),@"cleanup_observation_current":@YES,
        @"guardian_exit_confirmed":@(guardianGone),@"root_child_exit_confirmed":@(rootChildGone),@"proof_current":@(currentEntry(e)),
        @"installation_id":e[@"descriptor"][@"installation_id"],@"allocation_seq":e[@"descriptor"][@"allocation_seq"],
        @"account_policy_id":e[@"descriptor"][@"account_policy_id"],@"account_policy_sha256":e[@"descriptor"][@"account_policy_sha256"],
        @"allocation_sha256":e[@"descriptor"][@"allocation_sha256"],@"uid_history_tuple_verified":@((bool)(confirmed&&uidExclusive)),
        @"admission_closed":e[@"admission_closed"],@"spawn_exclusion_acquired":@(excluded),@"spawn_intents_resolved":@(intents),
        @"kernel_membership_method":@"proc_listpids(PROC_RUID_ONLY,nonnull_buffer);active_and_zombie_lists",
        @"kernel_membership_zero":@(zero),@"registered_authority_exited":@(authorityExited),
        @"authority_identity":e[@"authority"]?:NSNull.null,@"controller_identity":e[@"controller"],
        @"controller_excluded_from_boundary":@YES,@"persistent_broker_excluded_from_boundary":@YES,
        @"native_cleanup_facts_confirmed":@(confirmed),@"abort_latched":@((bool)abortedAttempt(e)),
        @"planned_terminal":@((bool)plannedAttempt(e)),@"capability_qualified":@(gCapabilityQualified),
        @"cleanup_confirmed":@((bool)(confirmed&&gCapabilityQualified)),@"state":state,@"receipt_kind":@"root_registry_not_os_signed_attestation",
        @"phase":@"terminal",@"terminal_cleanup":@YES,
        @"command_drain_sha256":e[@"command_drain_sha256"]?:NSNull.null,
        @"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"],@"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"],
        @"cleanup_budget_exceeded":e[@"cleanup_budget_exceeded"],
        @"observed_monotonic_ms":@(nowMS())};
    /* No env, output, tokens, arbitrary paths, or source contents in receipts.
     * A false -> true expiry transition needs a NEW immutable receipt. At
     * most one rewrite is needed: expired never becomes unexpired, and the
     * original cleanup epoch is never extended by persistence/readback. */
    NSString *priorActive=activeID();bool durable=false,registryDurable=false;
    NSDictionary *reply=nil;
    for(unsigned publication=0;publication<3;publication++){
    if(abortedAttempt(e)||[proof[@"abort_latched"] boolValue]){e[@"abort_latched"]=@YES;e[@"planned_terminal"]=@NO;}
    if(jsonData(proof).length>65536){gPoisoned=true;confirmed=false;}
    NSString *receipt=[NSString stringWithFormat:@"%@.%@.receipt.json",e[@"descriptor"][@"attempt_id"],sha(jsonData(proof))];
    durable=saveJSON(receipt,proof);
    /* Persistence is another observation boundary. If history changed during
     * receipt I/O, keep the reservation active and publish only unconfirmed. */
    if(durable&&confirmed&&!validUIDAllocation(e)){
        confirmed=false;state=@"cleanup_unconfirmed";NSMutableDictionary *revised=[proof mutableCopy];
        revised[@"native_cleanup_facts_confirmed"]=@NO;revised[@"cleanup_confirmed"]=@NO;
        revised[@"uid_history_tuple_verified"]=@NO;revised[@"state"]=state;proof=revised;
        receipt=[NSString stringWithFormat:@"%@.%@.receipt.json",e[@"descriptor"][@"attempt_id"],sha(jsonData(proof))];
        durable=saveJSON(receipt,proof);
    }
    e[@"proof"]=proof;e[@"receipt_sha256"]=sha(jsonData(proof));
    e[@"receipt_name"]=receipt;
    e[@"state"]=(durable?state:@"cleanup_unconfirmed");
    if(!durable){
        /* A failed receipt open can leave the registry writable. In a late
         * revision the earlier index already cleared active_attempt, so
         * restore it BEFORE any subsequent successful registry commit. */
        if(priorActive.length)gRegistry[@"active_attempt"]=priorActive;
        confirmed=false;state=@"cleanup_unconfirmed";
        NSMutableDictionary *unconfirmed=[proof mutableCopy];unconfirmed[@"state"]=state;
        unconfirmed[@"native_cleanup_facts_confirmed"]=@NO;unconfirmed[@"cleanup_confirmed"]=@NO;
        unconfirmed[@"uid_history_tuple_verified"]=@NO;proof=unconfirmed;e[@"proof"]=proof;
        [e removeObjectForKey:@"receipt_sha256"];[e removeObjectForKey:@"receipt_name"];
    }
    if(durable&&confirmed)gRegistry[@"active_attempt"]=@"";
    registryDurable=persist();
    if(!registryDurable){
        /* A failed final index commit cannot drop the cached active claim or
         * expose the earlier receipt as current positive cleanup. Its file is
         * historical only; never repair unknown registry bytes to publish it. */
        if(priorActive.length)gRegistry[@"active_attempt"]=priorActive;
        confirmed=false;e[@"state"]=@"cleanup_unconfirmed";
        NSMutableDictionary *unconfirmed=[proof mutableCopy];unconfirmed[@"state"]=@"cleanup_unconfirmed";
        unconfirmed[@"native_cleanup_facts_confirmed"]=@NO;unconfirmed[@"cleanup_confirmed"]=@NO;
        unconfirmed[@"uid_history_tuple_verified"]=@NO;e[@"proof"]=unconfirmed;
        [e removeObjectForKey:@"receipt_sha256"];[e removeObjectForKey:@"receipt_name"];
    }
    reply=registryDurable?statusReply(e):failure(@"CLEANUP_RECEIPT_DURABILITY_UNCONFIRMED");
    if(confirmed&&(![reply[@"allocation_tuple_verified_current"] boolValue]||![reply[@"registry_healthy"] boolValue])){
        /* The status readback may discover policy/history/index loss AFTER
         * the earlier index commit. Unknown current state cannot release the
         * cached claim or the barrier; its old receipt remains history only.
         * Do not overwrite unknown disk bytes to manufacture a downgrade. */
        confirmed=false;registryDurable=false;state=@"cleanup_unconfirmed";
        if(priorActive.length)gRegistry[@"active_attempt"]=priorActive;
        NSMutableDictionary *unconfirmed=[proof mutableCopy];unconfirmed[@"state"]=state;
        unconfirmed[@"native_cleanup_facts_confirmed"]=@NO;unconfirmed[@"cleanup_confirmed"]=@NO;
        unconfirmed[@"uid_history_tuple_verified"]=@NO;proof=unconfirmed;e[@"proof"]=proof;e[@"state"]=state;
        [e removeObjectForKey:@"receipt_sha256"];[e removeObjectForKey:@"receipt_name"];
        reply=failure(@"CLEANUP_CURRENT_STATE_UNCONFIRMED");
    }
    if(nowMS()>=gCloseDeadline&&![proof[@"cleanup_budget_exceeded"] boolValue]){
        e[@"cleanup_budget_exceeded"]=@YES;
        NSMutableDictionary *expired=[proof mutableCopy];expired[@"cleanup_budget_exceeded"]=@YES;proof=expired;
        if(publication<2&&durable&&registryDurable&&!gPoisoned)continue;
        /* A stale false receipt may exist only as historical evidence when
         * its late replacement cannot be durably published. Do not expose
         * that earlier receipt as the current result or release the claim. */
        confirmed=false;e[@"state"]=@"cleanup_unconfirmed";
        expired[@"state"]=@"cleanup_unconfirmed";expired[@"native_cleanup_facts_confirmed"]=@NO;
        expired[@"cleanup_confirmed"]=@NO;expired[@"uid_history_tuple_verified"]=@NO;e[@"proof"]=expired;
        [e removeObjectForKey:@"receipt_sha256"];[e removeObjectForKey:@"receipt_name"];
        if(priorActive.length)gRegistry[@"active_attempt"]=priorActive;
        reply=failure(@"CLEANUP_LATE_RECEIPT_DURABILITY_UNCONFIRMED");
    }
    /* An abort observed during durable receipt/index I/O invalidates a
     * pre-abort receipt as current. Publish a new immutable cause-bound one.
     * At most deadline and abort can each change false -> true once. */
    if(abortedAttempt(e)&&![proof[@"abort_latched"] boolValue]){
        e[@"abort_latched"]=@YES;
        NSMutableDictionary *aborted=[proof mutableCopy];aborted[@"abort_latched"]=@YES;aborted[@"planned_terminal"]=@NO;proof=aborted;
        if(publication<2&&durable&&registryDurable&&!gPoisoned)continue;
        registryDurable=retainAbortedClaim(e,priorActive);
        reply=failure(@"CLEANUP_ABORT_RECEIPT_UNCONFIRMED");confirmed=false;durable=false;
    }
    break;
    }
    if(durable&&confirmed&&registryDurable&&!retireTerminalObservation(e,proof)){
        /* An accepted abort between final I/O and retirement must survive
         * restart. Do not retire or release the exclusion for a stale proof. */
        registryDurable=retainAbortedClaim(e,priorActive);confirmed=false;durable=false;
        reply=failure(@"CLEANUP_LATE_TERMINAL_STATE_UNCONFIRMED");
    }
    if(gCloseWaiter>=0){sendJSON(gCloseWaiter,reply);finishTransport(gCloseWaiter);gCloseWaiter=-1;}
    if(lock>=0)close(lock);
    if(durable&&confirmed&&registryDurable&&gCleanupBarrier>=0){close(gCleanupBarrier);gCleanupBarrier=-1;gCleanupAttempt=nil;}
    gClosing=nil;gDrainOnly=false;
}

static NSString *sysctlString(const char *name) { size_t n=0;if(sysctlbyname(name,NULL,&n,NULL,0)||n<2||n>4096)return nil;
    NSMutableData *d=[NSMutableData dataWithLength:n];if(sysctlbyname(name,d.mutableBytes,&n,NULL,0))return nil;
    return [NSString stringWithUTF8String:d.bytes]; }
/* Check the protected pair before accepting requests. --describe is only a
 * consistency check; it cannot attest a build. Root-protected installation,
 * exact byte pins and quiescent updates remain separate prerequisites. This
 * direct startup child never executes user work and is reaped before serving. */
static bool inspectStub(void) {
    if(!hex64(@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA))return false;
    gStubBinarySHA=protectedFileSHA(gStubPath);if(!gStubBinarySHA)return false;
    int output[2];if(pipe(output))return false;
    posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;
    bool actionsReady=posix_spawn_file_actions_init(&actions)==0;
    bool attributesReady=posix_spawnattr_init(&attributes)==0;
    int null=open("/dev/null",O_RDWR|O_CLOEXEC);int source=fcntl(output[1],F_DUPFD_CLOEXEC,32);
    bool ok=actionsReady&&attributesReady&&null>=0&&source>=0;
    if(ok)ok=posix_spawn_file_actions_adddup2(&actions,null,0)==0
        &&posix_spawn_file_actions_adddup2(&actions,source,1)==0
        &&posix_spawn_file_actions_adddup2(&actions,null,2)==0
        &&posix_spawnattr_setflags(&attributes,POSIX_SPAWN_CLOEXEC_DEFAULT)==0;
    pid_t pid=0;bool spawned=false;NSDictionary *birth=nil;struct KIdentity broker;
    if(ok)ok=freshIdentity(getpid(),&broker)&&rootCredentials(&broker);
    char *args[]={(char *)gStubPath.fileSystemRepresentation,"--describe",NULL};
    char *environment[]={"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",NULL};
    if(ok){spawned=posix_spawn(&pid,gStubPath.fileSystemRepresentation,&actions,&attributes,args,environment)==0;ok=spawned;}
    if(spawned){struct KIdentity child,again;char image[PROC_PIDPATHINFO_MAXSIZE];
        if(freshIdentity(pid,&child)&&rootCredentials(&child)&&child.bsd.pbi_ppid==broker.bsd.pbi_pid
            &&child.unique.parent_uniqueid==broker.unique.uniqueid&&proc_pidpath(pid,image,sizeof(image))>0
            &&[gStubPath isEqual:@(image)]&&freshIdentity(pid,&again)&&sameKernelBirth(&child,&again))birth=identityJSON(&child);}
    if(actionsReady)posix_spawn_file_actions_destroy(&actions);
    if(attributesReady)posix_spawnattr_destroy(&attributes);
    if(null>=0)close(null);if(source>=0)close(source);close(output[1]);
    int flags=fcntl(output[0],F_GETFL);if(flags<0||fcntl(output[0],F_SETFL,flags|O_NONBLOCK)<0)ok=false;
    NSMutableData *data=[NSMutableData data];uint64_t deadline=nowMS()+30000;bool exited=false,eof=false,waitKnown=true;int status=0;
    while(ok&&(!exited||!eof)&&nowMS()<deadline){
        unsigned char bytes[1024];ssize_t n=read(output[0],bytes,sizeof(bytes));
        if(n>0){if(data.length+(NSUInteger)n>2048){ok=false;break;}[data appendBytes:bytes length:(NSUInteger)n];}
        else if(n==0)eof=true;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){ok=false;break;}
        if(!exited){pid_t reaped=waitpid(pid,&status,WNOHANG);if(reaped==pid)exited=true;
            else if(reaped<0&&errno!=EINTR){waitKnown=false;ok=false;break;}}
        if(!exited||!eof){struct pollfd event={output[0],POLLIN,0};poll(&event,1,20);}
    }
    close(output[0]);ok=ok&&exited&&eof&&WIFEXITED(status)&&WEXITSTATUS(status)==0;
    if(spawned&&!exited){
        /* ECHILD/unknown wait state never authorizes signaling a numeric PID.
         * Even a captured child uses the atomic birth-qualified signal API. */
        bool signalConfirmed=waitKnown&&birth&&signalExact(birth,0);
        uint64_t cleanupDeadline=nowMS()+30000;
        while(waitKnown&&!exited&&nowMS()<cleanupDeadline){pid_t reaped=waitpid(pid,&status,WNOHANG);
            if(reaped==pid)exited=true;else if(reaped<0&&errno!=EINTR){waitKnown=false;break;}
            if(!exited){struct pollfd idle={-1,0,0};poll(&idle,1,20);}}
        if(!exited||!signalConfirmed)fprintf(stderr,"stub describe cleanup_unconfirmed: pid=%d captured_birth=%s wait_known=%s reaped=%s\n",
            pid,birth?"true":"false",waitKnown?"true":"false",exited?"true":"false");
    }
    if(!ok)return false;
    NSDictionary *description=parseJSON(data);
    return description.count==5&&[description[@"schema"] isEqual:@"knowledge-darwin-stub.v1"]
        &&[description[@"broker_binary_sha256"] isEqual:gBinarySHA]
        &&[description[@"broker_source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA]
        &&[description[@"stub_source_sha256"] isEqual:@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA]
        &&booleanField(description[@"capability_qualified"])&&![description[@"capability_qualified"] boolValue]
        &&[protectedFileSHA(gStubPath) isEqual:gStubBinarySHA];
}
static NSDictionary *historyConfiguration(void) {
    return @{@"marker_path":pathChild(gAnchorPath,@"install.json"),@"head_path":pathChild(gAnchorPath,@"uid-head.json"),
        @"journal_path":pathChild(gAllocatorPath,@"consumed.journal"),@"lock_path":pathChild(gAllocatorPath,@"daemon.lock"),
        @"registry_path":pathChild(gRegistryPath,@"registry.json"),@"workspace_root":gWorkspaceRoot,@"host_id":gHost};
}
/* Shared native preflight creates no registry/history/lock and runs no JS. */
static bool nativePrerequisites(void) {
    gSetupStage="root-and-source-pins";
    if(getuid()!=0||geteuid()!=0||!hex64(@KNOWLEDGE_BROKER_SOURCE_SHA)
        ||!hex64(@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA)
        ||!hex64(@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA)||!hex64(@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA))return false;
    gSetupStage="protected-broker-image";
    gBinarySHA=protectedFileSHA(gExecutable);if(!gBinarySHA)return false;
    gSetupStage="native-birth-qualified-signal-api";
    void *sym=dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");memcpy(&gSignalToken,&sym,sizeof(gSignalToken));
    if(!gSignalToken)return false;
    gSetupStage="protected-C-only-stub-pair";
    if(!inspectStub())return false;
    gSetupStage="protected-directory-chains";
    if(!protectedPath(gRegistryPath,false,true)||!protectedPath(gWorkspaceRoot,false,true)
        ||!canonicalAbsolute(gSocketPath)||!protectedPath(pathParent(gSocketPath),false,true))return false;
    if([gRegistryPath isEqual:gWorkspaceRoot]||[gWorkspaceRoot hasPrefix:[gRegistryPath stringByAppendingString:@"/"]])return false;
    gRegistryFD=open(gRegistryPath.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    gWorkspaceFD=open(gWorkspaceRoot.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(gRegistryFD<0||gWorkspaceFD<0)return false;
    gSetupStage="workspace-mode0711-registry-mode0700";
    struct stat ws,rs;if(fstat(gWorkspaceFD,&ws)||(ws.st_mode&07777)!=0711
        ||fstat(gRegistryFD,&rs)||(rs.st_mode&07777)!=0700)return false;
    gSetupStage="native-signal-and-combined-identity-abi";
    struct KIdentity self;if(!freshIdentity(getpid(),&self)||!rootCredentials(&self))return false;
    gLaunchdCreationParent=launchdRootBirth(getpid());
    gSetupStage="kernel-ruid-positive-canary";
    pid_t *positive=calloc(K_PID_CAP,sizeof(pid_t));int positiveCount=positive?members(0,positive):-1;
    free(positive);if(positiveCount<=0)return false;
    gSetupStage="actual-host-and-boot-identities";
    gDaemonEpoch=randomHex();gBoot=sysctlString("kern.bootsessionuuid");uuid_t hostUUID;struct timespec timeout={2,0};
    if(gethostuuid(hostUUID,&timeout)==0){uuid_string_t text;uuid_unparse_lower(hostUUID,text);gHost=@(text);}
    if(!gBoot.length||!gHost.length)return false;
    gSetupStage="protected-allowed-runtime-pins";
    NSMutableDictionary *pins=[NSMutableDictionary dictionary];
    for(NSString *runtime in gRuntimes){NSString *digest=protectedFileSHA(runtime);if(!digest)return false;pins[runtime]=digest;}
    gRuntimePins=pins;return true;
}
static int initInstall(void) {
    if(!gUIDRangeConfirmed||![gAccountPolicyArgument isEqual:K_ACCOUNT_POLICY]||!gAllowedOwners.count)return 64;
    if(!nativePrerequisites()){fprintf(stderr,"init prerequisite failure: %s (errno=%d)\n",gSetupStage,errno);return 78;}
    /* Explicit root maintenance only, before registration of any history.
     * These calls may block in external directory services. No service loop or
     * active attempt is owned by this initializer. Never call from runtime. */
    NSMutableDictionary *owners=[NSMutableDictionary dictionary];
    uuid_t rootUUID;if(mbr_uid_to_uuid(0,rootUUID)||uuid_is_null(rootUUID))return 78;
    for(NSString *key in gAllowedOwners){uid_t uid;uuid_t uuid;uuid_string_t text;
        if(!ownerNumber(key,&uid))return 64;
        errno=0;struct passwd *owner=getpwuid(uid);
        if(!owner||owner->pw_uid!=uid||mbr_uid_to_uuid(uid,uuid)||uuid_is_null(uuid)||uuid_compare(uuid,rootUUID)==0)return 78;
        uuid_unparse_lower(uuid,text);if([owners.allValues containsObject:@(text)])return 78;owners[key]=@(text);
    }
    /* Existing/partial policy is evidence, never repairable through init. */
    struct stat policyStat;NSString *policyPath=pathChild(gAnchorPath,@"account-policy.json");
    if(lstat(policyPath.fileSystemRepresentation,&policyStat)==0||errno!=ENOENT)return 78;
    NSError *error=nil;
    gUIDHistory=[KVDarwinUIDHistory beginInitializationWithConfiguration:historyConfiguration() error:&error];
    if(!gUIDHistory||![gUIDHistory.reason isEqual:@"INITIALIZATION_PENDING"]||!gUIDHistory.checkpoint){
        fprintf(stderr,"explicit init failed: %s\n",gUIDHistory.reason.UTF8String?:"UNAVAILABLE");return 78;}
    /* Explicit fresh initialization only. No existing registry is overwritten,
     * including one that appeared after the component's empty-tree preflight. */
    struct stat prior;if(fstatat(gRegistryFD,"registry.json",&prior,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return 78;
    if(!writeInitialAccountPolicy(owners)){fprintf(stderr,"account policy creation unconfirmed; no reset\n");return 78;}
    gRegistry=[@{@"schema":K_SCHEMA,@"attempts":[NSMutableDictionary dictionary],@"active_attempt":@"",
        @"installation_id":gUIDHistory.installationID,@"uid_history_checkpoint":gUIDHistory.checkpoint,
        @"account_policy":@{@"id":K_ACCOUNT_POLICY,@"sha256":gAccountPolicySHA}} mutableCopy];
    if(!initializeRegistry()||!refreshAccountPolicy()||![gUIDHistory finalizeInitializationWithError:&error]){
        fprintf(stderr,"explicit init remains unconfirmed; no reset: %s\n",gUIDHistory.reason.UTF8String?:"REGISTRY_WRITE_FAILED");return 78;}
    gEntryStoreLoaded=true;
    NSDictionary *reply=@{@"ok":@YES,@"schema":@"knowledge-darwin-install-result.v1",
        @"installation_id":gUIDHistory.installationID,@"uid_history_checkpoint":gUIDHistory.checkpoint,
        @"capability_qualified":@NO,@"uid_range_admin_asserted":@YES,@"account_policy":accountPolicyStatus()};
    NSData *bytes=jsonData(reply);unsigned char newline='\n';
    return exactIO(1,(void *)bytes.bytes,bytes.length,true)&&exactIO(1,&newline,1,true)?0:74;
}
static void historyLockAcquired(void *unused) {
    (void)unused;atomic_store_explicit(&gHistoryLockReady,true,memory_order_release);
}
static bool startup(void) {
    gSetupStage="open-existing-independent-UID-history-singleton";
    gUIDHistory=[KVDarwinUIDHistory openWithConfiguration:historyConfiguration()
        didAcquireLock:historyLockAcquired context:NULL error:NULL];
    /* No safe singleton means no listener; an acquired but unhealthy history
     * permits independently authenticated status/exact-target recovery only. */
    if(!gUIDHistory)return false;
    gSetupStage="load-existing-protected-registry-never-create";
    int fd=openat(gRegistryFD,"registry.json",O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    NSDictionary *loaded=nil;NSData *loadedBytes=nil;
    if(fd>=0){struct stat st;
        if(fstat(fd,&st)||st.st_uid!=0||st.st_nlink!=1||!S_ISREG(st.st_mode)||(st.st_mode&07777)!=0600){close(fd);return false;}
        NSData *bytes=readFD(fd,K_MAX_JSON);loaded=parseJSON(bytes);close(fd);
        if(!loaded||![jsonData(loaded) isEqual:bytes])loaded=nil;else loadedBytes=bytes;
    }else if(errno!=ENOENT)return false;
    if(loaded&&[loaded[@"schema"] isEqual:K_SCHEMA]&&[loaded[@"attempts"] isKindOfClass:NSMutableDictionary.class]
        &&[loaded[@"active_attempt"] isKindOfClass:NSString.class]&&hex64(loaded[@"installation_id"])){
        gRegistry=[loaded mutableCopy];gRegistryDurableBytes=[loadedBytes copy];gEntryStoreLoaded=true;
    }else{
        /* In-memory probe shell only, never a fresh registry or allocator.
         * persist is poisoned, so missing/corrupt disk bytes stay untouched. */
        gRegistry=[@{@"attempts":[NSMutableDictionary dictionary],@"active_attempt":@""} mutableCopy];
        gPoisoned=true;gQuarantineReason=@"REGISTRY_MISSING_OR_INVALID_NO_REINITIALIZATION";
    }
    if(gEntryStoreLoaded&&gUIDHistory.healthy&&![gRegistry[@"installation_id"] isEqual:gUIDHistory.installationID]){
        /* CP equality alone must not adopt a registry from another install.
         * Preserve its bytes/known entries for exact-target diagnosis only. */
        gPoisoned=true;gQuarantineReason=@"REGISTRY_INSTALLATION_BINDING_MISMATCH";
    }
    /* Missing policy disables admission/UID-wide cleanup, not independently
     * authenticated exact-birth recovery of existing current-source entries. */
    refreshAccountPolicy();
    if(activeID().length){NSMutableDictionary *e=entryFor(activeID());
        if(!e||!validRecordedEntry(e,activeID())||![e[@"descriptor"][@"host_id"] isEqual:gHost]){
            gPoisoned=true;gQuarantineReason=@"REGISTRY_DESCRIPTOR_BOOT_HOST_OR_OWNERSHIP_UNKNOWN";
         }else if(!sameBootID(e[@"descriptor"][@"boot_id"],gBoot)){
            if(!beginRebootCleanup(e,[e[@"cleanup_budget_ms"] unsignedLongLongValue])){
                gPoisoned=true;gQuarantineReason=@"NEW_BOOT_RECOVERY_AUTHORITY_UNCONFIRMED";}
         }else {publishState();if(validUIDAllocation(e))armUIDStopTicket(e);
            closeAdmission(e,@"daemon_restart",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}}
    publishState();return true;
}
static bool openListener(void) {
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
    if(strlen(gSocketPath.fileSystemRepresentation)>=sizeof(addr.sun_path))return false;
    strlcpy(addr.sun_path,gSocketPath.fileSystemRepresentation,sizeof(addr.sun_path));
    struct stat old;if(lstat(addr.sun_path,&old)==0){if(!S_ISSOCK(old.st_mode)||old.st_uid!=0)return false;if(unlink(addr.sun_path))return false;}
    else if(errno!=ENOENT)return false;
    gListen=socket(AF_UNIX,SOCK_STREAM,0);if(gListen<0)return false;fcntl(gListen,F_SETFD,FD_CLOEXEC);
    mode_t previous=umask(0077);int bound=bind(gListen,(struct sockaddr *)&addr,sizeof(addr));umask(previous);
    if(bound||chmod(addr.sun_path,0666)||listen(gListen,16)||!kvtNonblocking(gListen))return false;return true;
}
static void *lifecycleActor(void *unused) {
    (void)unused;
    @autoreleasepool {
    if(!startup()){atomic_store_explicit(&gActorExitStatus,78,memory_order_release);
        atomic_store_explicit(&gWriterPending,false,memory_order_release);
        atomic_store_explicit(&gActorDone,true,memory_order_release);return NULL;}
    NSString *observedAttempt=nil;uint64_t nextStateRefresh=0;
    for(;;){@autoreleasepool{
        atomic_store_explicit(&gWriterPending,true,memory_order_release);
        NSMutableDictionary *e=activeID().length?entryFor(activeID()):nil;
        bool known=e&&validRecordedEntry(e,activeID())&&[e[@"descriptor"][@"boot_id"] isEqual:gBoot]&&[e[@"descriptor"][@"host_id"] isEqual:gHost];
        bool drained=[e[@"state"] isEqual:@"commands_drained"];
        if(![observedAttempt isEqual:activeID()]){observedAttempt=[activeID() copy];nextStateRefresh=nowMS()+K_ACTIVE_STATE_REFRESH_MS;}
        if(known&&!gClosing&&(![e[@"admission_closed"] boolValue]||drained)){struct KIdentity v;
            int controller=observeExact(e[@"controller"],&v),authority=e[@"authority"]?observeExact(e[@"authority"],&v):1;
            NSString *reason=(gStopping||stoppedAttempt(e))?(plannedAttempt(e)?@"close_requested":@"daemon_stopping"):gPoisoned?@"registry_durability_unconfirmed":!gAccountPolicyHealthy?@"account_policy_unconfirmed":!gUIDHistory.healthy?@"uid_history_unhealthy":controller<0||authority<0?@"owner_observation_unconfirmed":
                controller==0||authority==0?@"owner_exited":drained&&nowMS()>=[e[@"cleanup_deadline_ms"] unsignedLongLongValue]?@"cleanup_budget_exceeded":
                !drained&&nowMS()>=[e[@"work_deadline_ms"] unsignedLongLongValue]?@"work_budget_exceeded":nil;
            /* Prioritize already-known stop/owner/deadline facts over disk I/O.
             * A silent command must not retain cached healthy state forever
             * merely because no new RPC arrives. Each store is observed even
             * when another fails; none is healed from cached state. */
            if(!reason&&nowMS()>=nextStateRefresh){
                refreshEntryStore();refreshAccountPolicy();refreshUIDHistory();
                nextStateRefresh=nowMS()+K_ACTIVE_STATE_REFRESH_MS;
                controller=observeExact(e[@"controller"],&v);authority=e[@"authority"]?observeExact(e[@"authority"],&v):1;
                reason=(gStopping||stoppedAttempt(e))?(plannedAttempt(e)?@"close_requested":@"daemon_stopping"):gPoisoned?@"registry_durability_unconfirmed":!gAccountPolicyHealthy?@"account_policy_unconfirmed":!gUIDHistory.healthy?@"uid_history_unhealthy":controller<0||authority<0?@"owner_observation_unconfirmed":
                    controller==0||authority==0?@"owner_exited":drained&&nowMS()>=[e[@"cleanup_deadline_ms"] unsignedLongLongValue]?@"cleanup_budget_exceeded":
                    !drained&&nowMS()>=[e[@"work_deadline_ms"] unsignedLongLongValue]?@"work_budget_exceeded":nil;
            }
            if([reason isEqual:@"cleanup_budget_exceeded"])e[@"cleanup_budget_exceeded"]=@YES;
            if(reason)closeAdmission(e,reason,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
        advanceRun();advanceCleanup();advanceRebootCleanup();
        KWork *work=takeWork();
        if(work){gCurrentWork=work;
            if(atomic_load_explicit(&work->cancelled,memory_order_acquire)){
                sendJSON(work->client,failure(@"REQUEST_CANCELLED_UNCONFIRMED"));finishTransport(work->client);}
            else if(!revalidateWorkPeer(work)){sendJSON(work->client,failure(@"PEER_AUTHENTICATION_FAILED"));finishTransport(work->client);}
            else handleClient(work->client,work->peer,work->request);
            gCurrentWork=nil;retireWork(work);
        }
        if(gStopping&&!gClosing&&!gRebootClosing&&!gRun.pid){
            /* A request may have completed a reservation in this turn. Use
             * its current identity, not the entry cached before dispatch. */
            NSString *currentID=activeID();NSMutableDictionary *current=currentID.length?entryFor(currentID):nil;
            bool currentKnown=current&&validRecordedEntry(current,currentID)
                &&[current[@"descriptor"][@"boot_id"] isEqual:gBoot]&&[current[@"descriptor"][@"host_id"] isEqual:gHost];
            if(currentKnown&&(![current[@"admission_closed"] boolValue]||[current[@"state"] isEqual:@"commands_drained"])){
                closeAdmission(current,@"daemon_stopping",[current[@"cleanup_budget_ms"] unsignedLongLongValue]);
            }else break; /* unknown/unconfirmed claims are preserved, not healed */
        }
        atomic_store_explicit(&gWriterPending,false,memory_order_release);publishState();
        struct timespec pause={0,20000000};nanosleep(&pause,NULL);
    }}
    }
    atomic_store_explicit(&gWriterPending,false,memory_order_release);
    atomic_store_explicit(&gActorDone,true,memory_order_release);return NULL;
}
static int serve(void) {
    for(unsigned i=0;i<K_MAX_CLIENTS;i++)gClients[i].fd=-1;
    pthread_mutexattr_t attributes;pthread_mutexattr_init(&attributes);
    pthread_mutexattr_settype(&attributes,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&gTransportMutex,&attributes);pthread_mutexattr_destroy(&attributes);
    gWorkQueue=[NSMutableArray array];gWorkByClient=[NSMutableDictionary dictionary];
    if(!nativePrerequisites()||(!gQualificationMode&&!gLaunchdCreationParent)){
        fprintf(stderr,"broker setup/prerequisite failure: %s (errno=%d)\n",gSetupStage,errno);return 78;}
    signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    gQAServing=true;
#endif
    atomic_store_explicit(&gWriterPending,true,memory_order_release);
    pthread_t actor,observer;
    if(pthread_create(&actor,NULL,lifecycleActor,NULL))return 78;
    if(pthread_create(&observer,NULL,stopObserver,NULL)){gStopping=1;return 78;}
    /* Never unlink/bind before protected history singleton acquisition.
     * Post-lease journal replay runs on actor while reactor remains available. */
    while(!atomic_load_explicit(&gHistoryLockReady,memory_order_acquire)
        &&!atomic_load_explicit(&gActorDone,memory_order_acquire)){
        struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
    if(atomic_load_explicit(&gActorDone,memory_order_acquire)){
        pthread_join(actor,NULL);pthread_join(observer,NULL);return atomic_load_explicit(&gActorExitStatus,memory_order_acquire);}
    if(!atomic_load_explicit(&gHistoryLockReady,memory_order_acquire)||!openListener())return 78;
    while(!atomic_load_explicit(&gActorDone,memory_order_acquire)){@autoreleasepool{
        bool progressed=pumpTransports();struct pollfd p={gListen,POLLIN,0};
        int r=poll(&p,1,progressed?0:20);
        if(r>0&&(p.revents&POLLIN))for(unsigned accepted=0;accepted<4;accepted++){
            int fd=accept(gListen,NULL,NULL);if(fd<0)break;
            if(fcntl(fd,F_SETFD,FD_CLOEXEC)<0)close(fd);else acceptTransport(fd);}
    }}
    pthread_join(actor,NULL);pthread_join(observer,NULL);
    for(unsigned i=0;i<K_MAX_CLIENTS;i++)if(gClients[i].fd>=0)dropTransport(gClients[i].token,false);
    close(gListen);return atomic_load_explicit(&gActorExitStatus,memory_order_acquire);
}
static bool clientParentAlive(struct KIdentity *saved) {
    struct KIdentity current;
    return getppid()==(pid_t)saved->bsd.pbi_pid&&freshIdentity((pid_t)saved->bsd.pbi_pid,&current)
        &&current.unique.uniqueid==saved->unique.uniqueid&&current.unique.pidversion==saved->unique.pidversion;
}
static int clientGuard(uint64_t deadline,struct KIdentity *parent) {
    if(gStopping)return 130;if(nowMS()>=deadline)return 124;
    return clientParentAlive(parent)?0:75;
}
static int client(bool run) {
    uint64_t started=nowMS(),deadline=kvtDeadline(started,gLifecycleTimeoutMS),inputProgress=started;
    struct KIdentity parent;if(!freshIdentity(getppid(),&parent))return 75;
    if(!hex64(@KNOWLEDGE_BROKER_SOURCE_SHA)||!hex64(@KNOWLEDGE_DARWIN_TRANSPORT_HEADER_SHA)||!protectedFileSHA(gExecutable)
        ||!canonicalAbsolute(gSocketPath)||!protectedPath(pathParent(gSocketPath),false,true))return 78;
    struct stat st;if(lstat(gSocketPath.fileSystemRepresentation,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=0)return 78;
    int originals[4]={-1,-1,-1,-1},fd=-1;bool modified[4]={false,false,false,false};
    struct KVTReader rx={0};struct KVTBuffer tx={0},outputs[3]={{0}};
    uint64_t outputProgress[3]={started,started,started},txProgress=started;
    signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);
    @try {
        /* The integration supplies owned pipes. Save flags for manual CLI use;
         * every normal/error/cancel return restores them before helper exit. */
        unsigned count=run?4:2;
        for(unsigned i=0;i<count;i++){
            originals[i]=fcntl((int)i,F_GETFL);if(originals[i]<0)return 74;
            if(fcntl((int)i,F_SETFL,originals[i]|O_NONBLOCK)<0)return 74;modified[i]=true;
        }
        NSMutableData *input=[NSMutableData data];unsigned char bytes[32768];bool inputComplete=false;
        while(!inputComplete){
            int guard=clientGuard(deadline,&parent);if(guard)return guard;
            if(kvtExpired(nowMS(),inputProgress,gTransportTimeoutMS))return 124;
            for(unsigned calls=0;calls<KVT_TURN_CALLS;calls++){
                ssize_t n=read(0,bytes,sizeof(bytes));
                if(n>0){if(input.length+(NSUInteger)n>K_MAX_JSON)return 64;
                    [input appendBytes:bytes length:(NSUInteger)n];inputProgress=nowMS();continue;}
                if(n==0){inputComplete=true;break;}
                if(errno==EINTR)continue;if(errno!=EAGAIN&&errno!=EWOULDBLOCK)return 74;break;
            }
            if(!inputComplete){struct pollfd wait={0,POLLIN,0};if(poll(&wait,1,20)<0&&errno!=EINTR)return 74;}
        }
        NSMutableDictionary *q=[parseJSON(input) mutableCopy];if(!q)return 64;
        if(run&&![q[@"op"] isEqual:@"run"])return 64;if(!run&&[q[@"op"] isEqual:@"run"])return 64;
        if(!gLifecycleTimeoutExplicit){
            uint64_t duration=KVT_DEFAULT_LIFECYCLE_MS;
            if(run){if(!validDuration(q[@"timeout_ms"],K_MAX_WORK_MS))return 64;
                uint64_t cleanup=validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS)?[q[@"cleanup_budget_ms"] unsignedLongLongValue]:60000;
                duration=kvtDeadline([q[@"timeout_ms"] unsignedLongLongValue],kvtDeadline(cleanup,gTransportTimeoutMS));
            }else if(validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))
                duration=MAX(duration,kvtDeadline([q[@"cleanup_budget_ms"] unsignedLongLongValue],gTransportTimeoutMS));
            /* Derive from the original start; never restart on output/heartbeat. */
            deadline=kvtDeadline(started,duration);
        }
        q[@"source_sha256"]=@KNOWLEDGE_BROKER_SOURCE_SHA;NSData *data=jsonData(q);
        if(!data||!kvtQueueFrame(&tx,0,data.bytes,data.length,false))return 64;
        struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
        if(strlen(gSocketPath.fileSystemRepresentation)>=sizeof(addr.sun_path))return 64;
        strlcpy(addr.sun_path,gSocketPath.fileSystemRepresentation,sizeof(addr.sun_path));
        fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0||!kvtNonblocking(fd)||fcntl(fd,F_SETFD,FD_CLOEXEC)<0)return 69;
        uint64_t connectStarted=nowMS();bool connecting=false,connected=false;
        while(!connected){
            int guard=clientGuard(deadline,&parent);if(guard)return guard;
            if(kvtExpired(nowMS(),connectStarted,gTransportTimeoutMS))return 124;
            if(!connecting){int rc=connect(fd,(struct sockaddr *)&addr,sizeof(addr));
                if(rc==0||errno==EISCONN)connected=true;
                else if(errno==EINPROGRESS||errno==EALREADY)connecting=true;
                else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return 69;
            }
            if(!connected){struct pollfd wait={fd,POLLOUT,0};int ready=poll(&wait,1,20);
                if(ready<0&&errno!=EINTR)return 69;
                if(connecting&&ready>0){int error=0;socklen_t length=sizeof(error);
                    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&length)||error)return 69;connected=true;}
            }
        }
        uid_t uid;gid_t gid;pid_t pid;socklen_t len=sizeof(pid);char image[PROC_PIDPATHINFO_MAXSIZE];
        NSString *selfSHA=protectedFileSHA(gExecutable);
        if(getpeereid(fd,&uid,&gid)||uid!=0||getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&len)||len!=sizeof(pid)
            ||proc_pidpath(pid,image,sizeof(image))<=0||![protectedFileSHA(@(image)) isEqual:selfSHA])return 77;
        txProgress=nowMS();rx.last_progress_ms=txProgress;bool got=false;int result=74;
        for(;;){
            int guard=clientGuard(deadline,&parent);if(guard)return guard;
            uint64_t now=nowMS();bool progress=false;
            for(unsigned i=0;i<3;i++)if(outputs[i].length){size_t old=outputs[i].length;
                int wrote=kvtFlush((int)i+1,&outputs[i],KVT_TURN_BYTES,false,now,&outputProgress[i]);
                if(wrote<0)return 74;if(kvtExpired(now,outputProgress[i],gTransportTimeoutMS))return 124;
                progress=progress||old!=outputs[i].length;
            }
            if(got&&!outputs[0].length&&!outputs[1].length&&!outputs[2].length){
                int finalGuard=clientGuard(deadline,&parent);return finalGuard?:result;}
            if(tx.length){size_t old=tx.length;int wrote=kvtFlush(fd,&tx,KVT_TURN_BYTES,true,now,&txProgress);
                if(wrote<0)return 74;if(kvtExpired(now,txProgress,gTransportTimeoutMS))return 124;progress=progress||old!=tx.length;
            }
            if(!got&&!tx.length){size_t old=rx.header_used+rx.body_used;
                int read=kvtRead(fd,&rx,true,KVT_TURN_BYTES,now);if(read<0)return 74;
                progress=progress||old!=rx.header_used+rx.body_used;
                /* A silent healthy command has no transport-stall deadline.
                 * Partial frames do: a stalled frame is not semantic progress. */
                if(!rx.ready&&rx.header_used&&kvtExpired(now,rx.last_progress_ms,gTransportTimeoutMS))return 124;
                if(read==KVT_READY){
                    unsigned index=rx.header[0]=='E'?1:0;bool terminal=rx.header[0]=='J';
                    if(terminal)index=run?2:0;else if(!run)return 74;
                    size_t extra=rx.body_length+(terminal?1:0);
                    if(extra<=KVT_QUEUE_LIMIT&&outputs[index].length<=KVT_QUEUE_LIMIT-extra){
                        if(terminal){NSDictionary *reply=parseJSON([NSData dataWithBytes:rx.body length:rx.body_length]);
                            if(!reply||!booleanField(reply[@"ok"]))return 74;result=[reply[@"ok"] boolValue]?0:1;}
                        bool empty=!outputs[index].length;
                        if(!kvtAppend(&outputs[index],rx.body,rx.body_length,KVT_QUEUE_LIMIT))return 74;
                        if(terminal&&!kvtAppend(&outputs[index],"\n",1,KVT_QUEUE_LIMIT))return 74;
                        if(empty)outputProgress[index]=now;if(terminal)got=true;
                        kvtReaderClear(&rx);rx.last_progress_ms=now;progress=true;
                    }
                }
            }
            struct pollfd wait[4]={kvtPollSlot(fd,(short)(got?0:tx.length?POLLOUT:rx.ready?0:POLLIN)),
                kvtPollSlot(1,outputs[0].length?POLLOUT:0),kvtPollSlot(2,outputs[1].length?POLLOUT:0),
                kvtPollSlot(3,outputs[2].length?POLLOUT:0)};
            if(poll(wait,4,progress?0:20)<0&&errno!=EINTR)return 74;
        }
    } @finally {
        if(fd>=0)close(fd);kvtReaderClear(&rx);kvtBufferClear(&tx);
        for(unsigned i=0;i<3;i++)kvtBufferClear(&outputs[i]);
        for(unsigned i=0;i<4;i++)if(modified[i])fcntl((int)i,F_SETFL,originals[i]);
    }
}
int main(int argc,char **argv) {@autoreleasepool {
    signal(SIGPIPE,SIG_IGN);char self[PROC_PIDPATHINFO_MAXSIZE];if(proc_pidpath(getpid(),self,sizeof(self))<=0)return 78;gExecutable=@(self);
    gStubPath=pathChild(pathParent(gExecutable),@"knowledge-native-stub");
    NSString *canonicalState=@"/Library/PrivilegedHelperTools/KnowledgeVerification-state";
    NSString *canonicalAllocator=@"/Library/PrivilegedHelperTools/KnowledgeVerification-allocator";
    NSString *canonicalAnchors=@"/Library/PrivilegedHelperTools/KnowledgeVerification-anchors";
    NSString *canonicalWorkspaces=@"/Library/PrivilegedHelperTools/KnowledgeVerification-workspaces";
    NSString *canonicalSocket=@"/Library/PrivilegedHelperTools/KnowledgeVerification-control/broker.sock";
    gRegistryPath=canonicalState;gAllocatorPath=canonicalAllocator;gAnchorPath=canonicalAnchors;
    gSocketPath=canonicalSocket;gWorkspaceRoot=canonicalWorkspaces;
    NSMutableArray *runtimes=[NSMutableArray array];NSString *mode=nil;bool stateOptions=false;unsigned explicitRoots=0;
    gAllowedOwners=[NSMutableArray array];
    for(int i=1;i<argc;i++){NSString *s=@(argv[i]);
        if([@[@"--serve",@"--init-install",@"--request",@"--run",@"--print-profile"] containsObject:s]){if(mode)return 64;mode=s;}
        else if([s isEqual:@"--qualification-mode"])gQualificationMode=true;
        else if([s isEqual:@"--confirm-reserved-uid-range=1000000000:1900000000"])gUIDRangeConfirmed=true;
        else if([s hasPrefix:@"--account-policy="]){if(gAccountPolicyArgument)return 64;gAccountPolicyArgument=[s substringFromIndex:17];}
        else if([s hasPrefix:@"--allow-owner="]){NSString *key=[s substringFromIndex:14];uid_t uid;
            if(!ownerNumber(key,&uid)||[gAllowedOwners containsObject:key]||gAllowedOwners.count>=K_MAX_OWNERS)return 64;
            [gAllowedOwners addObject:key];}
        else if([s hasPrefix:@"--registry="]){gRegistryPath=[s substringFromIndex:11];stateOptions=true;explicitRoots|=1u;}
        else if([s hasPrefix:@"--allocator="]){gAllocatorPath=[s substringFromIndex:12];stateOptions=true;explicitRoots|=2u;}
        else if([s hasPrefix:@"--anchors="]){gAnchorPath=[s substringFromIndex:10];stateOptions=true;explicitRoots|=4u;}
        else if([s hasPrefix:@"--socket="]){gSocketPath=[s substringFromIndex:9];explicitRoots|=8u;}
        else if([s hasPrefix:@"--workspaces="]){gWorkspaceRoot=[s substringFromIndex:13];stateOptions=true;explicitRoots|=16u;}
        else if([s hasPrefix:@"--workspace="])gPrintWorkspace=[s substringFromIndex:12];
        else if([s hasPrefix:@"--runtime="])[runtimes addObject:[s substringFromIndex:10]];
        else if([s hasPrefix:@"--transport-timeout-ms="]){uint64_t value=0;
            if(gTransportTimeoutExplicit||!decimal64([s substringFromIndex:23],&value)||value<1||value>K_MAX_CLEANUP_MS)return 64;
            gTransportTimeoutMS=value;gTransportTimeoutExplicit=true;}
        else if([s hasPrefix:@"--lifecycle-timeout-ms="]){uint64_t value=0;
            if(gLifecycleTimeoutExplicit||!decimal64([s substringFromIndex:23],&value)||value<1
                ||value>K_MAX_WORK_MS+2*K_MAX_CLEANUP_MS)return 64;gLifecycleTimeoutMS=value;gLifecycleTimeoutExplicit=true;}
        else return 64;
    }
    gCapabilityQualified=capabilityForMode(gQualificationMode);
    for(NSString *path in [runtimes arrayByAddingObjectsFromArray:@[gRegistryPath,gSocketPath,gWorkspaceRoot,gAllocatorPath,gAnchorPath]])
        if(!canonicalAbsolute(path))return 64;
    gRuntimes=runtimes;
    if([mode isEqual:@"--print-profile"]){
        if(gQualificationMode||gUIDRangeConfirmed||gAccountPolicyArgument||gAllowedOwners.count||stateOptions
            ||gTransportTimeoutExplicit||gLifecycleTimeoutExplicit||!runtimes.count||!canonicalAbsolute(gPrintWorkspace))return 64;
        NSData *profile=[sandboxProfile(gPrintWorkspace) dataUsingEncoding:NSUTF8StringEncoding];
        return exactIO(1,(void *)profile.bytes,profile.length,true)?0:74;
    }
    if(gPrintWorkspace)return 64;
    bool serving=[mode isEqual:@"--serve"],initializing=[mode isEqual:@"--init-install"];
    if(serving||initializing){
        if(getuid()!=0||geteuid()!=0||!runtimes.count)return 64;
        if(initializing&&(gTransportTimeoutExplicit||gLifecycleTimeoutExplicit))return 64;
        bool canonical=[gRegistryPath isEqual:canonicalState]&&[gAllocatorPath isEqual:canonicalAllocator]
            &&[gAnchorPath isEqual:canonicalAnchors]&&[gWorkspaceRoot isEqual:canonicalWorkspaces]&&[gSocketPath isEqual:canonicalSocket];
        /* Diagnostic lineage relaxation must never use production state,
         * including when every default was silently inherited. */
        if(gQualificationMode){if(canonical||explicitRoots!=31u)return 64;}
        else if(!canonical)return 64;
        if(gQualificationMode){
            /* A diagnostic fixture selects ALL five roots outside every
             * production sibling. Partial overrides must never touch defaults,
             * even before native prerequisite inspection or singleton open. */
            NSArray *production=@[canonicalState,canonicalAllocator,canonicalAnchors,canonicalWorkspaces,pathParent(canonicalSocket)];
            for(NSString *path in @[gRegistryPath,gAllocatorPath,gAnchorPath,gWorkspaceRoot,gSocketPath])
                for(NSString *root in production)if([path isEqual:root]||[path hasPrefix:[root stringByAppendingString:@"/"]]
                    ||[root hasPrefix:[path stringByAppendingString:@"/"]])return 64;
        }
        if(serving&&(gUIDRangeConfirmed||gAccountPolicyArgument||gAllowedOwners.count))return 64;
        return initializing?initInstall():serve();
    }
    if(gQualificationMode||gUIDRangeConfirmed||gAccountPolicyArgument||gAllowedOwners.count||stateOptions||runtimes.count)return 64;
    /* Ordinary native request/profile clients can select a protected socket;
     * they neither initialize nor open allocator state. */
    if([mode isEqual:@"--request"])return client(false);
    if([mode isEqual:@"--run"])return client(true);
    return 64;
}}
