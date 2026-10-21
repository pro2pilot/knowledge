/*
 * Explicitly installed macOS isolated-copy verification broker.
 *
 * Build: clang -fobjc-arc -Wall -Wextra -Wno-deprecated-declarations -framework Foundation
 *   -DKNOWLEDGE_BROKER_SOURCE_SHA='"<sha256 of this source>"'
 *   -DKNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA='"<header sha256>"'
 *   -DKNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA='"<implementation sha256>"'
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
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <bsm/audit.h>
#include <dlfcn.h>
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
#include <pwd.h>
#include <sandbox.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
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
#define K_SCHEMA @"knowledge-darwin-broker.v1"
#define K_MAX_JSON (12u * 1024u * 1024u)
#define K_MAX_FRAME (1024u * 1024u)
#define K_MAX_FILES 50000u
#define K_MAX_COPY (2ull * 1024ull * 1024ull * 1024ull)
#define K_UID_FIRST 1000000000u
#define K_UID_LAST 1900000000u
#define K_PID_CAP 65536u
/* Match verification-policy.js. Valid caller budgets are never silently
 * shortened to the earlier one-hour work / one-minute cleanup prototype caps. */
#define K_MAX_WORK_MS (600000ull * 100000ull)
#define K_MAX_CLEANUP_MS 3600000ull
/* This must remain false until the exact installed source/profile/host matrix
 * has physical negative qualification, reviewed independently. A command-line
 * flag, environment variable, or successful diagnostic cannot change it. */
static const bool kCapabilityQualified = false;

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
static KVDarwinUIDHistory *gUIDHistory;
static bool gUIDRefreshAttempted,gEntryStoreLoaded,gUIDRangeConfirmed;
static uint64_t gUIDLastRefreshMS;
static NSString *gBoot, *gHost;
static NSArray<NSString *> *gRuntimes;
static NSDictionary<NSString *,NSString *> *gRuntimePins;
static NSMutableDictionary *gRegistry;
static NSData *gRegistryDurableBytes;
static int gRegistryFD = -1, gWorkspaceFD = -1, gListen = -1;
static bool gQualificationMode, gPoisoned, gLaunchdCreationParent;
static NSString *gQuarantineReason;
static const char *gSetupStage="initial";
static volatile sig_atomic_t gStopping;

static uint64_t nowMS(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000; }
static bool exactIO(int fd, void *p, size_t n, bool writing) {
    unsigned char *b = p; while (n) { ssize_t r = writing ? write(fd,b,n) : read(fd,b,n);
        if (r < 0 && errno == EINTR) continue; if (r <= 0) return false;
        b += r; n -= (size_t)r; } return true;
}
static bool waitIO(int fd, short events, uint64_t deadline) {
    while (nowMS() < deadline) { struct pollfd p = {fd,events,0};
        int r = poll(&p,1,(int)MIN((uint64_t)200,deadline-nowMS()));
        if (r > 0) return (p.revents & events) != 0;
        if (r < 0 && errno != EINTR) return false; } return false;
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
    @"error":code,@"capability_qualified":@(kCapabilityQualified),@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA }; }
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
static NSData *readFD(int fd, size_t max) { struct stat s;
    if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_size<0||(uint64_t)s.st_size>max)return nil;
    NSMutableData *d=[NSMutableData dataWithLength:(NSUInteger)s.st_size];
    return exactIO(fd,d.mutableBytes,d.length,false)?d:nil;
}
static NSString *protectedFileSHA(NSString *path) {
    if(!protectedPath(path,true,true))return nil;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); if(fd<0)return nil;
    NSData *d=readFD(fd,256u*1024u*1024u); close(fd); return d?sha(d):nil;
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
    int fd=openat(gRegistryFD,"registry.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;
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
    if(fd<0)return false; bool ok=exactIO(fd,(void *)d.bytes,d.length,true)&&fsync(fd)==0&&fcntl(fd,F_FULLFSYNC)==0;
    if(close(fd))ok=false;
    if(ok&&registry&&!registryMatches(expectedRegistry,initialCreation)){poisonEntryStore();ok=false;}
    if(ok)ok=renameat(gRegistryFD,temp.UTF8String,gRegistryFD,name.UTF8String)==0&&fsync(gRegistryFD)==0;
    if(!ok){unlinkat(gRegistryFD,temp.UTF8String,0);gPoisoned=true;return false;}
    fd=openat(gRegistryFD,name.UTF8String,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
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
    if(gPoisoned||!gEntryStoreLoaded)return false;
    bool ok=saveJSON(@"registry.json",gRegistry);
    if(!ok)gPoisoned=true;
    return ok;
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
static bool validRecordedEntry(NSMutableDictionary *e,NSString *id) {
    NSDictionary *d=e[@"descriptor"];uint64_t allocationSequence=0;if(![d isKindOfClass:NSDictionary.class])return false;
    return hex64(id)&&[d[@"boundary_id"] isEqual:id]&&[d[@"attempt_id"] isEqual:id]
        &&[d[@"backend"] isEqual:@"darwin_private_ruid"]&&[d[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA]
        &&[d[@"stub_source_sha256"] isEqual:@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA]
        &&[d[@"stub_binary_sha256"] isEqual:gStubBinarySHA]&&[d[@"stub_wire_version"] isEqual:@"KVS1"]
        &&hex64(d[@"installation_id"])&&[d[@"installation_id"] isEqual:gRegistry[@"installation_id"]]
        &&hex64(d[@"allocation_sha256"])&&isString(d[@"allocation_seq"],20)
        &&[d[@"uid_history_header_sha256"] isEqual:@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA]
        &&[d[@"uid_history_source_sha256"] isEqual:@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA]
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
        &&(!e[@"command_identity"]||(validRecordedIdentity(e[@"command_identity"])
            &&[e[@"command_identity"][@"ruid"] isEqual:d[@"task_ruid"]]));
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
    if(!refreshEntryStore()||!gUIDHistory.healthy||![d[@"installation_id"] isEqual:gUIDHistory.installationID])return false;
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
    uuid_t uuid; if(mbr_uid_to_uuid(owner,uuid))return false;
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
    if(!saved||fstat(fd,&st)||st.st_uid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue] || !S_ISDIR(st.st_mode)
        ||[saved[@"device"] unsignedLongLongValue]!=(uint64_t)st.st_dev||[saved[@"inode"] unsignedLongLongValue]!=(uint64_t)st.st_ino){
        close(fd);return -1; } return fd;
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

static bool sendFrame(int fd, char type, NSData *body) {
    if(body.length>K_MAX_JSON)return false; uint32_t size=htonl((uint32_t)body.length);
    /* No blocking writer may let a client stop the persistent service. */
    uint64_t deadline=nowMS()+20; unsigned char header[5];header[0]=(unsigned char)type;memcpy(header+1,&size,4);
    const void *buffers[]={header,body.bytes};size_t sizes[]={5,body.length};
    for(unsigned n=0;n<2;n++){const unsigned char *p=buffers[n];size_t left=sizes[n];
        while(left){ssize_t wrote=send(fd,p,left,MSG_DONTWAIT);
            if(wrote<0&&(errno==EAGAIN||errno==EWOULDBLOCK)){if(!waitIO(fd,POLLOUT,deadline))return false;continue;}
            if(wrote<0&&errno==EINTR)continue;if(wrote<=0)return false;p+=wrote;left-=(size_t)wrote;}}
    return true;
}
static bool sendJSON(int fd, NSDictionary *v) { return sendFrame(fd,'J',jsonData(v)); }
static NSData *receiveRequest(int fd) {
    uint32_t n; uint64_t deadline=nowMS()+100; unsigned char *p=(unsigned char *)&n;size_t left=4;
    while(left){if(!waitIO(fd,POLLIN,deadline))return nil;ssize_t r=recv(fd,p,left,MSG_DONTWAIT);
        if(r<=0)return nil;p+=r;left-=(size_t)r;}
    n=ntohl(n);if(!n||n>K_MAX_JSON)return nil;NSMutableData *d=[NSMutableData dataWithLength:n];
    p=d.mutableBytes;left=n;while(left){if(!waitIO(fd,POLLIN,deadline))return nil;
        ssize_t r=recv(fd,p,left,MSG_DONTWAIT);if(r<=0)return nil;p+=r;left-=(size_t)r;}
    return d;
}
struct KPeer { uid_t owner; struct KIdentity native, parent; };
static bool authenticate(int fd, struct KPeer *p) {
    gid_t gid;pid_t pid=0;socklen_t length=sizeof(pid);uid_t uid;
    if(getpeereid(fd,&uid,&gid)||getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&length)||length!=sizeof(pid)
        ||!freshIdentity(pid,&p->native)||p->native.bsd.pbi_ruid!=uid||p->native.bsd.pbi_uid!=uid
        ||!freshIdentity((pid_t)p->native.bsd.pbi_ppid,&p->parent)||p->parent.bsd.pbi_ruid!=uid
        ||p->native.unique.parent_uniqueid!=p->parent.unique.uniqueid)return false;
    char path[PROC_PIDPATHINFO_MAXSIZE];if(proc_pidpath(pid,path,sizeof(path))<=0)return false;
    if(![gExecutable isEqual:@(path)]||![protectedFileSHA(@(path)) isEqual:gBinarySHA])return false;
    p->owner=uid;return true;
}
static bool authenticatedEntry(NSMutableDictionary *e, NSDictionary *q, struct KPeer *p, bool secret) {
    if(!e || !validRecordedEntry(e,q[@"attempt_id"]) || [e[@"owner_uid"] unsignedIntValue]!=p->owner
        || ![e[@"descriptor"][@"boot_id"] isEqual:gBoot] || ![e[@"descriptor"][@"host_id"] isEqual:gHost])return false;
    if(secret){if(!hex64(q[@"token"]))return false;
        return equalSecret(e[@"token_sha256"],sha([q[@"token"] dataUsingEncoding:NSUTF8StringEncoding]));}
    return hex64(q[@"descriptor_sha256"]) && equalSecret(e[@"descriptor_sha256"],q[@"descriptor_sha256"]);
}
static bool isController(NSMutableDictionary *e,struct KPeer *p) { return sameBirth(e[@"controller"],&p->parent); }
static bool isAuthority(NSMutableDictionary *e,struct KPeer *p) { return e[@"authority"] && sameBirth(e[@"authority"],&p->parent); }

struct KRun { pid_t pid;int client,out,err,ready,gate,config;uint64_t deadline;bool exited,ready_seen;int status; };
static struct KRun gRun={.pid=0,.client=-1,.out=-1,.err=-1,.ready=-1,.gate=-1,.config=-1};
static NSData *gRunConfig;
static size_t gRunConfigOffset;
static NSMutableDictionary *gClosing;
static uint64_t gCloseDeadline;
static int gCloseWaiter=-1;
static bool gDrainOnly;
static int gCleanupBarrier=-1;
static NSString *gCleanupAttempt;
static void stopSignal(int sig) {(void)sig;gStopping=1;}
static bool closeAdmission(NSMutableDictionary *e,NSString *reason,uint64_t budget) {
    gDrainOnly=false; /* cancellation, crash, recovery and ordinary close are terminal */
    bool durable=!gPoisoned;
    /* Disk failure poisons positive proof, never the ability to stop work. */
    if(gPendingFD>=0){close(gPendingFD);gPendingFD=-1;}
    if(gRun.config>=0){close(gRun.config);gRun.config=-1;gRunConfig=nil;}
    if(gRun.gate>=0){close(gRun.gate);gRun.gate=-1;}
    /* Only validated request or persisted policy values reach this internal
     * stop path. An invalid stored value cannot grant an unbounded wait. */
    uint64_t profile=[e[@"cleanup_budget_ms"] unsignedLongLongValue];
    uint64_t bounded=budget>=1&&budget<=K_MAX_CLEANUP_MS&&profile>=1&&profile<=K_MAX_CLEANUP_MS?MIN(budget,profile):1;
    uint64_t started=nowMS(),deadline=started+bounded;
    if(e[@"cleanup_deadline_ms"])deadline=MIN(deadline,[e[@"cleanup_deadline_ms"] unsignedLongLongValue]);
    if(!e[@"cleanup_started_monotonic_ms"]){e[@"cleanup_started_monotonic_ms"]=@(started);e[@"cleanup_budget_exceeded"]=@NO;}
    e[@"cleanup_deadline_ms"]=@(deadline);
    if(![e[@"admission_closed"] boolValue]){e[@"stop_reason"]=reason;e[@"closed_monotonic_ms"]=@(started);}
    else if(![reason isEqual:@"close_requested"]&&![reason isEqual:@"recovery_requested"])e[@"stop_reason"]=reason;
    e[@"admission_closed"]=@YES;e[@"state"]=@"closing";
    durable=persist()&&durable;
    gCloseDeadline=deadline;gClosing=e;return durable;
}
static int admissionFD(NSMutableDictionary *e) {
    NSString *name=[NSString stringWithFormat:@"%@.admission",e[@"descriptor"][@"boundary_id"]];
    int fd=openat(gRegistryFD,name.UTF8String,O_RDWR|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    NSDictionary *saved=e[@"admission_inode"];
    if(fd<0)return -1;if(!saved||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||st.st_nlink!=1||(st.st_mode&0077)
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
    [p appendFormat:@"(allow file-write* (subpath %@)) (deny file-link) (allow sysctl-read) (allow process-info* (target self))",sbplString(workspace)];
    return p;
}
static bool runtimeAllowed(NSString *path) { return isString(path,4096) && gRuntimePins[path]
    && [protectedFileSHA(path) isEqual:gRuntimePins[path]]; }
/* Fixed endian KVS1, never a dump of an ABI-dependent C structure. The C-only
 * peer repeats all structural validation before using any field. */
static void wire32(NSMutableData *data,uint32_t value) { value=htonl(value);[data appendBytes:&value length:4]; }
static void wire64(NSMutableData *data,uint64_t value) { wire32(data,(uint32_t)(value>>32));wire32(data,(uint32_t)value); }
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
    uint64_t deadline,int lock,int workspace) {
    struct stat admission,directory;
    if(fstat(lock,&admission)||fstat(workspace,&directory)||env.count>256)return nil;
    NSMutableData *data=[NSMutableData data];wire32(data,0x4b565331u);
    wire32(data,[e[@"descriptor"][@"task_ruid"] unsignedIntValue]);wire32(data,(uint32_t)argv.count);wire32(data,(uint32_t)env.count);
    wire64(data,deadline);wire64(data,(uint64_t)admission.st_dev);wire64(data,(uint64_t)admission.st_ino);
    wire64(data,(uint64_t)directory.st_dev);wire64(data,(uint64_t)directory.st_ino);
    if(!wireString(data,e[@"descriptor"][@"attempt_id"],64,false)||!wireString(data,gRuntimePins[argv[0]],64,false)
        ||!wireString(data,cwd,4096,false)||!wireString(data,sandboxProfile(e[@"descriptor"][@"workspace_path"]),131072,false))return nil;
    for(NSString *arg in argv)if(!wireString(data,arg,131072,true))return nil;
    for(NSString *key in utf8Sorted(env.allKeys))
        if(!wireString(data,[NSString stringWithFormat:@"%@=%@",key,env[key]],131329,false))return nil;
    return data;
}
static bool launchRun(NSMutableDictionary *e,NSDictionary *q,int client) {
    uint64_t commandStarted=nowMS();
    if(!validUIDAllocation(e)){closeAdmission(e,@"uid_allocation_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return false;}
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
    clean[@"HOME"]=workspace;clean[@"TMPDIR"]=workspace;
    int lock=admissionFD(e),workspaceFD=openWorkspace(e),cfg[2]={-1,-1},ready[2]={-1,-1},gate[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1};
    bool ok=lock>=0&&workspaceFD>=0&&flock(lock,LOCK_EX|LOCK_NB)==0;
    NSData *data=ok?stubConfiguration(e,argv,clean,cwd,commandDeadline,lock,workspaceFD):nil;
    ok=ok&&data&&[protectedFileSHA(gStubPath) isEqual:gStubBinarySHA];
    if(ok)ok=pipe(cfg)==0&&pipe(ready)==0&&pipe(gate)==0&&pipe(out)==0&&pipe(err)==0;
    if(ok&&nowMS()>=commandDeadline){closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);ok=false;}
    if(ok){
        /* A prior command's dead stub cannot resolve this new launch intent. */
        [e removeObjectForKey:@"launch_stub"];[e removeObjectForKey:@"command_identity"];
        e[@"spawn_intent"]=@YES;ok=persist();
    }
    posix_spawn_file_actions_t fa;posix_spawnattr_t attr;bool initialized=false;pid_t pid=0;
    if(ok){ok=posix_spawn_file_actions_init(&fa)==0&&posix_spawnattr_init(&attr)==0;initialized=ok;}
    if(ok){int null=open("/dev/null",O_RDONLY|O_CLOEXEC);ok=null>=0;
        int originals[]={null,out[1],err[1],cfg[0],ready[1],gate[0],lock,workspaceFD};
        int targets[]={0,1,2,10,11,12,13,14},sources[8];for(unsigned i=0;i<8;i++)sources[i]=-1;
        /* Duplicate sources above EVERY target before adding file actions.
         * Pipe allocation can otherwise collide with another dup2 target. */
        for(unsigned i=0;ok&&i<8;i++){sources[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,32);ok=sources[i]>=0;}
        for(unsigned i=0;ok&&i<8;i++)ok=posix_spawn_file_actions_adddup2(&fa,sources[i],targets[i])==0;
        if(ok)ok=posix_spawnattr_setflags(&attr,POSIX_SPAWN_CLOEXEC_DEFAULT)==0;
        char *args[]={(char *)gStubPath.fileSystemRepresentation,"--internal-child",NULL};
        char *environment[]={"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",NULL};
        if(ok&&nowMS()>=commandDeadline){closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);ok=false;}
        if(ok)ok=posix_spawn(&pid,gStubPath.fileSystemRepresentation,&fa,&attr,args,environment)==0;
        for(unsigned i=0;i<8;i++)if(sources[i]>=0)close(sources[i]);
        if(null>=0)close(null);
    }
    if(initialized){posix_spawn_file_actions_destroy(&fa);posix_spawnattr_destroy(&attr);}
    /* Close, never LOCK_UN: the spawned stub holds the SAME open description
     * until its all-private credentials are kernel-visible or it exits. */
    if(lock>=0)close(lock);
    if(workspaceFD>=0)close(workspaceFD);
    if(ok){close(cfg[0]);cfg[0]=-1;close(ready[1]);ready[1]=-1;close(gate[0]);gate[0]=-1;
        close(out[1]);out[1]=-1;close(err[1]);err[1]=-1;
        struct KIdentity identity;
        if(freshIdentity(pid,&identity)){e[@"launch_stub"]=identityJSON(&identity);ok=persist();}
        else ok=false;
        uint32_t n=htonl((uint32_t)data.length);NSMutableData *message=[NSMutableData dataWithBytes:&n length:4];[message appendData:data];
        gRunConfig=message;gRunConfigOffset=0;
        gRun=(struct KRun){.pid=pid,.client=client,.out=out[0],.err=err[0],.ready=ready[0],.gate=gate[1],.config=cfg[1],
            .deadline=commandDeadline};
        int *nonblocking[]={&gRun.out,&gRun.err,&gRun.ready,&gRun.config};
        for(unsigned i=0;i<4;i++){
            int flags=fcntl(*nonblocking[i],F_GETFL);
            if(flags<0||fcntl(*nonblocking[i],F_SETFL,flags|O_NONBLOCK)<0){
                close(*nonblocking[i]);*nonblocking[i]=-1;ok=false;
            }
        }
        if(!ok)closeAdmission(e,@"launch_publication_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return true; /* accepted transport, even when launch must be stopped */
    }
    int *fds[]={cfg,ready,gate,out,err};for(unsigned i=0;i<5;i++)for(unsigned j=0;j<2;j++)if(fds[i][j]>=0)close(fds[i][j]);
    /* Only this still-live daemon knows no process was spawned on a failed
     * posix_spawn. A restart never guesses that from a missing child ledger. */
    e[@"spawn_intent"]=@NO;persist();return false;
}

static NSDictionary *prepare(NSDictionary *q,struct KPeer *peer) {
    uint64_t started=nowMS();
    if(!kCapabilityQualified&&!gQualificationMode)return failure(@"CAPABILITY_UNQUALIFIED");
    if(!gEntryStoreLoaded||gPoisoned)return failure(@"REGISTRY_DURABILITY_UNCONFIRMED");
    if(peer->owner==0||peer->owner>=K_UID_FIRST)return failure(@"ORDINARY_OWNER_REQUIRED");
    if(![q[@"mode"] isEqual:@"isolated_copy"]||!hex64(q[@"attempt_nonce"]))return failure(@"INVALID_PREPARE");
    if(!validDuration(q[@"work_budget_ms"],K_MAX_WORK_MS))return failure(@"INVALID_WORK_BUDGET");
    if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))return failure(@"INVALID_CLEANUP_BUDGET");
    uint64_t budget=[q[@"work_budget_ms"] unsignedLongLongValue],deadline=started+budget;
    if(!refreshUIDHistory())return failure(@"UID_HISTORY_UNHEALTHY");
    if(nowMS()>=deadline)return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");
    NSString *active=activeID();if(active.length){NSMutableDictionary *prior=entryFor(active);
        if([prior[@"owner_uid"] unsignedIntValue]==peer->owner&&[prior[@"descriptor"][@"attempt_nonce"] isEqual:q[@"attempt_nonce"]])
            return @{ @"ok":@NO,@"error":@"ATTEMPT_ALREADY_RESERVED",@"attempt_id":active,@"descriptor":prior[@"descriptor"],@"descriptor_sha256":prior[@"descriptor_sha256"] };
        return failure(@"ATTEMPT_ACTIVE");}
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));if(!pids)return failure(@"ALLOCATION_FAILED");
    uid_t uid=0;NSString *id=randomHex();NSDictionary *allocation=nil;
    for(unsigned i=0;i<1000&&nowMS()<deadline;i++){
        NSDictionary *candidate=[gUIDHistory consumeUIDForPlannedAttempt:id boot:gBoot.lowercaseString error:NULL];
        if(!candidate)break;
        /* Burn journal -> independent head -> actual registry, then confirm
         * before even inspecting this candidate. Never reuse failed candidates. */
        gRegistry[@"uid_history_checkpoint"]=gUIDHistory.checkpoint;
        if(!persist()||![gUIDHistory confirmRegistryCheckpointWithError:NULL]||nowMS()>=deadline)break;
        uid_t next=[candidate[@"uid"] unsignedIntValue];int count=members(next,pids);
        if(count<0)break;if(count>0)continue;if(nowMS()>=deadline)break;
        errno=0;struct passwd *account=getpwuid(next);int accountError=errno;
        if(nowMS()>=deadline)break;if(account)continue;if(accountError)break;
        errno=0;struct group *group=getgrgid((gid_t)next);int groupError=errno;
        if(nowMS()>=deadline)break;if(group)continue;if(groupError)break;
        if(nowMS()>=deadline)break;uid=next;allocation=candidate;break;}
    free(pids);
    if(nowMS()>=deadline)return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");
    if(!uid||gPoisoned||!gUIDHistory.healthy||!allocation)return failure(@"UID_RESERVATION_UNAVAILABLE");
    NSString *token=randomHex();
    NSString *workspacePath=pathChild(gWorkspaceRoot,id);
    NSDictionary *descriptor=@{@"schema":@"knowledge-darwin-private-ruid-descriptor.v1",@"backend":@"darwin_private_ruid",
        @"boundary_id":id,@"attempt_id":id,@"attempt_nonce":q[@"attempt_nonce"],@"task_ruid":@(uid),@"task_gid":@(uid),
        @"owner_uid":@(peer->owner),@"host_id":gHost,@"boot_id":gBoot,@"mode":@"isolated_copy",
        @"installation_id":allocation[@"installation_id"],@"allocation_seq":allocation[@"seq"],@"allocation_sha256":allocation[@"sha256"],
        @"uid_history_header_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_HEADER_SHA,
        @"uid_history_source_sha256":@KNOWLEDGE_DARWIN_UID_HISTORY_SOURCE_SHA,
        @"work_budget_ms":@(budget),@"cleanup_budget_ms":q[@"cleanup_budget_ms"],
        @"work_started_monotonic_ms":@(started),@"work_deadline_ms":@(deadline),
        @"workspace_path":workspacePath,@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"broker_binary_sha256":gBinarySHA,@"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,
        @"stub_binary_sha256":gStubBinarySHA,@"stub_wire_version":@"KVS1",
        @"allowed_runtimes":gRuntimePins,@"profile_sha256":sha([sandboxProfile(workspacePath) dataUsingEncoding:NSUTF8StringEncoding]),
        @"broker_creation_parent_is_launchd":@(gLaunchdCreationParent),
        @"capability_qualified":@(kCapabilityQualified),@"qualification_mode":@(gQualificationMode),
        @"scope":@"private_command_ruid_plus_exact_registered_authority;trusted_controller_and_persistent_broker_excluded"};
    NSMutableDictionary *e=[@{@"descriptor":descriptor,@"descriptor_sha256":sha(jsonData(descriptor)),@"owner_uid":@(peer->owner),
        @"token_sha256":sha([token dataUsingEncoding:NSUTF8StringEncoding]),@"controller":identityJSON(&peer->parent),@"state":@"reserved",
        @"admission_closed":@NO,@"spawn_intent":@NO,@"authority_spawn_intent":@NO,@"files":@0,@"bytes":@0,
        @"manifest":[NSMutableDictionary dictionary],@"directories":[NSMutableDictionary dictionary],
        @"work_started_monotonic_ms":@(started),@"work_budget_ms":@(budget),
        @"work_deadline_ms":@(deadline),@"cleanup_budget_ms":q[@"cleanup_budget_ms"]} mutableCopy];
    entries()[id]=e;gRegistry[@"active_attempt"]=id;
    /* Reservation and immutable descriptor are fsync/readback BEFORE any
     * private-owned inode, admission lock, stub, or command can exist. */
    if(!persist())return failure(@"RESERVATION_DURABILITY_FAILED");
    if(!validUIDAllocation(e)||nowMS()>=deadline){closeAdmission(e,@"reservation_history_or_budget_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return failure(@"RESERVATION_HISTORY_OR_BUDGET_UNCONFIRMED");}
    NSString *lockName=[id stringByAppendingString:@".admission"];
    int lock=openat(gRegistryFD,lockName.UTF8String,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat admission;bool ok=lock>=0&&fstat(lock,&admission)==0&&fsync(lock)==0&&fsync(gRegistryFD)==0;
    if(ok){e[@"admission_inode"]=@{@"device":@((uint64_t)admission.st_dev),@"inode":@((uint64_t)admission.st_ino)};ok=persist();}
    if(lock>=0)close(lock);
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
    if(!ok){closeAdmission(e,@"workspace_preparation_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);return failure(@"WORKSPACE_PREPARATION_FAILED");}
    e[@"state"]=@"copying";if(!persist())return failure(@"PREPARATION_DURABILITY_FAILED");
    if(nowMS()>=deadline){closeAdmission(e,@"work_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        return failure(@"WORK_BUDGET_EXCEEDED_PREPARATION");}
    return @{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":id,@"descriptor":descriptor,@"descriptor_sha256":e[@"descriptor_sha256"],
        @"workspace_path":descriptor[@"workspace_path"],@"token":token,@"capability":kCapabilityQualified?@"qualified":@"unqualified"};
}

static NSDictionary *statusReply(NSMutableDictionary *e) {
    bool allocationVerified=validUIDAllocation(e);
    NSMutableDictionary *r=[@{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor":e[@"descriptor"],@"descriptor_sha256":e[@"descriptor_sha256"],@"state":e[@"state"],
        @"admission_closed":e[@"admission_closed"],@"spawn_intent":e[@"spawn_intent"],
        @"authority_spawn_intent":e[@"authority_spawn_intent"],@"capability_qualified":@(kCapabilityQualified),
        @"work_budget_ms":e[@"work_budget_ms"]?:NSNull.null,@"cleanup_budget_ms":e[@"cleanup_budget_ms"],
        @"work_started_monotonic_ms":e[@"work_started_monotonic_ms"]?:NSNull.null,
        @"work_deadline_monotonic_ms":e[@"work_deadline_ms"],
        @"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"]?:NSNull.null,
        @"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"]?:NSNull.null,
        @"cleanup_budget_exceeded":e[@"cleanup_budget_exceeded"]?:@NO,
        @"stop_reason":e[@"stop_reason"]?:NSNull.null,@"registry_healthy":@((bool)!gPoisoned),
        @"registry_quarantine_reason":gQuarantineReason?:NSNull.null,
        @"entry_store_loaded":@(gEntryStoreLoaded),@"uid_history":uidHistoryStatus(false),
        @"allocation_tuple_verified_current":@(allocationVerified),
        @"sandbox_profile":sandboxProfile(e[@"descriptor"][@"workspace_path"])} mutableCopy];
    if(e[@"proof"])r[@"proof"]=e[@"proof"];
    if(e[@"command_drain_proof"])r[@"command_drain_proof"]=e[@"command_drain_proof"];return r;
}
static void handleClient(int fd) {
    struct KPeer peer;if(!authenticate(fd,&peer)){sendJSON(fd,failure(@"PEER_AUTHENTICATION_FAILED"));close(fd);return;}
    NSDictionary *q=parseJSON(receiveRequest(fd));NSString *op=q[@"op"];NSDictionary *reply=nil;
    if(!q||!isString(op,64)||!requestTypes(q)||![q[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA])reply=failure(@"PROTOCOL_OR_SOURCE_PIN_MISMATCH");
    else if([op isEqual:@"probe"]){
        /* Refresh can quarantine the entry store. Construct every health field
         * only after that observation; literal evaluation order is no guard. */
        NSDictionary *history=uidHistoryStatus(true);
        reply=@{@"ok":@YES,@"schema":K_SCHEMA,@"capability_qualified":@(kCapabilityQualified),
        @"qualification_mode":@(gQualificationMode),@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"binary_sha256":gBinarySHA,
        @"stub_source_sha256":@KNOWLEDGE_DARWIN_STUB_SOURCE_SHA,@"stub_binary_sha256":gStubBinarySHA,@"stub_wire_version":@"KVS1",
        @"host_id":gHost,@"boot_id":gBoot,@"allowed_runtimes":gRuntimePins,@"registry_healthy":@((bool)!gPoisoned),
        @"registry_quarantine_reason":gQuarantineReason?:NSNull.null,
        @"entry_store_loaded":@(gEntryStoreLoaded),@"uid_history":history};}
    /* A failed write forbids new work, not an authenticated best-effort stop
     * of a known owned reservation or read-only status. Unknown ownership
     * remains quarantined and never gains signal authority through recovery. */
    else if(gPoisoned&&![@[@"status",@"lookup",@"close",@"recover"] containsObject:op])reply=failure(gQuarantineReason?:@"REGISTRY_DURABILITY_UNCONFIRMED");
    else if(![@[@"prepare",@"status",@"lookup",@"close",@"recover"] containsObject:op]&&!gUIDHistory.healthy)reply=failure(@"UID_HISTORY_UNHEALTHY");
    else if([op isEqual:@"prepare"])reply=prepare(q,&peer);
    else if([op isEqual:@"lookup"]){NSMutableDictionary *found=nil;
        if(hex64(q[@"attempt_nonce"]))for(NSString *id in entries()){
            NSMutableDictionary *e=entryFor(id);
            if(e&&validRecordedEntry(e,id)&&[e[@"owner_uid"] unsignedIntValue]==peer.owner
                &&[e[@"descriptor"][@"attempt_nonce"] isEqual:q[@"attempt_nonce"]]){found=e;break;}}
        reply=found?statusReply(found):failure(@"RESERVATION_UNKNOWN");
    }else{NSMutableDictionary *e=hex64(q[@"attempt_id"])?entryFor(q[@"attempt_id"]):nil;
        bool publicOperation=[@[@"status",@"close",@"recover"] containsObject:op];
        if(!authenticatedEntry(e,q,&peer,!publicOperation))reply=failure(@"ATTEMPT_AUTHENTICATION_FAILED");
        else if(publicOperation){
            if([op isEqual:@"status"]||[e[@"state"] isEqual:@"closed"])reply=statusReply(e);
            else if(!validDuration(q[@"cleanup_budget_ms"],K_MAX_CLEANUP_MS))reply=failure(@"INVALID_CLEANUP_BUDGET");
            else if(gCloseWaiter>=0&&gDrainOnly){
                /* A waiting drain reply cannot block explicit terminal stop.
                 * Reject that phase's waiter, then bind the bounded terminal
                 * reply to this caller. No second waiter list or new epoch. */
                int interrupted=gCloseWaiter;gCloseWaiter=-1;
                bool durable=closeAdmission(e,[op isEqual:@"recover"]?@"recovery_during_command_drain":@"terminal_stop_during_command_drain",
                    [q[@"cleanup_budget_ms"] unsignedLongLongValue]);
                sendJSON(interrupted,failure(@"COMMAND_DRAIN_INTERRUPTED_BY_TERMINAL_STOP"));close(interrupted);
                if(durable){gCloseWaiter=fd;return;}else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
            }else if(gCloseWaiter>=0)reply=failure(@"CLEANUP_BUSY");
            else if(closeAdmission(e,[op isEqual:@"recover"]?@"recovery_requested":@"close_requested",[q[@"cleanup_budget_ms"] unsignedLongLongValue])){
                gCloseWaiter=fd;return;
            }else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
        }else if(![op isEqual:@"run"]&&!validUIDAllocation(e)){
            closeAdmission(e,@"uid_allocation_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);reply=failure(@"UID_HISTORY_OR_ALLOCATION_UNCONFIRMED");
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
            if(gRun.pid)reply=failure(@"COMMAND_BUSY");else if(launchRun(e,q,fd))return;else reply=failure(@"COMMAND_REJECTED");
        }else reply=failure(@"INVALID_TRANSITION");
    }
    sendJSON(fd,reply?:failure(@"INVALID_REQUEST"));close(fd);
}

static void drainOutput(int *fd,char type) {
    if(*fd<0)return;unsigned char b[32768];
    for(unsigned i=0;i<8;i++){ssize_t n=read(*fd,b,sizeof(b));
        if(n>0){if(gRun.client>=0&&!sendFrame(gRun.client,type,[NSData dataWithBytes:b length:(NSUInteger)n])){
                close(gRun.client);gRun.client=-1;NSMutableDictionary *e=entryFor(activeID());
                if(e)closeAdmission(e,@"run_transport_lost",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}continue;}
        if(n==0){close(*fd);*fd=-1;}else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR){close(*fd);*fd=-1;}break;
    }
}
static void advanceRun(void) {
    if(!gRun.pid)return;NSMutableDictionary *e=entryFor(activeID());
    if(gRun.config>=0){
        /* Configuration transfer must not block the sole stop/status loop. */
        const unsigned char *bytes=gRunConfig.bytes;
        size_t left=gRunConfig.length-gRunConfigOffset;
        ssize_t n=write(gRun.config,bytes+gRunConfigOffset,MIN(left,(size_t)16384));
        if(n>0)gRunConfigOffset+=(size_t)n;
        else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)
            closeAdmission(e,@"configuration_pipe_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        if(gRun.config>=0&&gRunConfigOffset==gRunConfig.length){close(gRun.config);gRun.config=-1;gRunConfig=nil;}
    }
    if(!gRun.ready_seen&&gRun.ready>=0){char c;ssize_t n=read(gRun.ready,&c,1);
        if(n==1){struct KIdentity child;bool valid=c=='R'&&freshIdentity(gRun.pid,&child)
                &&sameBirth(e[@"launch_stub"],&child)&&child.bsd.pbi_ruid==[e[@"descriptor"][@"task_ruid"] unsignedIntValue]
                &&child.bsd.pbi_uid==child.bsd.pbi_ruid&&child.bsd.pbi_svuid==child.bsd.pbi_ruid
                &&child.bsd.pbi_rgid==child.bsd.pbi_ruid&&child.bsd.pbi_gid==child.bsd.pbi_ruid&&child.bsd.pbi_svgid==child.bsd.pbi_ruid;
            gRun.ready_seen=true;close(gRun.ready);gRun.ready=-1;
            if(valid){e[@"command_identity"]=identityJSON(&child);e[@"spawn_intent"]=@NO;valid=persist();}
            if(valid)valid=validUIDAllocation(e);
            if(valid&&gRun.gate>=0&&![e[@"admission_closed"] boolValue]&&nowMS()<gRun.deadline){char go='G';if(write(gRun.gate,&go,1)!=1)valid=false;}
            else valid=false;
            close(gRun.gate);gRun.gate=-1;
            if(!valid)closeAdmission(e,@"child_publication_or_permit_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        }else if(n==0){close(gRun.ready);gRun.ready=-1;closeAdmission(e,@"child_setup_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    }
    if(gRun.client>=0){char c;ssize_t n=recv(gRun.client,&c,1,MSG_PEEK|MSG_DONTWAIT);
        if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)){
            close(gRun.client);gRun.client=-1;closeAdmission(e,@"run_client_lost",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}}
    if(nowMS()>=gRun.deadline&&![e[@"admission_closed"] boolValue])closeAdmission(e,@"command_budget_exceeded",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
    if(!gRun.exited){pid_t p=waitpid(gRun.pid,&gRun.status,WNOHANG);if(p==gRun.pid)gRun.exited=true;
        else if(p<0&&errno!=EINTR)closeAdmission(e,@"command_wait_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    drainOutput(&gRun.out,'O');drainOutput(&gRun.err,'E');
    if(gRun.exited&&gRun.out<0&&gRun.err<0){if(gRun.client>=0){sendJSON(gRun.client,@{@"ok":@YES,
            @"exit_code":WIFEXITED(gRun.status)?@(WEXITSTATUS(gRun.status)):(id)NSNull.null,
            @"signal":WIFSIGNALED(gRun.status)?@(WTERMSIG(gRun.status)):(id)NSNull.null,
            @"admission_closed":e[@"admission_closed"],@"capability_qualified":@(kCapabilityQualified)});close(gRun.client);}
        if(gRun.ready>=0)close(gRun.ready);if(gRun.gate>=0)close(gRun.gate);if(gRun.config>=0)close(gRun.config);
        gRunConfig=nil;
        gRun=(struct KRun){.client=-1,.out=-1,.err=-1,.ready=-1,.gate=-1,.config=-1};}
}
static void advanceCleanup(void) {
    if(!gClosing)return;NSMutableDictionary *e=gClosing;int lock=acquireCleanupBarrier(e);bool excluded=lock>=0;
    /* Every UID-wide signal and positive boundary proof requires current disk
     * history plus this exact tuple. Cached healthy never grants that scope. */
    bool uidExclusive=validUIDAllocation(e);
    /* A captured, exact owned launch stub may still hold the barrier before
     * credential drop. Never infer its exit from a private-UID zero scan. */
    bool stubObserved=true;
    if([e[@"spawn_intent"] boolValue]&&e[@"launch_stub"]){struct KIdentity stub;int rc=observeExact(e[@"launch_stub"],&stub);
        if(rc==0){e[@"spawn_intent"]=@NO;persist();}
        else if(rc<0)stubObserved=false;
        else if(stub.bsd.pbi_ruid==0){if(!signalExact(e[@"launch_stub"],0))stubObserved=false;}
        else if(stub.bsd.pbi_ruid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue])stubObserved=false;
        else if(!uidExclusive&&!signalExact(e[@"launch_stub"],stub.bsd.pbi_ruid))stubObserved=false;
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
        bool drainFacts=uidExclusive&&excluded&&zero&&observed&&intents&&!gRun.pid&&ownerAlive&&!gPoisoned;
        if(!ownerAlive||gStopping||gPoisoned||!uidExclusive||nowMS()>=gCloseDeadline){
            NSString *reason=gStopping?@"daemon_stopping":gPoisoned?@"registry_durability_unconfirmed":
                !uidExclusive?@"uid_history_or_allocation_unconfirmed":!ownerAlive?@"drain_owner_exit_or_observation_unconfirmed":@"cleanup_budget_exceeded";
            if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
            closeAdmission(e,reason,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            /* Full cleanup in the next scheduler turn, with the SAME epoch. */
            if(lock>=0)close(lock);return;
        }
        if(!drainFacts){if(lock>=0)close(lock);return;}
        NSDictionary *proof=@{@"schema":@"knowledge-darwin-command-drain-proof.v1",@"phase":@"commands_drained",
            @"attempt_id":e[@"descriptor"][@"attempt_id"],@"descriptor_sha256":e[@"descriptor_sha256"],
            @"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"host_id":gHost,@"boot_id":gBoot,
            @"installation_id":e[@"descriptor"][@"installation_id"],@"allocation_seq":e[@"descriptor"][@"allocation_seq"],
            @"allocation_sha256":e[@"descriptor"][@"allocation_sha256"],@"uid_history_tuple_verified":@YES,
            @"task_ruid":e[@"descriptor"][@"task_ruid"],@"admission_closed":@YES,
            @"spawn_exclusion_acquired":@YES,@"spawn_exclusion_held_until_terminal":@YES,
            @"spawn_intents_resolved":@YES,@"kernel_membership_zero":@YES,@"registered_authority_alive":@YES,
            @"authority_identity":e[@"authority"],@"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"],
            @"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"],@"observed_monotonic_ms":@(nowMS()),
            @"native_command_drain_facts_confirmed":@YES,@"capability_qualified":@(kCapabilityQualified),
            @"command_drain_confirmed":@(kCapabilityQualified),@"terminal_cleanup":@NO,
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
        if(!historyStillConfirmed||nowMS()>=gCloseDeadline||observeExact(e[@"controller"],&currentOwner)!=1
            ||observeExact(e[@"authority"],&currentOwner)!=1){
            if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
            closeAdmission(e,@"drain_completion_expired_or_owner_unconfirmed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
            if(lock>=0)close(lock);return;
        }
        if(gCloseWaiter>=0){sendJSON(gCloseWaiter,statusReply(e));close(gCloseWaiter);gCloseWaiter=-1;}
        /* Keep the shared OFD in gCleanupBarrier, and keep active_attempt. */
        if(lock>=0)close(lock);gClosing=nil;gDrainOnly=false;return;
    }
    bool facts=uidExclusive&&excluded&&zero&&authorityExited&&observed&&intents&&!gRun.pid;
    if(!facts&&nowMS()<gCloseDeadline){if(lock>=0)close(lock);return;}
    if(nowMS()>=gCloseDeadline)e[@"cleanup_budget_exceeded"]=@YES;
    bool confirmed=facts&&!gPoisoned&&validUIDAllocation(e);NSString *state=confirmed?@"closed":@"cleanup_unconfirmed";
    NSDictionary *proof=@{@"schema":@"knowledge-darwin-private-ruid-proof.v1",@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor_sha256":e[@"descriptor_sha256"],@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"host_id":gHost,@"boot_id":gBoot,@"task_ruid":e[@"descriptor"][@"task_ruid"],
        @"installation_id":e[@"descriptor"][@"installation_id"],@"allocation_seq":e[@"descriptor"][@"allocation_seq"],
        @"allocation_sha256":e[@"descriptor"][@"allocation_sha256"],@"uid_history_tuple_verified":@((bool)(confirmed&&uidExclusive)),
        @"admission_closed":e[@"admission_closed"],@"spawn_exclusion_acquired":@(excluded),@"spawn_intents_resolved":@(intents),
        @"kernel_membership_method":@"proc_listpids(PROC_RUID_ONLY,nonnull_buffer);active_and_zombie_lists",
        @"kernel_membership_zero":@(zero),@"registered_authority_exited":@(authorityExited),
        @"authority_identity":e[@"authority"]?:NSNull.null,@"controller_identity":e[@"controller"],
        @"controller_excluded_from_boundary":@YES,@"persistent_broker_excluded_from_boundary":@YES,
        @"native_cleanup_facts_confirmed":@(confirmed),@"capability_qualified":@(kCapabilityQualified),
        @"cleanup_confirmed":@((bool)(confirmed&&kCapabilityQualified)),@"state":state,@"receipt_kind":@"root_registry_not_os_signed_attestation",
        @"phase":@"terminal",@"terminal_cleanup":@YES,
        @"command_drain_sha256":e[@"command_drain_sha256"]?:NSNull.null,
        @"cleanup_started_monotonic_ms":e[@"cleanup_started_monotonic_ms"],@"cleanup_deadline_monotonic_ms":e[@"cleanup_deadline_ms"],
        @"cleanup_budget_exceeded":e[@"cleanup_budget_exceeded"],
        @"observed_monotonic_ms":@(nowMS())};
    /* No env, output, tokens, arbitrary paths, or source contents in receipts. */
    if(jsonData(proof).length>65536){gPoisoned=true;confirmed=false;}
    NSString *receipt=[NSString stringWithFormat:@"%@.%@.receipt.json",e[@"descriptor"][@"attempt_id"],sha(jsonData(proof))];
    bool durable=saveJSON(receipt,proof);
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
    NSString *priorActive=activeID();
    if(durable&&confirmed)gRegistry[@"active_attempt"]=@"";
    bool registryDurable=persist();
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
    NSDictionary *reply=registryDurable?statusReply(e):failure(@"CLEANUP_RECEIPT_DURABILITY_UNCONFIRMED");
    if(gCloseWaiter>=0){sendJSON(gCloseWaiter,reply);close(gCloseWaiter);gCloseWaiter=-1;}
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
    gBoot=sysctlString("kern.bootsessionuuid");uuid_t hostUUID;struct timespec timeout={2,0};
    if(gethostuuid(hostUUID,&timeout)==0){uuid_string_t text;uuid_unparse_lower(hostUUID,text);gHost=@(text);}
    if(!gBoot.length||!gHost.length)return false;
    gSetupStage="protected-allowed-runtime-pins";
    NSMutableDictionary *pins=[NSMutableDictionary dictionary];
    for(NSString *runtime in gRuntimes){NSString *digest=protectedFileSHA(runtime);if(!digest)return false;pins[runtime]=digest;}
    gRuntimePins=pins;return true;
}
static int initInstall(void) {
    if(!gUIDRangeConfirmed)return 64;
    if(!nativePrerequisites()){fprintf(stderr,"init prerequisite failure: %s (errno=%d)\n",gSetupStage,errno);return 78;}
    NSError *error=nil;
    gUIDHistory=[KVDarwinUIDHistory beginInitializationWithConfiguration:historyConfiguration() error:&error];
    if(!gUIDHistory||![gUIDHistory.reason isEqual:@"INITIALIZATION_PENDING"]||!gUIDHistory.checkpoint){
        fprintf(stderr,"explicit init failed: %s\n",gUIDHistory.reason.UTF8String?:"UNAVAILABLE");return 78;}
    /* Explicit fresh initialization only. No existing registry is overwritten,
     * including one that appeared after the component's empty-tree preflight. */
    struct stat prior;if(fstatat(gRegistryFD,"registry.json",&prior,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return 78;
    gRegistry=[@{@"schema":K_SCHEMA,@"attempts":[NSMutableDictionary dictionary],@"active_attempt":@"",
        @"installation_id":gUIDHistory.installationID,@"uid_history_checkpoint":gUIDHistory.checkpoint} mutableCopy];
    if(!initializeRegistry()||![gUIDHistory finalizeInitializationWithError:&error]){
        fprintf(stderr,"explicit init remains unconfirmed; no reset: %s\n",gUIDHistory.reason.UTF8String?:"REGISTRY_WRITE_FAILED");return 78;}
    gEntryStoreLoaded=true;
    NSDictionary *reply=@{@"ok":@YES,@"schema":@"knowledge-darwin-install-result.v1",
        @"installation_id":gUIDHistory.installationID,@"uid_history_checkpoint":gUIDHistory.checkpoint,
        @"capability_qualified":@NO,@"uid_range_admin_asserted":@YES};
    NSData *bytes=jsonData(reply);unsigned char newline='\n';
    return exactIO(1,(void *)bytes.bytes,bytes.length,true)&&exactIO(1,&newline,1,true)?0:74;
}
static bool startup(void) {
    if(!nativePrerequisites())return false;
    gSetupStage="system-creation-lineage-or-explicit-diagnostic";
    if(!gQualificationMode&&!gLaunchdCreationParent)return false;
    gSetupStage="open-existing-independent-UID-history-singleton";
    gUIDHistory=[KVDarwinUIDHistory openWithConfiguration:historyConfiguration() error:NULL];
    /* No safe singleton means no listener; an acquired but unhealthy history
     * permits independently authenticated status/exact-target recovery only. */
    if(!gUIDHistory)return false;
    gSetupStage="load-existing-protected-registry-never-create";
    int fd=openat(gRegistryFD,"registry.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
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
    if(activeID().length){NSMutableDictionary *e=entryFor(activeID());
        if(!e||!validRecordedEntry(e,activeID())||![e[@"descriptor"][@"boot_id"] isEqual:gBoot]||![e[@"descriptor"][@"host_id"] isEqual:gHost]){
            gPoisoned=true;gQuarantineReason=@"REGISTRY_DESCRIPTOR_BOOT_HOST_OR_OWNERSHIP_UNKNOWN";
        }else closeAdmission(e,@"daemon_restart",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    gSetupStage="protected-listener-bind";
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
    if(strlen(gSocketPath.fileSystemRepresentation)>=sizeof(addr.sun_path))return false;
    strlcpy(addr.sun_path,gSocketPath.fileSystemRepresentation,sizeof(addr.sun_path));
    struct stat old;if(lstat(addr.sun_path,&old)==0){if(!S_ISSOCK(old.st_mode)||old.st_uid!=0)return false;if(unlink(addr.sun_path))return false;}
    else if(errno!=ENOENT)return false;
    gListen=socket(AF_UNIX,SOCK_STREAM,0);if(gListen<0)return false;fcntl(gListen,F_SETFD,FD_CLOEXEC);
    mode_t previous=umask(0077);int bound=bind(gListen,(struct sockaddr *)&addr,sizeof(addr));umask(previous);
    if(bound||chmod(addr.sun_path,0666)||listen(gListen,16))return false;return true;
}
static int serve(void) {
    if(!startup()){fprintf(stderr,"broker setup/prerequisite failure: %s (errno=%d)\n",gSetupStage,errno);return 78;}
    signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
    for(;;){@autoreleasepool{
        NSMutableDictionary *e=activeID().length?entryFor(activeID()):nil;
        bool known=e&&validRecordedEntry(e,activeID())&&[e[@"descriptor"][@"boot_id"] isEqual:gBoot]&&[e[@"descriptor"][@"host_id"] isEqual:gHost];
        bool drained=[e[@"state"] isEqual:@"commands_drained"];
        if(known&&!gClosing&&(![e[@"admission_closed"] boolValue]||drained)){struct KIdentity v;
            int controller=observeExact(e[@"controller"],&v),authority=e[@"authority"]?observeExact(e[@"authority"],&v):1;
            NSString *reason=gStopping?@"daemon_stopping":gPoisoned?@"registry_durability_unconfirmed":!gUIDHistory.healthy?@"uid_history_unhealthy":controller<0||authority<0?@"owner_observation_unconfirmed":
                controller==0||authority==0?@"owner_exited":drained&&nowMS()>=[e[@"cleanup_deadline_ms"] unsignedLongLongValue]?@"cleanup_budget_exceeded":
                !drained&&nowMS()>=[e[@"work_deadline_ms"] unsignedLongLongValue]?@"work_budget_exceeded":nil;
            if([reason isEqual:@"cleanup_budget_exceeded"])e[@"cleanup_budget_exceeded"]=@YES;
            if(reason)closeAdmission(e,reason,[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
        advanceRun();advanceCleanup();
        if(gStopping&&!gClosing&&!gRun.pid)break;
        struct pollfd p={gListen,POLLIN,0};int r=poll(&p,1,20);
        if(r>0&&(p.revents&POLLIN)){int client=accept(gListen,NULL,NULL);if(client>=0){fcntl(client,F_SETFD,FD_CLOEXEC);handleClient(client);}}
    }}
    close(gListen);return 0;
}
static int client(bool run) {
    if(!hex64(@KNOWLEDGE_BROKER_SOURCE_SHA)||!protectedFileSHA(gExecutable)
        ||!canonicalAbsolute(gSocketPath)||!protectedPath(pathParent(gSocketPath),false,true))return 78;
    struct stat st;if(lstat(gSocketPath.fileSystemRepresentation,&st)||!S_ISSOCK(st.st_mode)||st.st_uid!=0)return 78;
    NSMutableData *input=[NSMutableData data];unsigned char bytes[32768];ssize_t n;
    while((n=read(0,bytes,sizeof(bytes)))>0){if(input.length+(NSUInteger)n>K_MAX_JSON)return 64;[input appendBytes:bytes length:(NSUInteger)n];}
    if(n<0)return 74;NSMutableDictionary *q=[parseJSON(input) mutableCopy];if(!q)return 64;
    if(run&&![q[@"op"] isEqual:@"run"])return 64;if(!run&&[q[@"op"] isEqual:@"run"])return 64;
    q[@"source_sha256"]=@KNOWLEDGE_BROKER_SOURCE_SHA;NSData *data=jsonData(q);
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;if(strlen(gSocketPath.fileSystemRepresentation)>=sizeof(addr.sun_path))return 64;
    strlcpy(addr.sun_path,gSocketPath.fileSystemRepresentation,sizeof(addr.sun_path));int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0||connect(fd,(struct sockaddr *)&addr,sizeof(addr)))return 69;
    uid_t uid;gid_t gid;pid_t pid;socklen_t len=sizeof(pid);
    char image[PROC_PIDPATHINFO_MAXSIZE];NSString *selfSHA=protectedFileSHA(gExecutable);
    if(getpeereid(fd,&uid,&gid)||uid!=0||getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&len)||len!=sizeof(pid)
        ||proc_pidpath(pid,image,sizeof(image))<=0||![protectedFileSHA(@(image)) isEqual:selfSHA]){close(fd);return 77;}
    uint32_t size=htonl((uint32_t)data.length);if(!exactIO(fd,&size,4,true)||!exactIO(fd,(void *)data.bytes,data.length,true)){close(fd);return 74;}
    /* Keep both socket directions open: daemon treats run-client EOF as loss. */
    bool got=false;int result=74;
    for(;;){unsigned char header[5];if(!exactIO(fd,header,5,false))break;memcpy(&size,header+1,4);size=ntohl(size);
        if(size>K_MAX_JSON)break;NSMutableData *body=[NSMutableData dataWithLength:size];if(!exactIO(fd,body.mutableBytes,size,false))break;
        if(header[0]=='J'){NSDictionary *reply=parseJSON(body);if(!reply)break;
            int target=run?3:1;unsigned char newline='\n';if(!exactIO(target,body.mutableBytes,body.length,true)||!exactIO(target,&newline,1,true))break;
            got=true;result=[reply[@"ok"] boolValue]?0:1;break;
        }else if(run&&(header[0]=='O'||header[0]=='E')){if(!exactIO(header[0]=='O'?1:2,body.mutableBytes,body.length,true))break;}
        else break;
    }
    close(fd);return got?result:74;
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
    NSMutableArray *runtimes=[NSMutableArray array];NSString *mode=nil;bool stateOptions=false;
    for(int i=1;i<argc;i++){NSString *s=@(argv[i]);
        if([@[@"--serve",@"--init-install",@"--request",@"--run",@"--print-profile"] containsObject:s]){if(mode)return 64;mode=s;}
        else if([s isEqual:@"--qualification-mode"])gQualificationMode=true;
        else if([s isEqual:@"--confirm-reserved-uid-range=1000000000:1900000000"])gUIDRangeConfirmed=true;
        else if([s hasPrefix:@"--registry="]){gRegistryPath=[s substringFromIndex:11];stateOptions=true;}
        else if([s hasPrefix:@"--allocator="]){gAllocatorPath=[s substringFromIndex:12];stateOptions=true;}
        else if([s hasPrefix:@"--anchors="]){gAnchorPath=[s substringFromIndex:10];stateOptions=true;}
        else if([s hasPrefix:@"--socket="])gSocketPath=[s substringFromIndex:9];
        else if([s hasPrefix:@"--workspaces="]){gWorkspaceRoot=[s substringFromIndex:13];stateOptions=true;}
        else if([s hasPrefix:@"--workspace="])gPrintWorkspace=[s substringFromIndex:12];
        else if([s hasPrefix:@"--runtime="])[runtimes addObject:[s substringFromIndex:10]];
        else return 64;
    }
    for(NSString *path in [runtimes arrayByAddingObjectsFromArray:@[gRegistryPath,gSocketPath,gWorkspaceRoot,gAllocatorPath,gAnchorPath]])
        if(!canonicalAbsolute(path))return 64;
    gRuntimes=runtimes;
    if([mode isEqual:@"--print-profile"]){
        if(gQualificationMode||gUIDRangeConfirmed||stateOptions||!runtimes.count||!canonicalAbsolute(gPrintWorkspace))return 64;
        NSData *profile=[sandboxProfile(gPrintWorkspace) dataUsingEncoding:NSUTF8StringEncoding];
        return exactIO(1,(void *)profile.bytes,profile.length,true)?0:74;
    }
    if(gPrintWorkspace)return 64;
    bool serving=[mode isEqual:@"--serve"],initializing=[mode isEqual:@"--init-install"];
    if(serving||initializing){
        if(getuid()!=0||geteuid()!=0||!runtimes.count)return 64;
        bool canonical=[gRegistryPath isEqual:canonicalState]&&[gAllocatorPath isEqual:canonicalAllocator]
            &&[gAnchorPath isEqual:canonicalAnchors]&&[gWorkspaceRoot isEqual:canonicalWorkspaces]&&[gSocketPath isEqual:canonicalSocket];
        if(!canonical&&!gQualificationMode)return 64;
        if(!canonical){
            /* A diagnostic fixture selects ALL five roots outside every
             * production sibling. Partial overrides must never touch defaults,
             * even before native prerequisite inspection or singleton open. */
            NSArray *production=@[canonicalState,canonicalAllocator,canonicalAnchors,canonicalWorkspaces,pathParent(canonicalSocket)];
            for(NSString *path in @[gRegistryPath,gAllocatorPath,gAnchorPath,gWorkspaceRoot,gSocketPath])
                for(NSString *root in production)if([path isEqual:root]||[path hasPrefix:[root stringByAppendingString:@"/"]]
                    ||[root hasPrefix:[path stringByAppendingString:@"/"]])return 64;
        }
        if(serving&&gUIDRangeConfirmed)return 64;
        return initializing?initInstall():serve();
    }
    if(gQualificationMode||gUIDRangeConfirmed||stateOptions||runtimes.count)return 64;
    /* Ordinary native request/profile clients can select a protected socket;
     * they neither initialize nor open allocator state. */
    if([mode isEqual:@"--request"])return client(false);
    if([mode isEqual:@"--run"])return client(true);
    return 64;
}}
