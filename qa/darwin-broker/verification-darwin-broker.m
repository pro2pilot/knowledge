/*
 * Explicitly installed macOS isolated-copy verification broker.
 *
 * Build: clang -fobjc-arc -Wall -Wextra -Wno-deprecated-declarations -framework Foundation
 *   -DKNOWLEDGE_BROKER_SOURCE_SHA='"<sha256 of this source>"' this.m -o broker
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
#define K_SCHEMA @"knowledge-darwin-broker.v1"
#define K_MAX_JSON (12u * 1024u * 1024u)
#define K_MAX_FRAME (1024u * 1024u)
#define K_MAX_FILES 50000u
#define K_MAX_COPY (2ull * 1024ull * 1024ull * 1024ull)
#define K_UID_FIRST 1000000000u
#define K_UID_LAST 1900000000u
#define K_PID_CAP 65536u
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
static NSString *gExecutable, *gBinarySHA, *gRegistryPath, *gSocketPath, *gWorkspaceRoot;
static NSString *gPrintWorkspace;
static NSString *gBoot, *gHost;
static NSArray<NSString *> *gRuntimes;
static NSDictionary<NSString *,NSString *> *gRuntimePins;
static NSMutableDictionary *gRegistry;
static int gRegistryFD = -1, gGlobalLock = -1, gWorkspaceFD = -1, gListen = -1;
static bool gQualificationMode, gPoisoned;
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
static bool saveJSON(NSString *name, NSDictionary *record) {
    NSData *d=jsonData(record); if(!d || d.length>K_MAX_JSON)return false;
    NSString *temp=[NSString stringWithFormat:@".%@.%@",name,randomHex()];
    int fd=openat(gRegistryFD,temp.UTF8String,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false; bool ok=exactIO(fd,(void *)d.bytes,d.length,true)&&fsync(fd)==0;
    if(close(fd))ok=false;
    if(ok)ok=renameat(gRegistryFD,temp.UTF8String,gRegistryFD,name.UTF8String)==0&&fsync(gRegistryFD)==0;
    if(!ok){unlinkat(gRegistryFD,temp.UTF8String,0);gPoisoned=true;return false;}
    fd=openat(gRegistryFD,name.UTF8String,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat s; NSData *back=nil;
    if(fd>=0 && !fstat(fd,&s) && s.st_uid==0 && s.st_nlink==1 && !(s.st_mode&0077))back=readFD(fd,K_MAX_JSON);
    if(fd>=0)close(fd); ok=back && [back isEqual:d]; if(!ok)gPoisoned=true; return ok;
}
static bool persist(void) {
    if(gPoisoned)return false;
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
    NSDictionary *d=e[@"descriptor"];if(![d isKindOfClass:NSDictionary.class])return false;
    return hex64(id)&&[d[@"boundary_id"] isEqual:id]&&[d[@"attempt_id"] isEqual:id]
        &&[d[@"backend"] isEqual:@"darwin_private_ruid"]&&[d[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA]
        &&[d[@"workspace_path"] isEqual:pathChild(gWorkspaceRoot,id)]
        &&numericField(d[@"task_ruid"])&&[d[@"task_ruid"] unsignedLongLongValue]>=K_UID_FIRST
        &&[d[@"task_ruid"] unsignedLongLongValue]<K_UID_LAST&&[d[@"task_gid"] isEqual:d[@"task_ruid"]]
        &&numericField(e[@"owner_uid"])&&[e[@"owner_uid"] unsignedLongLongValue]>0
        &&[e[@"owner_uid"] unsignedLongLongValue]<K_UID_FIRST&&[d[@"owner_uid"] isEqual:e[@"owner_uid"]]
        &&hex64(e[@"descriptor_sha256"])&&[e[@"descriptor_sha256"] isEqual:sha(jsonData(d))]
        &&validRecordedIdentity(e[@"controller"])&&(!e[@"authority"]||validRecordedIdentity(e[@"authority"]));
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
    if(!e || [e[@"owner_uid"] unsignedIntValue]!=p->owner
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
static void stopSignal(int sig) {(void)sig;gStopping=1;}
static bool closeAdmission(NSMutableDictionary *e,NSString *reason,uint64_t budget) {
    bool durable=!gPoisoned;
    if(![e[@"admission_closed"] boolValue]){e[@"admission_closed"]=@YES;e[@"state"]=@"closing";
        e[@"stop_reason"]=reason;e[@"closed_monotonic_ms"]=@(nowMS());
        durable=persist();
    }
    /* Disk failure poisons positive proof, never the ability to stop work. */
    if(gPendingFD>=0){close(gPendingFD);gPendingFD=-1;}
    if(gRun.config>=0){close(gRun.config);gRun.config=-1;gRunConfig=nil;}
    if(gRun.gate>=0){close(gRun.gate);gRun.gate=-1;}
    uint64_t deadline=nowMS()+MIN(MAX(budget,(uint64_t)100),(uint64_t)60000);
    gCloseDeadline=gClosing==e?MIN(gCloseDeadline,deadline):deadline;gClosing=e;return durable;
}
static int admissionFD(NSMutableDictionary *e) {
    NSString *name=[NSString stringWithFormat:@"%@.admission",e[@"descriptor"][@"boundary_id"]];
    int fd=openat(gRegistryFD,name.UTF8String,O_RDWR|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    NSDictionary *saved=e[@"admission_inode"];
    if(fd<0)return -1;if(!saved||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=0||st.st_nlink!=1||(st.st_mode&0077)
        ||[saved[@"device"] unsignedLongLongValue]!=(uint64_t)st.st_dev||[saved[@"inode"] unsignedLongLongValue]!=(uint64_t)st.st_ino){
        close(fd);return -1;}return fd;
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
static bool launchRun(NSMutableDictionary *e,NSDictionary *q,int client) {
    NSArray *argv=q[@"argv"];NSDictionary *env=q[@"env"]?:@{};NSString *cwd=q[@"cwd"]?:@".";
    if(![argv isKindOfClass:NSArray.class]||argv.count<1||argv.count>256||![env isKindOfClass:NSDictionary.class]
        ||env.count>256||!runtimeAllowed(argv[0])||(![cwd isEqual:@"."]&&!validRelative(cwd)))return false;
    for(id arg in argv)if(!safeText(arg,32768))return false;
    NSMutableDictionary *clean=[NSMutableDictionary dictionaryWithDictionary:@{@"PATH":@"/usr/bin:/bin",@"LANG":@"C",@"LC_ALL":@"C"}];
    NSSet *forbidden=[NSSet setWithArray:@[@"DYLD_INSERT_LIBRARIES",@"DYLD_LIBRARY_PATH",@"DYLD_FRAMEWORK_PATH",@"NODE_OPTIONS",@"BASH_ENV",@"ENV"]];
    for(id key in env){if(!isString(key,256)||[key containsString:@"="]||!safeText(env[key],32768)||[forbidden containsObject:key]
        ||[key hasPrefix:@"DYLD_"])return false;clean[key]=env[key];}
    NSString *workspace=e[@"descriptor"][@"workspace_path"];
    clean[@"HOME"]=workspace;clean[@"TMPDIR"]=workspace;
    NSDictionary *config=@{@"argv":argv,@"env":clean,@"cwd":cwd,
        @"workspace":workspace,@"uid":e[@"descriptor"][@"task_ruid"],@"profile":sandboxProfile(workspace)};
    NSData *data=jsonData(config);if(!data||data.length>K_MAX_FRAME)return false;
    int lock=admissionFD(e),workspaceFD=openWorkspace(e),cfg[2]={-1,-1},ready[2]={-1,-1},gate[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1};
    bool ok=lock>=0&&workspaceFD>=0&&flock(lock,LOCK_EX|LOCK_NB)==0;
    if(ok)ok=pipe(cfg)==0&&pipe(ready)==0&&pipe(gate)==0&&pipe(out)==0&&pipe(err)==0;
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
        char *args[]={(char *)gExecutable.fileSystemRepresentation,"--internal-child",NULL};
        char *environment[]={"PATH=/usr/bin:/bin","LANG=C","LC_ALL=C",NULL};
        if(ok)ok=posix_spawn(&pid,gExecutable.fileSystemRepresentation,&fa,&attr,args,environment)==0;
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
            .deadline=MIN([e[@"work_deadline_ms"] unsignedLongLongValue],nowMS()+MIN(MAX([q[@"timeout_ms"] unsignedLongLongValue],(uint64_t)1),(uint64_t)3600000))};
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
    if(!kCapabilityQualified&&!gQualificationMode)return failure(@"CAPABILITY_UNQUALIFIED");
    if(peer->owner==0||peer->owner>=K_UID_FIRST)return failure(@"ORDINARY_OWNER_REQUIRED");
    if(![q[@"mode"] isEqual:@"isolated_copy"]||!hex64(q[@"attempt_nonce"]))return failure(@"INVALID_PREPARE");
    NSString *active=activeID();if(active.length){NSMutableDictionary *prior=entryFor(active);
        if([prior[@"owner_uid"] unsignedIntValue]==peer->owner&&[prior[@"descriptor"][@"attempt_nonce"] isEqual:q[@"attempt_nonce"]])
            return @{ @"ok":@NO,@"error":@"ATTEMPT_ALREADY_RESERVED",@"attempt_id":active,@"descriptor":prior[@"descriptor"],@"descriptor_sha256":prior[@"descriptor_sha256"] };
        return failure(@"ATTEMPT_ACTIVE");}
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));if(!pids)return failure(@"ALLOCATION_FAILED");
    uid_t uid=0;
    for(unsigned i=0;i<1000;i++){uint64_t next=[gRegistry[@"next_uid"] unsignedLongLongValue];
        if(next<K_UID_FIRST||next>=K_UID_LAST)break;gRegistry[@"next_uid"]=@(next+1);
        /* Every inspected candidate is consumed durably, even a busy UID. */
        if(!persist())break;int count=members((uid_t)next,pids);
        if(count==0&&!getpwuid((uid_t)next)&&!getgrgid((gid_t)next)){uid=(uid_t)next;break;}}
    free(pids);if(!uid||gPoisoned)return failure(@"UID_RESERVATION_UNAVAILABLE");
    NSString *id=randomHex(),*token=randomHex();uint64_t budget=MIN(MAX([q[@"work_budget_ms"] unsignedLongLongValue],(uint64_t)1),(uint64_t)3600000);
    NSString *workspacePath=pathChild(gWorkspaceRoot,id);
    NSDictionary *descriptor=@{@"schema":@"knowledge-darwin-private-ruid-descriptor.v1",@"backend":@"darwin_private_ruid",
        @"boundary_id":id,@"attempt_id":id,@"attempt_nonce":q[@"attempt_nonce"],@"task_ruid":@(uid),@"task_gid":@(uid),
        @"owner_uid":@(peer->owner),@"host_id":gHost,@"boot_id":gBoot,@"mode":@"isolated_copy",
        @"workspace_path":workspacePath,@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"broker_binary_sha256":gBinarySHA,@"allowed_runtimes":gRuntimePins,@"profile_sha256":sha([sandboxProfile(workspacePath) dataUsingEncoding:NSUTF8StringEncoding]),
        @"capability_qualified":@(kCapabilityQualified),@"qualification_mode":@(gQualificationMode),
        @"scope":@"private_command_ruid_plus_exact_registered_authority;trusted_controller_and_persistent_broker_excluded"};
    NSMutableDictionary *e=[@{@"descriptor":descriptor,@"descriptor_sha256":sha(jsonData(descriptor)),@"owner_uid":@(peer->owner),
        @"token_sha256":sha([token dataUsingEncoding:NSUTF8StringEncoding]),@"controller":identityJSON(&peer->parent),@"state":@"reserved",
        @"admission_closed":@NO,@"spawn_intent":@NO,@"authority_spawn_intent":@NO,@"files":@0,@"bytes":@0,
        @"manifest":[NSMutableDictionary dictionary],@"directories":[NSMutableDictionary dictionary],
        @"work_deadline_ms":@(nowMS()+budget),@"cleanup_budget_ms":@(MIN(MAX([q[@"cleanup_budget_ms"] unsignedLongLongValue],(uint64_t)100),(uint64_t)60000))} mutableCopy];
    entries()[id]=e;gRegistry[@"active_attempt"]=id;
    /* Reservation and immutable descriptor are fsync/readback BEFORE any
     * private-owned inode, admission lock, stub, or command can exist. */
    if(!persist())return failure(@"RESERVATION_DURABILITY_FAILED");
    NSString *lockName=[id stringByAppendingString:@".admission"];
    int lock=openat(gRegistryFD,lockName.UTF8String,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat admission;bool ok=lock>=0&&fstat(lock,&admission)==0&&fsync(lock)==0&&fsync(gRegistryFD)==0;
    if(ok){e[@"admission_inode"]=@{@"device":@((uint64_t)admission.st_dev),@"inode":@((uint64_t)admission.st_ino)};ok=persist();}
    if(lock>=0)close(lock);
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
    return @{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":id,@"descriptor":descriptor,@"descriptor_sha256":e[@"descriptor_sha256"],
        @"workspace_path":descriptor[@"workspace_path"],@"token":token,@"capability":kCapabilityQualified?@"qualified":@"unqualified"};
}

static NSDictionary *statusReply(NSMutableDictionary *e) {
    NSMutableDictionary *r=[@{@"ok":@YES,@"schema":K_SCHEMA,@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor":e[@"descriptor"],@"descriptor_sha256":e[@"descriptor_sha256"],@"state":e[@"state"],
        @"admission_closed":e[@"admission_closed"],@"spawn_intent":e[@"spawn_intent"],
        @"authority_spawn_intent":e[@"authority_spawn_intent"],@"capability_qualified":@(kCapabilityQualified),
        @"sandbox_profile":sandboxProfile(e[@"descriptor"][@"workspace_path"])} mutableCopy];
    if(e[@"proof"])r[@"proof"]=e[@"proof"];return r;
}
static void handleClient(int fd) {
    struct KPeer peer;if(!authenticate(fd,&peer)){sendJSON(fd,failure(@"PEER_AUTHENTICATION_FAILED"));close(fd);return;}
    NSDictionary *q=parseJSON(receiveRequest(fd));NSString *op=q[@"op"];NSDictionary *reply=nil;
    if(!q||!isString(op,64)||!requestTypes(q)||![q[@"source_sha256"] isEqual:@KNOWLEDGE_BROKER_SOURCE_SHA])reply=failure(@"PROTOCOL_OR_SOURCE_PIN_MISMATCH");
    else if([op isEqual:@"probe"])reply=@{@"ok":@YES,@"schema":K_SCHEMA,@"capability_qualified":@(kCapabilityQualified),
        @"qualification_mode":@(gQualificationMode),@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,@"binary_sha256":gBinarySHA,
        @"host_id":gHost,@"boot_id":gBoot,@"allowed_runtimes":gRuntimePins,@"registry_healthy":@((bool)!gPoisoned)};
    else if(gPoisoned)reply=failure(gQuarantineReason?:@"REGISTRY_DURABILITY_UNCONFIRMED");
    else if([op isEqual:@"prepare"])reply=prepare(q,&peer);
    else if([op isEqual:@"lookup"]){NSMutableDictionary *found=nil;
        if(hex64(q[@"attempt_nonce"]))for(NSMutableDictionary *e in entries().allValues)
            if([e[@"owner_uid"] unsignedIntValue]==peer.owner&&[e[@"descriptor"][@"attempt_nonce"] isEqual:q[@"attempt_nonce"]]){found=e;break;}
        reply=found?statusReply(found):failure(@"RESERVATION_UNKNOWN");
    }else{NSMutableDictionary *e=hex64(q[@"attempt_id"])?entryFor(q[@"attempt_id"]):nil;
        bool publicOperation=[@[@"status",@"close",@"recover"] containsObject:op];
        if(!authenticatedEntry(e,q,&peer,!publicOperation))reply=failure(@"ATTEMPT_AUTHENTICATION_FAILED");
        else if(publicOperation){
            if([op isEqual:@"status"]||[e[@"state"] isEqual:@"closed"])reply=statusReply(e);
            else if(gCloseWaiter>=0)reply=failure(@"CLEANUP_BUSY");
            else if(closeAdmission(e,[op isEqual:@"recover"]?@"recovery_requested":@"close_requested",[q[@"cleanup_budget_ms"] unsignedLongLongValue])){
                gCloseWaiter=fd;return;
            }else reply=failure(@"ADMISSION_CLOSE_DURABILITY_FAILED");
        }else if([e[@"admission_closed"] boolValue])reply=failure(@"ADMISSION_CLOSED");
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
            if(valid&&gRun.gate>=0&&![e[@"admission_closed"] boolValue]&&nowMS()<gRun.deadline){char go='G';if(write(gRun.gate,&go,1)!=1)valid=false;}
            else valid=false;
            close(gRun.gate);gRun.gate=-1;
            if(!valid)closeAdmission(e,@"child_publication_or_permit_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
        }else if(n==0){close(gRun.ready);gRun.ready=-1;closeAdmission(e,@"child_setup_failed",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    }
    if(gRun.client>=0){char c;ssize_t n=recv(gRun.client,&c,1,MSG_PEEK|MSG_DONTWAIT);
        if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)){
            close(gRun.client);gRun.client=-1;closeAdmission(e,@"run_client_lost",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}}
    if(nowMS()>=gRun.deadline&&![e[@"admission_closed"] boolValue])closeAdmission(e,@"command_deadline",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);
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
    if(!gClosing)return;NSMutableDictionary *e=gClosing;int lock=admissionFD(e);bool excluded=false;
    /* A captured, exact owned launch stub may still hold the barrier before
     * credential drop. Never infer its exit from a private-UID zero scan. */
    bool stubObserved=true;
    if([e[@"spawn_intent"] boolValue]&&e[@"launch_stub"]){struct KIdentity stub;int rc=observeExact(e[@"launch_stub"],&stub);
        if(rc==0){e[@"spawn_intent"]=@NO;persist();}
        else if(rc<0)stubObserved=false;
        else if(stub.bsd.pbi_ruid==0){if(!signalExact(e[@"launch_stub"],0))stubObserved=false;}
        else if(stub.bsd.pbi_ruid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue])stubObserved=false;
    }
    if(lock>=0)excluded=flock(lock,LOCK_EX|LOCK_NB)==0;
    bool zero=false,authorityExited=!e[@"authority"],observed=stubObserved;
    pid_t *pids=calloc(K_PID_CAP,sizeof(pid_t));int count=-1;
    if(excluded&&pids){count=members([e[@"descriptor"][@"task_ruid"] unsignedIntValue],pids);zero=count==0;
        if(count>0)for(int i=0;i<count;i++){struct KIdentity v;
            if(!freshIdentity(pids[i],&v))continue;
            if(v.bsd.pbi_ruid!=[e[@"descriptor"][@"task_ruid"] unsignedIntValue])continue;
            audit_token_t t={{0}};t.val[5]=v.bsd.pbi_pid;t.val[7]=(uint32_t)v.unique.pidversion;
            int rc=gSignalToken(&t,SIGKILL);if(rc!=0&&rc!=ESRCH)observed=false;}}
    free(pids);
    if(e[@"authority"]){struct KIdentity v;int rc=observeExact(e[@"authority"],&v);
        authorityExited=rc==0;if(rc<0)observed=false;
        if(rc==1&&!signalExact(e[@"authority"],[e[@"owner_uid"] unsignedIntValue]))observed=false;}
    bool intents=![e[@"spawn_intent"] boolValue]&&![e[@"authority_spawn_intent"] boolValue];
    bool facts=excluded&&zero&&authorityExited&&observed&&intents&&!gRun.pid;
    if(!facts&&nowMS()<gCloseDeadline){if(lock>=0)close(lock);return;}
    bool confirmed=facts&&!gPoisoned;NSString *state=confirmed?@"closed":@"cleanup_unconfirmed";
    NSDictionary *proof=@{@"schema":@"knowledge-darwin-private-ruid-proof.v1",@"attempt_id":e[@"descriptor"][@"attempt_id"],
        @"descriptor_sha256":e[@"descriptor_sha256"],@"source_sha256":@KNOWLEDGE_BROKER_SOURCE_SHA,
        @"host_id":gHost,@"boot_id":gBoot,@"task_ruid":e[@"descriptor"][@"task_ruid"],
        @"admission_closed":e[@"admission_closed"],@"spawn_exclusion_acquired":@(excluded),@"spawn_intents_resolved":@(intents),
        @"kernel_membership_method":@"proc_listpids(PROC_RUID_ONLY,nonnull_buffer);active_and_zombie_lists",
        @"kernel_membership_zero":@(zero),@"registered_authority_exited":@(authorityExited),
        @"authority_identity":e[@"authority"]?:NSNull.null,@"controller_identity":e[@"controller"],
        @"controller_excluded_from_boundary":@YES,@"persistent_broker_excluded_from_boundary":@YES,
        @"native_cleanup_facts_confirmed":@(confirmed),@"capability_qualified":@(kCapabilityQualified),
        @"cleanup_confirmed":@((bool)(confirmed&&kCapabilityQualified)),@"state":state,@"receipt_kind":@"root_registry_not_os_signed_attestation",
        @"observed_monotonic_ms":@(nowMS())};
    /* No env, output, tokens, arbitrary paths, or source contents in receipts. */
    if(jsonData(proof).length>65536){gPoisoned=true;confirmed=false;}
    NSString *receipt=[NSString stringWithFormat:@"%@.%@.receipt.json",e[@"descriptor"][@"attempt_id"],sha(jsonData(proof))];
    bool durable=saveJSON(receipt,proof);e[@"proof"]=proof;e[@"receipt_sha256"]=sha(jsonData(proof));
    e[@"receipt_name"]=receipt;
    e[@"state"]=(durable?state:@"cleanup_unconfirmed");
    if(durable&&confirmed)gRegistry[@"active_attempt"]=@"";
    bool registryDurable=persist();
    NSDictionary *reply=registryDurable?statusReply(e):failure(@"CLEANUP_RECEIPT_DURABILITY_UNCONFIRMED");
    if(gCloseWaiter>=0){sendJSON(gCloseWaiter,reply);close(gCloseWaiter);gCloseWaiter=-1;}
    if(lock>=0)close(lock);gClosing=nil;
}

/* Executed as a CLEAN native image by posix_spawn, never a post-fork Foundation
 * continuation. Only protected broker parent + explicit fixed FDs can enter. */
static bool isolatedCwd(int root,const char *relative) {
    struct stat boundary;if(fstat(root,&boundary)||!S_ISDIR(boundary.st_mode))return false;
    int fd=dup(root);if(fd<0)return false;
    if(strcmp(relative,".")){
        char *copy=strdup(relative);if(!copy){close(fd);return false;}char *save=NULL;
        for(char *part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
            int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
            if(fd<0)break;
        }free(copy);if(fd<0)return false;
    }
    int cursor=dup(fd);bool within=false;
    for(unsigned depth=0;cursor>=0&&depth<1024;depth++){
        struct stat current;if(fstat(cursor,&current))break;
        if(current.st_dev==boundary.st_dev&&current.st_ino==boundary.st_ino){within=true;break;}
        int parent=openat(cursor,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat above;
        if(parent<0||fstat(parent,&above)){if(parent>=0)close(parent);break;}
        if(above.st_dev==current.st_dev&&above.st_ino==current.st_ino){close(parent);break;}
        close(cursor);cursor=parent;
    }
    if(cursor>=0)close(cursor);bool ok=within&&fchdir(fd)==0;close(fd);return ok;
}
static int nativeChild(void) {
    alarm(15); /* root stub cannot wait forever after daemon/config pipe loss */
    if(getuid()!=0||geteuid()!=0)return 120;
    struct KIdentity parent;if(!freshIdentity(getppid(),&parent)||parent.bsd.pbi_ruid!=0)return 121;
    char parentPath[PROC_PIDPATHINFO_MAXSIZE];if(proc_pidpath(getppid(),parentPath,sizeof(parentPath))<=0
        ||![protectedFileSHA(@(parentPath)) isEqual:protectedFileSHA(gExecutable)])return 122;
    struct stat lock;if(fstat(13,&lock)||lock.st_uid!=0||!S_ISREG(lock.st_mode)||lock.st_nlink!=1||(lock.st_mode&0077))return 123;
    uint32_t length;if(!exactIO(10,&length,4,false))return 124;length=ntohl(length);if(!length||length>K_MAX_FRAME)return 125;
    NSMutableData *d=[NSMutableData dataWithLength:length];if(!exactIO(10,d.mutableBytes,length,false))return 126;close(10);
    NSDictionary *q=parseJSON(d);uid_t uid=[q[@"uid"] unsignedIntValue];NSArray *argv=q[@"argv"];NSDictionary *env=q[@"env"];
    if(uid<K_UID_FIRST||uid>=K_UID_LAST||![argv isKindOfClass:NSArray.class]||!argv.count||![env isKindOfClass:NSDictionary.class])return 127;
    char **args=calloc(argv.count+1,sizeof(char *)),**environment=calloc(env.count+1,sizeof(char *));
    if(!args||!environment)return 128;
    for(NSUInteger i=0;i<argv.count;i++)args[i]=strdup([argv[i] UTF8String]);
    NSUInteger i=0;for(NSString *key in env)environment[i++]=strdup([[NSString stringWithFormat:@"%@=%@",key,env[key]] UTF8String]);
    char *profile=strdup([q[@"profile"] UTF8String]),*cwd=strdup([q[@"cwd"] fileSystemRepresentation]);
    if(!profile||!cwd)return 129;
    /* Remove imported bootstrap/registered/exception capabilities. Destroy all
     * remaining inherited non-self Mach rights before untrusted exec. */
    mach_port_t task=mach_task_self(),thread=mach_thread_self();
    mach_port_t access=MACH_PORT_NULL; kern_return_t kr;
    kr=task_get_special_port(task,TASK_ACCESS_PORT,&access);
    if(kr!=KERN_SUCCESS||access!=MACH_PORT_NULL){fprintf(stderr,"native setup stage=task-access rc=%d nonnull=%d\n",kr,access!=MACH_PORT_NULL);return 130;}
    mach_port_t inheritedHost=mach_host_self(),plainHost=MACH_PORT_NULL;
    kr=host_get_special_port(inheritedHost,HOST_LOCAL_NODE,HOST_PORT,&plainHost);
    if(kr!=KERN_SUCCESS||!MACH_PORT_VALID(plainHost)){fprintf(stderr,"native setup stage=plain-host rc=%d\n",kr);return 130;}
    kr=task_set_special_port(task,TASK_HOST_PORT,plainHost);
    if(kr!=KERN_SUCCESS){fprintf(stderr,"native setup stage=host-replace rc=%d\n",kr);return 130;}
    kernel_boot_info_t hostBuffer;
    if(host_get_boot_info(mach_host_self(),hostBuffer)==KERN_SUCCESS||host_get_boot_info(inheritedHost,hostBuffer)==KERN_SUCCESS){
        fprintf(stderr,"native setup stage=host-privilege-retained\n");return 130;
    }
    kr=task_set_special_port(task,TASK_BOOTSTRAP_PORT,MACH_PORT_NULL);
    if(kr!=KERN_SUCCESS){fprintf(stderr,"native setup stage=bootstrap-clear rc=%d\n",kr);return 130;}
    kr=mach_ports_register(task,NULL,0);
    if(kr!=KERN_SUCCESS){fprintf(stderr,"native setup stage=registered-clear rc=%d\n",kr);return 130;}
    kr=task_set_exception_ports(task,EXC_MASK_ALL,MACH_PORT_NULL,EXCEPTION_DEFAULT,THREAD_STATE_NONE);
    if(kr!=KERN_SUCCESS){fprintf(stderr,"native setup stage=exception-clear rc=%d\n",kr);return 130;}
    mach_port_name_array_t names=NULL;mach_port_type_array_t types=NULL;mach_msg_type_number_t nn=0,nt=0;
    if(mach_port_names(task,&names,&nn,&types,&nt)!=KERN_SUCCESS||nn!=nt)return 131;
    for(mach_msg_type_number_t n=0;n<nn;n++)if(names[n]!=task&&names[n]!=thread)
        if(mach_port_destroy(task,names[n])!=KERN_SUCCESS)return 132;
    vm_deallocate(task,(vm_address_t)names,nn*sizeof(*names));vm_deallocate(task,(vm_address_t)types,nt*sizeof(*types));
    mach_port_deallocate(task,thread);
    char *sandboxError=NULL;
    /* Public SDK entrypoint: workspace/runtime paths are already correctly
     * escaped literal SBPL strings, not unbound private parameter API calls. */
    if(sandbox_init(profile,0,&sandboxError)!=0){if(sandboxError)sandbox_free_error(sandboxError);return 133;}
    gid_t privateGroup=(gid_t)uid;
    if(setgroups(1,&privateGroup)||setgid(privateGroup)||setuid(uid))return 134;
    struct KIdentity own;
    gid_t actualGroups[2]={0,0};int groupCount=getgroups(2,actualGroups);
    if(!freshIdentity(getpid(),&own)||own.bsd.pbi_ruid!=uid||own.bsd.pbi_uid!=uid||own.bsd.pbi_svuid!=uid
        ||own.bsd.pbi_rgid!=uid||own.bsd.pbi_gid!=uid||own.bsd.pbi_svgid!=uid||groupCount!=1||actualGroups[0]!=privateGroup)return 135;
    if(!isolatedCwd(14,cwd))return 136;close(14);
    struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core))return 137;
    /* The only root-owned FD has now completed its purpose. UID membership is
     * visible before its lock is dropped. Admission still awaits daemon gate. */
    char ready='R';if(!exactIO(11,&ready,1,true))return 138;close(11);close(13);
    char go;if(!exactIO(12,&go,1,false)||go!='G')return 139;close(12);
    alarm(0);
    for(int fd=3;fd<getdtablesize();fd++)close(fd);
    execve(args[0],args,environment);return 140;
}

static NSString *sysctlString(const char *name) { size_t n=0;if(sysctlbyname(name,NULL,&n,NULL,0)||n<2||n>4096)return nil;
    NSMutableData *d=[NSMutableData dataWithLength:n];if(sysctlbyname(name,d.mutableBytes,&n,NULL,0))return nil;
    return [NSString stringWithUTF8String:d.bytes]; }
static bool startup(void) {
    gSetupStage="root-and-source-pin";
    if(getuid()!=0||geteuid()!=0||!hex64(@KNOWLEDGE_BROKER_SOURCE_SHA))return false;
    gSetupStage="protected-broker-image";
    gBinarySHA=protectedFileSHA(gExecutable);if(!gBinarySHA)return false;
    gSetupStage="protected-directory-chains";
    if(!protectedPath(gRegistryPath,false,true)||!protectedPath(gWorkspaceRoot,false,true)
        ||!canonicalAbsolute(gSocketPath)||!protectedPath(pathParent(gSocketPath),false,true))return false;
    if([gRegistryPath isEqual:gWorkspaceRoot]||[gWorkspaceRoot hasPrefix:[gRegistryPath stringByAppendingString:@"/"]])return false;
    gSetupStage="open-directory-fds";
    gRegistryFD=open(gRegistryPath.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    gWorkspaceFD=open(gWorkspaceRoot.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(gRegistryFD<0||gWorkspaceFD<0)return false;
    gSetupStage="workspace-mode0711-registry-mode0700";
    struct stat ws;if(fstat(gWorkspaceFD,&ws)||(ws.st_mode&0777)!=0711)return false;
    struct stat rs;if(fstat(gRegistryFD,&rs)||(rs.st_mode&0777)!=0700)return false;
    gSetupStage="exclusive-protected-daemon-lock";
    gGlobalLock=openat(gRegistryFD,"daemon.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    struct stat ls;if(gGlobalLock<0||fstat(gGlobalLock,&ls)||ls.st_uid!=0||ls.st_nlink!=1||!S_ISREG(ls.st_mode)
        ||(ls.st_mode&0077)||flock(gGlobalLock,LOCK_EX|LOCK_NB))return false;
    gSetupStage="native-signal-and-combined-identity-abi";
    void *sym=dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");memcpy(&gSignalToken,&sym,sizeof(gSignalToken));
    struct KIdentity self;if(!gSignalToken||!freshIdentity(getpid(),&self)||self.bsd.pbi_ruid!=0)return false;
    gSetupStage="kernel-ruid-positive-canary";
    pid_t *positive=calloc(K_PID_CAP,sizeof(pid_t));int positiveCount=positive?members(0,positive):-1;free(positive);if(positiveCount<=0)return false;
    gSetupStage="actual-host-and-boot-identities";
    gBoot=sysctlString("kern.bootsessionuuid");uuid_t hostUUID;struct timespec hostTimeout={2,0};
    if(gethostuuid(hostUUID,&hostTimeout)==0){uuid_string_t hostText;uuid_unparse_lower(hostUUID,hostText);gHost=@(hostText);}
    gSetupStage="load-protected-durable-registry";
    int fd=openat(gRegistryFD,"registry.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd>=0){struct stat st;if(fstat(fd,&st)||st.st_uid!=0||st.st_nlink!=1||!S_ISREG(st.st_mode)||(st.st_mode&0077)){close(fd);return false;}
        gRegistry=[parseJSON(readFD(fd,K_MAX_JSON)) mutableCopy];close(fd);
        if(![gRegistry[@"schema"] isEqual:K_SCHEMA]||![gRegistry[@"attempts"] isKindOfClass:NSMutableDictionary.class]
            ||![gRegistry[@"active_attempt"] isKindOfClass:NSString.class]||!numericField(gRegistry[@"next_uid"])
            ||![gRegistry[@"installation_id"] isKindOfClass:NSString.class])return false;
    }else if(errno==ENOENT)gRegistry=[@{@"schema":K_SCHEMA,@"next_uid":@(K_UID_FIRST),@"attempts":[NSMutableDictionary dictionary],
        @"active_attempt":@"",@"installation_id":randomHex()} mutableCopy];else return false;
    gSetupStage="host-boot-and-registry-fsync-readback";
    if(!gBoot.length||!gHost.length)return false;
    if(!persist())return false;
    gSetupStage="protected-allowed-runtime-pins";
    NSMutableDictionary *pins=[NSMutableDictionary dictionary];
    for(NSString *runtime in gRuntimes){NSString *digest=protectedFileSHA(runtime);if(!digest)return false;pins[runtime]=digest;}gRuntimePins=pins;
    if(activeID().length){NSMutableDictionary *e=entryFor(activeID());
        if(!e||!validRecordedEntry(e,activeID())||![e[@"descriptor"][@"boot_id"] isEqual:gBoot]||![e[@"descriptor"][@"host_id"] isEqual:gHost]){
            gPoisoned=true;gQuarantineReason=@"REGISTRY_DESCRIPTOR_BOOT_HOST_OR_OWNERSHIP_UNKNOWN";
            /* unknown boot/ownership never grants kill authority */
        }else closeAdmission(e,@"daemon_restart",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
    gSetupStage="protected-listener-bind";
    struct sockaddr_un addr={0};addr.sun_family=AF_UNIX;
    if(strlen(gSocketPath.fileSystemRepresentation)>=sizeof(addr.sun_path))return false;
    strlcpy(addr.sun_path,gSocketPath.fileSystemRepresentation,sizeof(addr.sun_path));
    struct stat old;if(lstat(addr.sun_path,&old)==0){if(!S_ISSOCK(old.st_mode)||old.st_uid!=0)return false;if(unlink(addr.sun_path))return false;}
    else if(errno!=ENOENT)return false;
    gListen=socket(AF_UNIX,SOCK_STREAM,0);if(gListen<0)return false;fcntl(gListen,F_SETFD,FD_CLOEXEC);
    mode_t previous=umask(0077);int bound=bind(gListen,(struct sockaddr *)&addr,sizeof(addr));umask(previous);
    /* Any ordinary owner may connect; socket peer identity, same installed
     * protected native image, role births and descriptor/token bind authority. */
    if(bound||chmod(addr.sun_path,0666)||listen(gListen,16))return false;return true;
}
static int serve(void) {
    if(!startup()){fprintf(stderr,"broker setup/prerequisite failure: %s (errno=%d)\n",gSetupStage,errno);return 78;}
    signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
    for(;;){@autoreleasepool{
        NSMutableDictionary *e=activeID().length?entryFor(activeID()):nil;
        if(e&&!gClosing&&![e[@"admission_closed"] boolValue]){struct KIdentity v;
            int controller=observeExact(e[@"controller"],&v),authority=e[@"authority"]?observeExact(e[@"authority"],&v):1;
            if(gStopping||controller!=1||authority!=1||nowMS()>=[e[@"work_deadline_ms"] unsignedLongLongValue])
                closeAdmission(e,gStopping?@"daemon_stopping":@"owner_lost_or_deadline",[e[@"cleanup_budget_ms"] unsignedLongLongValue]);}
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
    gRegistryPath=@"/Library/Application Support/KnowledgeVerification/registry";
    gSocketPath=@"/Library/Application Support/KnowledgeVerification/control/broker.sock";
    gWorkspaceRoot=@"/Library/Application Support/KnowledgeVerification/workspaces";
    NSMutableArray *runtimes=[NSMutableArray array];NSString *mode=nil;
    for(int i=1;i<argc;i++){NSString *s=@(argv[i]);
        if([@[@"--serve",@"--request",@"--run",@"--internal-child",@"--print-profile"] containsObject:s]){if(mode)return 64;mode=s;}
        else if([s isEqual:@"--qualification-mode"])gQualificationMode=true;
        else if([s hasPrefix:@"--registry="])gRegistryPath=[s substringFromIndex:11];
        else if([s hasPrefix:@"--socket="])gSocketPath=[s substringFromIndex:9];
        else if([s hasPrefix:@"--workspaces="])gWorkspaceRoot=[s substringFromIndex:13];
        else if([s hasPrefix:@"--workspace="])gPrintWorkspace=[s substringFromIndex:12];
        else if([s hasPrefix:@"--runtime="])[runtimes addObject:[s substringFromIndex:10]];
        else return 64;
    }
    for(NSString *path in [runtimes arrayByAddingObjectsFromArray:@[gRegistryPath,gSocketPath,gWorkspaceRoot]])
        if([path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)return 64;
    gRuntimes=runtimes;
    if([mode isEqual:@"--print-profile"]){
        if(gQualificationMode||!runtimes.count||!canonicalAbsolute(gPrintWorkspace))return 64;
        for(NSString *runtime in runtimes)if(!canonicalAbsolute(runtime))return 64;
        NSData *profile=[sandboxProfile(gPrintWorkspace) dataUsingEncoding:NSUTF8StringEncoding];
        return exactIO(1,(void *)profile.bytes,profile.length,true)?0:74;
    }
    if(gPrintWorkspace)return 64;
    if([mode isEqual:@"--internal-child"]){if(argc!=2)return 64;int result=nativeChild();
        if(result)fprintf(stderr,"native child setup/exec failure: code=%d errno=%d\n",result,errno);return result;}
    if([mode isEqual:@"--serve"])return runtimes.count?serve():64;
    if(gQualificationMode||runtimes.count)return 64;
    if([mode isEqual:@"--request"])return client(false);
    if([mode isEqual:@"--run"])return client(true);
    return 64;
}}
