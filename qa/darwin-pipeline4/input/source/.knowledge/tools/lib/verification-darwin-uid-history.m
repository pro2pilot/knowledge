/* Root-only native UID history. See the paired header for caller obligations.
 * clang -fobjc-arc -Wall -Wextra -Wno-deprecated-declarations -framework Foundation
 * No workload code is evaluated by this component. Unqualified by construction.
 */
#if !defined(__APPLE__)
#error "Darwin UID history requires the macOS SDK"
#endif
#import "verification-darwin-uid-history.h"
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
extern void KVDarwinQAPersistenceGate(const char *point);
extern void KVDarwinQAPersistenceGateComplete(const char *point,bool ok,int savedErrno);
#endif

static const uint32_t KVFirst=1000000000u, KVEnd=1900000000u;
static const NSUInteger KVMaxRecords=100000u, KVMaxJournal=64u*1024u*1024u;
static const NSUInteger KVMaxBody=2048u, KVMaxJSON=12u*1024u*1024u;
static NSString *const KVErrorDomain=@"knowledge.darwin.uid-history";

static BOOL KVFail(NSError **error,NSString *code) {
    if(error)*error=[NSError errorWithDomain:KVErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey:code}];
    return NO;
}
static BOOL KVRoot(void){return getuid()==0&&geteuid()==0;}
static BOOL KVHex(id value) {
    if(![value isKindOfClass:NSString.class]||[value length]!=64)return NO;
    for(NSUInteger i=0;i<64;i++){unichar c=[value characterAtIndex:i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return NO;}return YES;
}
static BOOL KVUUID(id value) {
    if(![value isKindOfClass:NSString.class]||[value length]!=36)return NO;
    NSUUID *uuid=[[NSUUID alloc]initWithUUIDString:value];return uuid&&[uuid.UUIDString.lowercaseString isEqual:value];
}
static NSString *KVRandom(void) { unsigned char bytes[32];arc4random_buf(bytes,sizeof(bytes));char out[65];
    for(unsigned i=0;i<32;i++)snprintf(out+2*i,3,"%02x",bytes[i]);return @(out);
}
static NSData *KVJSON(id value) {
    if(![NSJSONSerialization isValidJSONObject:value])return nil;
    /* Exact codec shared with the native broker's jsonData. Registry contains
     * absolute workspace paths; default slash escaping is NOT interchangeable. */
    return [NSJSONSerialization dataWithJSONObject:value
        options:NSJSONWritingSortedKeys|NSJSONWritingWithoutEscapingSlashes error:NULL];
}
static NSDictionary *KVParse(NSData *data) {
    if(!data)return nil;id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if(![value isKindOfClass:NSDictionary.class]||![KVJSON(value) isEqual:data])return nil;return value;
}
static NSString *KVHash(NSData *data) { unsigned char hash[32];CC_SHA256(data.bytes,(CC_LONG)data.length,hash);char out[65];
    for(unsigned i=0;i<32;i++)snprintf(out+2*i,3,"%02x",hash[i]);return @(out);
}
static BOOL KVKeys(NSDictionary *d,NSArray *keys) {
    return [d isKindOfClass:NSDictionary.class]&&d.count==keys.count
        &&[[NSSet setWithArray:d.allKeys] isEqual:[NSSet setWithArray:keys]];
}
static BOOL KVUInt(id value,uint64_t *out) {
    if(![value isKindOfClass:NSNumber.class]||CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID()
        ||CFNumberIsFloatType((__bridge CFNumberRef)value)||[value compare:@0]==NSOrderedAscending)return NO;
    *out=[value unsignedLongLongValue];return YES;
}
static BOOL KVDecimal(id value,uint64_t maximum,uint64_t *out) {
    if(![value isKindOfClass:NSString.class]||![value length]||[value length]>20
        ||([value length]>1&&[value characterAtIndex:0]=='0'))return NO;
    uint64_t n=0;for(NSUInteger i=0;i<[value length];i++){unichar c=[value characterAtIndex:i];
        if(c<'0'||c>'9'||(uint64_t)(c-'0')>maximum||n>(maximum-(c-'0'))/10)return NO;n=n*10+c-'0';}*out=n;return YES;
}
static BOOL KVPath(id path) {
    if(![path isKindOfClass:NSString.class]||![path hasPrefix:@"/"]||[path length]<2
        ||[path length]>4096||[path lengthOfBytesUsingEncoding:NSUTF8StringEncoding]>4096)return NO;
    const char *s=[path UTF8String];if(!s||strlen(s)!=[path lengthOfBytesUsingEncoding:NSUTF8StringEncoding])return NO;
    for(const unsigned char *p=(const unsigned char *)s;*p;p++)if(*p<32||*p==127||*p=='\\')return NO;
    for(NSString *part in [[path substringFromIndex:1] componentsSeparatedByString:@"/"])
        if(!part.length||[part isEqual:@"."]||[part isEqual:@".."])return NO;return YES;
}
static NSString *KVParent(NSString *path){return [path substringToIndex:[path rangeOfString:@"/" options:NSBackwardsSearch].location]?:@"";}
static NSString *KVLeaf(NSString *path){return [path substringFromIndex:[path rangeOfString:@"/" options:NSBackwardsSearch].location+1];}
static BOOL KVWithin(NSString *a,NSString *b){return [a isEqual:b]||[a hasPrefix:[b stringByAppendingString:@"/"]];}
static BOOL KVACL(NSString *path,const struct stat *expected) {
    filesec_t metadata=filesec_init();if(!metadata)return NO;struct stat st;int present=0;acl_t acl=NULL;
    BOOL ok=lstatx_np(path.fileSystemRepresentation,&st,metadata)==0&&st.st_dev==expected->st_dev&&st.st_ino==expected->st_ino
        &&!S_ISLNK(st.st_mode)&&filesec_query_property(metadata,FILESEC_ACL,&present)==0;
    if(ok&&present)ok=filesec_get_property(metadata,FILESEC_ACL,&acl)==0&&acl!=NULL;
    filesec_free(metadata);if(!ok)return NO;if(!present)return YES;
    if(acl_valid(acl)){acl_free(acl);return NO;}
    acl_entry_t e;int selector=ACL_FIRST_ENTRY;unsigned entries=0;
    while(acl_get_entry(acl,selector,&e)==0){if(++entries>1024){ok=NO;break;}selector=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t permissions;
        if(acl_get_tag_type(e,&tag)||acl_get_permset(e,&permissions)){ok=NO;break;}
        if(tag!=ACL_EXTENDED_ALLOW)continue;
        acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,ACL_WRITE_ATTRIBUTES,
            ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
        for(unsigned i=0;i<sizeof(writes)/sizeof(writes[0]);i++)if(acl_get_perm_np(permissions,writes[i])!=0){ok=NO;break;}
        if(!ok)break;
    }acl_free(acl);return ok;
}
/* Walk each component with openat/O_NOFOLLOW. The sole ancestor exception is
 * root-owned sticky /private/tmp, for explicit isolated diagnostic fixtures. */
static int KVDirectory(NSString *path,mode_t exactMode) {
    if(!KVPath(path))return -1;int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return -1;
    struct stat root;if(fstat(fd,&root)||!S_ISDIR(root.st_mode)||root.st_uid!=0
        ||(root.st_mode&(0022|S_ISUID|S_ISGID))||!KVACL(@"/",&root)){close(fd);return -1;}
    NSString *prefix=@"";NSArray *parts=[[path substringFromIndex:1] componentsSeparatedByString:@"/"];
    for(NSUInteger i=0;i<parts.count;i++){NSString *part=parts[i];prefix=[prefix stringByAppendingFormat:@"/%@",part];
        int next=openat(fd,part.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
        struct stat st;if(fd<0||fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0){if(fd>=0)close(fd);return -1;}
        BOOL temporary=[prefix isEqual:@"/private/tmp"]&&(st.st_mode&S_ISVTX)&&i+1<parts.count;
        if((!temporary&&((st.st_mode&0022)||!KVACL(prefix,&st)))||(st.st_mode&(S_ISUID|S_ISGID))
            ||(i+1==parts.count&&(st.st_mode&07777)!=exactMode)){close(fd);return -1;}
    }return fd;
}
static BOOL KVProtectedFile(int fd,NSString *path) { struct stat st;
    return fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_nlink==1
        &&(st.st_mode&07777)==0600&&KVACL(path,&st);
}
static NSData *KVRead(int fd,NSUInteger maximum) {struct stat st;
    if(fstat(fd,&st)||st.st_size<0||(uint64_t)st.st_size>maximum)return nil;
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t at=0;
    while(at<data.length){ssize_t n=pread(fd,(unsigned char *)data.mutableBytes+at,data.length-at,(off_t)at);
        if(n<0&&errno==EINTR)continue;if(n<=0)return nil;at+=(size_t)n;}
    unsigned char extra;ssize_t n=pread(fd,&extra,1,(off_t)data.length);return n==0?data:nil;
}
static BOOL KVWrite(int fd,NSData *data) {size_t at=0;
    while(at<data.length){ssize_t n=write(fd,(const unsigned char *)data.bytes+at,data.length-at);
        if(n<0&&errno==EINTR)continue;if(n<=0)return NO;at+=(size_t)n;}return YES;
}
static BOOL KVSync(int fd){return fsync(fd)==0&&fcntl(fd,F_FULLFSYNC)==0;}
static BOOL KVEmpty(int fd){int copy=dup(fd);if(copy<0)return NO;DIR *dir=fdopendir(copy);if(!dir){close(copy);return NO;}
    BOOL empty=YES;errno=0;struct dirent *e;while((e=readdir(dir)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,"..")){empty=NO;break;}
    if(!e&&errno)empty=NO;closedir(dir);return empty;
}

@interface KVDarwinUIDHistory () {
    NSDictionary *_configuration,*_marker,*_head,*_checkpoint;
    NSArray<NSDictionary *> *_records;
    NSString *_reason,*_installationID;
    NSData *_journalBytes;
    int _markerDir,_headDir,_journalDir,_registryDir,_workspaceDir,_lock;
    BOOL _healthy,_closed,_pending;
}
- (BOOL)quarantine:(NSString *)reason error:(NSError **)error;
@end

@implementation KVDarwinUIDHistory
- (instancetype)init {if((self=[super init])){_markerDir=_headDir=_journalDir=_registryDir=_workspaceDir=_lock=-1;
    _reason=@"NOT_OPEN";_records=@[];}return self;}
- (BOOL)healthy{return _healthy&&!_closed;}
- (NSString *)reason{return _closed?@"CLOSED":_reason;}
- (NSString *)installationID{return _installationID;}
- (NSDictionary *)checkpoint{return [_checkpoint copy];}
- (BOOL)quarantine:(NSString *)reason error:(NSError **)error{_healthy=NO;_pending=NO;_reason=reason;return KVFail(error,reason);}
- (void)close {if(_closed)return;_closed=YES;_healthy=NO;
    int *fds[]={&_lock,&_markerDir,&_headDir,&_journalDir,&_registryDir,&_workspaceDir};
    for(unsigned i=0;i<sizeof(fds)/sizeof(fds[0]);i++)if(*fds[i]>=0){close(*fds[i]);*fds[i]=-1;}}
- (void)dealloc {[self close];}
- (BOOL)configure:(NSDictionary *)c error:(NSError **)error {
    if(!KVRoot()||!KVKeys(c,@[@"marker_path",@"head_path",@"journal_path",@"lock_path",@"registry_path",@"workspace_root",@"host_id"]))return KVFail(error,@"CONFIG_OR_ROOT_REQUIRED");
    for(NSString *key in c)if(![key isEqual:@"host_id"]&&!KVPath(c[key]))return KVFail(error,@"NONCANONICAL_PATH");
    if(!KVUUID(c[@"host_id"]))return KVFail(error,@"INVALID_HOST_ID");
    NSString *journal=KVParent(c[@"journal_path"]),*registry=KVParent(c[@"registry_path"]),*workspace=c[@"workspace_root"];
    if(![journal isEqual:KVParent(c[@"lock_path"])]||[c[@"journal_path"] isEqual:c[@"lock_path"]]
        ||[c[@"marker_path"] isEqual:c[@"head_path"]])return KVFail(error,@"PATH_ALIAS");
    NSArray *isolated=@[journal,registry,workspace];
    for(NSUInteger i=0;i<isolated.count;i++)for(NSUInteger j=i+1;j<isolated.count;j++)
        if(KVWithin(isolated[i],isolated[j])||KVWithin(isolated[j],isolated[i]))return KVFail(error,@"STATE_TREES_OVERLAP");
    for(NSString *anchor in @[KVParent(c[@"marker_path"]),KVParent(c[@"head_path"])])for(NSString *tree in isolated)
        if(KVWithin(anchor,tree)||KVWithin(tree,anchor))return KVFail(error,@"ANCHOR_NOT_INDEPENDENT");
    /* Do not retain mutable NSString/dictionary leaves supplied by a caller. */
    _configuration=KVParse(KVJSON(c));if(!_configuration)return KVFail(error,@"CONFIG_SNAPSHOT_FAILED");
    _markerDir=KVDirectory(KVParent(c[@"marker_path"]),0755);_headDir=KVDirectory(KVParent(c[@"head_path"]),0755);
    _journalDir=KVDirectory(journal,0700);_registryDir=KVDirectory(registry,0700);_workspaceDir=KVDirectory(workspace,0711);
    if(_markerDir<0||_headDir<0||_journalDir<0||_registryDir<0||_workspaceDir<0)return KVFail(error,@"PROTECTED_DIRECTORIES_REQUIRED");
    /* Distinct lexical trees can still alias via mounts; reject directory identity aliases. */
    int dirs[]={_journalDir,_registryDir,_workspaceDir,_markerDir,_headDir};struct stat stats[5];
    for(unsigned i=0;i<5;i++)if(fstat(dirs[i],&stats[i]))return KVFail(error,@"DIRECTORY_IDENTITY_UNAVAILABLE");
    for(unsigned i=0;i<5;i++)for(unsigned j=i+1;j<5;j++)if(!(i==3&&j==4)&&stats[i].st_dev==stats[j].st_dev&&stats[i].st_ino==stats[j].st_ino)return KVFail(error,@"DIRECTORY_ALIAS");
    return YES;
}
- (NSData *)readPath:(NSString *)key directory:(int)dir maximum:(NSUInteger)maximum {
    NSString *path=_configuration[key];int fd=openat(dir,KVLeaf(path).fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return nil;bool safe=KVProtectedFile(fd,path);
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    bool gate=safe&&[key isEqual:@"journal_path"];
    if(gate)KVDarwinQAPersistenceGate("history_journal_read");
#endif
    NSData *bytes=safe?KVRead(fd,maximum):nil;int savedErrno=errno;
#if defined(KNOWLEDGE_DARWIN_QA_IO) && KNOWLEDGE_DARWIN_QA_IO
    if(gate)KVDarwinQAPersistenceGateComplete("history_journal_read",bytes!=nil,savedErrno);
#else
    (void)savedErrno;
#endif
    close(fd);return bytes;
}
- (BOOL)createBytes:(NSData *)bytes key:(NSString *)key directory:(int)dir {
    NSString *path=_configuration[key];int fd=openat(dir,KVLeaf(path).fileSystemRepresentation,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return NO;BOOL ok=KVProtectedFile(fd,path)&&KVWrite(fd,bytes)&&KVSync(fd)&&fsync(dir)==0
        &&[KVRead(fd,bytes.length) isEqual:bytes];if(close(fd))ok=NO;return ok;
}
- (BOOL)replaceJSON:(NSDictionary *)record key:(NSString *)key directory:(int)dir expected:(NSDictionary *)expected {
    NSData *before=[self readPath:key directory:dir maximum:16384];if(![before isEqual:KVJSON(expected)])return NO;
    NSString *path=_configuration[key],*temp=[@".uid-history-" stringByAppendingString:KVRandom()];NSData *bytes=KVJSON(record);
    int fd=openat(dir,temp.fileSystemRepresentation,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0)return NO;
    NSString *tempPath=[KVParent(path) stringByAppendingFormat:@"/%@",temp];
    BOOL ok=bytes&&bytes.length<=16384&&KVProtectedFile(fd,tempPath)&&KVWrite(fd,bytes)&&KVSync(fd)
        &&[KVRead(fd,bytes.length) isEqual:bytes];if(close(fd))ok=NO;
    if(ok)ok=renameat(dir,temp.fileSystemRepresentation,dir,KVLeaf(path).fileSystemRepresentation)==0&&fsync(dir)==0;
    if(!ok){unlinkat(dir,temp.fileSystemRepresentation,0);return NO;}
    return [[self readPath:key directory:dir maximum:16384] isEqual:bytes];
}
- (NSDictionary *)newCheckpoint:(uint64_t)sequence tip:(NSString *)tip {
    return @{@"schema":@"knowledge-darwin-uid-checkpoint.v1",@"installation_id":_installationID,
        @"host_id":_configuration[@"host_id"],@"seq":[NSString stringWithFormat:@"%llu",(unsigned long long)sequence],
        @"tip_sha256":tip,@"next_uid":@(KVFirst+sequence)};
}
- (NSDictionary *)header {
    return @{@"schema":@"knowledge-darwin-uid-journal.v1",@"installation_id":_installationID,@"host_id":_configuration[@"host_id"],
        @"uid_first":@(KVFirst),@"uid_end_exclusive":@(KVEnd),@"max_records":@(KVMaxRecords),@"max_bytes":@(KVMaxJournal)};
}
- (NSData *)headerBytes {NSData *body=KVJSON([self header]);uint32_t n=htonl((uint32_t)body.length);
    NSMutableData *bytes=[NSMutableData dataWithBytes:"KUID1HDR" length:8];[bytes appendBytes:&n length:4];[bytes appendData:body];return bytes;}
- (NSData *)recordFrame:(NSDictionary *)record {
    NSData *body=KVJSON(record);if(!body||body.length>KVMaxBody)return nil;uint32_t n=htonl((uint32_t)body.length);
    NSMutableData *hashInput=[NSMutableData dataWithBytes:"KUID1-record" length:sizeof("KUID1-record")]; /* includes NUL */
    [hashInput appendBytes:&n length:4];[hashInput appendData:body];unsigned char digest[32];CC_SHA256(hashInput.bytes,(CC_LONG)hashInput.length,digest);
    NSMutableData *frame=[NSMutableData dataWithBytes:&n length:4];[frame appendData:body];[frame appendBytes:digest length:32];return frame;
}
- (NSString *)frameDigest:(NSData *)frame {if(frame.length<32)return nil;const unsigned char *hash=(const unsigned char *)frame.bytes+frame.length-32;char text[65];
    for(unsigned i=0;i<32;i++)snprintf(text+2*i,3,"%02x",hash[i]);return @(text);}
- (BOOL)loadJournal:(NSData *)bytes error:(NSError **)error {
    NSData *header=[self headerBytes];if(bytes.length<header.length||bytes.length>KVMaxJournal
        ||memcmp(bytes.bytes,header.bytes,header.length))return [self quarantine:@"JOURNAL_HEADER_INVALID" error:error];
    NSString *tip=KVHash(header);if(![_marker[@"genesis_sha256"] isEqual:tip])return [self quarantine:@"GENESIS_MISMATCH" error:error];
    NSMutableArray *records=[NSMutableArray array];NSUInteger offset=header.length;
    while(offset<bytes.length){if(records.count>=KVMaxRecords||bytes.length-offset<4)return [self quarantine:@"JOURNAL_TORN_OR_LIMIT" error:error];
        uint32_t be;memcpy(&be,(const unsigned char *)bytes.bytes+offset,4);NSUInteger size=ntohl(be);
        if(!size||size>KVMaxBody||bytes.length-offset-4<size+32)return [self quarantine:@"JOURNAL_TORN_OR_OVERSIZED" error:error];
        NSData *frame=[bytes subdataWithRange:NSMakeRange(offset,4+size+32)];NSDictionary *r=KVParse([bytes subdataWithRange:NSMakeRange(offset+4,size)]);
        uint64_t sequence=0,uid=0;
        if(!KVKeys(r,@[@"schema",@"event",@"installation_id",@"host_id",@"boot_id",@"seq",@"uid",@"attempt_id",@"previous_sha256"])
            ||![r[@"schema"] isEqual:@"knowledge-darwin-uid-consume.v1"]||![r[@"event"] isEqual:@"consume"]
            ||![r[@"installation_id"] isEqual:_installationID]||![r[@"host_id"] isEqual:_configuration[@"host_id"]]
            ||!KVUUID(r[@"boot_id"])||!KVDecimal(r[@"seq"],KVMaxRecords,&sequence)||sequence!=records.count+1
            ||!KVUInt(r[@"uid"],&uid)||uid!=(uint64_t)KVFirst+records.count||uid>=KVEnd||!KVHex(r[@"attempt_id"])
            ||![r[@"previous_sha256"] isEqual:tip]||![[self recordFrame:r] isEqual:frame])return [self quarantine:@"JOURNAL_RECORD_INVALID" error:error];
        tip=[self frameDigest:frame];[records addObject:@{@"uid":@(uid),@"attempt_id":r[@"attempt_id"],@"seq":r[@"seq"],@"sha256":tip,@"installation_id":_installationID}];
        offset+=frame.length;
    }
    _records=[records copy];_checkpoint=[self newCheckpoint:records.count tip:tip];_journalBytes=[bytes copy];return YES;
}
- (BOOL)lockExisting:(NSError **)error {
    NSString *path=_configuration[@"lock_path"];
    _lock=openat(_journalDir,KVLeaf(path).fileSystemRepresentation,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if(_lock<0||!KVProtectedFile(_lock,path)||flock(_lock,LOCK_EX|LOCK_NB))return KVFail(error,@"SINGLETON_LOCK_UNAVAILABLE");return YES;
}
- (BOOL)loadMarker:(NSError **)error {
    NSDictionary *marker=KVParse([self readPath:@"marker_path" directory:_markerDir maximum:16384]);
    if(!KVKeys(marker,@[@"schema",@"state",@"installation_id",@"configuration",@"genesis_sha256",@"uid_first",@"uid_end_exclusive",@"max_records",@"max_bytes"])
        ||![marker[@"schema"] isEqual:@"knowledge-darwin-uid-install.v1"]||!KVHex(marker[@"installation_id"])
        ||![marker[@"configuration"] isEqual:_configuration]||!KVHex(marker[@"genesis_sha256"])
        ||![marker[@"uid_first"] isEqual:@(KVFirst)]||![marker[@"uid_end_exclusive"] isEqual:@(KVEnd)]
        ||![marker[@"max_records"] isEqual:@(KVMaxRecords)]||![marker[@"max_bytes"] isEqual:@(KVMaxJournal)]
        ||![@[@"initializing",@"ready"] containsObject:marker[@"state"]])return [self quarantine:@"INSTALL_MARKER_INVALID" error:error];
    /* Validate candidate against the last trusted marker BEFORE updating any
     * public cached identity. Quarantine must not adopt a foreign install ID. */
    if(_marker&&![marker isEqual:_marker])return [self quarantine:@"INSTALL_MARKER_CHANGED" error:error];
    _marker=marker;_installationID=marker[@"installation_id"];return YES;
}
- (BOOL)externalRegistryMatches {
    /* Caller owns registry serialization/rename; we do not write its bytes.
     * Also flush the actual protected inode before accepting its checkpoint,
     * so a matching dirty cache alone cannot complete this native handshake. */
    NSString *path=_configuration[@"registry_path"];
    int fd=openat(_registryDir,KVLeaf(path).fileSystemRepresentation,O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return NO;NSData *bytes=nil;
    if(KVProtectedFile(fd,path)&&KVSync(fd)&&fsync(_registryDir)==0)bytes=KVRead(fd,KVMaxJSON);
    BOOL ok=bytes&&[KVRead(fd,KVMaxJSON) isEqual:bytes];if(close(fd))ok=NO;
    NSDictionary *registry=ok?KVParse(bytes):nil;
    return registry&&_checkpoint&&[registry[@"uid_history_checkpoint"] isEqual:_checkpoint];
}
- (BOOL)reloadAgreed:(BOOL)requireRegistry error:(NSError **)error {
    if(_closed||!KVRoot())return [self quarantine:@"ROOT_OPEN_REQUIRED" error:error];
    struct stat opened,named;NSString *lock=_configuration[@"lock_path"];
    if(_lock<0||fstat(_lock,&opened)||fstatat(_journalDir,KVLeaf(lock).fileSystemRepresentation,&named,AT_SYMLINK_NOFOLLOW)
        ||opened.st_dev!=named.st_dev||opened.st_ino!=named.st_ino||!KVProtectedFile(_lock,lock))return [self quarantine:@"SINGLETON_LOCK_REPLACED" error:error];
    if(![self loadMarker:error])return NO;
    NSData *journal=[self readPath:@"journal_path" directory:_journalDir maximum:KVMaxJournal];
    /* A live instance has stronger evidence than a restarted one. Neither a
     * rollback nor an externally appended/replaced chain may discard its
     * already observed checkpoint. Only consume changes this snapshot. */
    if(_journalBytes&&![journal isEqual:_journalBytes])return [self quarantine:@"JOURNAL_CHANGED_OUTSIDE_CONSUME" error:error];
    if(!journal||![self loadJournal:journal error:error])return [self quarantine:@"JOURNAL_UNAVAILABLE_OR_INVALID" error:error];
    _head=KVParse([self readPath:@"head_path" directory:_headDir maximum:16384]);
    if(![_head isEqual:_checkpoint])return [self quarantine:@"HEAD_JOURNAL_MISMATCH" error:error];
    if(requireRegistry&&![self externalRegistryMatches])return [self quarantine:@"REGISTRY_CHECKPOINT_MISMATCH" error:error];
    return YES;
}
+ (instancetype)openWithConfiguration:(NSDictionary *)configuration error:(NSError **)error {
    return [self openWithConfiguration:configuration didAcquireLock:NULL context:NULL error:error];
}
+ (instancetype)openWithConfiguration:(NSDictionary *)configuration didAcquireLock:(void (*)(void *))callback
                              context:(void *)context error:(NSError **)error {
    KVDarwinUIDHistory *h=[self new];if(![h configure:configuration error:error]||![h lockExisting:error]){[h close];return nil;}
    if(callback)callback(context);
    if(![h reloadAgreed:YES error:error])return h;
    if(![h->_marker[@"state"] isEqual:@"ready"]){[h quarantine:@"INITIALIZATION_PENDING" error:error];return h;}
    h->_healthy=YES;h->_reason=@"HEALTHY";return h;
}
+ (instancetype)beginInitializationWithConfiguration:(NSDictionary *)configuration error:(NSError **)error {
    KVDarwinUIDHistory *h=[self new];if(![h configure:configuration error:error]){[h close];return nil;}
    if(!KVEmpty(h->_journalDir)||!KVEmpty(h->_registryDir)||!KVEmpty(h->_workspaceDir)){
        KVFail(error,@"FRESH_EMPTY_DIRECTORIES_REQUIRED");[h close];return nil;}
    for(NSString *key in @[@"marker_path",@"head_path"]){struct stat st;
        if(lstat([configuration[key] fileSystemRepresentation],&st)==0||errno!=ENOENT){KVFail(error,@"INSTALLATION_ALREADY_EXISTS_OR_UNKNOWN");[h close];return nil;}}
    h->_installationID=KVRandom();NSData *header=[h headerBytes];
    h->_marker=@{@"schema":@"knowledge-darwin-uid-install.v1",@"state":@"initializing",@"installation_id":h->_installationID,
        @"configuration":h->_configuration,@"genesis_sha256":KVHash(header),@"uid_first":@(KVFirst),@"uid_end_exclusive":@(KVEnd),
        @"max_records":@(KVMaxRecords),@"max_bytes":@(KVMaxJournal)};
    if(KVJSON(h->_marker).length>16384){KVFail(error,@"INSTALL_MARKER_TOO_LARGE");[h close];return nil;}
    if(![h createBytes:KVJSON(h->_marker) key:@"marker_path" directory:h->_markerDir]
        ||![h createBytes:[NSData data] key:@"lock_path" directory:h->_journalDir]||![h lockExisting:error]
        ||![h createBytes:header key:@"journal_path" directory:h->_journalDir]){
        [h quarantine:@"INITIALIZATION_PARTIAL_NO_RESET" error:error];return h;}
    h->_checkpoint=[h newCheckpoint:0 tip:KVHash(header)];h->_head=h->_checkpoint;h->_journalBytes=header;
    if(![h createBytes:KVJSON(h->_head) key:@"head_path" directory:h->_headDir]){[h quarantine:@"INITIALIZATION_PARTIAL_NO_RESET" error:error];return h;}
    h->_reason=@"INITIALIZATION_PENDING";return h;
}
- (BOOL)finalizeInitializationWithError:(NSError **)error {
    if(!_marker||![_marker[@"state"] isEqual:@"initializing"]||![self reloadAgreed:YES error:error])return [self quarantine:@"INITIALIZATION_NOT_COMPLETE" error:error];
    if(_records.count)return [self quarantine:@"INITIALIZATION_NONEMPTY_HISTORY" error:error];
    NSMutableDictionary *ready=[_marker mutableCopy];ready[@"state"]=@"ready";
    if(![self replaceJSON:ready key:@"marker_path" directory:_markerDir expected:_marker])return [self quarantine:@"INITIALIZATION_READY_WRITE_FAILED" error:error];
    _marker=[ready copy];_healthy=YES;_pending=NO;_reason=@"HEALTHY";return YES;
}
- (NSDictionary *)consumeUIDForPlannedAttempt:(NSString *)attemptID boot:(NSString *)bootID error:(NSError **)error {
    if(!self.healthy||![_marker[@"state"] isEqual:@"ready"]) {KVFail(error,_reason?:@"NOT_HEALTHY");return nil;}
    if(!KVHex(attemptID)||!KVUUID(bootID)){KVFail(error,@"INVALID_ATTEMPT_OR_BOOT");return nil;}
    if(![self reloadAgreed:YES error:error])return nil;
    if(_records.count>=KVMaxRecords||(uint64_t)KVFirst+_records.count>=KVEnd){[self quarantine:@"UID_HISTORY_EXHAUSTED" error:error];return nil;}
    uint64_t sequence=_records.count+1;uint32_t uid=KVFirst+(uint32_t)_records.count;
    NSDictionary *r=@{@"schema":@"knowledge-darwin-uid-consume.v1",@"event":@"consume",@"installation_id":_installationID,
        @"host_id":_configuration[@"host_id"],@"boot_id":bootID,@"seq":[NSString stringWithFormat:@"%llu",(unsigned long long)sequence],
        @"uid":@(uid),@"attempt_id":attemptID,@"previous_sha256":_checkpoint[@"tip_sha256"]};
    NSData *frame=[self recordFrame:r];if(!frame||frame.length>KVMaxJournal-_journalBytes.length){[self quarantine:@"UID_HISTORY_EXHAUSTED" error:error];return nil;}
    NSString *path=_configuration[@"journal_path"];int fd=openat(_journalDir,KVLeaf(path).fileSystemRepresentation,O_RDWR|O_APPEND|O_NOFOLLOW|O_CLOEXEC);
    NSMutableData *after=[_journalBytes mutableCopy];[after appendData:frame];
    BOOL written=fd>=0&&KVProtectedFile(fd,path)&&[KVRead(fd,KVMaxJournal) isEqual:_journalBytes]
        &&KVWrite(fd,frame)&&KVSync(fd)&&fsync(_journalDir)==0&&[KVRead(fd,KVMaxJournal) isEqual:after];
    if(fd>=0&&close(fd))written=NO;
    if(!written){[self quarantine:@"JOURNAL_APPEND_DURABILITY_UNKNOWN" error:error];return nil;}
    NSDictionary *next=[self newCheckpoint:sequence tip:[self frameDigest:frame]];
    if(![self replaceJSON:next key:@"head_path" directory:_headDir expected:_head]){[self quarantine:@"HEAD_ADVANCE_DURABILITY_UNKNOWN" error:error];return nil;}
    _head=next;if(![self loadJournal:after error:error])return nil;
    _healthy=NO;_pending=YES;_reason=@"REGISTRY_CHECKPOINT_PENDING";return [_records.lastObject copy];
}
- (BOOL)confirmRegistryCheckpointWithError:(NSError **)error {
    if(!_pending||_closed||![_marker[@"state"] isEqual:@"ready"])return KVFail(error,@"NO_PENDING_CHECKPOINT");
    if(![self reloadAgreed:YES error:error])return NO;_healthy=YES;_pending=NO;_reason=@"HEALTHY";return YES;
}
- (BOOL)refreshCurrentCheckpointWithError:(NSError **)error {
    if(!self.healthy||![_marker[@"state"] isEqual:@"ready"])return KVFail(error,_reason?:@"NOT_HEALTHY");
    return [self reloadAgreed:YES error:error];
}
- (BOOL)validReservationForUID:(uint32_t)uid attempt:(NSString *)attemptID sequence:(NSString *)sequence sha256:(NSString *)sha256 error:(NSError **)error {
    if(!self.healthy)return KVFail(error,_reason?:@"NOT_HEALTHY");
    uint64_t seq=0;if(!KVHex(attemptID)||!KVHex(sha256)||!KVDecimal(sequence,KVMaxRecords,&seq)||!seq
        ||uid<KVFirst||uid>=KVEnd||seq!=(uint64_t)uid-KVFirst+1)return KVFail(error,@"RESERVATION_TUPLE_INVALID");
    if(![self reloadAgreed:YES error:error])return NO;
    if(seq>_records.count)return KVFail(error,@"RESERVATION_UNKNOWN");NSDictionary *r=_records[(NSUInteger)seq-1];
    return ([r[@"attempt_id"] isEqual:attemptID]&&[r[@"sha256"] isEqual:sha256]&&[r[@"uid"] isEqual:@(uid)])
        ?YES:KVFail(error,@"RESERVATION_TUPLE_MISMATCH");
}
@end
