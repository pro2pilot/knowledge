/* Root-native Linux UID burn journal. See paired header for integration limits. */
#define _GNU_SOURCE
#include "verification-linux-uid-history.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#define RECORD_BYTES 256U
#define HASH_OFFSET 224U
#define MAX_RECORDS 100000U
#define KIND_HEADER 1U
#define KIND_BURN 2U
#define KIND_CLOSED 3U
static const unsigned char MAGIC[8]={'K','V','L','H','0','0','1',0};
struct kv_linux_uid_history {
    kv_linux_uid_configuration config;
    char anchor_path[PATH_MAX], journal_path[PATH_MAX];
    int anchor, directory, lock, journal, healthy;
    struct stat anchor_identity,directory_identity,lock_identity,journal_identity;
    unsigned char marker[RECORD_BYTES],head[RECORD_BYTES];
    kv_linux_uid_snapshot state;
    const char *reason;
};
#if defined(KNOWLEDGE_LINUX_UID_HISTORY_TEST_IO)
extern int knowledge_linux_uid_history_test_io(const char *phase);
#define IO_GATE(phase) knowledge_linux_uid_history_test_io(phase)
#else
#define IO_GATE(phase) 0
#endif
static int failure(kv_linux_uid_history *h,const char *reason) {
    if(h){h->healthy=0;h->reason=reason;}return -1;
}
static int nonzero(const unsigned char *bytes,size_t count) {
    unsigned char value=0;for(size_t i=0;i<count;i++)value|=bytes[i];return value!=0;
}
static uint32_t u32(const unsigned char *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static uint64_t u64(const unsigned char *p) {return (uint64_t)u32(p)|(uint64_t)u32(p+4)<<32;}
static void put32(unsigned char *p,uint32_t n) {for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i));}
static void put64(unsigned char *p,uint64_t n) {put32(p,(uint32_t)n);put32(p+4,(uint32_t)(n>>32));}
static int hash_record(const unsigned char *record,unsigned char out[32]) {
    /* Native history hashing must not load caller-selected provider/config
     * code while root. The SHA-256 implementation is the built-in provider. */
    if(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)!=1)return -1;
    unsigned length=0;EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return -1;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&EVP_DigestUpdate(ctx,record,HASH_OFFSET)==1&&
        EVP_DigestFinal_ex(ctx,out,&length)==1&&length==32;
    EVP_MD_CTX_free(ctx);return ok?0:-1;
}
static int protected_acl(int fd) {
    errno=0;ssize_t n=fgetxattr(fd,"system.posix_acl_access",NULL,0);
    if(n>=0)return 0;
    if(errno!=ENODATA&&errno!=ENOTSUP&&errno!=EOPNOTSUPP)return 0;
    errno=0;n=fgetxattr(fd,"system.posix_acl_default",NULL,0);
    return n<0&&(errno==ENODATA||errno==ENOTSUP||errno==EOPNOTSUPP);
}
static int same_object(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;
}
static int same_snapshot(const struct stat *a,const struct stat *b) {
    return same_object(a,b)&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_mode==b->st_mode&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int protected_file(int fd,struct stat *identity) {
    return fstat(fd,identity)==0&&S_ISREG(identity->st_mode)&&identity->st_uid==0&&identity->st_gid==0&&
        identity->st_nlink==1&&(identity->st_mode&07777)==0600&&protected_acl(fd);
}
static int safe_path(const char *path) {
    if(!path||path[0]!='/'||strlen(path)<2||strlen(path)>=PATH_MAX||path[strlen(path)-1]=='/')return 0;
    const char *start=path+1;
    for(const char *p=start;;p++){
        unsigned char c=(unsigned char)*p;
        if(c&& (c<32||c==127||c=='\\'))return 0;
        if(c==0||c=='/'){
            size_t length=(size_t)(p-start);
            if(!length||length>NAME_MAX||(length==1&&start[0]=='.')||(length==2&&start[0]=='.'&&start[1]=='.'))return 0;
            if(!c)break;
            start=p+1;
        }
    }return 1;
}
static int open_directory(const char *path) {
    if(!safe_path(path))return -1;
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat st;
    if(fd<0)return -1;
    if(fstat(fd,&st)||st.st_uid!=0||(st.st_mode&0022)||!protected_acl(fd)){close(fd);return -1;}
    const char *start=path+1;
    for(const char *p=start;;p++)if(!*p||*p=='/'){
        char name[NAME_MAX+1];size_t length=(size_t)(p-start);memcpy(name,start,length);name[length]=0;
        int next=openat(fd,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);close(fd);fd=next;
        if(fd<0)return -1;
        if(fstat(fd,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=0||(st.st_mode&0022)||
           (st.st_mode&(S_ISUID|S_ISGID))||!protected_acl(fd)||(!*p&&(st.st_mode&07777)!=0700)){
            close(fd);return -1;
        }
        if(!*p)break;
        start=p+1;
    }return fd;
}
static int nested(const char *a,const char *b) {
    size_t n=strlen(a);return !strncmp(a,b,n)&&(b[n]==0||b[n]=='/');
}
static int empty_directory(int fd) {
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(copy<0)return 0;
    DIR *directory=fdopendir(copy);if(!directory){close(copy);return 0;}
    int empty=1;struct dirent *entry;errno=0;
    while((entry=readdir(directory)))if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")){empty=0;break;}
    if(!entry&&errno)empty=0;
    closedir(directory);return empty;
}
static int write_exact(int fd,const unsigned char *body,size_t count) {
    size_t at=0;while(at<count){ssize_t n=write(fd,body+at,count-at);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;at+=(size_t)n;}return 0;
}
static int pread_exact(int fd,unsigned char *body,size_t count,off_t offset) {
    size_t at=0;while(at<count){ssize_t n=pread(fd,body+at,count-at,offset+(off_t)at);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;at+=(size_t)n;}return 0;
}
static int fixed_read(int directory,const char *name,unsigned char body[RECORD_BYTES]) {
    int fd=openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
    struct stat before,after,named;
    int ok=protected_file(fd,&before)&&before.st_size==RECORD_BYTES&&pread_exact(fd,body,RECORD_BYTES,0)==0&&
        protected_file(fd,&after)&&same_snapshot(&before,&after)&&fstatat(directory,name,&named,AT_SYMLINK_NOFOLLOW)==0&&same_snapshot(&before,&named);
    if(close(fd))ok=0;
    return ok?0:-1;
}
static int create_file(int directory,const char *name,const unsigned char *body,size_t count) {
    int fd=openat(directory,name,O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)return -1;
    struct stat st;int ok=fchown(fd,0,0)==0&&fchmod(fd,0600)==0&&protected_file(fd,&st)&&write_exact(fd,body,count)==0&&fsync(fd)==0;
    if(close(fd))ok=0;
    if(ok&&fsync(directory))ok=0;
    return ok?0:-1;
}
static int configure(kv_linux_uid_history *h,const kv_linux_uid_configuration *c) {
    if(getuid()!=0||geteuid()!=0||!c||!safe_path(c->anchor_dir)||!safe_path(c->journal_dir)||
       nested(c->anchor_dir,c->journal_dir)||nested(c->journal_dir,c->anchor_dir)||
       c->uid_first<1000000000U||c->uid_last>=1900000000U||c->uid_last<=c->uid_first||
       !nonzero(c->installation_id,16)||!nonzero(c->host_id,16))return failure(h,"configuration_or_root_required");
    h->config=*c;strcpy(h->anchor_path,c->anchor_dir);strcpy(h->journal_path,c->journal_dir);
    h->config.anchor_dir=h->anchor_path;h->config.journal_dir=h->journal_path;
    h->anchor=open_directory(h->anchor_path);h->directory=open_directory(h->journal_path);
    if(h->anchor<0||h->directory<0||fstat(h->anchor,&h->anchor_identity)||fstat(h->directory,&h->directory_identity)||
       same_object(&h->anchor_identity,&h->directory_identity))return failure(h,"protected_directories_required");
    memset(h->marker,0,RECORD_BYTES);memcpy(h->marker,MAGIC,8);put32(h->marker+8,KIND_HEADER);put32(h->marker+12,1);
    put32(h->marker+32,c->uid_first);put32(h->marker+36,c->uid_last);
    memcpy(h->marker+40,c->installation_id,16);memcpy(h->marker+56,c->host_id,16);
    if(hash_record(h->marker,h->marker+HASH_OFFSET))return failure(h,"sha256_unavailable");
    return 0;
}
static kv_linux_uid_history *allocate_context(void) {
    kv_linux_uid_history *h=calloc(1,sizeof(*h));if(!h)return NULL;
    h->anchor=h->directory=h->lock=h->journal=-1;h->reason="not_open";return h;
}
static int bind_storage(kv_linux_uid_history *h) {
    /* Bind the actual append log and singleton lock across process restarts.
     * Keeping old marker/head bytes while replacing either file is rejected. */
    put64(h->marker+184,(uint64_t)h->journal_identity.st_dev);
    put64(h->marker+192,(uint64_t)h->journal_identity.st_ino);
    put64(h->marker+200,(uint64_t)h->lock_identity.st_dev);
    put64(h->marker+208,(uint64_t)h->lock_identity.st_ino);
    put64(h->marker+216,1);
    return hash_record(h->marker,h->marker+HASH_OFFSET)?failure(h,"sha256_unavailable"):0;
}
static int anchors_current(kv_linux_uid_history *h) {
    int a=open_directory(h->anchor_path),j=open_directory(h->journal_path);struct stat sa,sj,sl,named;
    int ok=a>=0&&j>=0&&fstat(a,&sa)==0&&fstat(j,&sj)==0&&same_object(&sa,&h->anchor_identity)&&same_object(&sj,&h->directory_identity)&&
        protected_file(h->lock,&sl)&&same_object(&sl,&h->lock_identity)&&
        fstatat(h->directory,"lock",&named,AT_SYMLINK_NOFOLLOW)==0&&same_snapshot(&sl,&named);
    if(a>=0)close(a);
    if(j>=0)close(j);
    return ok?0:failure(h,"protected_anchor_changed");
}
static int reservation_equal(const kv_linux_uid_reservation *a,const kv_linux_uid_reservation *b) {
    return a&&b&&a->allocation_sequence==b->allocation_sequence&&a->authority_uid==b->authority_uid&&a->worker_uid==b->worker_uid&&
        !memcmp(a->attempt_nonce,b->attempt_nonce,32)&&!memcmp(a->boot_id,b->boot_id,16);
}
static void reservation_from(const unsigned char *record,kv_linux_uid_reservation *r) {
    memset(r,0,sizeof(*r));r->allocation_sequence=u64(record+24);r->authority_uid=u32(record+32);r->worker_uid=u32(record+36);
    memcpy(r->boot_id,record+72,16);memcpy(r->attempt_nonce,record+88,32);
}
static int nonce_compare(const void *a,const void *b){return memcmp(a,b,32);}
static int replay(kv_linux_uid_history *h,const unsigned char *new_nonce) {
    if(!h||!h->healthy)return -1;
    if(anchors_current(h))return -1;
    unsigned char marker[RECORD_BYTES],head[RECORD_BYTES],record[RECORD_BYTES],previous[32];
    if(fixed_read(h->anchor,"marker",marker)||memcmp(marker,h->marker,RECORD_BYTES)||fixed_read(h->anchor,"head",head))
        return failure(h,"marker_or_head_mismatch");
    struct stat before,after,named;
    if(!protected_file(h->journal,&before)||!same_object(&before,&h->journal_identity)||before.st_size<RECORD_BYTES||
       before.st_size%RECORD_BYTES||before.st_size>(off_t)(MAX_RECORDS+1)*RECORD_BYTES||
       fstatat(h->directory,"journal",&named,AT_SYMLINK_NOFOLLOW)||!same_snapshot(&before,&named))return failure(h,"journal_identity_or_size_invalid");
    if(pread_exact(h->journal,record,RECORD_BYTES,0)||memcmp(record,marker,RECORD_BYTES))return failure(h,"journal_genesis_mismatch");
    memcpy(previous,record+HASH_OFFSET,32);kv_linux_uid_snapshot state={0};
    size_t count=(size_t)(before.st_size/RECORD_BYTES)-1,nonces_count=0;
    unsigned char *nonces=count?malloc(count*32):NULL;if(count&&!nonces)return failure(h,"journal_replay_memory_unavailable");
    const char *error=NULL;int duplicate_new=0;
    for(size_t i=1;i<=count;i++){
        unsigned char digest[32];
        if(pread_exact(h->journal,record,RECORD_BYTES,(off_t)i*RECORD_BYTES)||hash_record(record,digest)||
           memcmp(record,MAGIC,8)||u32(record+12)!=1||u64(record+16)!=i||memcmp(record+40,marker+40,32)||
           memcmp(record+152,previous,32)||nonzero(record+184,40)||memcmp(digest,record+HASH_OFFSET,32)){
            error="journal_record_corrupt";break;
        }
        uint32_t kind=u32(record+8);kv_linux_uid_reservation r;reservation_from(record,&r);
        if(kind==KIND_BURN){
            uint64_t expected=(uint64_t)h->config.uid_first+state.allocations*2;
            if(state.pending_cleanup||r.allocation_sequence!=state.allocations+1||expected+1>h->config.uid_last||
               r.authority_uid!=expected||r.worker_uid!=expected+1||!nonzero(r.attempt_nonce,32)||!nonzero(r.boot_id,16)||nonzero(record+120,32)){
                error="journal_allocation_order_invalid";break;
            }
            memcpy(nonces+nonces_count*32,r.attempt_nonce,32);nonces_count++;
            if(new_nonce&&!memcmp(new_nonce,r.attempt_nonce,32))duplicate_new=1;
            state.allocations++;state.pending_cleanup=1;state.reservation=r;
        }else if(kind==KIND_CLOSED){
            if(!state.pending_cleanup||!reservation_equal(&r,&state.reservation)||!nonzero(record+120,32)){
                error="journal_closure_binding_invalid";break;
            }
            state.pending_cleanup=0;
        }else{error="journal_record_kind_invalid";break;}
        state.record_sequence=i;memcpy(previous,record+HASH_OFFSET,32);
    }
    if(!error&&nonces_count>1){qsort(nonces,nonces_count,32,nonce_compare);for(size_t i=1;i<nonces_count;i++)
        if(!memcmp(nonces+(i-1)*32,nonces+i*32,32)){error="journal_duplicate_nonce";break;}}
    free(nonces);
    if(!error&&(memcmp(head,record,RECORD_BYTES)||!protected_file(h->journal,&after)||!same_snapshot(&before,&after)))error="journal_head_mismatch_or_mutation";
    if(error)return failure(h,error);
    memcpy(h->head,head,RECORD_BYTES);memcpy(state.checkpoint_sha256,previous,32);h->state=state;
    h->reason=state.pending_cleanup?"pending_native_cleanup":"ready";
    if(duplicate_new){h->reason="attempt_nonce_already_burned";return -1;}
    return 0;
}
static int publish(kv_linux_uid_history *h,const unsigned char record[RECORD_BYTES]) {
    if(h->state.record_sequence>=MAX_RECORDS)return failure(h,"journal_capacity_exhausted");
    if(IO_GATE("before_journal_write")||write_exact(h->journal,record,RECORD_BYTES)||IO_GATE("before_journal_fsync")||fsync(h->journal))
        return failure(h,"journal_append_unconfirmed");
    if(IO_GATE("after_journal_fsync"))return failure(h,"journal_head_pending");
    unsigned char random[16];ssize_t got=getrandom(random,sizeof(random),0);if(got!=sizeof(random))return failure(h,"head_nonce_unavailable");
    char temp[64]=".head-";static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<16;i++){temp[6+i*2]=hex[random[i]>>4];temp[7+i*2]=hex[random[i]&15];}temp[38]=0;
    if(create_file(h->anchor,temp,record,RECORD_BYTES)||IO_GATE("before_head_rename"))return failure(h,"head_publication_unconfirmed");
    unsigned char prior[RECORD_BYTES];if(fixed_read(h->anchor,"head",prior)||memcmp(prior,h->head,RECORD_BYTES))return failure(h,"head_changed_during_publication");
    if(renameat(h->anchor,temp,h->anchor,"head")||IO_GATE("before_head_directory_fsync")||fsync(h->anchor))return failure(h,"head_publication_unconfirmed");
    return replay(h,NULL);
}
int kv_linux_uid_initialize(const kv_linux_uid_configuration *c,const char **reason) {
    kv_linux_uid_history *h=allocate_context();if(!h){if(reason)*reason="allocation_failed";return -1;}
    int ok=configure(h,c)==0;
    if(ok&&(!empty_directory(h->anchor)||!empty_directory(h->directory))){failure(h,"initialization_requires_empty_directories");ok=0;}
    /* Exclusive empty files fence partial initialization. Their identities are
     * in the immutable genesis/marker before any admission becomes possible. */
    if(ok&&create_file(h->directory,"lock",NULL,0)){failure(h,"initial_lock_unconfirmed");ok=0;}
    if(ok&&create_file(h->directory,"journal",NULL,0)){failure(h,"initial_journal_unconfirmed");ok=0;}
    if(ok){
        h->lock=openat(h->directory,"lock",O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        h->journal=openat(h->directory,"journal",O_RDWR|O_APPEND|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        if(h->lock<0||h->journal<0||!protected_file(h->lock,&h->lock_identity)||h->lock_identity.st_size||
           !protected_file(h->journal,&h->journal_identity)||h->journal_identity.st_size||flock(h->lock,LOCK_EX|LOCK_NB)||
           bind_storage(h)||write_exact(h->journal,h->marker,RECORD_BYTES)||fsync(h->journal)){
            failure(h,"initial_storage_binding_unconfirmed");ok=0;
        }
    }
    if(ok&&create_file(h->anchor,"marker",h->marker,RECORD_BYTES)){failure(h,"initial_marker_unconfirmed");ok=0;}
    if(ok&&create_file(h->anchor,"head",h->marker,RECORD_BYTES)){failure(h,"initial_head_unconfirmed");ok=0;}
    if(reason)*reason=ok?"initialized":h->reason;
    kv_linux_uid_close(h);return ok?0:-1;
}
kv_linux_uid_history *kv_linux_uid_open(const kv_linux_uid_configuration *c,const char **reason) {
    kv_linux_uid_history *h=allocate_context();if(!h){if(reason)*reason="allocation_failed";return NULL;}
    if(configure(h,c))goto bad;
    h->lock=openat(h->directory,"lock",O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(h->lock<0||!protected_file(h->lock,&h->lock_identity)||h->lock_identity.st_size!=0||flock(h->lock,LOCK_EX|LOCK_NB)){
        failure(h,"singleton_lock_unavailable");goto bad;
    }
    h->journal=openat(h->directory,"journal",O_RDWR|O_APPEND|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(h->journal<0||!protected_file(h->journal,&h->journal_identity)){failure(h,"journal_unavailable");goto bad;}
    if(bind_storage(h))goto bad;
    h->healthy=1;if(replay(h,NULL))goto bad;
    if(reason)*reason=h->reason;
    return h;
bad:
    if(reason)*reason=h->reason;
    kv_linux_uid_close(h);return NULL;
}
int kv_linux_uid_read(kv_linux_uid_history *h,kv_linux_uid_snapshot *state) {
    if(!h||!state||replay(h,NULL))return -1;
    *state=h->state;return 0;
}
int kv_linux_uid_reserve(kv_linux_uid_history *h,const unsigned char nonce[32],const unsigned char boot[16],kv_linux_uid_reservation *out) {
    if(!h||!nonce||!boot||!out||!nonzero(nonce,32)||!nonzero(boot,16))return -1;
    if(replay(h,nonce))return -1;
    if(h->state.pending_cleanup){h->reason="pending_native_cleanup";return -1;}
    uint64_t uid=(uint64_t)h->config.uid_first+h->state.allocations*2;
    if(uid+1>h->config.uid_last){h->reason="reserved_uid_range_exhausted";return -1;}
    unsigned char record[RECORD_BYTES]={0};memcpy(record,MAGIC,8);put32(record+8,KIND_BURN);put32(record+12,1);
    put64(record+16,h->state.record_sequence+1);put64(record+24,h->state.allocations+1);put32(record+32,(uint32_t)uid);put32(record+36,(uint32_t)uid+1);
    memcpy(record+40,h->marker+40,32);memcpy(record+72,boot,16);memcpy(record+88,nonce,32);memcpy(record+152,h->state.checkpoint_sha256,32);
    if(hash_record(record,record+HASH_OFFSET)||publish(h,record))return -1;
    *out=h->state.reservation;return 0;
}
int kv_linux_uid_record_closed(kv_linux_uid_history *h,const kv_linux_uid_reservation *reservation,const unsigned char proof[32]) {
    if(!h||!reservation||!proof||!nonzero(proof,32)||replay(h,NULL))return -1;
    if(!h->state.pending_cleanup||!reservation_equal(reservation,&h->state.reservation)){h->reason="closure_reservation_mismatch";return -1;}
    unsigned char record[RECORD_BYTES];memcpy(record,h->head,RECORD_BYTES);put32(record+8,KIND_CLOSED);put64(record+16,h->state.record_sequence+1);
    memcpy(record+120,proof,32);memcpy(record+152,h->state.checkpoint_sha256,32);
    if(hash_record(record,record+HASH_OFFSET)||publish(h,record))return -1;
    return 0;
}
const char *kv_linux_uid_reason(const kv_linux_uid_history *h){return h?h->reason:"not_open";}
void kv_linux_uid_close(kv_linux_uid_history *h) {
    if(!h)return;
    if(h->journal>=0)close(h->journal);
    if(h->lock>=0)close(h->lock);
    if(h->directory>=0)close(h->directory);
    if(h->anchor>=0)close(h->anchor);
    memset(h,0,sizeof(*h));free(h);
}
