#define _GNU_SOURCE
#include "verification-linux-service-configuration.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

_Static_assert(KV_LINUX_IMPORT_DEPENDENCIES==6&&KV_LINUX_VERIFY_DEPENDENCIES==7&&
    KV_LINUX_SEMANTIC_DEPENDENCIES==7&&KV_LINUX_WORKER_DEPENDENCIES==7,"reviewed digest vector counts");
_Static_assert(KV_LINUX_SERVICE_CONFIGURATION_HEADER_BYTES==128&&KV_LINUX_SERVICE_CONFIGURATION_PIN_BYTES==1024&&
    KV_LINUX_SERVICE_CONFIGURATION_BYTES==1152&&sizeof(struct kv_linux_service_child_runtime_pins)==1024,
    "explicit configuration field mapping; never a native struct wire copy");
static uint64_t le(const unsigned char *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static int nonzero(const unsigned char *p,size_t n){unsigned v=0;while(n--)v|=*p++;return v!=0;}
int kv_linux_service_configuration_no_attributes(int fd){
    const char *names[]={"system.posix_acl_access","system.posix_acl_default","security.capability"};
    for(unsigned i=0;i<3;i++){
        errno=0;
        if(fgetxattr(fd,names[i],NULL,0)>=0||(errno!=ENODATA&&errno!=ENOTSUP&&errno!=EOPNOTSUPP))return -1;
    }
    return 0;
}
int kv_linux_service_configuration_same(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
int kv_linux_service_configuration_regular(int fd,mode_t mode,off_t size,struct stat *out){
    struct stat st;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
        (st.st_mode&07777)!=mode||st.st_size!=size||kv_linux_service_configuration_no_attributes(fd))return -1;
    if(out)*out=st;
    return 0;
}
static int directory_metadata(int fd){
    struct stat st;
    return !fstat(fd,&st)&&S_ISDIR(st.st_mode)&&!st.st_uid&&!st.st_gid&&!(st.st_mode&0022)&&
        !(st.st_mode&(S_ISUID|S_ISGID))&&!kv_linux_service_configuration_no_attributes(fd)?0:-1;
}
int kv_linux_service_configuration_directory(enum kv_linux_service_fixed_directory which){
    static const struct {const char *path;mode_t mode;} fixed[]={
        {"/etc/knowledge",0755},{KV_LINUX_SERVICE_STATE_PATH,0700},{KV_LINUX_SERVICE_ANCHOR_PATH,0700},
        {KV_LINUX_SERVICE_JOURNAL_PATH,0700},{"/run/knowledge-linux-service",0711},
        {"/run/knowledge-linux-service/imports",0711},{"/run/knowledge-linux-service/custody",0711},
        {"/run/knowledge-linux-service/semantics",0711},{"/run/knowledge-linux-service/verifications",0711},
        {"/run/knowledge-linux-service/workers",0711}};
    if((unsigned)which>=sizeof fixed/sizeof fixed[0]){errno=EINVAL;return -1;}
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    char path[256];size_t n=strlen(fixed[which].path);
    if(n>=sizeof path){close(fd);return -1;}
    memcpy(path,fixed[which].path+1,n);char *save=NULL;
    for(char *part=strtok_r(path,"/",&save);part;part=strtok_r(NULL,"/",&save)){
        if(directory_metadata(fd)){close(fd);return -1;}
        int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;
        if(fd<0)return -1;
    }
    struct stat st;
    if(directory_metadata(fd)||fstat(fd,&st)||(st.st_mode&07777)!=fixed[which].mode){close(fd);return -1;}
    return fd;
}
static int exact_read(int fd,unsigned char *bytes,size_t size){
    size_t done=0;unsigned interrupted=0;
    while(done<size){
        ssize_t n=pread(fd,bytes+done,size-done,(off_t)done);
        if(n<0&&errno==EINTR&&++interrupted<8)continue;
        if(n<=0)return -1;
        done+=(size_t)n;
    }
    return 0;
}
static int digest(unsigned char out[32],const unsigned char bytes[KV_LINUX_SERVICE_CONFIGURATION_BYTES],size_t *offset){
    if(*offset>KV_LINUX_SERVICE_CONFIGURATION_BYTES-32||!nonzero(bytes+*offset,32))return -1;
    memcpy(out,bytes+*offset,32);*offset+=32;return 0;
}
static int decode(const unsigned char b[KV_LINUX_SERVICE_CONFIGURATION_BYTES],struct kv_linux_service_configuration *out){
    if(memcmp(b,"KVLSCFG1",8)||le(b+8,4)!=1||le(b+12,4)!=KV_LINUX_SERVICE_CONFIGURATION_BYTES||
        le(b+16,4)!=KV_LINUX_SERVICE_CONFIGURATION_ABI||le(b+20,4)!=128||le(b+24,4)!=1024||
        nonzero(b+28,4)||nonzero(b+112,16)||!nonzero(b+48,16)||!nonzero(b+64,16))return -1;
    struct kv_linux_service_configuration c;memset(&c,0,sizeof c);
    c.history.anchor_dir=KV_LINUX_SERVICE_ANCHOR_PATH;c.history.journal_dir=KV_LINUX_SERVICE_JOURNAL_PATH;
    c.history.uid_first=(uint32_t)le(b+40,4);c.history.uid_last=(uint32_t)le(b+44,4);
    memcpy(c.history.installation_id,b+48,16);memcpy(c.history.host_id,b+64,16);
    c.policy.authorized_uid=(uid_t)le(b+32,4);c.policy.authorized_gid=(gid_t)le(b+36,4);
    c.policy.max_source_bytes=le(b+80,8);c.policy.setup_ns=le(b+88,8);c.policy.work_ns=le(b+96,8);c.policy.cleanup_ns=le(b+104,8);
    if(!c.policy.authorized_uid||!c.policy.authorized_gid||c.policy.authorized_uid>=1000000000U||c.policy.authorized_gid>=1000000000U||
        c.history.uid_first<1000000000U||c.history.uid_last>=1900000000U||c.history.uid_last<=c.history.uid_first||
        !c.policy.max_source_bytes||c.policy.max_source_bytes>KV_LINUX_SERVICE_MAX_SOURCE_BYTES||
        !c.policy.setup_ns||!c.policy.work_ns||!c.policy.cleanup_ns||c.policy.setup_ns>c.policy.work_ns||
        c.policy.work_ns>UINT64_C(3600000000000)||c.policy.cleanup_ns>UINT64_C(60000000000))return -1;
    size_t offset=128;
    if(digest(c.pins.imports.node,b,&offset))return -1;
    for(unsigned i=0;i<KV_LINUX_IMPORT_DEPENDENCIES;i++)if(digest(c.pins.imports.dependencies[i],b,&offset))return -1;
    if(digest(c.pins.verifies.node,b,&offset))return -1;
    for(unsigned i=0;i<KV_LINUX_VERIFY_DEPENDENCIES;i++)if(digest(c.pins.verifies.dependencies[i],b,&offset))return -1;
    if(digest(c.pins.semantic.node,b,&offset))return -1;
    for(unsigned i=0;i<KV_LINUX_SEMANTIC_DEPENDENCIES;i++)if(digest(c.pins.semantic.dependencies[i],b,&offset))return -1;
    if(digest(c.pins.key.executable,b,&offset)||digest(c.pins.worker.node,b,&offset))return -1;
    for(unsigned i=0;i<KV_LINUX_WORKER_DEPENDENCIES;i++)if(digest(c.pins.worker.dependencies[i],b,&offset))return -1;
    if(offset!=KV_LINUX_SERVICE_CONFIGURATION_BYTES||memcmp(c.pins.imports.node,c.pins.verifies.node,32)||
        memcmp(c.pins.imports.node,c.pins.semantic.node,32)||memcmp(c.pins.imports.node,c.pins.worker.node,32))return -1;
    *out=c;return 0;
}
int kv_linux_service_configuration_load(struct kv_linux_service_configuration *out){
    if(!out){errno=EINVAL;return -1;}
    int directory=kv_linux_service_configuration_directory(KV_SERVICE_CONFIG_DIRECTORY);if(directory<0)return -1;
    int fd=openat(directory,KV_LINUX_SERVICE_CONFIGURATION_NAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK),result=-1;
    struct stat before,after,named;unsigned char bytes[KV_LINUX_SERVICE_CONFIGURATION_BYTES];
    if(fd>=0&&!kv_linux_service_configuration_regular(fd,0600,sizeof bytes,&before)&&!exact_read(fd,bytes,sizeof bytes)&&
        !kv_linux_service_configuration_regular(fd,0600,sizeof bytes,&after)&&kv_linux_service_configuration_same(&before,&after)&&
        !fstatat(directory,KV_LINUX_SERVICE_CONFIGURATION_NAME,&named,AT_SYMLINK_NOFOLLOW)&&
        kv_linux_service_configuration_same(&after,&named)&&!decode(bytes,out))result=0;
    if(fd>=0)close(fd);
    close(directory);return result;
}
