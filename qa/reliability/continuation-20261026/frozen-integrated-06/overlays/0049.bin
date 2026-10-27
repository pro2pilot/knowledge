/* Experimental, deliberately C-only privileged launch stub. No Foundation,
 * Objective-C, XPC, dispatch, Mach descriptor imports or asynchronous callbacks.
 * This is not a qualified backend. The paired broker remains unqualified.
 * Build the broker first; embed its actual binary hash when compiling this file.
 */
#if !defined(__APPLE__)
#error "verification-darwin-stub requires the macOS SDK"
#endif
#include <CommonCrypto/CommonDigest.h>
#include <arpa/inet.h>
#include <bsm/audit.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/host_priv.h>
#include <mach/task_special_ports.h>
#include <poll.h>
#include <sandbox.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef KNOWLEDGE_BROKER_BINARY_SHA
#define KNOWLEDGE_BROKER_BINARY_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_BROKER_SOURCE_SHA
#define KNOWLEDGE_BROKER_SOURCE_SHA "UNPINNED"
#endif
#ifndef KNOWLEDGE_DARWIN_STUB_SOURCE_SHA
#define KNOWLEDGE_DARWIN_STUB_SOURCE_SHA "UNPINNED"
#endif
#define K_UID_FIRST 1000000000u
#define K_UID_LAST 1900000000u
#define K_WIRE_MAX (1024u * 1024u)
#define K_BOOTSTRAP_MS 60000u
#define K_PID_CAP 65536u
#define K_MAX_CLEANUP_MS 3600000ull

/* Darwin's feature-macro getgroups$DARWIN_EXTSN enumerates an account's default
 * groups via getpwuid/getgrouplist, not the current setgroups kernel state.
 * A reserved synthetic UID deliberately has no account. Bind the ordinary
 * public getgroups ABI explicitly, independent of this TU's Darwin extensions.
 * Apple bsd/man/man2/getgroups.2 documents the two different semantics.
 * Link/import checks and physical tests must confirm this exact symbol. */
extern int kernel_getgroups(int, gid_t *) __asm("_getgroups");

struct KUnique { uint8_t uuid[16]; uint64_t uniqueid,parent_uniqueid;
    int32_t pidversion; uint32_t reserved; uint64_t reserved2,reserved3; };
struct KIdentity { struct proc_bsdinfo bsd; struct KUnique unique; };
_Static_assert(sizeof(struct KUnique)==56,"Darwin combined process ABI");
struct KOwnerBirth { uint32_t pid,uid;uint64_t unique_id,start_sec,start_usec; };
struct Config {
    unsigned char *wire; size_t length,offset;
    uid_t uid; gid_t gid; bool writable;
    uint64_t writable_device,writable_inode;uint32_t writable_owner,writable_mode;
    uint64_t deadline,cleanup_budget,allocation_seq,lock_device,lock_inode,workspace_device,workspace_inode,scratch_device,scratch_inode;
    char *attempt,*cwd,*profile,*runtime_sha,*daemon_epoch,*installation_id,*allocation_sha;
    struct KOwnerBirth controller,authority;
    uint32_t argc,envc; char **argv,**env;
};
static uint64_t now_ms(void) {
    static uint64_t last;struct timespec t={0};
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000
        ||(uint64_t)t.tv_sec>(UINT64_MAX-K_BOOTSTRAP_MS-999)/1000)_exit(119);
    uint64_t now=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
    if(now<last)_exit(119);
    last=now;return now;
}
static bool hex64(const char *s) { if(!s||strlen(s)!=64)return false;
    for(unsigned i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
static bool fresh(pid_t pid,struct KIdentity *v) { memset(v,0,sizeof(*v));
    return pid>0&&proc_pidinfo(pid,18,0,v,sizeof(*v))==(int)sizeof(*v)
        &&v->bsd.pbi_pid==(uint32_t)pid&&v->unique.uniqueid>0&&v->unique.pidversion>0;
}
static bool root_credentials(const struct KIdentity *v) {
    return v->bsd.pbi_ruid==0&&v->bsd.pbi_uid==0&&v->bsd.pbi_svuid==0;
}
static bool same_birth(const struct KIdentity *a,const struct KIdentity *b) {
    return a->bsd.pbi_pid==b->bsd.pbi_pid&&a->bsd.pbi_ppid==b->bsd.pbi_ppid
        &&a->unique.uniqueid==b->unique.uniqueid&&a->unique.pidversion==b->unique.pidversion
        &&a->unique.parent_uniqueid==b->unique.parent_uniqueid
        &&a->bsd.pbi_start_tvsec==b->bsd.pbi_start_tvsec&&a->bsd.pbi_start_tvusec==b->bsd.pbi_start_tvusec;
}
static bool safe_acl(const char *path) {
    filesec_t metadata=filesec_init();if(!metadata)return false;
    struct stat st;int present=0;acl_t acl=NULL;
    bool ok=lstatx_np(path,&st,metadata)==0&&!S_ISLNK(st.st_mode)
        &&filesec_query_property(metadata,FILESEC_ACL,&present)==0;
    if(ok&&present)ok=filesec_get_property(metadata,FILESEC_ACL,&acl)==0&&acl!=NULL;
    filesec_free(metadata);if(!ok)return false;if(!present)return true;
    acl_entry_t e;int next=ACL_FIRST_ENTRY;
    while(acl_get_entry(acl,next,&e)==0){next=ACL_NEXT_ENTRY;acl_tag_t tag;acl_permset_t permissions;
        if(acl_get_tag_type(e,&tag)||acl_get_permset(e,&permissions)){ok=false;break;}
        if(tag!=ACL_EXTENDED_ALLOW)continue;
        acl_perm_t writes[]={ACL_WRITE_DATA,ACL_APPEND_DATA,ACL_DELETE,ACL_DELETE_CHILD,
            ACL_WRITE_ATTRIBUTES,ACL_WRITE_EXTATTRIBUTES,ACL_WRITE_SECURITY,ACL_CHANGE_OWNER};
        for(unsigned i=0;i<sizeof(writes)/sizeof(writes[0]);i++)if(acl_get_perm_np(permissions,writes[i])!=0){ok=false;break;}
        if(!ok)break;
    }acl_free(acl);return ok;
}
static bool canonical(const char *path,bool absolute) {
    if(!path||!path[0]||strlen(path)>4096||(absolute?(path[0]!='/'):(path[0]=='/')))return false;
    if(!absolute&&!strcmp(path,"."))return true;
    const char *part=path+(absolute?1:0);
    for(const unsigned char *p=(const unsigned char *)path;*p;p++)if(*p<32||*p==127||*p=='\\')return false;
    for(const char *p=part;;p++)if(*p=='/'||!*p){size_t n=(size_t)(p-part);
        if(!n||(n==1&&part[0]=='.')||(n==2&&part[0]=='.'&&part[1]=='.'))return false;
        if(!*p)break;part=p+1;
    }return true;
}
/* A bounded read must reject a file changed during the observation, including
 * same-size rewrites. atime is deliberately excluded: reading may change it.
 * This detects interference; it is not a snapshot against a hostile root or
 * a replacement for quiescent administrator updates. */
static bool same_file_snapshot(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode
        &&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&a->st_size==b->st_size
        &&a->st_mtimespec.tv_sec==b->st_mtimespec.tv_sec&&a->st_mtimespec.tv_nsec==b->st_mtimespec.tv_nsec
        &&a->st_ctimespec.tv_sec==b->st_ctimespec.tv_sec&&a->st_ctimespec.tv_nsec==b->st_ctimespec.tv_nsec;
}
static bool protected_image(const char *path,char digest[65]) {
    if(!canonical(path,true))return false;
    char current[4097];size_t length=strlen(path);struct stat named={0};
    for(size_t i=1;i<=length;i++)if(path[i]=='/'||!path[i]){
        memcpy(current,path,i);current[i]=0;struct stat st;
        if(lstat(current,&st)||st.st_uid!=0||S_ISLNK(st.st_mode))return false;
        bool temporary=!strcmp(current,"/private/tmp")&&S_ISDIR(st.st_mode)&&(st.st_mode&S_ISVTX);
        if((st.st_mode&0022)&&!temporary)return false;
        if(!temporary&&!safe_acl(current))return false;
        if(i<length&&!S_ISDIR(st.st_mode))return false;
        if(i==length){if(!S_ISREG(st.st_mode)||st.st_nlink!=1||(st.st_mode&(S_ISUID|S_ISGID)))return false;named=st;}
    }
    /* O_NOFOLLOW does not reject a regular-file-to-FIFO swap. Open without
     * waiting for a writer, then validate the actual descriptor. */
    int fd=open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return false;
    struct stat st;bool ok=fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_uid==0&&st.st_nlink==1
        &&!(st.st_mode&0022)&&st.st_size>=0&&(uint64_t)st.st_size<=256u*1024u*1024u
        &&same_file_snapshot(&named,&st);
    CC_SHA256_CTX ctx;CC_SHA256_Init(&ctx);unsigned char bytes[65536];off_t offset=0;
    while(ok&&offset<st.st_size){size_t wanted=(uint64_t)(st.st_size-offset)<sizeof(bytes)?(size_t)(st.st_size-offset):sizeof(bytes);
        ssize_t n=pread(fd,bytes,wanted,offset);
        if(n<0&&errno==EINTR)continue;if(n<=0){ok=false;break;}
        offset+=n;CC_SHA256_Update(&ctx,bytes,(CC_LONG)n);
    }
    if(ok){unsigned char extra;ssize_t n;
        do{n=pread(fd,&extra,1,st.st_size);}while(n<0&&errno==EINTR);
        struct stat after,currentName;
        ok=n==0&&fstat(fd,&after)==0&&same_file_snapshot(&st,&after)
            &&lstat(path,&currentName)==0&&same_file_snapshot(&after,&currentName);
    }
    if(close(fd))ok=false;if(!ok)return false;
    unsigned char hash[32];CC_SHA256_Final(hash,&ctx);
    for(unsigned i=0;i<32;i++)snprintf(digest+2*i,3,"%02x",hash[i]);return true;
}
static bool parent_origin(void) {
    struct KIdentity own,parent,init,parent_again,init_again;pid_t p=getppid();
    char image[PROC_PIDPATHINFO_MAXSIZE],digest[65],self[PROC_PIDPATHINFO_MAXSIZE];
    if(!fresh(getpid(),&own)||!root_credentials(&own)||!fresh(p,&parent)||!root_credentials(&parent)
        ||own.bsd.pbi_ppid!=parent.bsd.pbi_pid||own.unique.parent_uniqueid!=parent.unique.uniqueid
        ||!fresh(1,&init)||!root_credentials(&init)||parent.bsd.pbi_ppid!=1
        ||parent.unique.parent_uniqueid!=init.unique.uniqueid)return false;
    if(proc_pidpath(p,image,sizeof(image))<=0||!protected_image(image,digest)||strcmp(digest,KNOWLEDGE_BROKER_BINARY_SHA))return false;
    if(proc_pidpath(1,image,sizeof(image))<=0||strcmp(image,"/sbin/launchd")||!protected_image(image,digest))return false;
    if(proc_pidpath(getpid(),self,sizeof(self))<=0||!protected_image(self,digest))return false;
    return fresh(p,&parent_again)&&fresh(1,&init_again)&&root_credentials(&parent_again)&&root_credentials(&init_again)
        &&same_birth(&parent,&parent_again)&&same_birth(&init,&init_again);
}
static bool read_exact(int fd,void *data,size_t size,uint64_t deadline) {
    unsigned char *p=data;
    while(size){uint64_t now=now_ms();if(now>=deadline)return false;
        struct pollfd event={fd,POLLIN,0};int wait=poll(&event,1,(int)((deadline-now)>200?200:deadline-now));
        if(wait<0&&errno==EINTR)continue;if(wait<0)return false;if(!wait)continue;
        if(!(event.revents&(POLLIN|POLLHUP)))return false;
        ssize_t n=read(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return false;
        p+=n;size-=(size_t)n;
    }return true;
}
static bool u32(struct Config *c,uint32_t *out) {
    if(c->offset>c->length||c->length-c->offset<4)return false;uint32_t n;
    memcpy(&n,c->wire+c->offset,4);c->offset+=4;*out=ntohl(n);return true;
}
static bool u64(struct Config *c,uint64_t *out) { uint32_t hi,lo;
    if(!u32(c,&hi)||!u32(c,&lo))return false;*out=((uint64_t)hi<<32)|lo;return true;
}
static bool owner_birth(struct Config *c,struct KOwnerBirth *out) {
    return u32(c,&out->pid)&&out->pid>1&&out->pid<=INT32_MAX
        &&u32(c,&out->uid)&&out->uid>0&&out->uid<K_UID_FIRST
        &&u64(c,&out->unique_id)&&out->unique_id>0
        &&u64(c,&out->start_sec)&&out->start_sec>0
        &&u64(c,&out->start_usec)&&out->start_usec<1000000;
}
static bool valid_utf8(const unsigned char *s,size_t size) {
    for(size_t i=0;i<size;){uint32_t cp;unsigned more;unsigned char first=s[i++];
        if(first<0x80)continue;
        if(first>=0xc2&&first<=0xdf){cp=first&31;more=1;}
        else if(first>=0xe0&&first<=0xef){cp=first&15;more=2;}
        else if(first>=0xf0&&first<=0xf4){cp=first&7;more=3;}else return false;
        if(more>size-i)return false;
        for(unsigned j=0;j<more;j++){unsigned char next=s[i++];if((next&0xc0)!=0x80)return false;cp=(cp<<6)|(next&63);}
        if((more==1&&cp<0x80)||(more==2&&cp<0x800)||(more==3&&cp<0x10000)
            ||(cp>=0xd800&&cp<=0xdfff)||cp>0x10ffff)return false;
    }return true;
}
static char *string_field(struct Config *c,size_t maximum,bool empty) { uint32_t n;
    if(!u32(c,&n)||(!empty&&!n)||n>maximum||c->offset>c->length||n>c->length-c->offset
        ||memchr(c->wire+c->offset,0,n)||!valid_utf8(c->wire+c->offset,n))return NULL;
    char *s=malloc((size_t)n+1);if(!s)return NULL;
    memcpy(s,c->wire+c->offset,n);s[n]=0;c->offset+=n;return s;
}
static bool decode(struct Config *c) {
    uint32_t magic,uid,gid;
    if(!u32(c,&magic)||(magic!=0x4b565332u&&magic!=0x4b565333u)
        ||!u32(c,&uid)||uid<K_UID_FIRST||uid>=K_UID_LAST)return false;
    c->writable=magic==0x4b565333u;gid=uid;
    if(c->writable&&(!u32(c,&gid)||gid<2000000000u||gid>=2100000000u))return false;
    if(!u32(c,&c->argc)||!c->argc||c->argc>256||!u32(c,&c->envc)||c->envc>256
        ||!u64(c,&c->deadline)||!c->deadline||!u64(c,&c->cleanup_budget)||!c->cleanup_budget||c->cleanup_budget>K_MAX_CLEANUP_MS
        ||!u64(c,&c->allocation_seq)||c->allocation_seq!=(uint64_t)uid-K_UID_FIRST+1
        ||!u64(c,&c->lock_device)||!u64(c,&c->lock_inode)
        ||!u64(c,&c->workspace_device)||!u64(c,&c->workspace_inode)
        ||!u64(c,&c->scratch_device)||!u64(c,&c->scratch_inode))return false;
    if(c->writable&&(!u64(c,&c->writable_device)||!u64(c,&c->writable_inode)
        ||!u32(c,&c->writable_owner)||!c->writable_owner||c->writable_owner>=K_UID_FIRST
        ||!u32(c,&c->writable_mode)||c->writable_mode!=0770))return false;
    if(!owner_birth(c,&c->controller)||!owner_birth(c,&c->authority)
        ||c->controller.uid!=c->authority.uid||c->controller.pid==c->authority.pid)return false;
    if(c->writable&&c->writable_owner!=c->controller.uid)return false;
    c->uid=(uid_t)uid;c->gid=(gid_t)gid;
    c->attempt=string_field(c,64,false);c->runtime_sha=string_field(c,64,false);
    c->daemon_epoch=string_field(c,64,false);c->installation_id=string_field(c,64,false);c->allocation_sha=string_field(c,64,false);
    c->cwd=string_field(c,4096,false);c->profile=string_field(c,131072,false);
    if(!hex64(c->attempt)||!hex64(c->runtime_sha)||!hex64(c->daemon_epoch)||!hex64(c->installation_id)
        ||!hex64(c->allocation_sha)||!canonical(c->cwd,false)||!c->profile)return false;
    c->argv=calloc((size_t)c->argc+1,sizeof(char *));c->env=calloc((size_t)c->envc+1,sizeof(char *));
    if(!c->argv||!c->env)return false;
    for(uint32_t i=0;i<c->argc;i++)if(!(c->argv[i]=string_field(c,131072,true)))return false;
    if(!canonical(c->argv[0],true))return false;
    for(uint32_t i=0;i<c->envc;i++){
        if(!(c->env[i]=string_field(c,131329,false)))return false;
        const char *equals=strchr(c->env[i],'=');if(!equals||equals==c->env[i]||(size_t)(equals-c->env[i])>256)return false;
        size_t key_size=(size_t)(equals-c->env[i]);
        for(size_t j=0;j<key_size;j++){unsigned char ch=c->env[i][j];
            if(!((ch>='A'&&ch<='Z')||(ch>='a'&&ch<='z')||ch=='_'||(j&&ch>='0'&&ch<='9')))return false;}
        if(!strncmp(c->env[i],"DYLD_",5))return false;
        const char *blocked[]={"NODE_OPTIONS","BASH_ENV","ENV"};
        for(unsigned j=0;j<sizeof(blocked)/sizeof(blocked[0]);j++)
            if(strlen(blocked[j])==key_size&&!memcmp(c->env[i],blocked[j],key_size))return false;
        for(uint32_t j=0;j<i;j++)if(!strncmp(c->env[j],c->env[i],key_size)&&c->env[j][key_size]=='=')return false;
    }
    return c->offset==c->length;
}
static bool read_config(struct Config *c,int fd,uint64_t deadline) {
    uint32_t length;if(!read_exact(fd,&length,4,deadline))return false;
    c->length=ntohl(length);if(!c->length||c->length>K_WIRE_MAX)return false;
    c->wire=malloc(c->length);if(!c->wire||!read_exact(fd,c->wire,c->length,deadline)||!decode(c))return false;
    /* No appended frame, hidden strings, or indefinitely open config channel.
     * The decoded work deadline also bounds waiting for EOF in launch mode. */
    if(c->deadline<deadline)deadline=c->deadline;
    unsigned char extra;
    while(now_ms()<deadline){struct pollfd p={fd,POLLIN,0};int n=poll(&p,1,100);
        if(n<0&&errno==EINTR)continue;if(n<0)return false;if(!n)continue;
        if(!(p.revents&(POLLIN|POLLHUP)))return false;
        ssize_t count=read(fd,&extra,1);if(count<0&&errno==EINTR)continue;return count==0;
    }return false;
}
static bool bound_fds(const struct Config *c) {
    struct stat lock,workspace,scratch,writable;int mode=fcntl(13,F_GETFL);
    if(c->writable&&(fstat(16,&writable)||!S_ISDIR(writable.st_mode)
        ||writable.st_uid!=c->writable_owner||writable.st_gid!=c->gid
        ||(writable.st_mode&07777)!=c->writable_mode
        ||(uint64_t)writable.st_dev!=c->writable_device||(uint64_t)writable.st_ino!=c->writable_inode))return false;
    return fstat(13,&lock)==0&&S_ISREG(lock.st_mode)&&lock.st_uid==0&&lock.st_nlink==1
        &&(lock.st_mode&0777)==0600&&mode>=0&&(mode&O_ACCMODE)==O_RDWR
        &&(uint64_t)lock.st_dev==c->lock_device&&(uint64_t)lock.st_ino==c->lock_inode
        &&flock(13,LOCK_EX|LOCK_NB)==0&&fstat(14,&workspace)==0&&S_ISDIR(workspace.st_mode)
        &&workspace.st_uid==c->uid&&workspace.st_gid==c->uid&&(workspace.st_mode&0777)==0700
        &&(uint64_t)workspace.st_dev==c->workspace_device&&(uint64_t)workspace.st_ino==c->workspace_inode
        &&fstat(15,&scratch)==0&&S_ISDIR(scratch.st_mode)&&scratch.st_uid==c->uid&&scratch.st_gid==c->gid
        &&(scratch.st_mode&0777)==0700&&(uint64_t)scratch.st_dev==c->scratch_device&&(uint64_t)scratch.st_ino==c->scratch_inode
        &&(scratch.st_dev!=workspace.st_dev||scratch.st_ino!=workspace.st_ino);
}
static bool private_credentials(uid_t uid,gid_t gid) {
    struct KIdentity own={0};gid_t groups[256]={0};
    errno=0;int observed_bytes=proc_pidinfo(getpid(),18,0,&own,sizeof(own));int observation_errno=errno;
    bool observed=observed_bytes==(int)sizeof(own)&&own.bsd.pbi_pid==(uint32_t)getpid()
        &&own.unique.uniqueid>0&&own.unique.pidversion>0;
    errno=0;int count=kernel_getgroups(256,groups);int group_errno=errno;
    bool ok=observed&&own.bsd.pbi_ruid==uid&&own.bsd.pbi_uid==uid&&own.bsd.pbi_svuid==uid
        &&own.bsd.pbi_rgid==gid&&own.bsd.pbi_gid==gid&&own.bsd.pbi_svgid==gid
        &&count==1&&groups[0]==gid;
    if(!ok){/* Diagnostic comparison only; it does not turn a failed check into admission. */
        errno=0;int query_count=kernel_getgroups(0,NULL);int query_errno=errno;
        struct proc_bsdinfo bsd={0};errno=0;int bsd_bytes=proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&bsd,sizeof(bsd));int bsd_errno=errno;
        bool bsd_matches=bsd_bytes==(int)sizeof(bsd)&&bsd.pbi_pid==(uint32_t)getpid()
            &&bsd.pbi_ruid==uid&&bsd.pbi_uid==uid&&bsd.pbi_svuid==uid
            &&bsd.pbi_rgid==gid&&bsd.pbi_gid==gid&&bsd.pbi_svgid==gid;
        fprintf(stderr,"native C stub private-credential observation: combined_bytes=%d expected_bytes=%zu combined_observed=%s observation_errno=%d bsd_bytes=%d bsd_errno=%d bsd_credentials_match=%s groups_count=%d groups_errno=%d groups_query_count=%d groups_query_errno=%d\n",
            observed_bytes,sizeof(own),observed?"true":"false",observation_errno,bsd_bytes,bsd_errno,bsd_matches?"true":"false",count,group_errno,query_count,query_errno);
    }
    return ok;
}
/* Only for this reviewed tiny C image. New task spaces inherit SEND slots,
 * not arbitrary RECEIVE rights. There are no descriptor-bearing inputs or
 * asynchronous callbacks. Own runtime RECEIVE queues must be empty. Never
 * destroy or unguard libc receive ports; unknown rights fail closed. */
static bool scrub_names(void) {
    task_t task=mach_task_self();thread_t self=mach_thread_self();
    thread_act_array_t threads=NULL;mach_msg_type_number_t thread_count=0;
    if(task_threads(task,&threads,&thread_count)!=KERN_SUCCESS||thread_count!=1||threads[0]!=self)return false;
    if(mach_port_deallocate(task,threads[0])!=KERN_SUCCESS
        ||vm_deallocate(task,(vm_address_t)threads,sizeof(*threads))!=KERN_SUCCESS)return false;
    if(task_set_special_port(task,TASK_BOOTSTRAP_PORT,MACH_PORT_NULL)!=KERN_SUCCESS
        ||mach_ports_register(task,NULL,0)!=KERN_SUCCESS
        ||task_set_exception_ports(task,EXC_MASK_ALL,MACH_PORT_NULL,EXCEPTION_DEFAULT,THREAD_STATE_NONE)!=KERN_SUCCESS
        ||thread_set_exception_ports(self,EXC_MASK_ALL,MACH_PORT_NULL,EXCEPTION_DEFAULT,THREAD_STATE_NONE)!=KERN_SUCCESS)return false;
    for(unsigned pass=0;pass<2;pass++){
        mach_port_name_array_t names=NULL;mach_port_type_array_t types=NULL;mach_msg_type_number_t nn=0,nt=0;
        if(mach_port_names(task,&names,&nn,&types,&nt)!=KERN_SUCCESS||nn!=nt||nn>256)return false;
        bool ok=true;
        for(mach_msg_type_number_t i=0;i<nn;i++){
            mach_port_t name=names[i];mach_port_type_t type=types[i];
            if(name==task||name==self){if(type!=MACH_PORT_TYPE_SEND)ok=false;}
            else if(type==MACH_PORT_TYPE_RECEIVE||type==(MACH_PORT_TYPE_RECEIVE|MACH_PORT_TYPE_SEND)){
                mach_port_status_t status={0};mach_msg_type_number_t count=MACH_PORT_RECEIVE_STATUS_COUNT;
                if(mach_port_get_attributes(task,name,MACH_PORT_RECEIVE_STATUS,(mach_port_info_t)&status,&count)!=KERN_SUCCESS
                    ||count!=MACH_PORT_RECEIVE_STATUS_COUNT||status.mps_msgcount!=0)ok=false;
            }else if(type==MACH_PORT_TYPE_SEND){mach_port_urefs_t refs=0;
                if(pass||mach_port_get_refs(task,name,MACH_PORT_RIGHT_SEND,&refs)!=KERN_SUCCESS||!refs||refs>65535
                    ||mach_port_mod_refs(task,name,MACH_PORT_RIGHT_SEND,-(mach_port_delta_t)refs)!=KERN_SUCCESS)ok=false;
            }else if(type!=MACH_PORT_TYPE_DEAD_NAME)ok=false;
            if(!ok)break;
        }
        kern_return_t n=vm_deallocate(task,(vm_address_t)names,nn*sizeof(*names));
        kern_return_t t=vm_deallocate(task,(vm_address_t)types,nt*sizeof(*types));
        if(!ok||n!=KERN_SUCCESS||t!=KERN_SUCCESS)return false;
    }return true;
}
static bool ordinary_host(void) {
    task_t task=mach_task_self();mach_port_t host=MACH_PORT_NULL;mach_port_type_t type=0;
    host_basic_info_data_t basic={0};mach_msg_type_number_t count=HOST_BASIC_INFO_COUNT;kernel_boot_info_t boot={0};
    bool ok=task_get_special_port(task,TASK_HOST_PORT,&host)==KERN_SUCCESS&&MACH_PORT_VALID(host)
        &&mach_port_type(task,host,&type)==KERN_SUCCESS&&(type&MACH_PORT_TYPE_SEND)
        &&host_info(host,HOST_BASIC_INFO,(host_info_t)&basic,&count)==KERN_SUCCESS&&count==HOST_BASIC_INFO_COUNT
        &&host_get_boot_info(host,boot)==KERN_INVALID_HOST;
    memset(boot,0,sizeof(boot));if(MACH_PORT_VALID(host)&&mach_port_deallocate(task,host)!=KERN_SUCCESS)ok=false;
    return ok;
}
static bool isolated_cwd(int root,const char *relative) {
    struct stat boundary;if(fstat(root,&boundary)||!S_ISDIR(boundary.st_mode))return false;
    int fd=dup(root);if(fd<0)return false;
    if(strcmp(relative,".")){char *copy=strdup(relative);if(!copy){close(fd);return false;}char *save=NULL;
        for(char *part=strtok_r(copy,"/",&save);part;part=strtok_r(NULL,"/",&save)){
            int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);fd=next;if(fd<0)break;
        }free(copy);if(fd<0)return false;
    }
    int cursor=dup(fd);bool within=false;
    for(unsigned depth=0;cursor>=0&&depth<1024;depth++){struct stat current,above;
        if(fstat(cursor,&current))break;
        if(current.st_dev==boundary.st_dev&&current.st_ino==boundary.st_ino){within=true;break;}
        int parent=openat(cursor,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(parent<0||fstat(parent,&above)){if(parent>=0)close(parent);break;}
        if(above.st_dev==current.st_dev&&above.st_ino==current.st_ino){close(parent);break;}close(cursor);cursor=parent;
    }
    if(cursor>=0)close(cursor);bool ok=within&&fchdir(fd)==0;close(fd);return ok;
}
static int launch_child(const struct Config *c,uint64_t bootstrap) {
    /* The root guardian remains an independent process. This command child
     * has no signal handlers, control channel writers, or root guardian FDs. */
    signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);alarm(60);
    uint64_t deadline=c->deadline<bootstrap?c->deadline:bootstrap;
    mach_port_t access=MACH_PORT_NULL;mach_port_type_t type=0;task_t task=mach_task_self();
    if(task_get_special_port(task,TASK_ACCESS_PORT,&access)!=KERN_SUCCESS
        ||(access!=MACH_PORT_NULL&&(!MACH_PORT_VALID(access)||mach_port_type(task,access,&type)!=KERN_SUCCESS||!(type&MACH_PORT_TYPE_SEND))))return 130;
    if(!scrub_names())return 132;
    char *sandbox_error=NULL;if(sandbox_init(c->profile,0,&sandbox_error)){if(sandbox_error)sandbox_free_error(sandbox_error);return 133;}
    gid_t group=c->gid;
    if(setgroups(1,&group)){fprintf(stderr,"native C stub credential stage=setgroups errno=%d\n",errno);return 134;}
    if(setgid(group)){fprintf(stderr,"native C stub credential stage=setgid errno=%d\n",errno);return 134;}
    if(setuid(c->uid)){fprintf(stderr,"native C stub credential stage=setuid errno=%d\n",errno);return 134;}
    if(!private_credentials(c->uid,c->gid))return 134;
    if(!ordinary_host()||!scrub_names())return 135;
    if(!isolated_cwd(c->writable?16:14,c->cwd))return 136;close(14);close(15);if(c->writable)close(16);
    struct rlimit core={0,0};if(setrlimit(RLIMIT_CORE,&core))return 137;
    if(now_ms()>=deadline)return 125;
    char ready='R';if(write(11,&ready,1)!=1)return 138;close(11);
    /* Close the inherited OFD only AFTER private credentials are visible.
     * Never LOCK_UN: parent and stub share the same admission description. */
    close(13);char go;if(!read_exact(12,&go,1,deadline)||go!='G')return 139;close(12);
    if(now_ms()>=deadline)return 125;
    /* Descriptor cleanup can be delayed too. Keep the bootstrap alarm until
     * after it, and recheck the original command deadline immediately before
     * exec-> A successful gate is not permission to start after its budget. */
    int descriptor_limit=getdtablesize();
    if(descriptor_limit<3)return 137;
    for(int fd=3;fd<descriptor_limit;fd++)close(fd);
    if(now_ms()>=deadline)return 125;
    alarm(0);
    execve(c->argv[0],c->argv,c->env);return 140;
}

/* BEGIN EXACT PORTABLE GUARDIAN STATE MACHINE
 * This control core is compiled verbatim by portable adversarial tests. Native
 * wrappers below supply checked CLOCK_MONOTONIC, exact births and UID scans.
 * A cleanup deadline reports failure; it never releases the enforcer. */
enum { KVG_STOP_REQUEST=1u, KVG_PARENT_LOST=2u, KVG_DEADLINE=4u,
       KVG_CLOCK=8u, KVG_WAIT_UNKNOWN=16u, KVG_CHILD_EXIT=32u };
struct KGuardState {
    uint64_t deadline,cleanup_budget,last_now,cleanup_started,cleanup_deadline;
    unsigned reasons;
    bool stopped,child_reaped,clock_failed,cleanup_expired,complete;
    int child_status;
};
struct KGuardOps {
    bool (*clock)(void *,uint64_t *);
    int (*parent)(void *);
    int (*reap)(void *,int *);
    void (*signal_child)(void *);
    int (*drain_uid)(void *);
};
static void kvg_step(struct KGuardState *s,const struct KGuardOps *ops,void *ctx,bool requested) {
    if(s->complete)return;
    uint64_t now=0;bool clockOK=ops->clock(ctx,&now);
    if(!clockOK||now<s->last_now){s->clock_failed=true;s->reasons|=KVG_CLOCK;}
    else s->last_now=now;
    if(requested)s->reasons|=KVG_STOP_REQUEST;
    if(ops->parent(ctx)!=1)s->reasons|=KVG_PARENT_LOST;
    if(clockOK&&now>=s->deadline)s->reasons|=KVG_DEADLINE;
    if(!s->child_reaped){int status=0,wait=ops->reap(ctx,&status);
        if(wait==1){s->child_reaped=true;s->child_status=status;s->reasons|=KVG_CHILD_EXIT;}
        else if(wait<0)s->reasons|=KVG_WAIT_UNKNOWN;
    }
    if(s->reasons&&!s->stopped){s->stopped=true;s->cleanup_started=s->last_now;
        s->cleanup_deadline=UINT64_MAX-s->last_now<s->cleanup_budget?UINT64_MAX:s->last_now+s->cleanup_budget;}
    if(!s->stopped)return;
    if(s->clock_failed||(clockOK&&now>=s->cleanup_deadline))s->cleanup_expired=true;
    if(!s->child_reaped)ops->signal_child(ctx);
    /* The last full scan is after direct-child reap. Its zero is a current
     * observation, never a guess based on a timeout, ECHILD or stale scan. */
    int count=ops->drain_uid(ctx);
    /* Reap, UID enumeration and scheduling consume the existing allowance.
     * Keep actual closure separate from timely success: a late or clockless
     * zero can finish enforcement only after reap, but cannot return PASS. */
    uint64_t finished=0;bool finalClockOK=ops->clock(ctx,&finished);
    if(!finalClockOK||finished<s->last_now){s->clock_failed=true;s->reasons|=KVG_CLOCK;}
    else s->last_now=finished;
    if(finalClockOK&&finished>=s->deadline)s->reasons|=KVG_DEADLINE;
    if(s->clock_failed||(finalClockOK&&finished>=s->cleanup_deadline))s->cleanup_expired=true;
    if(s->child_reaped&&count==0)s->complete=true;
}
/* END EXACT PORTABLE GUARDIAN STATE MACHINE */

typedef int (*KSignalToken)(const audit_token_t *,int);
static volatile sig_atomic_t guardian_stop;
static void guardian_signal(int signal_number) {(void)signal_number;guardian_stop=1;}
struct KGuardian {
    const struct Config *config;struct KIdentity parent,own,child;
    pid_t child_pid;bool child_known;pid_t *pids;KSignalToken signal_token;
};
static bool guardian_clock(void *opaque,uint64_t *now) {
    (void)opaque;struct timespec t={0};
    if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000
        ||(uint64_t)t.tv_sec>(UINT64_MAX-999)/1000)return false;
    *now=(uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;return true;
}
/* Exec may change pidversion while retaining the same process birth. The
 * signal always uses the freshly observed version, so PID reuse cannot be hit. */
static bool guardian_same_process(const struct KIdentity *a,const struct KIdentity *b) {
    return a->bsd.pbi_pid==b->bsd.pbi_pid&&a->unique.uniqueid==b->unique.uniqueid
        &&a->bsd.pbi_start_tvsec==b->bsd.pbi_start_tvsec&&a->bsd.pbi_start_tvusec==b->bsd.pbi_start_tvusec;
}
static int guardian_owner(const struct KOwnerBirth *expected) {
    struct KIdentity owner;errno=0;
    if(!fresh((pid_t)expected->pid,&owner))return errno==ESRCH?0:-1;
    return owner.unique.uniqueid==expected->unique_id&&owner.bsd.pbi_start_tvsec==expected->start_sec
        &&owner.bsd.pbi_start_tvusec==expected->start_usec&&owner.bsd.pbi_ruid==expected->uid
        &&owner.bsd.pbi_uid==expected->uid&&owner.bsd.pbi_svuid==expected->uid?1:0;
}
static int guardian_parent(void *opaque) {
    struct KGuardian *g=opaque;struct KIdentity parent;errno=0;
    if(!fresh((pid_t)g->parent.bsd.pbi_pid,&parent))return errno==ESRCH?0:-1;
    if(!root_credentials(&parent)||!same_birth(&g->parent,&parent))return 0;
    /* Controller/authority loss is independently observable even when the
     * entire daemon is SIGSTOPped. Only negative liveness is delegated here:
     * these cached births never grant a launch or a positive cleanup proof. */
    int controller=guardian_owner(&g->config->controller);
    return controller==1?guardian_owner(&g->config->authority):controller;
}
static int guardian_reap(void *opaque,int *status) {
    struct KGuardian *g=opaque;pid_t observed=waitpid(g->child_pid,status,WNOHANG);
    if(observed==g->child_pid)return 1;
    if(observed==0||(observed<0&&errno==EINTR))return 0;
    return -1; /* ECHILD is not permission to invent a reaped exit. */
}
static bool guardian_signal_identity(struct KGuardian *g,const struct KIdentity *v,int sig) {
    audit_token_t token={{0}};token.val[5]=v->bsd.pbi_pid;token.val[7]=(uint32_t)v->unique.pidversion;
    int result=g->signal_token(&token,sig);return result==0||result==ESRCH;
}
static void guardian_signal_child(void *opaque) {
    struct KGuardian *g=opaque;struct KIdentity current;
    if(!fresh(g->child_pid,&current))return;
    /* Before private credentials there may be no UID member. Only this
     * exact kernel child of this guardian can receive a root-phase signal. */
    if(current.bsd.pbi_ppid!=(uint32_t)getpid()||current.unique.parent_uniqueid!=g->own.unique.uniqueid)return;
    if(g->child_known&&!guardian_same_process(&g->child,&current))return;
    if(!root_credentials(&current)&&current.bsd.pbi_ruid!=g->config->uid)return;
    if(!g->child_known){g->child=current;g->child_known=true;}
    guardian_signal_identity(g,&current,SIGKILL);
}
static int guardian_members(struct KGuardian *g) {
    errno=0;int bytes=proc_listpids(PROC_RUID_ONLY,g->config->uid,g->pids,(int)(K_PID_CAP*sizeof(pid_t)));
    if(bytes<0||(bytes==0&&errno)||bytes%(int)sizeof(pid_t)||bytes>=(int)(K_PID_CAP*sizeof(pid_t)))return -1;
    return bytes/(int)sizeof(pid_t);
}
static int guardian_drain(void *opaque) {
    struct KGuardian *g=opaque;int count=guardian_members(g);if(count<0)return -1;
    for(int i=0;i<count;i++){if(g->pids[i]<=0)continue;struct KIdentity member;errno=0;
        if(!fresh(g->pids[i],&member)){if(errno==ESRCH)continue;return -1;}
        /* A reused PID outside this never-reused allocation is ignored. */
        if(member.bsd.pbi_ruid!=g->config->uid)continue;
        if(!guardian_signal_identity(g,&member,SIGKILL))return -1;
    }
    return count;
}
static void guardian_put32(unsigned char *p,uint32_t v) {v=htonl(v);memcpy(p,&v,4);}
static void guardian_put64(unsigned char *p,uint64_t v) {guardian_put32(p,(uint32_t)(v>>32));guardian_put32(p+4,(uint32_t)v);}
static int guard_command(struct Config *c,uint64_t bootstrap) {
    struct KGuardian g={.config=c};uint64_t before=0;
    g.signal_token=(KSignalToken)dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");
    g.pids=calloc(K_PID_CAP,sizeof(pid_t));
    if(!g.signal_token||!g.pids||!fresh(getpid(),&g.own)||!root_credentials(&g.own)
        ||!fresh(getppid(),&g.parent)||!root_credentials(&g.parent)
        ||g.own.unique.parent_uniqueid!=g.parent.unique.uniqueid||!guardian_clock(&g,&before)
        ||before>=c->deadline||guardian_members(&g)!=0)return 141;
    int readiness[2],permit[2];if(pipe(readiness))return 142;
    if(pipe(permit)){close(readiness[0]);close(readiness[1]);return 142;}
    int watched[]={readiness[0],11,12,permit[1]};
    for(unsigned i=0;i<4;i++){int flags=fcntl(watched[i],F_GETFL);
        if(flags<0||fcntl(watched[i],F_SETFL,flags|O_NONBLOCK)<0){
            close(readiness[0]);close(readiness[1]);close(permit[0]);close(permit[1]);return 142;}}
    struct sigaction action={0};action.sa_handler=guardian_signal;sigemptyset(&action.sa_mask);
    if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)){
        close(readiness[0]);close(readiness[1]);close(permit[0]);close(permit[1]);return 143;}
    /* No alarm may kill the enforcer once a child exists. */
    alarm(0);
    if(guardian_stop||guardian_parent(&g)!=1){
        close(readiness[0]);close(readiness[1]);close(permit[0]);close(permit[1]);return 125;}
    pid_t pid=fork();
    if(pid<0){close(readiness[0]);close(readiness[1]);close(permit[0]);close(permit[1]);return 144;}
    if(pid==0){
        /* Close the ONLY inherited S/G writer before waiting. If the guardian
         * dies before publishing this root child's birth, EOF exits the child
         * before any Mach, filesystem, sandbox or credential transition. */
        close(permit[1]);close(readiness[0]);signal(SIGTERM,SIG_DFL);signal(SIGINT,SIG_DFL);alarm(60);
        int ready_source=fcntl(readiness[1],F_DUPFD_CLOEXEC,32),permit_source=fcntl(permit[0],F_DUPFD_CLOEXEC,32);
        if(ready_source<0||permit_source<0||dup2(ready_source,11)<0||dup2(permit_source,12)<0)_exit(138);
        close(ready_source);close(permit_source);close(readiness[1]);close(permit[0]);
        uint64_t start_deadline=c->deadline<bootstrap?c->deadline:bootstrap;char setup;
        if(!read_exact(12,&setup,1,start_deadline)||setup!='S')_exit(139);
        int result=launch_child(c,bootstrap);_exit(result);
    }
    g.child_pid=pid;g.child_known=fresh(pid,&g.child);
    close(readiness[1]);close(permit[0]);close(13);close(14);close(15);if(c->writable)close(16);
    struct KGuardState state={.deadline=c->deadline,.cleanup_budget=c->cleanup_budget,.last_now=before};
    const struct KGuardOps ops={guardian_clock,guardian_parent,guardian_reap,guardian_signal_child,guardian_drain};
    unsigned char registration[88];size_t registration_sent=0;
    bool birth_sent=false,setup_permitted=false,registered=false,child_ready=false,exec_permitted=false;
    guardian_put32(registration,0x4b564232u);guardian_put32(registration+4,(uint32_t)getpid());
    guardian_put32(registration+8,(uint32_t)pid);guardian_put32(registration+12,(uint32_t)c->uid);
    guardian_put64(registration+16,c->allocation_seq);memcpy(registration+24,c->daemon_epoch,64);
    while(!state.complete){
        kvg_step(&state,&ops,&g,guardian_stop!=0);
        if(state.stopped&&permit[1]>=0){close(permit[1]);permit[1]=-1;}
        if(!state.stopped&&(!birth_sent||(child_ready&&!registered))){
            ssize_t n=write(11,registration+registration_sent,sizeof(registration)-registration_sent);
            if(n>0){registration_sent+=(size_t)n;if(registration_sent==sizeof(registration)){
                if(!birth_sent){birth_sent=true;registration_sent=0;guardian_put32(registration,0x4b565232u);}
                else{registered=true;close(11);}}}
            else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)guardian_stop=1;
        }
        if(!state.stopped&&setup_permitted&&!child_ready){unsigned char ready;ssize_t n=read(readiness[0],&ready,1);
            if(n==1){struct KIdentity child;
                bool valid=ready=='R'&&fresh(pid,&child)&&child.bsd.pbi_ppid==(uint32_t)getpid()
                    &&child.unique.parent_uniqueid==g.own.unique.uniqueid&&(!g.child_known||guardian_same_process(&g.child,&child))
                    &&child.bsd.pbi_ruid==c->uid&&child.bsd.pbi_uid==c->uid&&child.bsd.pbi_svuid==c->uid
                    &&child.bsd.pbi_rgid==c->gid&&child.bsd.pbi_gid==c->gid&&child.bsd.pbi_svgid==c->gid;
                if(valid){g.child=child;g.child_known=true;child_ready=true;}else guardian_stop=1;
            }else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))guardian_stop=1;
        }
        if(!state.stopped&&!exec_permitted){unsigned char go;ssize_t n=read(12,&go,1);
            if(n==1){uint64_t live_now=0;bool live=!guardian_stop&&guardian_parent(&g)==1
                    &&guardian_clock(&g,&live_now)&&live_now>=state.last_now&&live_now<c->deadline;
                if(live)state.last_now=live_now;
                char child_token=0;
                if(live&&go=='B'&&birth_sent&&!setup_permitted){child_token='S';setup_permitted=true;}
                else if(live&&go=='G'&&setup_permitted&&registered){child_token='G';exec_permitted=true;}
                else guardian_stop=1;
                if(child_token&&write(permit[1],&child_token,1)!=1)guardian_stop=1;
                if(exec_permitted){close(permit[1]);permit[1]=-1;close(12);}
            }else if(n==0||(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR))guardian_stop=1;
        }
        if(!state.complete){struct timespec pause={0,10000000};nanosleep(&pause,NULL);}
    }
    if(!registered)close(11);if(!exec_permitted)close(12);if(permit[1]>=0)close(permit[1]);
    close(readiness[0]);free(g.pids);
    /* A normal command exit is returned only after all of its detached or
     * closed-pipe descendants have disappeared. An abort cannot become PASS. */
    if(state.reasons&~KVG_CHILD_EXIT)return 125;
    if(state.cleanup_expired)return 126;
    if(WIFEXITED(state.child_status))return WEXITSTATUS(state.child_status);
    if(WIFSIGNALED(state.child_status)){int sig=WTERMSIG(state.child_status);signal(sig,SIG_DFL);raise(sig);return 128+sig;}
    return 127;
}
static int launch(void) {
    alarm(60);if(getuid()||geteuid()||!hex64(KNOWLEDGE_BROKER_BINARY_SHA)
        ||!hex64(KNOWLEDGE_BROKER_SOURCE_SHA)||!hex64(KNOWLEDGE_DARWIN_STUB_SOURCE_SHA)||!parent_origin())return 120;
    uint64_t bootstrap=now_ms()+K_BOOTSTRAP_MS;struct Config c={0};
    if(!read_config(&c,10,bootstrap))return 124;close(10);
    if(!bound_fds(&c))return 123;
    if(now_ms()>=c.deadline)return 125;
    char digest[65];if(!protected_image(c.argv[0],digest)||strcmp(digest,c.runtime_sha))return 127;
    return guard_command(&c,bootstrap);
}

int main(int argc,char **argv) {
    signal(SIGPIPE,SIG_IGN);
    if(argc==2&&!strcmp(argv[1],"--describe")){
        if(!hex64(KNOWLEDGE_BROKER_BINARY_SHA)||!hex64(KNOWLEDGE_BROKER_SOURCE_SHA)||!hex64(KNOWLEDGE_DARWIN_STUB_SOURCE_SHA))return 78;
        printf("{\"schema\":\"knowledge-darwin-stub.v1\",\"broker_binary_sha256\":\"%s\",\"broker_source_sha256\":\"%s\",\"stub_source_sha256\":\"%s\",\"capability_qualified\":false}\n",
            KNOWLEDGE_BROKER_BINARY_SHA,KNOWLEDGE_BROKER_SOURCE_SHA,KNOWLEDGE_DARWIN_STUB_SOURCE_SHA);return 0;
    }
    if(argc==2&&!strcmp(argv[1],"--check-config")){
        struct Config c={0};if(!read_config(&c,0,now_ms()+5000))return 64;
        printf("{\"schema\":\"knowledge-darwin-wire-check.v1\",\"decode_only\":true,\"argc\":%u,\"envc\":%u,\"capability_qualified\":false}\n",c.argc,c.envc);return 0;
    }
    if(argc!=2||strcmp(argv[1],"--internal-child"))return 64;
    int code=launch();if(code)fprintf(stderr,"native C stub setup/exec failure: code=%d errno=%d\n",code,errno);return code;
}
