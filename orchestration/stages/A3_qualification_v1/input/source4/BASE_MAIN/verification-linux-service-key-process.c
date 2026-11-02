#define _GNU_SOURCE
#include "verification-linux-service-key-process.h"
#include "verification-linux-service-key-wire.h"
#include "verification-linux-service-semantic-plan-input.h"
#include "verification-linux-service-execution-input.h"
#include "verification-linux-service-cleanup-phase-input.h"
#include "verification-linux-service-key-phase-wire.h"
#include "verification-linux-service-finalization-input.h"
#include "verification-linux-service-transport.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/nsfs.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#define KEY_EXECUTABLE "/usr/libexec/knowledge/knowledge-key"
#define KEY_MAX_ELF (16U*1024U*1024U)
#if defined(KNOWLEDGE_LINUX_KEY_PROCESS_TEST_HOOK)
extern int knowledge_linux_key_process_test_hook(const char *,int,int);
#define HOOK(s,a,b) knowledge_linux_key_process_test_hook(s,a,b)
#else
#define HOOK(s,a,b) 0
#endif

struct kv_linux_key_process {
    pid_t owner_pid,pid;
    kv_linux_semantic_plan_lease *lease;
    struct kv_linux_key_pins pins;
    struct kv_linux_semantic_plan_input input;
    struct kv_linux_key_binding binding;
    uint64_t work,cleanup,time_dev,time_ino;
    unsigned char boot[16],context[KV_LINUX_KEY_CONTEXT_BYTES],public_key[32];
    int parent_pidfd,creator_namespace_fd,pidfd,key_namespace_fd,context_fd;
    int control_fd,preparation_fd,diagnostic_fd,start_fd;
    int failed,cancelled,reaped,exit_code;
    int control_eof,preparation_eof,diagnostic_eof;
    int preparation_received,realm_admitted,ordinary_ready,release_attempted,release_sent,public_registered;
    int worker_input_attempted;
    kv_linux_execution *worker_execution;
    kv_linux_cleanup_phase *phase;
    kv_linux_owned_worker_result *phase_result;
    struct kv_linux_phase_binding phase_binding;
    int phase_fenced,phase_bound_complete,phase_prepare_attempted,phase_prepared,phase_commit_attempted,phase_acked,phase_retired;
    int sign_attempted,sign_sent,sign_received;
    kv_linux_finalization *sign_finalizer;
    unsigned char sign_message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],signature[64];
    size_t diagnostic_bytes;
};
static uint64_t le(const unsigned char *p,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);return v;}
static int nonzero(const unsigned char *p,size_t n){unsigned v=0;while(n--)v|=*p++;return v!=0;}
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0)return 0;return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;}
static int before(uint64_t deadline){uint64_t t=now();return t&&t<deadline;}
static int live(int fd){struct pollfd p={fd,POLLIN,0};int n;do{n=poll(&p,1,0);}while(n<0&&errno==EINTR);return fd>=0&&n==0&&!p.revents;}
static int high(int fd){if(fd<0)return -1;int out=fcntl(fd,F_DUPFD_CLOEXEC,16);close(fd);return out;}
static int same(int a,int b){struct stat x,y;return !fstat(a,&x)&&!fstat(b,&y)&&x.st_dev==y.st_dev&&x.st_ino==y.st_ino;}
static int ns_open(pid_t pid,const char *name){char path[80];snprintf(path,sizeof path,"/proc/%ld/ns/%s",(long)pid,name);return open(path,O_RDONLY|O_CLOEXEC);}
static pid_t pidfd_target(int fd){
    char path[80],bytes[1024];snprintf(path,sizeof path,"/proc/self/fdinfo/%d",fd);int input=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(input<0)return -1;
    ssize_t n=read(input,bytes,sizeof bytes-1);close(input);if(n<=0)return -1;bytes[n]=0;char *p=strstr(bytes,"Pid:\t"),tail=0;long pid=0;
    return p&&sscanf(p,"Pid:\t%ld%c",&pid,&tail)==2&&tail=='\n'&&pid>0&&pid<=INT32_MAX?(pid_t)pid:-1;
}
static int clock_current_epoch(const kv_linux_key_process *p,uint64_t deadline){
    struct stat held;struct kv_linux_service_clock_identity c={.namespace_fd=-1};
    if(!before(deadline)||fstat(p->input.clock_namespace_fd,&held)||(uint64_t)held.st_dev!=p->time_dev||
        (uint64_t)held.st_ino!=p->time_ino||kv_linux_service_clock_open(&c))return 0;
    int ok=!memcmp(c.boot_id,p->boot,16)&&c.time_namespace_dev==p->time_dev&&c.time_namespace_ino==p->time_ino;
    kv_linux_service_clock_close(&c);return ok&&before(deadline);
}
static int clock_current(const kv_linux_key_process *p){return clock_current_epoch(p,p->work);}
static int current(kv_linux_key_process *p){
    return p&&p->owner_pid==getpid()&&!p->phase_fenced&&!p->failed&&!p->cancelled&&p->lease&&clock_current(p)&&live(p->input.peer_pidfd)&&
        !kv_linux_semantic_plan_lease_current(p->lease)&&clock_current(p)&&live(p->input.peer_pidfd)&&before(p->work);
}
/* Setup executes only in the actual retained root child. No installed-path I/O
 * or potentially blocking executable read/copy is performed in the owner. */
static int setup_gate=-1,setup_parent=-1,setup_peer=-1;
static uint64_t setup_work;
static pid_t setup_parent_pid;
static int setup_current(void){
    if(!before(setup_work)||!live(setup_parent)||!live(setup_peer)||getppid()!=setup_parent_pid)return 0;
    unsigned char b;ssize_t n=recv(setup_gate,&b,1,MSG_PEEK|MSG_DONTWAIT);
    return n<0&&(errno==EAGAIN||errno==EWOULDBLOCK);
}
static int wait_byte(unsigned char expected){
    while(before(setup_work)&&live(setup_parent)&&live(setup_peer)&&getppid()==setup_parent_pid){
        struct pollfd p={setup_gate,POLLIN,0};int n=poll(&p,1,5);if(n<0&&errno==EINTR)continue;if(n<0)return 0;if(!n)continue;
        unsigned char bytes[2];ssize_t got=recv(setup_gate,bytes,sizeof bytes,MSG_DONTWAIT);
        if(got<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
        return got==1&&bytes[0]==expected&&setup_current();
    }return 0;
}
static int no_acl(int fd){
    const char *names[]={"system.posix_acl_access","system.posix_acl_default","security.capability"};
    for(unsigned i=0;i<3;i++){errno=0;if(fgetxattr(fd,names[i],NULL,0)>=0||(errno!=ENODATA&&errno!=ENOTSUP&&errno!=EOPNOTSUPP))return 0;}return 1;
}
static int protected_directory(void){
    const char *parts[]={"usr","libexec","knowledge"};int fd=high(open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    for(unsigned i=0;i<=3;i++){
        struct stat st;if(fd<0)return -1;
        if(!setup_current()||fstat(fd,&st)||st.st_uid||st.st_gid||(st.st_mode&0022)||!no_acl(fd)||!setup_current()){close(fd);return -1;}
        if(i==3)return fd;
        int next=high(openat(fd,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));close(fd);fd=next;
    }return -1;
}
static int bounded_read(int fd,void *out,size_t n,off_t at){
    size_t got=0;while(got<n){if(!setup_current())return -1;ssize_t r=pread(fd,(unsigned char*)out+got,n-got,at+(off_t)got);if(r<=0)return -1;got+=(size_t)r;}
    return setup_current()?0:-1;
}
/* Pin qualification additionally audits constructors/IFUNCs for the exact ELF.
 * This structural gate excludes a dynamic-loader or writable-executable fallback. */
static int static_elf(int fd,off_t size){
    Elf64_Ehdr h;if(bounded_read(fd,&h,sizeof h,0)||memcmp(h.e_ident,ELFMAG,SELFMAG)||h.e_ident[EI_CLASS]!=ELFCLASS64||
        h.e_ident[EI_DATA]!=ELFDATA2LSB||h.e_ident[EI_VERSION]!=EV_CURRENT||h.e_type!=ET_DYN||h.e_machine!=EM_X86_64||h.e_version!=EV_CURRENT||
        h.e_ehsize!=sizeof h||h.e_phentsize!=sizeof(Elf64_Phdr)||!h.e_phnum||h.e_phnum>128||h.e_phoff>(uint64_t)size||
        (uint64_t)h.e_phnum*sizeof(Elf64_Phdr)>(uint64_t)size-h.e_phoff)return -1;
    int stack=0,relro=0,dynamic=0,terminated=0,pie=0,bind=0,entry=0;
    for(unsigned i=0;i<h.e_phnum;i++){
        Elf64_Phdr p;if(bounded_read(fd,&p,sizeof p,(off_t)(h.e_phoff+(uint64_t)i*sizeof p))||p.p_offset>(uint64_t)size||p.p_filesz>(uint64_t)size-p.p_offset)return -1;
        if(p.p_type==PT_INTERP)return -1;
        if(p.p_type==PT_LOAD){if(p.p_memsz<p.p_filesz||(p.p_flags&(PF_W|PF_X))==(PF_W|PF_X))return -1;if((p.p_flags&PF_X)&&h.e_entry>=p.p_vaddr&&h.e_entry-p.p_vaddr<p.p_filesz)entry=1;}
        if(p.p_type==PT_GNU_STACK){if(stack++||p.p_flags&PF_X)return -1;}
        if(p.p_type==PT_GNU_RELRO){if(relro++||!p.p_memsz)return -1;}
        if(p.p_type==PT_DYNAMIC){
            if(dynamic++||p.p_filesz%sizeof(Elf64_Dyn)||p.p_filesz>65536)return -1;
            for(uint64_t j=0;j<p.p_filesz/sizeof(Elf64_Dyn);j++){
                Elf64_Dyn d;if(bounded_read(fd,&d,sizeof d,(off_t)(p.p_offset+j*sizeof d)))return -1;
                if(d.d_tag==DT_NULL){terminated=1;break;}
                if(d.d_tag==DT_NEEDED||d.d_tag==DT_TEXTREL)return -1;
                if(d.d_tag==DT_FLAGS_1){pie=!!(d.d_un.d_val&DF_1_PIE);if(d.d_un.d_val&DF_1_NOW)bind=1;}
                if(d.d_tag==DT_BIND_NOW||(d.d_tag==DT_FLAGS&&(d.d_un.d_val&DF_BIND_NOW)))bind=1;
            }
        }
    }return stack==1&&relro==1&&dynamic==1&&terminated&&pie&&bind&&entry?0:-1;
}
static int sealed_image(const unsigned char pin[32]){
    int directory=protected_directory();if(directory<0)return -1;
    int input=high(openat(directory,"knowledge-key",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)),output=-1;
    struct stat st,after,named;EVP_MD_CTX *hash=NULL;int ok=input>=0&&!fstat(input,&st)&&S_ISREG(st.st_mode)&&!st.st_uid&&!st.st_gid&&
        st.st_nlink==1&&!(st.st_mode&0022)&&st.st_size>0&&st.st_size<=KEY_MAX_ELF&&no_acl(input)&&setup_current();
    if(ok)ok=(output=high(memfd_create("knowledge-fixed-key-elf",MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_EXEC)))>=0&&
        OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)==1&&(hash=EVP_MD_CTX_new())&&EVP_DigestInit_ex(hash,EVP_sha256(),NULL)==1;
    unsigned char bytes[65536],digest[32];unsigned length=0;off_t at=0;
    while(ok&&at<st.st_size){
        size_t n=(uint64_t)(st.st_size-at)<sizeof bytes?(size_t)(st.st_size-at):sizeof bytes;
        if(bounded_read(input,bytes,n,at)||EVP_DigestUpdate(hash,bytes,n)!=1){ok=0;break;}
        size_t wrote=0;while(wrote<n){if(!setup_current()){ok=0;break;}ssize_t r=write(output,bytes+wrote,n-wrote);if(r<=0){ok=0;break;}wrote+=(size_t)r;}at+=(off_t)n;
    }
    if(ok)ok=EVP_DigestFinal_ex(hash,digest,&length)==1&&length==32&&!memcmp(digest,pin,32)&&
        !fstat(input,&after)&&!fstatat(directory,"knowledge-key",&named,AT_SYMLINK_NOFOLLOW)&&st.st_dev==after.st_dev&&st.st_ino==after.st_ino&&
        st.st_size==after.st_size&&st.st_mtim.tv_sec==after.st_mtim.tv_sec&&st.st_mtim.tv_nsec==after.st_mtim.tv_nsec&&
        st.st_ctim.tv_sec==after.st_ctim.tv_sec&&st.st_ctim.tv_nsec==after.st_ctim.tv_nsec&&st.st_dev==named.st_dev&&st.st_ino==named.st_ino&&
        !fchmod(output,0555)&&!fcntl(output,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)&&setup_current();
    if(ok)ok=EVP_DigestInit_ex(hash,EVP_sha256(),NULL)==1;
    at=0;while(ok&&at<st.st_size){size_t n=(uint64_t)(st.st_size-at)<sizeof bytes?(size_t)(st.st_size-at):sizeof bytes;if(bounded_read(output,bytes,n,at)||EVP_DigestUpdate(hash,bytes,n)!=1){ok=0;break;}at+=(off_t)n;}
    if(ok)ok=EVP_DigestFinal_ex(hash,digest,&length)==1&&length==32&&!memcmp(digest,pin,32)&&!static_elf(output,st.st_size)&&setup_current();
    EVP_MD_CTX_free(hash);if(input>=0)close(input);close(directory);if(ok)return output;if(output>=0)close(output);return -1;
}
struct packet {unsigned char bytes[KV_LINUX_KEY_SIGN_FRAME_BYTES+1];size_t size;int rights[2],right_count;struct ucred cred;};
static void close_packet(struct packet *p){for(int i=0;i<2;i++)if(p->rights[i]>=0){close(p->rights[i]);p->rights[i]=-1;}}
/* 1 packet, 0 EAGAIN, 2 actual EOF, -1 refusal. Always close received surplus. */
static int receive_packet(int fd,struct packet *out){
    struct packet p={.rights={-1,-1}};unsigned char ancillary[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(8*sizeof(int))]={0};
    struct iovec io={p.bytes,sizeof p.bytes};struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=ancillary,.msg_controllen=sizeof ancillary};
    ssize_t n=recvmsg(fd,&m,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;if(n<0)return -1;
    int credentials=0,bad=0;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&m);c;c=CMSG_NXTHDR(&m,c)){
        if(c->cmsg_level!=SOL_SOCKET){bad=1;continue;}
        if(c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof p.cred)&&!credentials){memcpy(&p.cred,CMSG_DATA(c),sizeof p.cred);credentials++;}
        else if(c->cmsg_type==SCM_RIGHTS&&c->cmsg_len>=CMSG_LEN(sizeof(int))){
            size_t bytes=c->cmsg_len-CMSG_LEN(0);if(bytes%sizeof(int))bad=1;int *fds=(int*)CMSG_DATA(c);
            for(size_t i=0;i<bytes/sizeof(int);i++){if(p.right_count<2)p.rights[p.right_count]=fds[i];else close(fds[i]);p.right_count++;}
        }else bad=1;
    }
    if(!n&&!credentials&&!p.right_count&&!bad&&!(m.msg_flags&~MSG_CMSG_CLOEXEC))return 2;
    if(n<=0||n>KV_LINUX_KEY_SIGN_FRAME_BYTES||credentials!=1||p.right_count>2||bad||(m.msg_flags&~MSG_CMSG_CLOEXEC)){close_packet(&p);errno=EPROTO;return -1;}
    p.size=(size_t)n;*out=p;return 1;
}
static int send_packet(int fd,const unsigned char bytes[KV_LINUX_KEY_FRAME_BYTES],const int *rights){
    unsigned char ancillary[CMSG_SPACE(2*sizeof(int))]={0};struct iovec io={(void*)bytes,KV_LINUX_KEY_FRAME_BYTES};struct msghdr m={.msg_iov=&io,.msg_iovlen=1};
    if(rights){m.msg_control=ancillary;m.msg_controllen=sizeof ancillary;struct cmsghdr *c=CMSG_FIRSTHDR(&m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(2*sizeof(int));memcpy(CMSG_DATA(c),rights,2*sizeof(int));}
    return sendmsg(fd,&m,MSG_NOSIGNAL)==KV_LINUX_KEY_FRAME_BYTES?0:-1;
}
static int make_context(const unsigned char bytes[KV_LINUX_KEY_CONTEXT_BYTES]){
    int fd=high(memfd_create("knowledge-key-private-context",MFD_CLOEXEC|MFD_ALLOW_SEALING));if(fd<0)return -1;
    size_t at=0;while(at<KV_LINUX_KEY_CONTEXT_BYTES){if(!setup_current()){close(fd);return -1;}ssize_t n=write(fd,bytes+at,KV_LINUX_KEY_CONTEXT_BYTES-at);if(n<=0){close(fd);return -1;}at+=(size_t)n;}
    if(fcntl(fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)||!setup_current()){close(fd);return -1;}return fd;
}
static int realm_matches(kv_linux_key_process *p,int realm){
    if(!current(p)||p->reaped||!live(p->pidfd))return 0;
    int actual=ns_open(p->pid,"user"),parent=-1;struct statfs fs;uid_t owner=(uid_t)-1;
    int ok=actual>=0&&same(realm,actual)&&!fstatfs(realm,&fs)&&fs.f_type==NSFS_MAGIC&&ioctl(realm,NS_GET_NSTYPE)==CLONE_NEWUSER&&
        !ioctl(realm,NS_GET_OWNER_UID,&owner)&&owner==0&&(parent=ioctl(realm,NS_GET_PARENT))>=0&&same(parent,p->creator_namespace_fd)&&!same(realm,p->creator_namespace_fd);
    if(actual>=0)close(actual);
    if(parent>=0)close(parent);
    actual=ns_open(p->pid,"user");ok=ok&&actual>=0&&same(realm,actual)&&live(p->pidfd)&&current(p);if(actual>=0)close(actual);return ok;
}
static int proc_write(kv_linux_key_process *p,const char *name,const char *text){
    if(!current(p)||!live(p->pidfd)||p->reaped)return -1;
    char path[96];snprintf(path,sizeof path,"/proc/%ld/%s",(long)p->pid,name);int fd=open(path,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    size_t size=strlen(text);int ok=write(fd,text,size)==(ssize_t)size;close(fd);return ok&&current(p)&&live(p->pidfd)?0:-1;
}
static int map_read(kv_linux_key_process *p,const char *name,uint32_t id){
    if(!current(p)||!live(p->pidfd)||p->reaped)return -1;
    char path[96],bytes[256];snprintf(path,sizeof path,"/proc/%ld/%s",(long)p->pid,name);int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    ssize_t n=read(fd,bytes,sizeof bytes-1);close(fd);if(n<=0||n>=(ssize_t)sizeof bytes-1)return -1;bytes[n]=0;int ok=0;
    if(!id)ok=!strcmp(bytes,"deny\n");
    else {unsigned a,b,c,d,e,f;int at=0;ok=sscanf(bytes," %u %u %u %u %u %u %n",&a,&b,&c,&d,&e,&f,&at)==6&&bytes[at]==0&&!a&&!b&&c==1&&d==id&&e==id&&f==1;}
    return ok&&current(p)&&live(p->pidfd)?0:-1;
}
static int maps(kv_linux_key_process *p,int install){
    uint32_t uid=(uint32_t)le(p->input.pending_record+184,4),gid=(uint32_t)le(p->input.pending_record+188,4);char text[96];
    if(install){
        if(proc_write(p,"setgroups","deny\n"))return -1;
        snprintf(text,sizeof text,"0 0 1\n%u %u 1\n",uid,uid);if(proc_write(p,"uid_map",text))return -1;
        snprintf(text,sizeof text,"0 0 1\n%u %u 1\n",gid,gid);if(proc_write(p,"gid_map",text))return -1;
    }
    return map_read(p,"setgroups",0)||map_read(p,"uid_map",uid)||map_read(p,"gid_map",gid)?-1:0;
}
static int root_state(void){uid_t a,b,c;gid_t d,e,f;return !getresuid(&a,&b,&c)&&!a&&!b&&!c&&!getresgid(&d,&e,&f)&&!d&&!e&&!f;}
static int reaping_profile(void){struct sigaction action;return !sigaction(SIGCHLD,NULL,&action)&&action.sa_handler==SIG_DFL&&!(action.sa_flags&SA_NOCLDWAIT);}
static int child_drop(uint32_t uid,uint32_t gid){
    if(setresgid(gid,gid,gid)||setresuid(uid,uid,uid))return -1;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0},{0}};
    if(syscall(SYS_capset,&h,caps)||prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;
    uid_t a,b,c;gid_t d,e,f;return !getresuid(&a,&b,&c)&&a==uid&&b==uid&&c==uid&&!getresgid(&d,&e,&f)&&d==gid&&e==gid&&f==gid&&getgroups(0,NULL)==0?0:-1;
}
static void child_exec(kv_linux_key_process *p,int control,int preparation,int diagnostics){
    if(HOOK("child_before_image",preparation,setup_gate)||!setup_current())_exit(121);
    int image=sealed_image(p->pins.executable);if(image<0||!setup_current())_exit(121);
    if(!root_state()||setgroups(0,NULL)||getgroups(0,NULL)||HOOK("child_before_unshare",preparation,image)||!setup_current()||unshare(CLONE_NEWUSER))_exit(122);
    int realm=high(ns_open(getpid(),"user"));struct stat st;struct kv_linux_key_binding b=p->binding;
    if(realm<0||fstat(realm,&st)||!setup_current())_exit(122);
    b.key_pid=(uint32_t)getpid();b.key_namespace_dev=(uint64_t)st.st_dev;b.key_namespace_ino=(uint64_t)st.st_ino;
    unsigned char context[KV_LINUX_KEY_CONTEXT_BYTES],frame[KV_LINUX_KEY_FRAME_BYTES];
    if(kv_linux_key_context_encode(context,&b,p->input.pending_record,p->input.semantic_report))_exit(122);
    int input=make_context(context),rights[2]={realm,input};
    if(input<0||kv_linux_key_frame_encode(frame,context,KV_LINUX_KEY_PREP,NULL)||HOOK("child_before_preparation",realm,input)||
        !setup_current()||send_packet(preparation,frame,rights)||!wait_byte('E'))_exit(122);
    uint32_t uid=(uint32_t)le(p->input.pending_record+184,4),gid=(uint32_t)le(p->input.pending_record+188,4);
    int nullfd=high(open("/dev/null",O_RDWR|O_CLOEXEC));struct rlimit core={0,0};
    if(nullfd<0||!setup_current()||setrlimit(RLIMIT_CORE,&core)||child_drop(uid,gid)||prctl(PR_SET_PDEATHSIG,SIGKILL)||
        !setup_current()||HOOK("child_after_drop",realm,input))_exit(123);
    if(HOOK("child_before_exec_mapping",control,diagnostics)||!setup_current())_exit(123);
    /* All inputs were staged above16. No dup can overwrite another source. */
    int source[10]={nullfd,nullfd,diagnostics,input,p->input.peer_pidfd,p->input.clock_namespace_fd,p->parent_pidfd,realm,control,image};
    for(int i=0;i<10;i++)if(source[i]<16||dup2(source[i],i)!=i)_exit(123);
    if(fcntl(9,F_SETFD,FD_CLOEXEC)||syscall(SYS_close_range,10,~0U,0)||getppid()!=setup_parent_pid||!live(6)||!live(4)||!before(setup_work))_exit(123);
    char *argv[]={(char*)"knowledge-key",NULL};char *env[]={NULL};
    if(HOOK("child_before_exec",8,9))_exit(123);
    syscall(SYS_execveat,9,"",argv,env,AT_EMPTY_PATH);_exit(123);
}
static int random_nonce(unsigned char nonce[32]){
    size_t at=0;unsigned interrupted=0;while(at<32){ssize_t n=getrandom(nonce+at,32-at,GRND_NONBLOCK);if(n<0&&errno==EINTR&&++interrupted<8)continue;if(n<=0)return -1;at+=(size_t)n;}return nonzero(nonce,32)?0:-1;
}
kv_linux_key_process *kv_linux_key_start(const struct kv_linux_key_pins *pins,kv_linux_semantic_plan_lease **owned){
    if(!pins||!owned||!*owned||!nonzero(pins->executable,32)||!root_state()||getpid()<=1||!reaping_profile()){errno=EINVAL;return NULL;}
#if !defined(__x86_64__) || defined(__ILP32__)
    errno=ENOTSUP;return NULL;
#endif
    kv_linux_key_process *p=calloc(1,sizeof *p);if(!p)return NULL;
    p->owner_pid=getpid();p->pins=*pins;p->exit_code=-1;p->reaped=p->control_eof=p->preparation_eof=p->diagnostic_eof=1;
    p->input.peer_pidfd=p->input.clock_namespace_fd=p->input.parser_pidfd=-1;
    p->parent_pidfd=p->creator_namespace_fd=p->pidfd=p->key_namespace_fd=p->context_fd=-1;
    p->control_fd=p->preparation_fd=p->diagnostic_fd=p->start_fd=-1;
    if(kv_linux_semantic_plan_lease_move(owned,&p->lease)){free(p);return NULL;}
    int control[2]={-1,-1},preparation[2]={-1,-1},diagnostics[2]={-1,-1},gate[2]={-1,-1};
    struct kv_linux_semantic_plan_input input={.peer_pidfd=-1,.clock_namespace_fd=-1,.parser_pidfd=-1};
    if(HOOK("after_move",-1,-1)||kv_linux_semantic_plan_lease_claim_launch_input(p->lease,&input))goto fail;
    p->input=input;p->input.peer_pidfd=high(input.peer_pidfd);p->input.clock_namespace_fd=high(input.clock_namespace_fd);p->input.parser_pidfd=high(input.parser_pidfd);
    p->work=le(p->input.pending_record+272,8);p->cleanup=le(p->input.pending_record+280,8);
    p->time_dev=le(p->input.pending_record+240,8);p->time_ino=le(p->input.pending_record+248,8);memcpy(p->boot,p->input.pending_record+224,16);
    if(p->input.peer_pidfd<0||p->input.clock_namespace_fd<0||p->input.parser_pidfd<0||!p->input.native_revision||kv_linux_attempt_pending_validate(p->input.pending_record,sizeof p->input.pending_record)||!current(p))goto fail;
    p->binding.parent_pid=(uint32_t)getpid();pid_t peer=pidfd_target(p->input.peer_pidfd);if(peer<=0)goto fail;p->binding.peer_pid=(uint32_t)peer;
    p->binding.semantic_sequence=input.semantic_sequence;p->binding.exclusive_sequence=input.exclusive_sequence;p->binding.native_revision=input.native_revision;
    p->parent_pidfd=high((int)syscall(SYS_pidfd_open,getpid(),0));p->creator_namespace_fd=high(ns_open(getpid(),"user"));struct stat own;
    if(p->parent_pidfd<0||p->creator_namespace_fd<0||fstat(p->creator_namespace_fd,&own)||random_nonce(p->binding.nonce)||!current(p))goto fail;
    p->binding.creator_namespace_dev=(uint64_t)own.st_dev;p->binding.creator_namespace_ino=(uint64_t)own.st_ino;
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,control)||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,preparation)||
        socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,gate)||pipe2(diagnostics,O_CLOEXEC|O_NONBLOCK))goto fail;
    for(unsigned i=0;i<2;i++){
        int one=1;if(setsockopt(control[i],SOL_SOCKET,SO_PASSCRED,&one,sizeof one)||setsockopt(preparation[i],SOL_SOCKET,SO_PASSCRED,&one,sizeof one))goto fail;
        control[i]=high(control[i]);preparation[i]=high(preparation[i]);diagnostics[i]=high(diagnostics[i]);gate[i]=high(gate[i]);
        if(control[i]<0||preparation[i]<0||diagnostics[i]<0||gate[i]<0)goto fail;
    }
    if(HOOK("before_fork",-1,-1)||!current(p))goto fail;
    /* Birth and kernel pidfd publication are atomic. A fork→pidfd_open gap
     * cannot be repaired by comparing a recycled numeric PID afterwards. The
     * supported owner is single-threaded and its sole reaper; no atfork state
     * or inherited crypto RNG is used by this SHA-only fixed setup. */
    int born_pidfd=-1;
    if(HOOK("before_atomic_clone",-1,-1))goto fail;
    pid_t child=(pid_t)syscall(SYS_clone,CLONE_PIDFD|SIGCHLD,NULL,&born_pidfd,NULL,0);
    if(child<0){(void)HOOK("atomic_clone_refused",errno,-1);goto fail;}
    if(!child){
        close(control[0]);close(preparation[0]);close(diagnostics[0]);close(gate[0]);
        setup_gate=gate[1];setup_parent=p->parent_pidfd;setup_peer=p->input.peer_pidfd;setup_work=p->work;setup_parent_pid=p->owner_pid;
        if(prctl(PR_SET_PDEATHSIG,SIGKILL)||!wait_byte('B'))_exit(120);
        child_exec(p,control[1],preparation[1],diagnostics[1]);_exit(124);
    }
    p->pid=child;p->binding.key_pid=(uint32_t)child;p->reaped=0;
    p->control_fd=control[0];control[0]=-1;p->control_eof=0;p->preparation_fd=preparation[0];preparation[0]=-1;p->preparation_eof=0;
    p->diagnostic_fd=diagnostics[0];diagnostics[0]=-1;p->diagnostic_eof=0;p->start_fd=gate[0];gate[0]=-1;
    p->pidfd=born_pidfd;
    /* Relocation must never discard the sole atomic birth handle on EMFILE. */
    if(HOOK("before_pidfd_relocation",p->pidfd,(int)child))p->failed=1;
    int relocated=p->pidfd>=0?fcntl(p->pidfd,F_DUPFD_CLOEXEC,16):-1;
    if(relocated>=0){close(p->pidfd);p->pidfd=relocated;}else {(void)HOOK("pidfd_relocation_refused",errno,p->pidfd);p->failed=1;}
    if(HOOK("parent_owned_channels",p->control_fd,p->diagnostic_fd)||HOOK("parent_owned_preparation",p->preparation_fd,p->pidfd))p->failed=1;
    if(p->pidfd<0||p->failed||!reaping_profile()||pidfd_target(p->pidfd)!=child||HOOK("before_birth_release",p->pidfd,p->start_fd)||!current(p)||send(p->start_fd,"B",1,MSG_NOSIGNAL)!=1)p->failed=1;
    goto done;
fail:
    p->failed=1;
done:
    for(unsigned i=0;i<2;i++){if(control[i]>=0)close(control[i]);if(preparation[i]>=0)close(preparation[i]);if(diagnostics[i]>=0)close(diagnostics[i]);if(gate[i]>=0)close(gate[i]);}
    if(p->failed)(void)kv_linux_key_cancel(p);
    return p;
}
int kv_linux_key_cancel(kv_linux_key_process *p){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(p->phase&&kv_linux_cleanup_phase_revoke(p->phase,p->phase_result))return -1;
    p->cancelled=1;
    if(p->start_fd>=0){(void)send(p->start_fd,"S",1,MSG_NOSIGNAL);(void)shutdown(p->start_fd,SHUT_WR);}
    if(p->pid<=0||p->reaped)return 0;
    if(p->pidfd<0){errno=EBADF;return -1;}
    int n=(int)syscall(SYS_pidfd_send_signal,p->pidfd,SIGKILL,NULL,0);
    return !n||errno==ESRCH?0:-1;
}
static int preparation_poll(kv_linux_key_process *p){
    for(unsigned round=0;!p->preparation_eof&&round<16;round++){
        struct packet packet;int n=receive_packet(p->preparation_fd,&packet);if(!n)break;
        if(n==2){p->preparation_eof=1;if(!p->realm_admitted&&!p->cancelled)p->failed=1;break;}
        if(n<0){(void)HOOK("preparation_packet_refused",errno,0);p->failed=1;continue;}
        int bad=p->failed||p->cancelled||p->preparation_received||p->reaped||packet.size!=KV_LINUX_KEY_FRAME_BYTES||packet.right_count!=2||packet.cred.pid!=p->pid||packet.cred.uid||packet.cred.gid||!current(p);
        p->preparation_received=1;
        if(!bad){
            struct stat ns;unsigned char actual[KV_LINUX_KEY_CONTEXT_BYTES];struct kv_linux_key_binding expected=p->binding;
            if(!realm_matches(p,packet.rights[0])){(void)HOOK("preparation_realm_refused",packet.rights[0],p->pidfd);bad=1;}
            else if(fstat(packet.rights[0],&ns))bad=1;
            else {
                expected.key_namespace_dev=(uint64_t)ns.st_dev;expected.key_namespace_ino=(uint64_t)ns.st_ino;
                if(kv_linux_key_context_encode(p->context,&expected,p->input.pending_record,p->input.semantic_report)||
                    kv_linux_key_context_read(packet.rights[1],actual)||memcmp(actual,p->context,sizeof actual)||
                    kv_linux_key_frame_validate(packet.bytes,KV_LINUX_KEY_FRAME_BYTES,p->context,KV_LINUX_KEY_PREP,NULL)||
                    HOOK("after_preparation_compare",packet.rights[0],packet.rights[1])||!current(p)||!realm_matches(p,packet.rights[0])||maps(p,1)||
                    !realm_matches(p,packet.rights[0])||!current(p))bad=1;
                if(!bad){
                    p->binding=expected;p->key_namespace_fd=high(packet.rights[0]);packet.rights[0]=-1;p->context_fd=high(packet.rights[1]);packet.rights[1]=-1;
                    if(p->key_namespace_fd<0||p->context_fd<0||HOOK("before_mapping_release",p->key_namespace_fd,p->context_fd)||!current(p)||send(p->start_fd,"E",1,MSG_NOSIGNAL)!=1)bad=1;
                    else p->realm_admitted=1;
                }
            }
        }
        close_packet(&packet);if(bad)p->failed=1;
    }return 0;
}
static int control_poll(kv_linux_key_process *p){
    for(unsigned round=0;!p->control_eof&&round<16;round++){
        struct packet packet;int n=receive_packet(p->control_fd,&packet);if(!n)break;
        if(n==2){p->control_eof=1;if(!p->cancelled)p->failed=1;break;}if(n<0){p->failed=1;continue;}
        uint32_t uid=(uint32_t)le(p->input.pending_record+184,4),gid=(uint32_t)le(p->input.pending_record+188,4);
        int bad=p->failed||p->cancelled||!p->realm_admitted||p->reaped||packet.size!=KV_LINUX_KEY_FRAME_BYTES||packet.right_count||packet.cred.pid!=p->pid||packet.cred.uid!=uid||packet.cred.gid!=gid||
            !live(p->pidfd)||!current(p)||!realm_matches(p,p->key_namespace_fd)||maps(p,0);
        if(!bad&&!p->ordinary_ready){
            if(kv_linux_key_frame_validate(packet.bytes,KV_LINUX_KEY_FRAME_BYTES,p->context,KV_LINUX_KEY_READY,NULL)||
                HOOK("after_ready_compare",p->pidfd,p->control_fd)||!current(p)||!live(p->pidfd)||!realm_matches(p,p->key_namespace_fd))bad=1;
            else {
                p->ordinary_ready=1;unsigned char release[KV_LINUX_KEY_FRAME_BYTES];
                /* Burn before encoding/current/send. No EAGAIN or lost reply retry. */
                p->release_attempted=1;
                if(kv_linux_key_frame_encode(release,p->context,KV_LINUX_KEY_RELEASE,NULL)||HOOK("before_keygen_release",p->pidfd,p->control_fd)||
                    !current(p)||!live(p->pidfd)||send_packet(p->control_fd,release,NULL))bad=1;
                else p->release_sent=1;
                if(p->start_fd>=0){close(p->start_fd);p->start_fd=-1;}
            }
        }else if(!bad&&p->release_sent&&!p->public_registered){
            unsigned char public_key[32];
            if(kv_linux_key_frame_validate(packet.bytes,KV_LINUX_KEY_FRAME_BYTES,p->context,KV_LINUX_KEY_PUBLIC,public_key)||
                HOOK("before_public_registration",p->pidfd,p->control_fd)||!current(p)||!live(p->pidfd)||!realm_matches(p,p->key_namespace_fd)||!current(p))bad=1;
            else {memcpy(p->public_key,public_key,32);p->public_registered=1;}
        }else {
#if defined(KNOWLEDGE_LINUX_KEY_PROCESS_TEST_HOOK)
            unsigned char duplicate[32];
            if(!bad&&p->public_registered&&p->release_sent&&
                !kv_linux_key_frame_validate(packet.bytes,KV_LINUX_KEY_FRAME_BYTES,p->context,KV_LINUX_KEY_PUBLIC,duplicate)&&
                !memcmp(duplicate,p->public_key,sizeof duplicate))
                (void)HOOK("duplicate_public_refused",packet.cred.pid,(int)packet.cred.uid);
#endif
            bad=1;
        }
        close_packet(&packet);if(bad)p->failed=1;
    }return 0;
}
static int diagnostics_poll(kv_linux_key_process *p){
    for(unsigned round=0;!p->diagnostic_eof&&round<16;round++){
        unsigned char bytes[256];ssize_t n=read(p->diagnostic_fd,bytes,sizeof bytes);
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;
        if(n<0&&errno==EINTR)continue;
        if(n<0){p->failed=1;return -1;}
        if(!n){p->diagnostic_eof=1;break;}p->diagnostic_bytes+=(size_t)n;
        /* Fixed entry has no diagnostic success output or private-key logger. */
        p->failed=1;if(p->diagnostic_bytes>4096)break;
    }return 0;
}
int kv_linux_key_poll(kv_linux_key_process *p){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(p->phase)return kv_linux_key_phase_poll(p,p->worker_execution,p->phase_result,p->phase)?-1:
        (p->reaped&&p->control_eof&&p->preparation_eof&&p->diagnostic_eof?1:0);
    if(p->phase_fenced)return p->reaped&&p->control_eof&&p->preparation_eof&&p->diagnostic_eof?1:-1;
    if(p->pid<=0)return p->reaped&&p->control_eof&&p->preparation_eof&&p->diagnostic_eof?1:-1;
    if(!current(p)){p->failed=1;if(kv_linux_key_cancel(p))return -1;}
    preparation_poll(p);control_poll(p);if(diagnostics_poll(p))return -1;
    if(!p->reaped){int status=0;pid_t got=waitpid(p->pid,&status,WNOHANG);if(got==p->pid){p->reaped=1;p->exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;}else if(got<0&&errno!=EINTR){p->failed=1;return -1;}}
    if(p->reaped&&!p->cancelled)p->failed=1;
    if(HOOK("after_native_observation",p->reaped,p->control_eof))p->failed=1;
    if(p->failed&&!p->reaped&&kv_linux_key_cancel(p))return -1;
    if(p->reaped&&p->control_eof&&p->preparation_eof&&p->diagnostic_eof)return 1;
    return before(p->cleanup)?0:-1;
}
int kv_linux_key_move(kv_linux_key_process **from,kv_linux_key_process **to){
    if(!from||!to||from==to||!*from||*to){errno=EINVAL;return -1;}
    kv_linux_key_process *p=*from;if(p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    *to=p;*from=NULL;return 0;
}
int kv_linux_key_current(kv_linux_key_process *p){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(p->phase_fenced){errno=EPERM;return -1;} /* Refuse before legacy source I/O. */
    if(p->failed||p->cancelled||p->reaped||p->control_eof||p->diagnostic_eof)goto refuse;
    if(!p->public_registered){errno=EAGAIN;return -1;}
    if(kv_linux_key_poll(p)||p->failed||p->cancelled||p->reaped||p->control_eof||p->diagnostic_eof||
        !p->preparation_eof||!p->realm_admitted||!p->ordinary_ready||!p->release_sent||!reaping_profile()||
        !current(p)||!live(p->pidfd)||!realm_matches(p,p->key_namespace_fd)||maps(p,0)||!current(p)||!live(p->pidfd))goto refuse;
    return 0;
refuse:
    p->failed=1;(void)kv_linux_key_cancel(p);errno=ECANCELED;return -1;
}
int kv_linux_key_worker_link_matches(const kv_linux_key_process *p,
    const kv_linux_semantic_plan_lease *lease,const kv_linux_execution *execution){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(!lease||!execution||p->lease!=lease||!p->worker_input_attempted||p->worker_execution!=execution){errno=EINVAL;return -1;}
    /* Failed linkage is retained for cleanup; no validity/current recursion. */
    return 0;
}
int kv_linux_key_claim_worker_input(kv_linux_key_process *p,kv_linux_execution *execution,struct kv_linux_worker_input *out){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(!out||out->request_fd!=-1||out->readonly_root_fd!=-1||out->peer_pidfd!=-1||out->clock_namespace_fd!=-1||
        !execution||!p->lease||kv_linux_execution_start_matches(execution,p)){errno=EINVAL;return -1;}
    if(p->worker_input_attempted){errno=EALREADY;return -1;}
    p->worker_input_attempted=1;p->worker_execution=execution;
    struct kv_linux_worker_input staged={.request_fd=-1,.readonly_root_fd=-1,.peer_pidfd=-1,.clock_namespace_fd=-1};
    if(HOOK("worker_input_key_burned",-1,-1)||kv_linux_key_current(p)||
        kv_linux_semantic_plan_lease_claim_worker_input(p->lease,p,execution,&staged))goto refused;
    if(staged.semantic_sequence!=p->input.semantic_sequence||staged.exclusive_sequence!=p->input.exclusive_sequence||staged.native_revision!=p->input.native_revision||
        memcmp(staged.pending_record,p->input.pending_record,sizeof staged.pending_record)||
        memcmp(staged.semantic_report,p->input.semantic_report,sizeof staged.semantic_report)||
        HOOK("worker_input_key_before_publish",-1,-1)||kv_linux_key_current(p)||
        kv_linux_key_worker_link_matches(p,p->lease,execution))goto refused;
    *out=staged;return 0;
refused:
    {int saved=errno;int fds[4]={staged.request_fd,staged.readonly_root_fd,staged.peer_pidfd,staged.clock_namespace_fd};
        for(unsigned i=0;i<4;i++)if(fds[i]>=0)close(fds[i]);
        p->failed=1;(void)kv_linux_key_cancel(p);errno=saved?saved:ECANCELED;return -1;}
}
int kv_linux_key_worker_detach(kv_linux_key_process *p,kv_linux_execution *execution){
    if(!p||p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(!execution){errno=EINVAL;return -1;}
    if(p->phase){errno=EBUSY;return -1;}
    if(!p->worker_execution)return 0; /* Pure idempotent cleanup, no rearm. */
    if(p->worker_execution!=execution||!p->worker_input_attempted){errno=EINVAL;return -1;}
    if(kv_linux_execution_worker_drain_matches(execution,p)){errno=EBUSY;return -1;}
    p->failed=1;
    if(kv_linux_semantic_plan_lease_worker_detach(p->lease,p,execution))return -1;
    p->worker_execution=NULL;return 0;
}
static int phase_actual_chain(const kv_linux_key_process *p,const kv_linux_execution *execution,
    const kv_linux_owned_worker_result *result,const kv_linux_cleanup_phase *phase){
    return p&&p->owner_pid==getpid()&&p->lease&&execution&&result&&phase&&(!p->phase||p->phase==phase)&&(!p->phase_result||p->phase_result==result)&&
        p->worker_input_attempted&&p->worker_execution==execution&&kv_linux_cleanup_phase_result_matches(phase,result)&&
        kv_linux_execution_result_phase_matches(execution,p,result,phase);
}
static int phase_link(const kv_linux_key_process *p,const kv_linux_execution *execution,
    const kv_linux_owned_worker_result *result,const kv_linux_cleanup_phase *phase){
    return phase_actual_chain(p,execution,result,phase)&&p->phase_fenced&&p->phase==phase&&p->phase_result==result;
}
int kv_linux_key_phase_bind(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!p||p->owner_pid!=getpid()||!execution||!result||!phase||!p->lease||p->worker_execution!=execution||!p->worker_input_attempted||
        !kv_linux_cleanup_phase_result_matches(phase,result)||!kv_linux_execution_result_phase_matches(execution,p,result,phase)){
        errno=EINVAL;return -1;
    }
    if(p->phase)return phase_link(p,execution,result,phase)&&p->phase_bound_complete?0:(errno=EINVAL,-1);
    if(p->phase_fenced||p->failed||p->cancelled||p->reaped||!p->public_registered||!p->realm_admitted||!p->ordinary_ready||
        !p->release_sent||!p->preparation_eof||p->control_eof||p->diagnostic_eof){errno=EPERM;return -1;}
    p->phase_fenced=1;p->phase=phase;p->phase_result=result;
    if(kv_linux_semantic_plan_lease_phase_bind(p->lease,p,execution,result,phase)){p->failed=1;return -1;}
    p->phase_bound_complete=1;
    return 0;
}
int kv_linux_key_phase_seed(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,
    kv_linux_cleanup_phase *phase,struct kv_linux_cleanup_phase_seed *out){
    if(!out||!phase_link(p,execution,result,phase)||!p->phase_bound_complete||p->failed||p->cancelled){errno=EINVAL;return -1;}
    struct kv_linux_cleanup_phase_seed staged=*out;
    if(kv_linux_semantic_plan_lease_phase_seed(p->lease,p,execution,result,phase,&staged))return -1;
    if(staged.native_revision!=p->input.native_revision||p->binding.native_revision!=p->input.native_revision||!staged.guard||!staged.custody){errno=EPROTO;return -1;}
    staged.key=p;staged.execution=execution;memcpy(staged.pending_record,p->input.pending_record,sizeof staged.pending_record);
    memcpy(staged.boot_id,p->boot,sizeof staged.boot_id);staged.work_deadline_ns=p->work;staged.cleanup_deadline_ns=p->cleanup;
    staged.time_namespace_dev=p->time_dev;staged.time_namespace_ino=p->time_ino;
    staged.semantic_sequence=p->input.semantic_sequence;staged.exclusive_sequence=p->input.exclusive_sequence;
    struct kv_linux_cleanup_participant key={.role=KV_LINUX_PHASE_KEY,.pid=p->pid,
        .uid=(uid_t)le(p->input.pending_record+184,4),.gid=(gid_t)le(p->input.pending_record+188,4)};
    memcpy(key.participant_nonce,p->binding.nonce,32);unsigned size=0;
    if(EVP_Digest(p->context,sizeof p->context,key.startup_context_sha256,&size,EVP_sha256(),NULL)!=1||size!=32){errno=EIO;return -1;}
    staged.participants[1]=key;*out=staged;return 0;
}
int kv_linux_key_phase_guard_matches(const kv_linux_key_process *p,const kv_linux_execution *execution,
    const kv_linux_owned_worker_result *result,const kv_linux_cleanup_phase *phase,const kv_linux_service_input_guard *guard){
    return phase_actual_chain(p,execution,result,phase)&&guard&&kv_linux_semantic_plan_lease_phase_guard_matches(p->lease,p,execution,result,phase,guard);
}
int kv_linux_key_phase_revoke_guard(kv_linux_key_process *p,kv_linux_execution *execution,
    kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!p||p->owner_pid!=getpid()||!p->lease||!execution||!result||!phase||p->worker_execution!=execution||
        (p->phase&&p->phase!=phase)||(p->phase_result&&p->phase_result!=result)||
        !kv_linux_cleanup_phase_result_matches(phase,result)||!kv_linux_execution_result_phase_matches(execution,p,result,phase)){
        errno=EINVAL;return -1;
    }
    return kv_linux_semantic_plan_lease_phase_revoke_guard(p->lease,p,execution,result,phase);
}
int kv_linux_key_phase_custody_matches(const kv_linux_key_process *p,const kv_linux_execution *execution,
    const kv_linux_owned_worker_result *result,const kv_linux_cleanup_phase *phase,const kv_linux_source_custody *custody){
    return phase_actual_chain(p,execution,result,phase)&&custody&&kv_linux_semantic_plan_lease_phase_custody_matches(p->lease,p,execution,result,phase,custody);
}
static int phase_realm_live(const kv_linux_key_process *p){
    if(p->reaped||!live(p->pidfd)||!p->realm_admitted)return 0;
    int actual=ns_open(p->pid,"user");struct statfs fs;uid_t owner=(uid_t)-1;
    int ok=actual>=0&&same(actual,p->key_namespace_fd)&&!fstatfs(actual,&fs)&&fs.f_type==NSFS_MAGIC&&
        ioctl(actual,NS_GET_NSTYPE)==CLONE_NEWUSER&&!ioctl(actual,NS_GET_OWNER_UID,&owner)&&owner==0&&live(p->pidfd);
    if(actual>=0)close(actual);
    return ok;
}
static int phase_live(kv_linux_key_process *p){
    enum kv_linux_cleanup_state state=kv_linux_cleanup_phase_state(p->phase,p->phase_result);
    uint64_t deadline=state==KV_CLEANUP_ACTIVE?p->cleanup:p->work;
    return !p->failed&&!p->cancelled&&!p->phase_retired&&
        !kv_linux_cleanup_phase_component_current(p->phase,p->phase_result,KV_LINUX_PHASE_KEY)&&
        clock_current_epoch(p,deadline)&&live(p->input.peer_pidfd)&&phase_realm_live(p)&&
        !kv_linux_cleanup_phase_component_current(p->phase,p->phase_result,KV_LINUX_PHASE_KEY)&&before(deadline);
}
/* After the one exact request, a queued SIGNED may precede actual child exit.
 * Use the original source-free phase C/peer/revision guard before consuming it;
 * requiring key pidfd/realm liveness here would reject valid finite completion.
 * Healthy drain still requires signature plus exact exit/reap and every EOF. */
static int sign_guard(kv_linux_key_process *p){
    return p&&p->owner_pid==getpid()&&!p->failed&&!p->cancelled&&p->phase&&p->sign_finalizer&&
        p->sign_attempted&&p->sign_sent&&p->phase_acked&&p->public_registered&&
        kv_linux_finalization_key_matches(p->sign_finalizer,p)==1&&
        kv_linux_cleanup_phase_state(p->phase,p->phase_result)==KV_CLEANUP_ACTIVE&&
        !kv_linux_cleanup_phase_finalization_guard(p->phase,p->sign_finalizer)&&before(p->cleanup);
}
static int verify_signature(kv_linux_key_process *p,const unsigned char signature[64]){
    EVP_PKEY *public_key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,p->public_key,32);
    EVP_MD_CTX *verify=EVP_MD_CTX_new();
    int ok=public_key&&verify&&EVP_DigestVerifyInit(verify,NULL,NULL,NULL,public_key)==1&&
        EVP_DigestVerify(verify,signature,64,p->sign_message,sizeof p->sign_message)==1;
    if(verify)EVP_MD_CTX_free(verify);
    if(public_key)EVP_PKEY_free(public_key);
    return ok&&sign_guard(p)?0:-1;
}
int kv_linux_key_phase_prepare(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!phase_link(p,execution,result,phase)){errno=EINVAL;return -1;}
    enum kv_linux_cleanup_state state=kv_linux_cleanup_phase_state(phase,result);
    unsigned char frame[KV_LINUX_PHASE_FRAME_BYTES];enum kv_linux_phase_kind kind;
    if(state==KV_CLEANUP_PREPARING){
        if(p->phase_prepare_attempted)return 0;
        p->phase_prepare_attempted=1;
        struct kv_linux_phase_binding binding,checked;
        if(kv_linux_cleanup_phase_binding(phase,result,KV_LINUX_PHASE_KEY,KV_CLEANUP_TO_PARTICIPANT,&binding)||
            kv_linux_phase_frame_encode(frame,KV_LINUX_PHASE_PREPARE,&binding)||
            kv_linux_key_phase_prepare_validate(frame,sizeof frame,p->context,&checked))goto fail;
        p->phase_binding=checked;kind=KV_LINUX_PHASE_PREPARE;
    }else if(state==KV_CLEANUP_COMMITTING){
        if(p->phase_commit_attempted)return 0;
        if(!p->phase_prepared){errno=EPERM;return -1;}
        p->phase_commit_attempted=1;kind=KV_LINUX_PHASE_COMMIT;
    }else {errno=EPERM;return -1;}
    if(!phase_live(p)||!before(p->work)||kv_linux_phase_frame_encode(frame,kind,&p->phase_binding)||
        send(p->control_fd,frame,sizeof frame,MSG_DONTWAIT|MSG_NOSIGNAL)!=(ssize_t)sizeof frame||!phase_live(p)||!before(p->work))goto fail;
    return 0;
fail:
    p->failed=1;(void)kv_linux_key_cancel(p);errno=ECANCELED;return -1;
}
int kv_linux_key_phase_poll(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!phase_actual_chain(p,execution,result,phase)){errno=EINVAL;return -1;}
    enum kv_linux_cleanup_state state=kv_linux_cleanup_phase_state(phase,result);
    if(!p->phase){
        if(state!=KV_CLEANUP_FAILED_RETAINED&&state!=KV_CLEANUP_CANCELLING){errno=EPERM;return -1;}
        /* No registration occurred. Cancel before legacy poll, whose actual
         * failed/cancelled checks short-circuit all WORK/source current. */
        p->failed=1;if(kv_linux_key_cancel(p))return -1;
        int key_poll=kv_linux_key_poll(p);
        int upstream_poll=kv_linux_semantic_plan_lease_phase_cancel_poll(p->lease,p,execution,result,phase);
        return key_poll<0||upstream_poll?-1:0;
    }
    int negative=p->failed||p->cancelled||state==KV_CLEANUP_FAILED_RETAINED||state==KV_CLEANUP_CANCELLING;
    int signing=p->sign_sent&&p->sign_finalizer;
    if(p->phase_retired)return negative?-1:0;
    if(!negative&&!(signing?sign_guard(p):phase_live(p))){p->failed=1;negative=1;}
    if(negative&&kv_linux_key_cancel(p))return -1;
    if(negative&&kv_linux_semantic_plan_lease_phase_cancel_poll(p->lease,p,execution,result,phase))p->failed=1;
    for(unsigned round=0;!p->control_eof&&round<16;round++){
        struct packet packet;int n=receive_packet(p->control_fd,&packet);if(!n)break;
        if(n==2){p->control_eof=1;if(!p->cancelled&&!p->sign_received)p->failed=1;break;}
        if(n<0){p->failed=1;continue;}
        int bad=negative||p->failed||p->cancelled||packet.right_count||
            packet.cred.pid!=p->pid||packet.cred.uid!=(uid_t)le(p->input.pending_record+184,4)||packet.cred.gid!=(gid_t)le(p->input.pending_record+188,4)||
            !(signing?sign_guard(p):phase_live(p));
        if(!bad&&signing){
            unsigned char signature[64];
            if(p->sign_received||packet.size!=KV_LINUX_KEY_SIGN_FRAME_BYTES||
                kv_linux_key_sign_frame_validate(packet.bytes,packet.size,KV_LINUX_KEY_SIGNED,p->sign_message,signature)||
                verify_signature(p,signature))bad=1;
            else {memcpy(p->signature,signature,sizeof p->signature);p->sign_received=1;}
            if(!bad&&!sign_guard(p))bad=1;
        }else if(!bad){
            struct kv_linux_phase_binding back=p->phase_binding;back.sender_pid=p->phase_binding.receiver_pid;back.receiver_pid=p->phase_binding.sender_pid;
            if(packet.size!=KV_LINUX_PHASE_FRAME_BYTES)bad=1;
            else if(p->phase_prepare_attempted&&!p->phase_prepared&&!p->phase_commit_attempted&&before(p->work)&&
                !kv_linux_phase_frame_validate(packet.bytes,packet.size,KV_LINUX_PHASE_PREPARED,&back))p->phase_prepared=1;
            else if(p->phase_prepared&&p->phase_commit_attempted&&!p->phase_acked&&before(p->work)&&
                !kv_linux_phase_frame_validate(packet.bytes,packet.size,KV_LINUX_PHASE_ACK,&back))p->phase_acked=1;
            else bad=1;
            if(!bad&&(!phase_live(p)||!before(p->work)))bad=1;
        }
        close_packet(&packet);if(bad)p->failed=1;
    }
    if(!p->failed&&!p->cancelled&&!p->control_eof){
        unsigned char byte;ssize_t n=recv(p->control_fd,&byte,1,MSG_PEEK|MSG_DONTWAIT);
        int expected=signing?!p->sign_received:
            ((p->phase_prepare_attempted&&!p->phase_prepared)||(p->phase_commit_attempted&&!p->phase_acked));
        if(!n){p->control_eof=1;if(!p->sign_received)p->failed=1;}
        else if(n>0){
            /* A first expected reply may arrive after the preceding EAGAIN.
             * Leave it for the next bounded parse; no saved fact advances.
             * Once the expected reply is latched, any queued extra poisons. */
            if(!expected)p->failed=1;
        }else if(errno!=EAGAIN&&errno!=EWOULDBLOCK)p->failed=1;
    }
    if(diagnostics_poll(p))p->failed=1;
    if(!p->reaped){int status=0;pid_t got=waitpid(p->pid,&status,WNOHANG);
        if(got==p->pid){p->reaped=1;p->exit_code=WIFEXITED(status)?WEXITSTATUS(status):-1;}
        else if(got<0&&errno!=EINTR)p->failed=1;
    }
    if(p->reaped&&!p->cancelled&&(p->exit_code||(!p->sign_received&&(!signing||p->control_eof))))p->failed=1;
    if(p->failed&&!p->cancelled)(void)kv_linux_key_cancel(p);
    if(p->failed||p->cancelled){errno=ECANCELED;return -1;}
    return 0;
}
int kv_linux_key_finalization_start(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,
    kv_linux_cleanup_phase *phase,kv_linux_finalization *finalizer){
    if(!phase_link(p,execution,result,phase)||!finalizer||kv_linux_finalization_key_matches(finalizer,p)!=1||
        kv_linux_cleanup_phase_finalization_matches(phase,finalizer)!=1){errno=EINVAL;return -1;}
    if(p->sign_attempted){errno=EALREADY;return -1;}
    p->sign_attempted=1;p->sign_finalizer=finalizer; /* Burn before dynamic checks/encode/write. */
    struct kv_linux_key_final_data data;unsigned char frame[KV_LINUX_KEY_SIGN_FRAME_BYTES];
    if(!p->phase_acked||kv_linux_cleanup_phase_state(phase,result)!=KV_CLEANUP_ACTIVE||
        kv_linux_finalization_key_data(finalizer,p,&data)||!phase_live(p)||
        kv_linux_cleanup_phase_finalization_guard(phase,finalizer)||
        kv_linux_key_sign_message_encode(p->sign_message,p->context,&p->phase_binding,p->public_key,&data)||
        kv_linux_key_sign_frame_encode(frame,KV_LINUX_KEY_SIGN_REQUEST,p->sign_message,NULL)||
        !phase_live(p)||kv_linux_cleanup_phase_finalization_guard(phase,finalizer)||
        send(p->control_fd,frame,sizeof frame,MSG_DONTWAIT|MSG_NOSIGNAL)!=(ssize_t)sizeof frame)goto failed;
    p->sign_sent=1;
    if(!sign_guard(p))goto failed;
    return 0;
failed:
    p->failed=1;(void)kv_linux_key_cancel(p);errno=ECANCELED;return -1;
}
int kv_linux_key_finalization_copy_signed(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,
    kv_linux_cleanup_phase *phase,kv_linux_finalization *finalizer,unsigned char message[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],unsigned char signature[64]){
    if(!message||!signature||!phase_link(p,execution,result,phase)||p->sign_finalizer!=finalizer||
        kv_linux_finalization_key_matches(finalizer,p)!=1){errno=EINVAL;return -1;}
    if(!sign_guard(p)){errno=ECANCELED;return -1;}
    if(!p->sign_received){errno=EAGAIN;return -1;}
    unsigned char m[KV_LINUX_KEY_SIGN_MESSAGE_BYTES],s[64];memcpy(m,p->sign_message,sizeof m);memcpy(s,p->signature,sizeof s);
    if(!sign_guard(p)){errno=ECANCELED;return -1;}
    memcpy(message,m,sizeof m);memcpy(signature,s,sizeof s);return 0;
}
int kv_linux_key_phase_state_matches(const kv_linux_key_process *p,const kv_linux_execution *execution,
    const kv_linux_owned_worker_result *result,const kv_linux_cleanup_phase *phase,enum kv_linux_cleanup_fact fact){
    if(!phase_actual_chain(p,execution,result,phase))return 0;
    if(fact==KV_CLEANUP_NATIVE_RESOURCES_RETIRED)return p->phase_retired;
    if(!phase_link(p,execution,result,phase))return 0;
    if(fact==KV_CLEANUP_BOUND)return p->phase_bound_complete;
    if(p->failed||p->cancelled)return 0;
    switch(fact){
        case KV_CLEANUP_PREPARED:return p->phase_prepared;
        case KV_CLEANUP_ACKED:return p->phase_acked;
        case KV_CLEANUP_EXPECTED_NATIVE_DRAINED:return p->phase_acked&&p->sign_attempted&&p->sign_received&&p->reaped&&!p->exit_code&&
            p->control_eof&&p->preparation_eof&&p->diagnostic_eof&&!p->diagnostic_bytes;
        default:return 0;
    }
}
int kv_linux_key_phase_retire(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!phase_actual_chain(p,execution,result,phase)){errno=EINVAL;return -1;}
    if(p->phase_retired)return 0;
    enum kv_linux_cleanup_state state=kv_linux_cleanup_phase_state(phase,result);
    int negative=state==KV_CLEANUP_FAILED_RETAINED||state==KV_CLEANUP_CANCELLING;
    if(!negative&&state!=KV_CLEANUP_ACTIVE){errno=EPERM;return -1;}
    /* Retire upstream WORK resources after their own actual drain while the
     * live key remains available for its future one-shot SIGN. EBUSY below is
     * retained progress, never key drain or permission to free this chain. */
    if(kv_linux_semantic_plan_lease_phase_retire(p->lease,p,execution,result,phase))return -1;
    if(negative?(!p->reaped||!p->control_eof||!p->preparation_eof||!p->diagnostic_eof):
        !kv_linux_key_phase_state_matches(p,execution,result,phase,KV_CLEANUP_EXPECTED_NATIVE_DRAINED)){errno=EBUSY;return -1;}
    int *fds[]={&p->input.peer_pidfd,&p->input.clock_namespace_fd,&p->input.parser_pidfd,&p->parent_pidfd,&p->creator_namespace_fd,&p->pidfd,
        &p->key_namespace_fd,&p->context_fd,&p->control_fd,&p->preparation_fd,&p->diagnostic_fd,&p->start_fd};
    for(unsigned i=0;i<sizeof fds/sizeof fds[0];i++)if(*fds[i]>=0){close(*fds[i]);*fds[i]=-1;}
    p->phase_retired=1;
    /* QA observes the actual terminal resource transition, never a saved
     * positive observer or a caller-supplied drain flag. Macro-off builds have
     * no callback. exit_code is the normalized wait result (-1 for a signal). */
    (void)HOOK("key_phase_native_retired",(p->reaped?1:0)|(p->control_eof?2:0)|
        (p->preparation_eof?4:0)|(p->diagnostic_eof?8:0),p->exit_code);
    return 0;
}
int kv_linux_key_phase_detach(kv_linux_key_process *p,kv_linux_execution *execution,kv_linux_owned_worker_result *result,kv_linux_cleanup_phase *phase){
    if(!phase_actual_chain(p,execution,result,phase)){errno=EINVAL;return -1;}
    if(!p->phase)return 0;
    if(!p->phase_retired||!p->reaped||!p->control_eof||!p->preparation_eof||!p->diagnostic_eof){errno=EBUSY;return -1;}
    if(kv_linux_semantic_plan_lease_phase_detach(p->lease,p,execution,result,phase))return -1;
    p->phase=NULL;p->phase_result=NULL;p->sign_finalizer=NULL;return 0; /* Fence is never cleared. */
}
int kv_linux_key_observe(const kv_linux_key_process *p,struct kv_linux_key_observation *out){
    if(!p||!out||p->owner_pid!=getpid()){errno=EINVAL;return -1;}
    struct kv_linux_key_observation o={.pid=p->pid,.failed=p->failed,.cancelled=p->cancelled,.reaped=p->reaped,.exit_code=p->exit_code,
        .preparation_eof=p->preparation_eof,.control_eof=p->control_eof,.diagnostic_eof=p->diagnostic_eof,
        .realm_admitted=p->realm_admitted,.ordinary_ready=p->ordinary_ready,.release_sent=p->release_sent,.public_registered=p->public_registered,
        .work_deadline_ns=p->work,.cleanup_deadline_ns=p->cleanup};
    if(p->public_registered)memcpy(o.public_key,p->public_key,32);
    *out=o;return 0;
}
int kv_linux_key_close(kv_linux_key_process **owned){
    if(!owned){errno=EINVAL;return -1;}kv_linux_key_process *p=*owned;if(!p)return 0;
    if(p->owner_pid!=getpid()){errno=ECHILD;return -1;}
    if(kv_linux_key_cancel(p))return -1;
    if(p->phase){errno=EBUSY;return -1;}
    if(p->worker_execution){errno=EBUSY;return -1;}
    if(!p->reaped||!p->control_eof||!p->preparation_eof||!p->diagnostic_eof){errno=EBUSY;return -1;}
    int *fds[]={&p->input.peer_pidfd,&p->input.clock_namespace_fd,&p->input.parser_pidfd,&p->parent_pidfd,&p->creator_namespace_fd,&p->pidfd,
        &p->key_namespace_fd,&p->context_fd,&p->control_fd,&p->preparation_fd,&p->diagnostic_fd,&p->start_fd};
    for(unsigned i=0;i<sizeof fds/sizeof fds[0];i++)if(*fds[i]>=0){close(*fds[i]);*fds[i]=-1;}
    if(kv_linux_semantic_plan_lease_release(&p->lease))return -1;
    *owned=NULL;free(p);return 0;
}
