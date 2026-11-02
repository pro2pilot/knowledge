/* Fixed native service entry SOURCE PROTOTYPE. No installation/runtime
 * qualification. No root project/Node/CLI-path/socket-activation entry exists.
 * Trusted admin/proc/filesystem and cooperative fixed single-thread program
 * premises are explicit; this is not a CFI or hard kernel-I/O latency claim. */
#define _GNU_SOURCE
#if !defined(__linux__) || !defined(__x86_64__)
#error fixed native service requires Linux AMD64
#endif
#include "../BASE_MAIN/verification-linux-service-configuration.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <unistd.h>
#include "../main-h-birth-core.inc"
#include "main-intake.inc"

_Static_assert(sizeof(uid_t)==4&&sizeof(gid_t)==4,"fixed Linux native configuration ABI");
#define SERVICE_CAPS ((UINT64_C(1)<<CAP_SETUID)|(UINT64_C(1)<<CAP_SETGID)|(UINT64_C(1)<<CAP_CHOWN)|\
    (UINT64_C(1)<<CAP_KILL)|(UINT64_C(1)<<CAP_SYS_PTRACE)|(UINT64_C(1)<<CAP_SETFCAP))
static volatile sig_atomic_t stopping;
static void stop_signal(int number){(void)number;stopping=1;mi_stop_original();}
static int high(int fd){
    if(fd<0)return -1;
    int n=fcntl(fd,F_DUPFD_CLOEXEC,16),saved=errno;close(fd);errno=saved;return n;
}
static int profile(void){
    uid_t a,b,c;gid_t d,e,f;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2];
    memset(caps,0xff,sizeof caps);
    if(getresuid(&a,&b,&c)||getresgid(&d,&e,&f)||a||b||c||d||e||f||setfsuid((uid_t)-1)||setfsgid((gid_t)-1)||
        syscall(SYS_capget,&h,caps)||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return -1;
    uint64_t effective=(uint64_t)caps[0].effective|((uint64_t)caps[1].effective<<32);
    uint64_t permitted=(uint64_t)caps[0].permitted|((uint64_t)caps[1].permitted<<32);
    if(effective!=SERVICE_CAPS||permitted!=SERVICE_CAPS||caps[0].inheritable||caps[1].inheritable)return -1;
    for(int i=0;i<64;i++){
        errno=0;int value=prctl(PR_CAPBSET_READ,i,0,0,0);
        if(value<0){if(errno==EINVAL&&!(SERVICE_CAPS&(UINT64_C(1)<<i)))continue;return -1;}
        if(value!=(int)((SERVICE_CAPS>>i)&1))return -1;
    }
    return 0;
}
static int safe_policy(void){
    int fd=open("/proc/sys/fs/suid_dumpable",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return -1;
    unsigned char data[3]={255,255,255};ssize_t n=pread(fd,data,sizeof data,0);close(fd);
    return n==2&&data[0]=='0'&&data[1]=='\n'?0:-1;
}
static int one_thread(void){
    DIR *d=opendir("/proc/self/task");if(!d)return 0;
    unsigned n=0;struct dirent *entry;errno=0;
    while((entry=readdir(d)))if(entry->d_name[0]!='.')n++;
    int good=!errno&&n==1;closedir(d);return good;
}
static int startup(void){
    if(profile()||clearenv()||chdir("/")||syscall(SYS_close_range,0,~0U,0))return -1;
    umask(0077);
    if(setgroups(0,NULL)||getgroups(0,NULL)!=0||prctl(PR_SET_KEEPCAPS,0,0,0,0)||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||prctl(PR_SET_DUMPABLE,0)||prctl(PR_GET_DUMPABLE)!=0)return -1;
    sigset_t empty;if(sigemptyset(&empty)||sigprocmask(SIG_SETMASK,&empty,NULL))return -1;
    struct sigaction action;memset(&action,0,sizeof action);action.sa_handler=SIG_DFL;
    if(sigemptyset(&action.sa_mask))return -1;
    for(int n=1;n<NSIG;n++)if(n!=SIGKILL&&n!=SIGSTOP&&sigaction(n,&action,NULL)&&errno!=EINVAL)return -1;
    action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL))return -1;
    action.sa_handler=stop_signal;
    if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL)||!one_thread()||safe_policy()||profile())return -1;
    return 0;
}
static int exact_io(int fd,unsigned char *data,size_t size,int writing){
    size_t done=0;unsigned interrupted=0;
    while(done<size){
        ssize_t n=writing?pwrite(fd,data+done,size-done,(off_t)done):pread(fd,data+done,size-done,(off_t)done);
        if(n<0&&errno==EINTR&&++interrupted<8)continue;
        if(n<=0)return -1;
        done+=(size_t)n;
    }
    return 0;
}
static int named_lock(int dir,int fd){
    struct stat held,named;
    return !kv_linux_service_configuration_regular(fd,0600,32,&held)&&
        !fstatat(dir,KV_LINUX_SERVICE_SINGLETON_NAME,&named,AT_SYMLINK_NOFOLLOW)&&
        kv_linux_service_configuration_same(&held,&named)?0:-1;
}
static int singleton(int dir,int initialize){
    static const unsigned char marker[32]={'K','V','L','R','U','N','1',0,1,0,0,0,32,0,0,0};
    int flags=O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK;
    int fd=openat(dir,KV_LINUX_SERVICE_SINGLETON_NAME,flags|(initialize?(O_CREAT|O_EXCL):0),0600);
    if(fd<0)return -1;
    if(kv_linux_service_configuration_regular(fd,0600,initialize?0:32,NULL)||flock(fd,LOCK_EX|LOCK_NB))goto fail;
    if(initialize){
        unsigned char bytes[32];memcpy(bytes,marker,sizeof bytes);
        if(exact_io(fd,bytes,sizeof bytes,1)||fsync(fd)||fsync(dir))goto fail;
    }
    struct stat before,after;unsigned char bytes[32];
    if(kv_linux_service_configuration_regular(fd,0600,32,&before)||exact_io(fd,bytes,sizeof bytes,0)||
        memcmp(bytes,marker,sizeof bytes)||kv_linux_service_configuration_regular(fd,0600,32,&after)||
        !kv_linux_service_configuration_same(&before,&after)||named_lock(dir,fd))goto fail;
    return high(fd);
fail:
    /* No unlink, truncation, replacement, LOCK_UN or automatic repair. A
     * partial O_EXCL initialization remains visible for administrator review. */
    close(fd);return -1;
}
static int socket_attributes(void){
    const char *names[]={"system.posix_acl_access","system.posix_acl_default","security.capability"};
    for(unsigned i=0;i<3;i++){
        errno=0;
        if(lgetxattr(KV_LINUX_SERVICE_RUNTIME_SOCKET,names[i],NULL,0)>=0||
            (errno!=ENODATA&&errno!=ENOTSUP&&errno!=EOPNOTSUPP))return -1;
    }
    return 0;
}
static int socket_stat(int dir,gid_t group,struct stat *st){
    return !fstatat(dir,KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME,st,AT_SYMLINK_NOFOLLOW)&&S_ISSOCK(st->st_mode)&&
        !st->st_uid&&st->st_gid==group&&(st->st_mode&07777)==0660&&st->st_nlink==1&&!socket_attributes()?0:-1;
}
static int hold_socket(int dir,gid_t group,struct stat *identity){
    struct stat named,held,after;if(socket_stat(dir,group,&named))return -1;
    int fd=high(openat(dir,KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME,O_PATH|O_NOFOLLOW|O_CLOEXEC));if(fd<0)return -1;
    if(fstat(fd,&held)||!kv_linux_service_configuration_same(&named,&held)||socket_stat(dir,group,&after)||
        !kv_linux_service_configuration_same(&held,&after)){close(fd);return -1;}
    *identity=held;return fd;
}
static int unlink_held_socket(int dir,int held_fd,const struct stat *identity,gid_t group,int state,int lock){
    struct stat held,named;
    if(named_lock(state,lock)||fstat(held_fd,&held)||!kv_linux_service_configuration_same(identity,&held)||
        socket_stat(dir,group,&named)||!kv_linux_service_configuration_same(&held,&named))return -1;
    return unlinkat(dir,KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME,0);
}
static int remove_stale(int dir,gid_t group,int state,int lock){
    struct stat st;
    if(fstatat(dir,KV_LINUX_SERVICE_RUNTIME_SOCKET_NAME,&st,AT_SYMLINK_NOFOLLOW))return errno==ENOENT?0:-1;
    /* Exclusive SAME named flock + cooperative fixed Main is required. Every
     * legitimate inherited listener retains this lock until its close-first
     * path; PID text, age, timeout or configured label is never proof. */
    int held=hold_socket(dir,group,&st);if(held<0)return -1;
    int result=unlink_held_socket(dir,held,&st,group,state,lock);close(held);return result;
}
static int listener(gid_t group){
    int fd=high(socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0));if(fd<0)return -1;
    int one=1;
    if(setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&one,sizeof one)){close(fd);return -1;}
    struct sockaddr_un address;memset(&address,0,sizeof address);address.sun_family=AF_UNIX;
    memcpy(address.sun_path,KV_LINUX_SERVICE_RUNTIME_SOCKET,sizeof(KV_LINUX_SERVICE_RUNTIME_SOCKET));
    umask(0117);(void)setfsgid(group);
    int bound=setfsgid((gid_t)-1)==(int)group&&
        !bind(fd,(struct sockaddr*)&address,offsetof(struct sockaddr_un,sun_path)+sizeof(KV_LINUX_SERVICE_RUNTIME_SOCKET));
    (void)setfsgid(0);umask(0077);
    if(setfsgid((gid_t)-1)!=0||prctl(PR_SET_DUMPABLE,0)||prctl(PR_GET_DUMPABLE)!=0||profile())_exit(1);
    if(!bound){close(fd);return -1;}
    return fd;
}
/* SOURCE ONLY. This file deliberately has no executable main entry. */
static __attribute__((used)) int mi_private_main_source_only(int argc,char **argv){
    if(startup())_exit(77);
    if(argc!=1)_exit(1);
    (void)argv;
    struct kv_linux_service_configuration configuration;
    if(kv_linux_service_configuration_load(&configuration))_exit(1);
    int state=high(kv_linux_service_configuration_directory(KV_SERVICE_STATE_DIRECTORY));
    int runtime=high(kv_linux_service_configuration_directory(KV_SERVICE_RUNTIME_DIRECTORY));
    int lock=-1,original=-1,socket_file=-1,result=1;struct stat socket_identity;
    /* A2 does not open the old runtime front or create any child. */
    if(state<0||runtime<0)goto done;
    for(int i=KV_SERVICE_ANCHOR_DIRECTORY;i<=KV_SERVICE_WORKER_DIRECTORY;i++){
        int fd=kv_linux_service_configuration_directory((enum kv_linux_service_fixed_directory)i);
        if(fd<0)goto done;
        close(fd);
    }
    lock=singleton(state,0);if(lock<0)goto done;
    if(named_lock(state,lock)||remove_stale(runtime,configuration.policy.authorized_gid,state,lock))goto done;
    original=listener(configuration.policy.authorized_gid);if(original<0)goto done;
    socket_file=hold_socket(runtime,configuration.policy.authorized_gid,&socket_identity);
    if(socket_file<0||named_lock(state,lock)||listen(original,16))goto done;
    /* Fixed source origin: these are Main's local verified administrative
     * configuration and its sole actual listener. No packet chooses either. */
    struct mi_admin intake_admin={configuration.policy.authorized_uid,
        configuration.policy.authorized_gid,configuration.policy.setup_ns,
        configuration.policy.work_ns,configuration.policy.cleanup_ns};
    if(mi_main_capture(original,&intake_admin))goto done;
    /* One bounded intake attempt. This is not an H/recovery event loop.
     * Every outcome is terminal unavailable; no public reply/authority. */
    while(!stopping){
        int step=mi_state.phase==MI_MAIN_CAPTURED?mi_accept_original():
            mi_state.phase==MI_PEER_HELD?mi_receive_original():-1;
        if(step<0)break;
        if(mi_state.phase==MI_B1_READY){(void)mi_core_offer_original();break;}
        if(mi_guard())break;
        struct pollfd watches[2]={{mi_state.phase==MI_MAIN_CAPTURED?original:
            mi_state.fd[MI_CONNECTION],POLLIN|POLLHUP,0},
            {mi_state.fd[MI_PEER_PIDFD],POLLIN,0}};
        uint64_t now=mi_now();if(!now||now>=mi_state.admission_end)break;
        uint64_t ms=(mi_state.admission_end-now)/UINT64_C(1000000);
        if(ms>10)ms=10;
        if(poll(watches,mi_state.phase==MI_MAIN_CAPTURED?1:2,(int)ms)<0)break;
        if(watches[0].revents&(POLLERR|POLLNVAL))break;
        if(watches[1].revents)break;
    }
    if(stopping)mi_stop_original();
    result=1; /* unavailable is never a successful birth/release receipt */
done:
    (void)mi_cancel_original();
    (void)mi_finish_original();
    if(original>=0)close(original);
    if(socket_file>=0){
        if(unlink_held_socket(runtime,socket_file,&socket_identity,configuration.policy.authorized_gid,state,lock))result=1;
        close(socket_file);
    }
    if(runtime>=0)close(runtime);
    /* Close-only OFD lifetime; never LOCK_UN. Pending UID/work scopes are not
     * reset, deleted or declared closed by service exit or a successful reap. */
    if(lock>=0)close(lock);
    if(state>=0)close(state);
    _exit(result);
}
