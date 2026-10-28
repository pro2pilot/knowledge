/* Installed Linux native service. Privileged code accepts fixed binary frames
 * and opaque sealed descriptors only. Node and repository code execute after
 * real UID/GID/capability/descriptor separation, never as host root.
 *
 * The installer fixes every privileged path/identity/runtime at build time.
 * No public caller selects a privileged executable, path, UID or proof.
 */
#define _GNU_SOURCE
#include "verification-linux-service.h"
#include "verification-linux-uid-history.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/memfd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#ifndef KLS_ROOT
#error Installer must fix KLS_ROOT and all identity/provenance constants
#endif
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error Native ABI supports little-endian Linux only
#endif
#if defined(__aarch64__)
#define LOADER_DIR "lib"
#define LOADER_NAME "ld-linux-aarch64.so.1"
#elif defined(__x86_64__)
#define LOADER_DIR "lib64"
#define LOADER_NAME "ld-linux-x86-64.so.2"
#else
#error Native ABI supports x64 and ARM64 only
#endif
#define STACK_BYTES (1024U*1024U)
#define MAX_CLIENTS 8
#define MAX_WRITERS 16
#define INTERNAL_MAGIC UINT32_C(0x4b4c4931)
enum { INTERNAL_BIRTH=1, INTERNAL_PERMIT=2, INTERNAL_STOP=3, INTERNAL_FINAL=4, INTERNAL_AUTHORITY=5, INTERNAL_WORK_RESULT=6, INTERNAL_CLEANUP=7 };
struct work_result {
  uint32_t phase,importer_drained,source_readonly,authority_readback;
  uint32_t files,directories,source_bytes,commands,commands_drained;
  int32_t authority_pid,authority_status,authority_wait_known,reason,authority_host_pid;
  uint64_t authority_birth;
  unsigned char manifest[32],directory_hash[32];
};
struct native_result {
  uint32_t magic,kind;
  int32_t init,init_status,init_reaped,reason,stop_dispatched;
  uint64_t cleanup_start,cleanup_end,observed;
  struct work_result work;
};
struct writer { int pid,pidfd,guardian,guardianfd,guard_channel,closed;uint32_t ordinal;uint64_t deadline,birth;char cgroup[PATH_MAX],record[80]; };
struct client {
  int fd,peerfd,parentfd,cancel_read,cancel_write,pid,parent,uid,ordinal,opened,terminal;
  uint64_t parent_birth,accepted_ns;
  struct kls_request first;
  struct writer writers[MAX_WRITERS];unsigned writers_count;
};
struct attempt {
  int active,closed,permitted,quarantined,client_slot,keeper,keeperfd,initfd,authorityfd,channel,resultfd,resultpipe,result_eof;
  int keeper_reaped,keeper_status,final_received;
  uint64_t started,work_deadline,cleanup_ms,result_bytes;
  struct native_result result;
  kv_linux_uid_reservation reservation;
  char root[PATH_MAX],cgroup[PATH_MAX],terminal_json[8192];
};
static struct client clients[MAX_CLIENTS];
static struct attempt attempt;
static kv_linux_uid_history *history;
static int rootfd=-1,daemonfd=-1,serverfd=-1,quarantine;
static unsigned char boot_id[16],epoch[32];
static char boot_hex[33],epoch_hex[65],binary_hex[65],service_cgroup[PATH_MAX];
static volatile sig_atomic_t cancelled;
static uint64_t now_ns(void) { struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(110);return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec; }
static int pidfd_open_exact(pid_t pid) { return (int)syscall(SYS_pidfd_open,pid,0); }
static int pidfd_dead(int fd) { struct pollfd p={fd,POLLIN,0};int n=poll(&p,1,0);return n>0&&(p.revents&(POLLIN|POLLHUP|POLLERR)); }
static int pidfd_stop(int fd) { int n=(int)syscall(SYS_pidfd_send_signal,fd,SIGKILL,NULL,0);return n==0||errno==ESRCH?0:-1; }
static void stop_signal(int sig) { (void)sig;cancelled=1; }
static int nonblock(int fd) { int flags=fcntl(fd,F_GETFL);return flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)?-1:0; }
static int write_all(int fd,const void *body,size_t bytes) { const unsigned char *p=body;while(bytes){ssize_t n=write(fd,p,bytes);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;bytes-=(size_t)n;}return 0; }
static int read_all(int fd,void *body,size_t bytes) { unsigned char *p=body;while(bytes){ssize_t n=read(fd,p,bytes);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;p+=n;bytes-=(size_t)n;}return 0; }
static int close_except(const int *keep,size_t count) {
  int sorted[64];if(count>64)return -1;
  for(size_t i=0;i<count;i++){if(keep[i]<0)return -1;sorted[i]=keep[i];}
  for(size_t i=0;i<count;i++)for(size_t j=i+1;j<count;j++)if(sorted[j]<sorted[i]){int n=sorted[i];sorted[i]=sorted[j];sorted[j]=n;}
  unsigned first=0;for(size_t i=0;i<count;i++){unsigned fd=(unsigned)sorted[i];if(fd<first)continue;if(fd>first&&syscall(SYS_close_range,first,fd-1,0))return -1;first=fd+1;}
  return syscall(SYS_close_range,first,UINT_MAX,0)?-1:0;
}
static void hex(const unsigned char *bytes,size_t count,char *out) { static const char d[]="0123456789abcdef";for(size_t i=0;i<count;i++){out[2*i]=d[bytes[i]>>4];out[2*i+1]=d[bytes[i]&15];}out[count*2]=0; }
static int unhex(const char *text,unsigned char *out,size_t bytes) {
  if(strlen(text)!=bytes*2)return -1;
  for(size_t i=0;i<bytes;i++){unsigned char a=(unsigned char)text[i*2],b=(unsigned char)text[i*2+1];if(!((a>='0'&&a<='9')||(a>='a'&&a<='f'))||!((b>='0'&&b<='9')||(b>='a'&&b<='f')))return -1;out[i]=(unsigned char)(((a<='9'?a-'0':a-'a'+10)<<4)|(b<='9'?b-'0':b-'a'+10));}return 0;
}
static int digest_bytes(const void *body,size_t bytes,unsigned char out[32]) {
  EVP_MD_CTX *ctx=EVP_MD_CTX_new();unsigned size=0;if(!ctx)return -1;
  int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1&&EVP_DigestUpdate(ctx,body,bytes)==1&&EVP_DigestFinal_ex(ctx,out,&size)==1&&size==32;EVP_MD_CTX_free(ctx);return ok?0:-1;
}
static int digest_fd(int fd,uint64_t limit,char out[65]) {
  EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return -1;int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL)==1;uint64_t at=0;unsigned char block[65536],sum[32];unsigned size=0;
  while(ok){ssize_t n=pread(fd,block,sizeof(block),(off_t)at);if(n<0&&errno==EINTR)continue;if(n<0){ok=0;break;}if(!n)break;at+=(uint64_t)n;if(at>limit||EVP_DigestUpdate(ctx,block,(size_t)n)!=1){ok=0;break;}}
  ok=ok&&EVP_DigestFinal_ex(ctx,sum,&size)==1&&size==32;EVP_MD_CTX_free(ctx);if(ok)hex(sum,32,out);return ok?0:-1;
}
static int make_dir(const char *name,uid_t uid,gid_t gid,mode_t mode) { if(mkdir(name,0700)||chown(name,uid,gid)||chmod(name,mode))return -1;struct stat s;return lstat(name,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=uid||s.st_gid!=gid||(s.st_mode&07777)!=mode?-1:0; }
static int cgroup_empty(const char *group) { char file[PATH_MAX],body[512];int n=snprintf(file,sizeof(file),"%s/cgroup.events",group);if(n<0||(size_t)n>=sizeof(file))return 0;int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;ssize_t size=read(fd,body,sizeof(body)-1);close(fd);if(size<=0||size>=(ssize_t)sizeof(body)-1)return 0;body[size]=0;return !strncmp(body,"populated 0\n",12)||strstr(body,"\npopulated 0\n")!=NULL; }
static int join_cgroup(const char *group,pid_t pid) { char file[PATH_MAX],body[32];int n=snprintf(file,sizeof(file),"%s/cgroup.procs",group);if(n<0||(size_t)n>=sizeof(file))return -1;int fd=open(file,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;n=snprintf(body,sizeof(body),"%d",pid);int ok=write_all(fd,body,(size_t)n)==0;close(fd);return ok?0:-1; }
static int kill_cgroup(const char *group) { char file[PATH_MAX];int n=snprintf(file,sizeof(file),"%s/cgroup.kill",group);if(n<0||(size_t)n>=sizeof(file))return -1;int fd=open(file,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;int ok=write_all(fd,"1",1)==0;close(fd);return ok?0:-1; }
static int mount_readonly(const char *from,const char *to) { if(mount(from,to,NULL,MS_BIND,NULL)||mount(NULL,to,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))return -1;struct statvfs s;return statvfs(to,&s)||(s.f_flag&ST_RDONLY)==0?-1:0; }
static int drop_role(uid_t uid,gid_t worker,int importer) {
  if(uid<KLS_UID_FIRST||uid>KLS_UID_LAST||worker<KLS_UID_FIRST||worker>KLS_UID_LAST)return -1;
  if(setgroups(importer?1:0,importer?&worker:NULL))return -1;
  for(int cap=0;cap<64;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0)&&errno!=EINVAL)return -1;
  if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)||setresgid(uid,uid,uid)||setresuid(uid,uid,uid))return -1;
  struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct d[2]={{0},{0}};
  if(syscall(SYS_capset,&h,d)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_DUMPABLE,1,0,0,0)||prctl(PR_SET_PDEATHSIG,SIGKILL))return -1;
  uid_t r,e,s;gid_t gr,ge,gs,groups[2];int count=getgroups(2,groups);
  if(getresuid(&r,&e,&s)||getresgid(&gr,&ge,&gs)||r!=uid||e!=uid||s!=uid||gr!=uid||ge!=uid||gs!=uid||count!=(importer?1:0)||(importer&&groups[0]!=worker)||syscall(SYS_capget,&h,d)||getppid()!=1)return -1;
  return d[0].effective|d[0].permitted|d[0].inheritable|d[1].effective|d[1].permitted|d[1].inheritable?-1:0;
}
static int packet_send(int fd,const void *body,size_t bytes,int passed) {
  union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(int))];} control={0};struct iovec io={(void *)body,bytes};struct msghdr msg={0};msg.msg_iov=&io;msg.msg_iovlen=1;
  if(passed>=0){msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(sizeof(int));memcpy(CMSG_DATA(c),&passed,sizeof(passed));}
  return sendmsg(fd,&msg,MSG_NOSIGNAL|MSG_DONTWAIT)==(ssize_t)bytes?0:-1;
}
static ssize_t packet_recv(int fd,void *body,size_t cap,int *passed,struct ucred *credentials,int require_credentials) {
  union {struct cmsghdr align;char bytes[CMSG_SPACE(16*sizeof(int))+CMSG_SPACE(sizeof(struct ucred))];} control={0};struct iovec io={body,cap};struct msghdr msg={0};msg.msg_iov=&io;msg.msg_iovlen=1;msg.msg_control=control.bytes;msg.msg_controllen=sizeof(control.bytes);*passed=-1;
  ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);if(n<0)return n;
  int rights=0,creds=0,bad=0;
  for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)){
    if(c->cmsg_len<CMSG_LEN(0)){bad=1;continue;}
    if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS){size_t bytes=c->cmsg_len-CMSG_LEN(0);if(bytes%sizeof(int))bad=1;int *fds=(int *)CMSG_DATA(c);for(size_t i=0;i<bytes/sizeof(int);i++){if(rights++==0)*passed=fds[i];else close(fds[i]);}}
    else if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_CREDENTIALS&&c->cmsg_len==CMSG_LEN(sizeof(struct ucred))&&credentials){memcpy(credentials,CMSG_DATA(c),sizeof(*credentials));creds++;}
    else bad=1;
  }
  if((msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC))||bad||rights>1||creds!=(require_credentials?1:0)){if(*passed>=0)close(*passed);*passed=-1;errno=EPROTO;return -1;}return n;
}
static int json_packet(int fd,const char *json,int passed) { size_t bytes=strlen(json);if(bytes>8191)return -1;return packet_send(fd,json,bytes,passed); }
static int sealed_input(int fd,uint32_t bytes) { struct stat s;int seals=F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE,actual=fd>=0?fcntl(fd,F_GET_SEALS):-1;return fd>=0&&bytes>0&&bytes<=KLS_MAX_INPUT&&fstat(fd,&s)==0&&S_ISREG(s.st_mode)&&s.st_nlink==0&&s.st_size==(off_t)bytes&&actual>=0&&(actual&seals)==seals; }

struct work_args { int gate,keeperfd,input,report,result,cancel_read;uid_t authority,worker;uint64_t deadline;unsigned guards_count;int guards[MAX_WRITERS];char root[PATH_MAX],cgroup[PATH_MAX]; };
static int send_work_progress(const struct work_args *a,const struct work_result *work) {
  struct native_result report={.magic=INTERNAL_MAGIC,.kind=INTERNAL_WORK_RESULT,.work=*work};return packet_send(a->report,&report,sizeof(report),-1);
}
static int exact_reap(pid_t pid,int *status) { for(;;){pid_t n=waitpid(pid,status,0);if(n==pid)return 0;if(n<0&&errno==EINTR)continue;return -1;} }
static int layout(const struct work_args *a) {
  char name[PATH_MAX],source[PATH_MAX];
  if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))return -1;
  /* The import and A's staging state live only in this private mount
   * namespace. Exact namespace drain releases all temporary bytes; no root
   * recursive traversal of caller-controlled names is needed afterward. */
  if(mount("knowledge-private-copy",a->root,"tmpfs",MS_NOSUID|MS_NODEV,"mode=0755,size=134217728,nr_inodes=65536"))return -1;
  const char *fixed[]={"runtime",LOADER_DIR,"proc","dev"};
  for(size_t i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++){if(snprintf(name,sizeof(name),"%s/%s",a->root,fixed[i])>=(int)sizeof(name)||make_dir(name,0,0,0755))return -1;}
  if(snprintf(name,sizeof(name),"%s/source",a->root)>=(int)sizeof(name)||make_dir(name,a->authority,a->worker,0750)||
     snprintf(name,sizeof(name),"%s/state",a->root)>=(int)sizeof(name)||make_dir(name,a->authority,a->authority,0700)||
     snprintf(name,sizeof(name),"%s/scratch",a->root)>=(int)sizeof(name)||make_dir(name,a->worker,a->worker,0700)||
     snprintf(name,sizeof(name),"%s/tmp",a->root)>=(int)sizeof(name)||make_dir(name,a->worker,a->worker,0700))return -1;
  if(snprintf(name,sizeof(name),"%s/" LOADER_DIR "/" LOADER_NAME,a->root)>=(int)sizeof(name))return -1;
  int loader=open(name,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0555);if(loader<0)return -1;close(loader);
  if(mount_readonly(KLS_ROOT "/runtime/loader",name)||snprintf(name,sizeof(name),"%s/runtime",a->root)>=(int)sizeof(name)||mount_readonly(KLS_ROOT "/runtime",name))return -1;
  if(snprintf(name,sizeof(name),"%s/dev/null",a->root)>=(int)sizeof(name))return -1;
  int nullfd=open(name,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0666);if(nullfd<0)return -1;close(nullfd);
  if(mount("/dev/null",name,NULL,MS_BIND,NULL)||snprintf(source,sizeof(source),"%s/proc",a->root)>=(int)sizeof(source)||
     mount("proc",source,"proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||chroot(a->root)||chdir("/"))return -1;
  return 0;
}
static void node_actor(const char *entry,int importing,const struct work_args *a,int input,int result,int commands,int replies) {
  int src[4]={input,result,commands,replies},held[4];
  for(int i=0;i<4;i++){held[i]=fcntl(src[i],F_DUPFD_CLOEXEC,20);if(held[i]<0)_exit(120);}
  int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)_exit(121);
  for(int fd=0;fd<3;fd++)if(dup2(nullfd,fd)<0)_exit(122);
  for(int i=0;i<4;i++)if(dup2(held[i],i+3)<0)_exit(123);
  int keep[]={0,1,2,3,4,5,6};if(close_except(keep,7)||drop_role(a->authority,a->worker,importing))_exit(124);
  char authority[32],worker[32];snprintf(authority,sizeof(authority),"%u",(unsigned)a->authority);snprintf(worker,sizeof(worker),"%u",(unsigned)a->worker);
  char *argv[]={"/runtime/node",(char *)entry,"/source","/state",authority,worker,NULL};
  char *env[]={"PATH=/runtime","LD_LIBRARY_PATH=/runtime/lib","LANG=C","LC_ALL=C","HOME=/state","TMPDIR=/state",NULL};
  execve(argv[0],argv,env);_exit(125);
}
struct import_args { struct work_args *work;int receipt,gate; };
static int importer_init(void *pointer) {
  struct import_args *a=pointer;int keep[]={a->work->input,a->receipt,a->gate};
  if(close_except(keep,3)||getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=0)return 126;
  char permit;if(read(a->gate,&permit,1)!=1||permit!='I')return 127;close(a->gate);
  if(umount2("/proc",MNT_DETACH)||mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return 128;
  int nullfd=open("/dev/null",O_RDWR|O_CLOEXEC);if(nullfd<0)return 129;
  pid_t importer=fork();if(importer<0)return 130;
  if(!importer)node_actor("/runtime/knowledge/tools/lib/verification-linux-service-importer.js",1,a->work,a->work->input,a->receipt,nullfd,nullfd);
  close(a->work->input);close(nullfd);close(a->receipt);int status;
  if(exact_reap(importer,&status)||!WIFEXITED(status)||WEXITSTATUS(status)!=0)return 131;
  /* Exiting this namespace init kills and drains every importer descendant,
   * including detached sessions and retained writable source descriptors. */
  return 0;
}
static int import_phase(struct work_args *a,struct work_result *result) {
  int receipt[2],gate[2];if(pipe2(receipt,O_CLOEXEC)||pipe2(gate,O_CLOEXEC))return -1;
  char *stack=malloc(STACK_BYTES);if(!stack)return -1;struct import_args arg={a,receipt[1],gate[0]};
  pid_t init=clone(importer_init,stack+STACK_BYTES,CLONE_NEWPID|CLONE_NEWNS|SIGCHLD,&arg);
  if(init<0)return -1;close(receipt[1]);close(gate[0]);int held=pidfd_open_exact(init);
  if(held<0||now_ns()>=a->deadline||write_all(gate[1],"I",1)){close(gate[1]);return -1;}close(gate[1]);
  int status;if(exact_reap(init,&status))return -1;
  char line[257];size_t used=0;for(;;){ssize_t n=read(receipt[0],line+used,sizeof(line)-1-used);if(n<0&&errno==EINTR)continue;if(n<0)return -1;if(!n)break;used+=(size_t)n;if(used==sizeof(line)-1)return -1;}line[used]=0;close(receipt[0]);
  if(!pidfd_dead(held)||!WIFEXITED(status)||WEXITSTATUS(status)!=0||now_ns()>=a->deadline)return -1;
  close(held);free(stack);char manifest[65],directories[65];int count=0;
  if(sscanf(line,"KSI2 %64[0-9a-f] %64[0-9a-f] %u %u %u\n%n",manifest,directories,&result->files,&result->source_bytes,&result->directories,&count)!=5||
     count!=(int)used||unhex(manifest,result->manifest,32)||unhex(directories,result->directory_hash,32)||
     result->files+result->directories>50000U||result->source_bytes>32U*1024U*1024U)return -1;
  result->importer_drained=1;return 0;
}
static int relative_name(const char *name,int dot_ok) {
  if(dot_ok&&!strcmp(name,"."))return 1;size_t n=strlen(name);if(!n||n>=PATH_MAX||name[0]=='/'||name[n-1]=='/')return 0;
  const char *part=name;for(size_t i=0;i<=n;i++){unsigned char c=(unsigned char)name[i];if(c&&((c<32)||c==127||c=='\\'))return 0;if(c=='/'||!c){size_t len=(size_t)(name+i-part);if(!len||(len==1&&part[0]=='.')||(len==2&&part[0]=='.'&&part[1]=='.'))return 0;part=name+i+1;}}
  return 1;
}
struct command_args { struct work_args *work;int out,err,status,gate;char *argv[KLS_MAX_ARGS+4];char cwd[PATH_MAX]; };
static int command_init(void *pointer) {
  struct command_args *a=pointer;int keep[]={a->out,a->err,a->status,a->gate};
  if(close_except(keep,4)||getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=0)return 132;
  char permit;if(read(a->gate,&permit,1)!=1||permit!='W')return 133;close(a->gate);
  if(umount2("/proc",MNT_DETACH)||mount("proc","/proc","proc",MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL))return 134;
  pid_t worker=fork();if(worker<0)return 135;
  if(!worker){
    int out=fcntl(a->out,F_DUPFD_CLOEXEC,20),err=fcntl(a->err,F_DUPFD_CLOEXEC,20),nullfd=open("/dev/null",O_RDONLY|O_CLOEXEC);
    if(out<0||err<0||nullfd<0||dup2(nullfd,0)<0||dup2(out,1)<0||dup2(err,2)<0)_exit(136);
    int allowed[]={0,1,2};if(close_except(allowed,3)||chdir(a->cwd)||drop_role(a->work->worker,a->work->worker,0))_exit(137);
    char *env[]={"PATH=/runtime","LD_LIBRARY_PATH=/runtime/lib","LANG=C","LC_ALL=C","HOME=/scratch","TMPDIR=/scratch","TMP=/scratch","TEMP=/scratch",NULL};
    execve(a->argv[0],a->argv,env);_exit(138);
  }
  close(a->out);close(a->err);int status;if(exact_reap(worker,&status)||write_all(a->status,&status,sizeof(status)))return 139;
  close(a->status);return 0;
}
static int body_string(const unsigned char *body,size_t bytes,size_t *offset,size_t count,char **out) {
  if(!count||count>4096||*offset>bytes||count>bytes-*offset||memchr(body+*offset,0,count))return -1;
  char *s=malloc(count+1);if(!s)return -1;memcpy(s,body+*offset,count);s[count]=0;*offset+=count;*out=s;return 0;
}
static int execute_command(struct work_args *a,const struct kls_command *request,const unsigned char *body,int replyfd,struct work_result *result) {
  struct command_args args={.work=a};char *script=NULL,*cwd=NULL,*extra[KLS_MAX_ARGS]={0};size_t offset=0;uint32_t script_len;
  if(request->body_len<4||request->argc>KLS_MAX_ARGS||request->flags>1||request->cwd_len<1||request->cwd_len>4096)return -1;
  memcpy(&script_len,body,4);offset=4;
  if(body_string(body,request->body_len,&offset,script_len,&script)||!relative_name(script,0)||
     body_string(body,request->body_len,&offset,request->cwd_len,&cwd)||!relative_name(cwd,1))return -1;
  for(unsigned i=0;i<request->argc;i++){uint32_t count;if(offset>request->body_len||request->body_len-offset<4)return -1;memcpy(&count,body+offset,4);offset+=4;
    if(count==0){extra[i]=strdup("");if(!extra[i])return -1;}else if(body_string(body,request->body_len,&offset,count,&extra[i]))return -1;}
  if(offset!=request->body_len||(request->flags&&request->argc))return -1;
  char full[PATH_MAX];if(snprintf(full,sizeof(full),"/source/%s",script)>=(int)sizeof(full)||snprintf(args.cwd,sizeof(args.cwd),"/source/%s",cwd)>=(int)sizeof(args.cwd))return -1;
  struct stat st;if(lstat(full,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=a->authority||st.st_gid!=a->worker)return -1;
  unsigned at=0;args.argv[at++]="/runtime/node";if(request->flags)args.argv[at++]="--test";args.argv[at++]=full;for(unsigned i=0;i<request->argc;i++)args.argv[at++]=extra[i];args.argv[at]=NULL;
  int out[2],err[2],status_pipe[2],gate[2];if(pipe2(out,O_CLOEXEC)||pipe2(err,O_CLOEXEC)||pipe2(status_pipe,O_CLOEXEC)||pipe2(gate,O_CLOEXEC))return -1;
  args.out=out[1];args.err=err[1];args.status=status_pipe[1];args.gate=gate[0];char *stack=malloc(STACK_BYTES);if(!stack)return -1;
  pid_t init=clone(command_init,stack+STACK_BYTES,CLONE_NEWPID|CLONE_NEWNS|SIGCHLD,&args);
  if(init<0)return -1;close(out[1]);close(err[1]);close(status_pipe[1]);close(gate[0]);int held=pidfd_open_exact(init);
  if(held<0||now_ns()>=request->deadline_ns||now_ns()>=a->deadline||write_all(gate[1],"W",1)){close(gate[1]);return -1;}close(gate[1]);
  result->commands++;if(send_work_progress(a,result))return -1;
  if(nonblock(out[0])||nonblock(err[0])||nonblock(status_pipe[0]))return -1;
  unsigned char *buffers[2]={malloc(KLS_MAX_STREAM),malloc(KLS_MAX_STREAM)};uint32_t sizes[2]={0,0};int fds[2]={out[0],err[0]},eof[2]={0,0},worker_status=0,got_worker=0,init_status=0,reaped=0;
  if(!buffers[0]||!buffers[1])return -1;
  while(!(eof[0]&&eof[1]&&reaped&&got_worker)){
    if(now_ns()>=request->deadline_ns||now_ns()>=a->deadline){result->reason=3;pidfd_stop(held);return -1;}
    for(int i=0;i<2;i++)if(!eof[i]){unsigned char overflow;void *target=sizes[i]<KLS_MAX_STREAM?buffers[i]+sizes[i]:&overflow;size_t cap=sizes[i]<KLS_MAX_STREAM?KLS_MAX_STREAM-sizes[i]:1;ssize_t n=read(fds[i],target,cap);
      if(n>0){if((uint64_t)sizes[i]+(uint64_t)n>KLS_MAX_STREAM){result->reason=6;pidfd_stop(held);return -1;}sizes[i]+=(uint32_t)n;}else if(n==0){eof[i]=1;close(fds[i]);}else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return -1;}
    if(!got_worker){ssize_t n=read(status_pipe[0],&worker_status,sizeof(worker_status));if(n==sizeof(worker_status)){got_worker=1;close(status_pipe[0]);}else if(n==0||n>0)return -1;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)return -1;}
    if(!reaped&&pidfd_dead(held)){pid_t n=waitpid(init,&init_status,WNOHANG);if(n==init)reaped=1;else if(n<0&&errno!=EINTR)return -1;}
    if(!(eof[0]&&eof[1]&&reaped&&got_worker))poll(NULL,0,2);
  }
  if(!WIFEXITED(init_status)||WEXITSTATUS(init_status)!=0||now_ns()>=request->deadline_ns)return -1;
  result->commands_drained++;close(held);free(stack);
  struct kls_reply reply={KLS_REPLY_MAGIC,KLS_VERSION,request->ordinal,WIFEXITED(worker_status)?WEXITSTATUS(worker_status):-1,WIFSIGNALED(worker_status)?(uint32_t)WTERMSIG(worker_status):0,sizes[0],sizes[1],0};
  int ok=write_all(replyfd,&reply,sizeof(reply))==0&&write_all(replyfd,buffers[0],sizes[0])==0&&write_all(replyfd,buffers[1],sizes[1])==0;
  free(buffers[0]);free(buffers[1]);free(script);free(cwd);for(unsigned i=0;i<request->argc;i++)free(extra[i]);return ok?0:-1;
}

static int authority_phase(struct work_args *a,struct work_result *result) {
  if(mount_readonly("/source","/source"))return -1;result->source_readonly=1;
  int commands[2],replies[2],birthgate[2];if(pipe2(commands,O_CLOEXEC)||pipe2(replies,O_CLOEXEC)||pipe2(birthgate,O_CLOEXEC))return -1;
  pid_t authority=fork();if(authority<0)return -1;
  if(!authority){close(birthgate[1]);char permit;if(read(birthgate[0],&permit,1)!=1||permit!='A')_exit(184);close(birthgate[0]);node_actor("/runtime/knowledge/tools/lib/verification-linux-service-authority.js",0,a,a->input,a->result,commands[1],replies[0]);}
  close(birthgate[0]);
  result->authority_pid=authority;close(commands[1]);close(replies[0]);close(a->input);close(a->result);
  int authorityfd=pidfd_open_exact(authority);if(authorityfd<0)return -1;
  struct native_result identity={.magic=INTERNAL_MAGIC,.kind=INTERNAL_AUTHORITY,.init=authority};
  if(packet_send(a->report,&identity,sizeof(identity),authorityfd))return -1;
  for(;;){uint32_t ack;int passed=-1;ssize_t n=packet_recv(a->report,&ack,sizeof(ack),&passed,NULL,0);if(passed>=0)close(passed);
    if(n==sizeof(ack)&&passed<0&&ack==INTERNAL_PERMIT&&now_ns()<a->deadline)break;
    if(n>=0||(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)||now_ns()>=a->deadline)return -1;poll(NULL,0,1);
  }
  if(write_all(birthgate[1],"A",1))return -1;close(birthgate[1]);
  unsigned ordinal=0;int ready=0,protocol_ok=1;
  for(;;){
    struct kls_command command;ssize_t first=read(commands[0],&command,sizeof(command));
    if(first<0&&errno==EINTR)continue;if(first==0)break;
    if(first<0||(size_t)first>sizeof(command)||read_all(commands[0],(unsigned char *)&command+first,sizeof(command)-(size_t)first)){protocol_ok=0;break;}
    if(now_ns()>=a->deadline||command.magic!=KLS_COMMAND_MAGIC||command.version!=KLS_VERSION||command.body_len>KLS_MAX_COMMAND||
       command.deadline_ns> a->deadline||command.deadline_ns<=now_ns()){result->reason=3;protocol_ok=0;break;}
    unsigned char *body=malloc(command.body_len?command.body_len:1);if(!body||read_all(commands[0],body,command.body_len)){free(body);protocol_ok=0;break;}
    if(!ready){
      struct kls_ready observed;
      if(command.op!=KLS_AUTHORITY_READY||command.ordinal||command.flags||command.argc||command.cwd_len||command.body_len!=sizeof(observed))protocol_ok=0;
      else {memcpy(&observed,body,sizeof(observed));
        if(memcmp(observed.manifest_sha256,result->manifest,32)||memcmp(observed.directories_sha256,result->directory_hash,32)||observed.files!=result->files||observed.bytes!=result->source_bytes||observed.directories!=result->directories)protocol_ok=0;
        else {ready=1;result->authority_readback=1;if(send_work_progress(a,result))protocol_ok=0;}
      }
    } else if(command.op!=KLS_RUN||command.ordinal!=ordinal+1||ordinal>=KLS_MAX_COMMANDS||execute_command(a,&command,body,replies[1],result))protocol_ok=0;
    else ordinal++;
    free(body);if(!protocol_ok)break;
  }
  close(commands[0]);close(replies[1]);
  if(!protocol_ok){pidfd_stop(authorityfd);close(authorityfd);return -1;}
  int status;if(exact_reap(authority,&status))return -1;
  result->authority_status=status;result->authority_wait_known=1;
  int exited=pidfd_dead(authorityfd);close(authorityfd);
  return ready&&ordinal>0&&exited&&WIFEXITED(status)&&WEXITSTATUS(status)==0&&now_ns()<a->deadline?0:-1;
}
static int work_init(void *pointer) {
  struct work_args *a=pointer;int keep[]={a->gate,a->keeperfd,a->input,a->report,a->result};
  if(close_except(keep,5)||getpid()!=1||prctl(PR_SET_PDEATHSIG,SIGKILL)||pidfd_dead(a->keeperfd))return 140;
  char gate;if(read(a->gate,&gate,1)!=1||gate!='G')return 141;close(a->gate);close(a->keeperfd);
  struct work_result result={.phase=1,.authority_status=-1};int ok=0;
  if(now_ns()<a->deadline&&join_cgroup(a->cgroup,0)==0&&layout(a)==0){
    result.phase=2;
    if(import_phase(a,&result)==0){result.phase=3;if(authority_phase(a,&result)==0){result.phase=4;ok=1;}}
  }
  if(!result.reason&&!ok)result.reason=5;
  struct native_result final={.magic=INTERNAL_MAGIC,.kind=INTERNAL_WORK_RESULT,.work=result};
  (void)packet_send(a->report,&final,sizeof(final),-1);close(a->report);
  return ok?0:142;
}
static int process_identity(pid_t pid,pid_t *parent,uint64_t *birth,uid_t *uid);
static int host_pid_from_pidfd(int held) {
  char file[96],body[1024];snprintf(file,sizeof(file),"/proc/self/fdinfo/%d",held);int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
  ssize_t size=read(fd,body,sizeof(body)-1);close(fd);if(size<=0||size>=(ssize_t)sizeof(body)-1)return -1;body[size]=0;char *line=strstr(body,"\nPid:\t");int pid=0;
  return !line||sscanf(line,"\nPid:\t%d",&pid)!=1||pid<2?-1:pid;
}
static int collect_work_reports(int report,int channel,struct native_result *result) {
  for(unsigned i=0;i<4;i++){
    struct native_result item;int passed=-1;ssize_t size=packet_recv(report,&item,sizeof(item),&passed,NULL,0);
    if(size<0&&errno==ECONNRESET)continue;
    if(size<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return 0;if(!size)return 0;
    if(size!=sizeof(item)||item.magic!=INTERNAL_MAGIC){if(passed>=0)close(passed);return -1;}
    if(item.kind==INTERNAL_AUTHORITY&&passed>=0&&!result->work.authority_host_pid){
      pid_t parent;uid_t uid;uint64_t birth;int host=host_pid_from_pidfd(passed);
      if(host<2||process_identity(host,&parent,&birth,&uid)||parent!=result->init||uid!=0||pidfd_dead(passed)){close(passed);return -1;}
      result->work.authority_host_pid=host;result->work.authority_birth=birth;
      result->work.authority_pid=item.init;
      item.work.authority_host_pid=host;item.work.authority_birth=birth;
      if(packet_send(channel,&item,sizeof(item),passed)){close(passed);return -1;}close(passed);
      uint32_t ack=INTERNAL_PERMIT;if(packet_send(report,&ack,sizeof(ack),-1))return -1;
    } else if(item.kind==INTERNAL_WORK_RESULT&&passed<0){
      int host=result->work.authority_host_pid;uint64_t birth=result->work.authority_birth;result->work=item.work;result->work.authority_host_pid=host;result->work.authority_birth=birth;
    } else {if(passed>=0)close(passed);return -1;}
  }
  return 0;
}
static void keeper_main(int channel,int ownerfd,int controllerfd,int brokerfd,int input,int output,
                        const struct work_args *configuration,uint64_t cleanup_ms) {
  int keep[7+MAX_WRITERS]={channel,ownerfd,controllerfd,brokerfd,input,output,configuration->cancel_read};for(unsigned i=0;i<configuration->guards_count;i++)keep[7+i]=configuration->guards[i];if(close_except(keep,7+configuration->guards_count))_exit(143);
  int report[2],gate[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,report)||pipe2(gate,O_CLOEXEC))_exit(144);
  int self=pidfd_open_exact(getpid());if(self<0)_exit(145);
  char *stack=malloc(STACK_BYTES);if(!stack)_exit(146);
  struct work_args args=*configuration;args.gate=gate[0];args.keeperfd=self;args.input=input;args.report=report[1];args.result=output;
  pid_t init=clone(work_init,stack+STACK_BYTES,CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|SIGCHLD,&args);
  if(init<0)_exit(147);close(gate[0]);close(report[1]);close(self);close(input);close(output);
  int held=pidfd_open_exact(init);if(held<0){close(gate[1]);_exit(148);}
  struct native_result result={.magic=INTERNAL_MAGIC,.kind=INTERNAL_BIRTH,.init=init,.init_status=-1};
  if(packet_send(channel,&result,sizeof(result),held)){close(gate[1]);_exit(149);}
  int permitted=0;uint64_t setup_end=now_ns()+UINT64_C(5000000000);if(setup_end>args.deadline)setup_end=args.deadline;
  while(now_ns()<setup_end&&!pidfd_dead(ownerfd)&&!pidfd_dead(controllerfd)&&!pidfd_dead(brokerfd)&&!pidfd_dead(args.cancel_read)&&!cancelled){
    struct pollfd p={channel,POLLIN,0};int polled=poll(&p,1,10);if(polled<0&&errno==EINTR)continue;if(polled<0||p.revents&(POLLHUP|POLLERR))break;
    if(p.revents&POLLIN){uint32_t message;int passed=-1;ssize_t n=packet_recv(channel,&message,sizeof(message),&passed,NULL,0);if(passed>=0)close(passed);if(n==sizeof(message)&&passed<0&&message==INTERNAL_PERMIT)permitted=1;break;}
  }
  if(cancelled||pidfd_dead(args.cancel_read))result.reason=1;
  else if(pidfd_dead(ownerfd)||pidfd_dead(controllerfd)||pidfd_dead(brokerfd))result.reason=2;
  else if(now_ns()>=args.deadline)result.reason=3;
  else if(!permitted||now_ns()>=setup_end||write_all(gate[1],"G",1))result.reason=5;
  close(gate[1]);
  while(!result.reason){
    if(collect_work_reports(report[0],channel,&result)){result.reason=5;break;}
    struct pollfd p={channel,POLLIN,0};int rc=poll(&p,1,10);if(rc<0&&errno==EINTR)continue;
    if(rc<0)result.reason=5;
    else if(cancelled||pidfd_dead(args.cancel_read))result.reason=1;
    else if(pidfd_dead(ownerfd)||pidfd_dead(controllerfd)||pidfd_dead(brokerfd)||p.revents&(POLLHUP|POLLERR))result.reason=2;
    else if(now_ns()>=args.deadline)result.reason=3;
    else if(pidfd_dead(held))result.reason=4;
    else if(p.revents&POLLIN){uint32_t message;int passed=-1;ssize_t n=packet_recv(channel,&message,sizeof(message),&passed,NULL,0);if(passed>=0)close(passed);result.reason=n==sizeof(message)&&passed<0&&message==INTERNAL_STOP?1:5;}
  }
  /* An exited init may have queued its final progress after the last running
   * poll. Resolve that native report before choosing whether S may finalize. */
  if(collect_work_reports(report[0],channel,&result))result.reason=5;
  if(result.work.reason&&result.reason==4)result.reason=result.work.reason;
  result.cleanup_start=now_ns();result.cleanup_end=result.cleanup_start+cleanup_ms*UINT64_C(1000000);
  uint64_t hard_end=args.deadline+cleanup_ms*UINT64_C(1000000);if(result.cleanup_end>hard_end)result.cleanup_end=hard_end;
  result.kind=INTERNAL_CLEANUP;(void)packet_send(channel,&result,sizeof(result),-1);
  /* The independent native keeper latches storage guardians too. A broker
   * blocked in fsync cannot silently give S a new or longer cleanup window. */
  for(unsigned i=0;i<args.guards_count;i++){
    (void)send(args.guards[i],&result.cleanup_end,sizeof(result.cleanup_end),MSG_NOSIGNAL|MSG_DONTWAIT);
    /* Zero is an irreversible stop instruction, not a replacement endpoint.
     * Timeout/failure starts S drain now; a completed A leaves S time to
     * publish its verified finalization within the same cleanup endpoint. */
    if(result.reason!=4){uint64_t stop=0;(void)send(args.guards[i],&stop,sizeof(stop),MSG_NOSIGNAL|MSG_DONTWAIT);}
    close(args.guards[i]);
  }
  if(!pidfd_dead(held)){if(pidfd_stop(held))result.reason=5;else result.stop_dispatched=1;}
  while(now_ns()<result.cleanup_end){
    pid_t got=waitpid(init,&result.init_status,WNOHANG);if(got==init){result.init_reaped=1;break;}if(got<0&&errno!=EINTR)break;poll(NULL,0,2);
  }
  if(collect_work_reports(report[0],channel,&result)&&result.reason==4)result.reason=5;close(report[0]);
  result.observed=now_ns();result.kind=INTERNAL_FINAL;
  if(result.work.reason&&result.reason==4)result.reason=result.work.reason;
  if(result.init_reaped&&pidfd_dead(held)&&result.observed<result.cleanup_end){
    (void)packet_send(channel,&result,sizeof(result),-1);close(held);free(stack);_exit(0);
  }
  (void)packet_send(channel,&result,sizeof(result),-1);_exit(150);
}

static int process_identity(pid_t pid,pid_t *parent,uint64_t *birth,uid_t *uid) {
  char file[96],body[8192];snprintf(file,sizeof(file),"/proc/%d/stat",pid);int fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
  ssize_t size=read(fd,body,sizeof(body)-1);close(fd);if(size<=0||size>=(ssize_t)sizeof(body)-1)return -1;body[size]=0;
  char *tail=strrchr(body,')');if(!tail||tail[1]!=' ')return -1;char *p=tail+2;unsigned field=3;uint64_t start=0;pid_t ppid=0;
  while(field<=22){char *end=strchr(p,' ');if(!end&&field<22)return -1;if(end)*end=0;
    if(field==4){char *after;long value=strtol(p,&after,10);if(*after||value<1||value>INT_MAX)return -1;ppid=(pid_t)value;}
    if(field==22){char *after;errno=0;unsigned long long value=strtoull(p,&after,10);if(errno||*after||!value)return -1;start=(uint64_t)value;}
    if(!end)break;p=end+1;field++;
  }
  snprintf(file,sizeof(file),"/proc/%d/status",pid);fd=open(file,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;size=read(fd,body,sizeof(body)-1);close(fd);if(size<=0||size>=(ssize_t)sizeof(body)-1)return -1;body[size]=0;
  char *line=strstr(body,"\nUid:");unsigned r,e,s,fs;if(!line||sscanf(line,"\nUid:\t%u\t%u\t%u\t%u",&r,&e,&s,&fs)!=4||r!=e||r!=s||r!=fs)return -1;
  *parent=ppid;*birth=start;*uid=(uid_t)r;return 0;
}
static int discover_cgroup(void) {
  char body[4096];int fd=open("/proc/self/cgroup",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;ssize_t size=read(fd,body,sizeof(body)-1);close(fd);
  if(size<=4||size>=(ssize_t)sizeof(body)-1)return -1;body[size]=0;if(strncmp(body,"0::/",4)||body[size-1]!='\n'||memchr(body,'\n',(size_t)size-1))return -1;body[size-1]=0;
  if(snprintf(service_cgroup,sizeof(service_cgroup),"/sys/fs/cgroup%s",body+3)>=(int)sizeof(service_cgroup))return -1;
  fd=open(service_cgroup,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat s;struct statfs type;
  int ok=fd>=0&&fstat(fd,&s)==0&&s.st_uid==0&&(s.st_mode&0022)==0&&fstatfs(fd,&type)==0&&(unsigned long)type.f_type==0x63677270UL;if(fd>=0)close(fd);return ok?0:-1;
}
static int read_boot(void) {
  char body[40],compact[33]={0};int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;ssize_t bytes=read(fd,body,sizeof(body));close(fd);if(bytes!=37||body[36]!='\n')return -1;
  unsigned at=0;for(unsigned i=0;i<36;i++)if(i==8||i==13||i==18||i==23){if(body[i]!='-')return -1;}else compact[at++]=body[i];
  if(unhex(compact,boot_id,16))return -1;memcpy(boot_hex,compact,sizeof(boot_hex));return 0;
}
static int write_registration(struct writer *writer,struct client *client,uint64_t birth,uint64_t parent_birth) {
  struct stat group;int cg=open(writer->cgroup,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(cg<0||fstat(cg,&group)){if(cg>=0)close(cg);return -1;}close(cg);
  struct {uint32_t version,pid,parent,uid;uint64_t birth,parent_birth,deadline,group_dev,group_ino;unsigned char boot[16],nonce[32];} record;
  memset(&record,0,sizeof(record));record.version=1;record.pid=(uint32_t)writer->pid;record.parent=(uint32_t)client->parent;record.uid=(uint32_t)client->uid;record.birth=birth;record.parent_birth=parent_birth;record.deadline=writer->deadline;record.group_dev=(uint64_t)group.st_dev;record.group_ino=(uint64_t)group.st_ino;memcpy(record.boot,boot_id,16);memcpy(record.nonce,client->first.nonce,32);
  int fd=openat(rootfd,writer->record,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(fd<0)return -1;int ok=write_all(fd,&record,sizeof(record))==0&&fsync(fd)==0;close(fd);return ok&&fsync(rootfd)==0?0:-1;
}
static void writer_guardian(int writerfd,int parentfd,int clientfd,int brokerfd,int readyfd,int control,int cancel_read,const char *group,uint64_t end) {
  int keep[]={writerfd,parentfd,clientfd,brokerfd,readyfd,control,cancel_read};if(close_except(keep,cancel_read>=0?7:6)||join_cgroup(group,0)||now_ns()>=end||pidfd_dead(parentfd)||pidfd_dead(clientfd)||pidfd_dead(brokerfd))_exit(151);
  if(write_all(readyfd,"G",1))_exit(152);close(readyfd);
  while(!pidfd_dead(writerfd)){
    uint64_t update;ssize_t received=recv(control,&update,sizeof(update),MSG_DONTWAIT|MSG_TRUNC);
    if(received==sizeof(update)){if(!update||update>end){(void)pidfd_stop(writerfd);break;}end=update;}
    else if(received==0||(received<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)||received>0){(void)pidfd_stop(writerfd);break;}
    if(now_ns()>=end||pidfd_dead(parentfd)||pidfd_dead(clientfd)||pidfd_dead(brokerfd)||(cancel_read>=0&&pidfd_dead(cancel_read))||cancelled){(void)pidfd_stop(writerfd);break;}
    struct pollfd fds[]={{writerfd,POLLIN,0},{parentfd,POLLIN,0},{clientfd,POLLIN,0},{brokerfd,POLLIN,0},{control,POLLIN,0}};poll(fds,5,10);
  }
  /* The writer may have descendants. Move this root-only guardian out of its
   * private group, kill the entire retained group, then observe both exact S
   * and the live group. A kernel-stalled actor keeps custody and its fence. */
  if(join_cgroup(service_cgroup,0)||kill_cgroup(group))_exit(185);
  while(!pidfd_dead(writerfd)||!cgroup_empty(group))poll(NULL,0,20);
  _exit(0);
}
static int register_writer(struct client *c,const struct kls_request *request) {
  if(quarantine||request->pid<2||request->pid>INT_MAX||c->writers_count>=MAX_WRITERS||pidfd_dead(c->parentfd)||pidfd_dead(c->peerfd)||
     (c->opened&&(!c->terminal||attempt.client_slot!=(int)(c-clients))))return -1;
  for(unsigned ci=0;ci<MAX_CLIENTS;ci++)for(unsigned wi=0;wi<clients[ci].writers_count;wi++)if(!clients[ci].writers[wi].closed&&clients[ci].writers[wi].pid==(int)request->pid)return -1;
  int held=pidfd_open_exact((pid_t)request->pid);if(held<0)return -1;
  pid_t parent,grandparent;uint64_t birth,parent_birth;uid_t uid,parent_uid;
  if(process_identity((pid_t)request->pid,&parent,&birth,&uid)||process_identity(c->parent,&grandparent,&parent_birth,&parent_uid)||
     parent!=c->parent||parent_birth!=c->parent_birth||uid!=(uid_t)c->uid||parent_uid!=(uid_t)c->uid||pidfd_dead(held)||pidfd_dead(c->parentfd)){close(held);return -1;}
  unsigned index=c->writers_count++;struct writer *w=&c->writers[index];memset(w,0,sizeof(*w));w->pid=(int)request->pid;w->pidfd=held;w->guardianfd=w->guard_channel=-1;w->birth=birth;w->ordinal=request->ordinal;w->deadline=c->terminal?attempt.result.cleanup_end:c->first.work_deadline_ns+c->first.cleanup_ms*UINT64_C(1000000);
  char nonce[65];hex(c->first.nonce,32,nonce);
  if(snprintf(w->cgroup,sizeof(w->cgroup),"%s/writer-%s-%u",service_cgroup,nonce,index)>=(int)sizeof(w->cgroup)||
     snprintf(w->record,sizeof(w->record),"writer-%d-%u.bin",c->pid,index)>=(int)sizeof(w->record)||mkdir(w->cgroup,0700)||join_cgroup(w->cgroup,w->pid))return -1;
  int ready_pipe[2],guard[2];if(pipe2(ready_pipe,O_CLOEXEC|O_NONBLOCK)||socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,guard))return -1;
  pid_t guardian=fork();if(guardian<0)return -1;
  if(!guardian){close(ready_pipe[0]);close(guard[0]);writer_guardian(held,c->parentfd,c->peerfd,daemonfd,ready_pipe[1],guard[1],c->terminal?-1:c->cancel_read,w->cgroup,w->deadline);}
  close(ready_pipe[1]);close(guard[1]);w->guard_channel=guard[0];w->guardian=guardian;w->guardianfd=pidfd_open_exact(guardian);if(w->guardianfd<0)return -1;
  uint64_t end=now_ns()+UINT64_C(5000000000),phase_end=c->terminal?attempt.result.cleanup_end:c->first.work_deadline_ns;if(end>phase_end)end=phase_end;
  int ready=0;while(now_ns()<end&&!pidfd_dead(c->parentfd)&&!pidfd_dead(held)&&!pidfd_dead(w->guardianfd)){
    char byte;ssize_t n=read(ready_pipe[0],&byte,1);if(n==1){ready=byte=='G';break;}if(n==0)break;if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;poll(NULL,0,2);
  }
  close(ready_pipe[0]);if(!ready||write_registration(w,c,birth,parent_birth)||now_ns()>=end||pidfd_dead(c->parentfd)||pidfd_dead(held)){(void)pidfd_stop(held);return -1;}
  char reply[1024];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"writer_registered\",\"status\":\"registered\",\"ordinal\":%u,\"pid\":%u,\"birth_ticks\":\"%llu\",\"controller_pid\":%d,\"controller_birth_ticks\":\"%llu\",\"deadline_ns\":\"%llu\",\"registered_before_storage_permit\":true}",request->ordinal,request->pid,(unsigned long long)birth,c->parent,(unsigned long long)parent_birth,(unsigned long long)w->deadline);
  return json_packet(c->fd,reply,-1);
}
static void observe_writers(struct client *c) {
  for(unsigned i=0;i<c->writers_count;i++){
    struct writer *w=&c->writers[i];if(w->closed||w->pidfd<0)continue;
    /* Expired live custody fences new admission immediately. Physical exit
     * arriving later cannot defer this fence or retroactively meet the bound. */
    if(now_ns()>=w->deadline)quarantine=1;
    if(pidfd_dead(c->parentfd)||pidfd_dead(c->peerfd))pidfd_stop(w->pidfd);
    if(c->opened){if(!c->terminal)continue;if(attempt.result.cleanup_end<w->deadline)w->deadline=attempt.result.cleanup_end;}
    if(pidfd_dead(w->pidfd)&&w->guardianfd>=0&&pidfd_dead(w->guardianfd)){
      int status;pid_t got=waitpid(w->guardian,&status,WNOHANG);
      if(got==w->guardian&&WIFEXITED(status)&&WEXITSTATUS(status)==0&&cgroup_empty(w->cgroup)){
        /* Exact native finality precedes durable registration removal. */
        if(now_ns()<w->deadline&&unlinkat(rootfd,w->record,0)==0&&fsync(rootfd)==0&&now_ns()<w->deadline){w->closed=1;close(w->pidfd);close(w->guardianfd);close(w->guard_channel);w->pidfd=w->guardianfd=w->guard_channel=-1;
          char reply[768];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"writer_closed\",\"status\":\"closed\",\"pid\":%d,\"birth_ticks\":\"%llu\",\"registration_ordinal\":%u,\"pidfd_exit_observed\":true,\"guardian_reaped\":true,\"writer_cgroup_empty\":true,\"registration_removed\":true,\"closed_in_budget\":true,\"deadline_ns\":\"%llu\",\"observed_ns\":\"%llu\"}",w->pid,(unsigned long long)w->birth,w->ordinal,(unsigned long long)w->deadline,(unsigned long long)now_ns());if(c->fd>=0)(void)json_packet(c->fd,reply,-1);}
        else quarantine=1;
      }
    }
  }
}
static int start_attempt(int slot,int input) {
  struct client *c=&clients[slot];
  if(quarantine||attempt.active||c->opened||now_ns()>=c->first.work_deadline_ns||pidfd_dead(c->peerfd)||pidfd_dead(c->parentfd)||pidfd_dead(c->cancel_read))return -1;
  memset(&attempt,0,sizeof(attempt));attempt.keeperfd=attempt.initfd=attempt.authorityfd=attempt.channel=attempt.resultfd=attempt.resultpipe=-1;
  if(kv_linux_uid_reserve(history,c->first.nonce,boot_id,&attempt.reservation)){
    /* A replayed caller nonce is denied without corrupting a valid service
     * epoch. Durability/pending-history failures still fence all admission. */
    const char *reason=kv_linux_uid_reason(history);if(!reason||strcmp(reason,"attempt_nonce_already_burned"))quarantine=1;return -1;
  }
  attempt.active=1;attempt.client_slot=slot;attempt.started=now_ns();attempt.work_deadline=c->first.work_deadline_ns;attempt.cleanup_ms=c->first.cleanup_ms;c->opened=1;
  if(snprintf(attempt.root,sizeof(attempt.root),KLS_ROOT "/attempt-%llu",(unsigned long long)attempt.reservation.allocation_sequence)>=(int)sizeof(attempt.root)||
     snprintf(attempt.cgroup,sizeof(attempt.cgroup),"%s/attempt-%llu",service_cgroup,(unsigned long long)attempt.reservation.allocation_sequence)>=(int)sizeof(attempt.cgroup)||
     make_dir(attempt.root,0,0,0755)||mkdir(attempt.cgroup,0700))goto failed;
  int channel[2],output[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channel)||pipe2(output,O_CLOEXEC)||nonblock(output[0]))goto failed;
  struct work_args args={.authority=attempt.reservation.authority_uid,.worker=attempt.reservation.worker_uid,.deadline=attempt.work_deadline,.cancel_read=c->cancel_read};
  for(unsigned i=0;i<c->writers_count;i++)if(!c->writers[i].closed&&c->writers[i].guard_channel>=0)args.guards[args.guards_count++]=c->writers[i].guard_channel;
  memcpy(args.root,attempt.root,sizeof(args.root));memcpy(args.cgroup,attempt.cgroup,sizeof(args.cgroup));
  if(now_ns()>=attempt.work_deadline||pidfd_dead(c->peerfd)||pidfd_dead(c->parentfd))goto failed;
  pid_t keeper=fork();if(keeper<0)goto failed;
  if(!keeper){close(channel[0]);close(output[0]);keeper_main(channel[1],c->peerfd,c->parentfd,daemonfd,input,output[1],&args,attempt.cleanup_ms);_exit(153);}
  close(channel[1]);close(output[1]);attempt.keeper=keeper;attempt.keeperfd=pidfd_open_exact(keeper);attempt.channel=channel[0];
  attempt.resultfd=(int)syscall(SYS_memfd_create,"knowledge-native-result",MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_NOEXEC_SEAL);
  attempt.result.init=-1;attempt.resultpipe=output[0];
  if(attempt.keeperfd<0||attempt.resultfd<0)goto failed;
  return 0;
failed:
  attempt.quarantined=quarantine=1;return -1;
}

static const char *truth(int value) { return value?"true":"false"; }
static int terminal_body(struct attempt *a,const char *status,int physical,int journal,char *body,size_t cap) {
  char nonce[65],manifest[65],directories[65],result_hash[65];hex(a->reservation.attempt_nonce,32,nonce);hex(a->result.work.manifest,32,manifest);hex(a->result.work.directory_hash,32,directories);
  if(digest_fd(a->resultfd,KLS_MAX_RESULT,result_hash))return -1;
  struct native_result *r=&a->result;struct work_result *w=&r->work;
  int authority_exit=physical&&w->authority_host_pid>0;int authority_status=w->authority_wait_known&&WIFEXITED(w->authority_status)?WEXITSTATUS(w->authority_status):-1;
  int n=snprintf(body,cap,"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"terminal\",\"status\":\"%s\",\"installation_id\":\"%s\",\"host_id\":\"%s\",\"boot_id\":\"%s\",\"daemon_epoch\":\"%s\",\"native_source_sha256\":\"%s\",\"trusted_runtime_manifest_sha256\":\"%s\",\"trusted_source_manifest_sha256\":\"%s\",\"node_sha256\":\"%s\",\"broker_binary_sha256\":\"%s\",\"nonce\":\"%s\",\"allocation_sequence\":%llu,\"authority_uid\":%u,\"worker_uid\":%u,\"keeper_pid\":%d,\"init_pid\":%d,\"authority_namespace_pid\":%d,\"authority_pid\":%d,\"authority_birth_ticks\":\"%llu\",\"authority_pidfd_exit_observed\":%s,\"work_deadline_ns\":\"%llu\",\"cleanup_budget_ms\":%llu,\"cleanup_started_ns\":\"%llu\",\"cleanup_deadline_ns\":\"%llu\",\"observed_ns\":\"%llu\",\"importer_drained\":%s,\"source_readonly\":%s,\"authority_readback\":%s,\"manifest_sha256\":\"%s\",\"directories_sha256\":\"%s\",\"files\":%u,\"directories\":%u,\"source_bytes\":%u,\"commands\":%u,\"commands_drained\":%u,\"authority_exited\":%s,\"authority_status\":%d,\"init_exit_observed\":%s,\"init_reaped\":%s,\"keeper_exited\":%s,\"output_eof\":%s,\"cgroup_empty\":%s,\"cgroup_scope\":\"private_authority_and_workers\",\"journal_closed\":%s,\"cleanup_confirmed\":%s,\"result_bytes\":%llu,\"result_sha256\":\"%s\"}",
      status,KLS_INSTALLATION_ID,KLS_HOST_ID,boot_hex,epoch_hex,KLS_NATIVE_SOURCE_SHA,KLS_RUNTIME_MANIFEST_SHA,KLS_TRUSTED_SOURCE_MANIFEST_SHA,KLS_NODE_SHA,binary_hex,nonce,(unsigned long long)a->reservation.allocation_sequence,a->reservation.authority_uid,a->reservation.worker_uid,a->keeper,r->init,w->authority_pid,w->authority_host_pid,(unsigned long long)w->authority_birth,truth(a->authorityfd>=0&&pidfd_dead(a->authorityfd)),
      (unsigned long long)a->work_deadline,(unsigned long long)a->cleanup_ms,(unsigned long long)r->cleanup_start,(unsigned long long)r->cleanup_end,(unsigned long long)now_ns(),
      truth(w->importer_drained),truth(w->source_readonly),truth(w->authority_readback),manifest,directories,w->files,w->directories,w->source_bytes,w->commands,w->commands_drained,
      truth(authority_exit),authority_status,truth(physical),truth(r->init_reaped),truth(a->keeper_reaped),truth(a->result_eof),truth(physical&&cgroup_empty(a->cgroup)),truth(journal),truth(physical),
      (unsigned long long)a->result_bytes,result_hash);
  return n<0||(size_t)n>=cap?-1:n;
}
static void publish_cleanup_start(const struct attempt *a,struct client *c) {
  char nonce[65],reply[1024];hex(a->reservation.attempt_nonce,32,nonce);
  snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"cleanup_started\",\"nonce\":\"%s\",\"work_deadline_ns\":\"%llu\",\"cleanup_started_ns\":\"%llu\",\"cleanup_deadline_ns\":\"%llu\",\"cleanup_budget_ms\":%llu}",nonce,(unsigned long long)a->work_deadline,(unsigned long long)a->result.cleanup_start,(unsigned long long)a->result.cleanup_end,(unsigned long long)a->cleanup_ms);
  if(c->fd>=0)(void)json_packet(c->fd,reply,-1);
}
static void latch_keeper_loss(struct attempt *a,struct client *c) {
  if(a->result.reason==5)return;
  if(!a->result.cleanup_start){
    a->result.cleanup_start=now_ns();a->result.cleanup_end=a->result.cleanup_start+a->cleanup_ms*UINT64_C(1000000);
    uint64_t hard=a->work_deadline+a->cleanup_ms*UINT64_C(1000000);if(a->result.cleanup_end>hard)a->result.cleanup_end=hard;
    publish_cleanup_start(a,c);
  }
  /* A prior CLEANUP may have deliberately left S alive for finalization. The
   * keeper's subsequent loss revokes that permission even though its original
   * cleanup epoch is already latched. Never recompute or extend that epoch. */
  a->result.reason=5;
  for(unsigned i=0;i<c->writers_count;i++)if(!c->writers[i].closed&&c->writers[i].guard_channel>=0){
    if(a->result.cleanup_end<c->writers[i].deadline)c->writers[i].deadline=a->result.cleanup_end;
    (void)send(c->writers[i].guard_channel,&a->result.cleanup_end,sizeof(a->result.cleanup_end),MSG_NOSIGNAL|MSG_DONTWAIT);
    uint64_t stop=0;(void)send(c->writers[i].guard_channel,&stop,sizeof(stop),MSG_NOSIGNAL|MSG_DONTWAIT);
  }
}
static void observe_attempt(void) {
  struct attempt *a=&attempt;if(!a->active||a->closed||a->keeperfd<0)return;
  struct client *c=&clients[a->client_slot];
  if(!a->result_eof&&a->resultpipe>=0){
    for(unsigned batch=0;batch<8;batch++){unsigned char bytes[65536];ssize_t n=read(a->resultpipe,bytes,sizeof(bytes));
      if(n>0){a->result_bytes+=(uint64_t)n;if(a->result_bytes>KLS_MAX_RESULT||write_all(a->resultfd,bytes,(size_t)n)){a->quarantined=quarantine=1;uint32_t stop=INTERNAL_STOP;(void)packet_send(a->channel,&stop,sizeof(stop),-1);break;}}
      else if(!n){a->result_eof=1;close(a->resultpipe);a->resultpipe=-1;break;}
      else if(errno==EINTR)continue;else if(errno==EAGAIN||errno==EWOULDBLOCK)break;else{a->quarantined=quarantine=1;break;}
    }
  }
  for(unsigned i=0;i<4;i++){
    struct native_result value;int passed=-1;ssize_t n=packet_recv(a->channel,&value,sizeof(value),&passed,NULL,0);
    /* A keeper may publish FINAL and exit while a late STOP remains unread.
     * Linux exposes a one-shot ECONNRESET BEFORE the still-queued FINAL.
     * Consume the error and drain in this same bounded loop before considering
     * keeper-loss fallback; transport state alone never proves finality. */
    if(n<0&&errno==ECONNRESET)continue;
    if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))break;if(!n)break;
    if(n!=sizeof(value)||value.magic!=INTERNAL_MAGIC){if(passed>=0)close(passed);a->quarantined=quarantine=1;break;}
    if(value.kind==INTERNAL_BIRTH&&a->initfd<0&&passed>=0&&value.init>1){
      a->initfd=passed;a->result.init=value.init;
      if(now_ns()>=a->work_deadline||pidfd_dead(c->peerfd)||pidfd_dead(c->parentfd)||pidfd_dead(c->cancel_read)||a->quarantined){uint32_t stop=INTERNAL_STOP;(void)packet_send(a->channel,&stop,sizeof(stop),-1);}
      char nonce[65],reply[1024];hex(a->reservation.attempt_nonce,32,nonce);
      snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"opened\",\"status\":\"starting\",\"nonce\":\"%s\",\"allocation_sequence\":%llu,\"authority_uid\":%u,\"worker_uid\":%u,\"keeper_pid\":%d,\"init_pid\":%d,\"work_deadline_ns\":\"%llu\",\"cleanup_budget_ms\":%llu}",nonce,(unsigned long long)a->reservation.allocation_sequence,a->reservation.authority_uid,a->reservation.worker_uid,a->keeper,value.init,(unsigned long long)a->work_deadline,(unsigned long long)a->cleanup_ms);
      if(c->fd<0||json_packet(c->fd,reply,-1)){uint32_t stop=INTERNAL_STOP;(void)packet_send(a->channel,&stop,sizeof(stop),-1);}
    } else if(value.kind==INTERNAL_AUTHORITY&&passed>=0&&a->authorityfd<0&&value.work.authority_host_pid>1&&value.work.authority_birth){
      a->authorityfd=passed;a->result.work.authority_host_pid=value.work.authority_host_pid;a->result.work.authority_birth=value.work.authority_birth;
      a->result.work.authority_pid=value.init;
      char reply[1024];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"authority_bound\",\"status\":\"admitted\",\"authority_pid\":%d,\"authority_namespace_pid\":%d,\"authority_birth_ticks\":\"%llu\",\"authority_uid\":%u,\"worker_uid\":%u,\"pidfd_retained\":true}",value.work.authority_host_pid,value.init,(unsigned long long)value.work.authority_birth,a->reservation.authority_uid,a->reservation.worker_uid);
      if(c->fd>=0)(void)json_packet(c->fd,reply,-1);
    } else if(value.kind==INTERNAL_CLEANUP&&passed<0&&!a->final_received&&!a->result.cleanup_start&&value.init==a->result.init&&value.cleanup_start&&value.cleanup_end>value.cleanup_start&&
      value.cleanup_end-value.cleanup_start<=a->cleanup_ms*UINT64_C(1000000)&&value.cleanup_end<=a->work_deadline+a->cleanup_ms*UINT64_C(1000000)){
      a->result.cleanup_start=value.cleanup_start;a->result.cleanup_end=value.cleanup_end;
      for(unsigned wi=0;wi<c->writers_count;wi++)if(!c->writers[wi].closed&&value.cleanup_end<c->writers[wi].deadline)c->writers[wi].deadline=value.cleanup_end;
      publish_cleanup_start(a,c);
    } else if(value.kind==INTERNAL_FINAL&&passed<0&&!a->final_received&&value.init==a->result.init&&value.cleanup_start&&value.cleanup_end>value.cleanup_start&&
      value.cleanup_end-value.cleanup_start<=a->cleanup_ms*UINT64_C(1000000)&&value.cleanup_end<=a->work_deadline+a->cleanup_ms*UINT64_C(1000000)){
      if(a->result.cleanup_start&&(a->result.cleanup_start!=value.cleanup_start||a->result.cleanup_end!=value.cleanup_end)){a->quarantined=quarantine=1;continue;}
      if(a->authorityfd>=0&&(value.work.authority_host_pid!=a->result.work.authority_host_pid||value.work.authority_birth!=a->result.work.authority_birth)){a->quarantined=quarantine=1;continue;}
      a->result=value;a->final_received=1;
    } else {if(passed>=0)close(passed);a->quarantined=quarantine=1;}
  }
  if(!a->keeper_reaped&&pidfd_dead(a->keeperfd)){pid_t n=waitpid(a->keeper,&a->keeper_status,WNOHANG);if(n==a->keeper)a->keeper_reaped=1;else if(n<0&&errno!=EINTR)a->quarantined=quarantine=1;}
  /* A surviving root broker retains the exact init pidfd if its keeper dies.
   * Subreaper custody permits an exact wait after that parent death. */
  if(a->keeper_reaped&&!a->final_received&&a->initfd>=0){
    latch_keeper_loss(a,c);
    (void)pidfd_stop(a->initfd);int status;pid_t n=waitpid(a->result.init,&status,WNOHANG);if(n==a->result.init){a->result.init_reaped=1;a->result.init_status=status;a->result.observed=now_ns();a->final_received=1;}
  }
  uint64_t hard=a->result.cleanup_end?a->result.cleanup_end:a->work_deadline+a->cleanup_ms*UINT64_C(1000000);
  if(now_ns()>=hard){a->quarantined=quarantine=1;if(a->initfd>=0)(void)pidfd_stop(a->initfd);}
  if(!a->keeper_reaped||!a->final_received||!a->result_eof||a->initfd<0||!pidfd_dead(a->initfd)||!a->result.init_reaped||!cgroup_empty(a->cgroup))return;
  int physical=!a->quarantined&&now_ns()<a->result.cleanup_end;
  int successful=physical&&a->authorityfd>=0&&pidfd_dead(a->authorityfd)&&a->result.reason==4&&WIFEXITED(a->keeper_status)&&WEXITSTATUS(a->keeper_status)==0&&WIFEXITED(a->result.init_status)&&WEXITSTATUS(a->result.init_status)==0&&
    a->result.work.importer_drained&&a->result.work.source_readonly&&a->result.work.authority_readback&&a->result.work.authority_wait_known&&
    WIFEXITED(a->result.work.authority_status)&&WEXITSTATUS(a->result.work.authority_status)==0&&a->result.work.commands>0&&
    a->result.work.commands==a->result.work.commands_drained&&a->result_bytes>0;
  const char *status=successful?"completed":a->result.reason==1?"cancelled":a->result.reason==3?"timed_out":"failed";
  char body[8000];int bytes=terminal_body(a,physical?status:"cleanup_unconfirmed",physical,physical,body,sizeof(body));unsigned char digest[32];char digest_hex[65];
  int journal=bytes>0&&physical&&digest_bytes(body,(size_t)bytes,digest)==0&&kv_linux_uid_record_closed(history,&a->reservation,digest)==0&&now_ns()<a->result.cleanup_end;
  if(!journal){a->quarantined=quarantine=1;bytes=terminal_body(a,"cleanup_unconfirmed",0,0,body,sizeof(body));if(bytes<=0)return;digest_bytes(body,(size_t)bytes,digest);}
  hex(digest,32,digest_hex);
  if(fcntl(a->resultfd,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE)){a->quarantined=quarantine=1;return;}
  if(bytes<1||body[bytes-1]!='}')return;body[bytes-1]=0;
  int size=snprintf(a->terminal_json,sizeof(a->terminal_json),"%s,\"proof_sha256\":\"%s\"}",body,digest_hex);if(size<0||(size_t)size>=sizeof(a->terminal_json))return;
  /* Last endpoint check precedes the terminal send; successful root fsync is
   * neither an extension nor permission to publish a late acceptance. */
  if(journal&&now_ns()>=a->result.cleanup_end){a->quarantined=quarantine=1;return;}
  if(c->fd>=0)(void)json_packet(c->fd,a->terminal_json,a->resultfd);
  a->closed=1;c->terminal=1;
}

static int no_acl(int fd) {
  const char *names[]={"system.posix_acl_access","system.posix_acl_default"};
  for(unsigned i=0;i<2;i++){errno=0;ssize_t n=fgetxattr(fd,names[i],NULL,0);if(n>=0||(errno!=ENODATA&&errno!=ENOTSUP&&errno!=EOPNOTSUPP))return -1;}
  return 0;
}
/* Resolve each fixed installation component with openat/NOFOLLOW. Merely
 * checking the final directory would leave a renameable ancestor unbound. */
static int protected_open(const char *name,int directory) {
  if(!name||name[0]!='/'||strlen(name)>=PATH_MAX)return -1;
  char copy[PATH_MAX];memcpy(copy,name,strlen(name)+1);int current=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(current<0)return -1;
  char *save=NULL,*part=strtok_r(copy+1,"/",&save);if(!part){close(current);return -1;}
  while(part){char *next=strtok_r(NULL,"/",&save);if(!strcmp(part,".")||!strcmp(part,"..")){close(current);return -1;}
    int fd=openat(current,part,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|((next||directory)?O_DIRECTORY:0));close(current);if(fd<0)return -1;
    struct stat s;if(fstat(fd,&s)||s.st_uid!=0||(s.st_mode&0022)||no_acl(fd)||((next||directory)?!S_ISDIR(s.st_mode):(!S_ISREG(s.st_mode)||s.st_nlink!=1))){close(fd);return -1;}
    current=fd;part=next;
  }
  return current;
}
static int protected_hash(const char *file,const char *expected,uint64_t limit) {
  int fd=protected_open(file,0);if(fd<0)return -1;char actual[65];int ok=digest_fd(fd,limit,actual)==0&&!strcmp(actual,expected);close(fd);return ok?0:-1;
}
static int validate_runtime(void) {
  if(protected_hash(KLS_ROOT "/runtime.manifest",KLS_RUNTIME_MANIFEST_SHA,UINT64_C(8)*1024*1024)||
     protected_hash(KLS_ROOT "/runtime/node",KLS_NODE_SHA,UINT64_C(256)*1024*1024))return -1;
  int fd=protected_open(KLS_ROOT "/runtime.manifest",0);if(fd<0)return -1;
  FILE *manifest=fdopen(fd,"r");if(!manifest){close(fd);return -1;}
  char line[PATH_MAX+80],previous[PATH_MAX]={0};unsigned count=0;int ok=1;
  while(fgets(line,sizeof(line),manifest)){
    size_t bytes=strlen(line);if(bytes<67||bytes>=sizeof(line)-1||line[64]!=' '||line[bytes-1]!='\n'||++count>20000){ok=0;break;}
    line[64]=0;line[bytes-1]=0;unsigned char digest[32];char *relative=line+65;
    if(unhex(line,digest,32)||!relative_name(relative,0)||strcmp(previous,relative)>=0){ok=0;break;}
    char file[PATH_MAX];if(snprintf(file,sizeof(file),KLS_ROOT "/runtime/%s",relative)>=(int)sizeof(file)||protected_hash(file,line,UINT64_C(512)*1024*1024)){ok=0;break;}
    memcpy(previous,relative,strlen(relative)+1);
  }
  if(ferror(manifest)||!count)ok=0;fclose(manifest);return ok?0:-1;
}
static int fixed_configuration(kv_linux_uid_configuration *config) {
  memset(config,0,sizeof(*config));config->anchor_dir=KLS_ROOT "/anchor";config->journal_dir=KLS_ROOT "/journal";config->uid_first=KLS_UID_FIRST;config->uid_last=KLS_UID_LAST;
  if(KLS_CALLER_UID<1||KLS_UID_FIRST<1000000000U||KLS_UID_LAST>=1900000000U||KLS_UID_LAST<=KLS_UID_FIRST||KLS_CALLER_UID>=KLS_UID_FIRST&&KLS_CALLER_UID<=KLS_UID_LAST||
     unhex(KLS_INSTALLATION_ID,config->installation_id,16)||unhex(KLS_HOST_ID,config->host_id,16))return -1;
  return 0;
}
static unsigned writers_open(const struct client *c) { unsigned count=0;for(unsigned i=0;i<c->writers_count;i++)if(!c->writers[i].closed)count++;return count; }
static void close_client(int slot) {
  struct client *c=&clients[slot];if(c->fd>=0){close(c->fd);c->fd=-1;}
  if(c->cancel_write>=0){unsigned char byte=1;ssize_t ignored=write(c->cancel_write,&byte,1);(void)ignored;}
  if(attempt.active&&!attempt.closed&&attempt.client_slot==slot&&attempt.channel>=0){uint32_t stop=INTERNAL_STOP;(void)packet_send(attempt.channel,&stop,sizeof(stop),-1);}
}
static void reset_attempt(void) {
  if(!attempt.active||!attempt.closed||attempt.quarantined)return;
  int descriptors[]={attempt.keeperfd,attempt.initfd,attempt.authorityfd,attempt.channel,attempt.resultfd,attempt.resultpipe};for(unsigned i=0;i<6;i++)if(descriptors[i]>=0)close(descriptors[i]);
  /* History is permanent. Only empty fixed host mountpoints/cgroups are
   * removed after exact closure; private tmpfs bytes died with the namespace. */
  (void)rmdir(attempt.cgroup);(void)rmdir(attempt.root);memset(&attempt,0,sizeof(attempt));attempt.keeperfd=attempt.initfd=attempt.authorityfd=attempt.channel=attempt.resultfd=attempt.resultpipe=-1;
}
static void release_client(int slot) {
  struct client *c=&clients[slot];if(c->fd>=0||c->peerfd<0||writers_open(c)||(attempt.active&&attempt.client_slot==slot&&!attempt.closed))return;
  if(attempt.active&&attempt.client_slot==slot){if(attempt.quarantined)return;reset_attempt();}
  int fds[]={c->peerfd,c->parentfd,c->cancel_read,c->cancel_write};for(unsigned i=0;i<4;i++)if(fds[i]>=0)close(fds[i]);
  for(unsigned i=0;i<c->writers_count;i++)if(c->writers[i].closed)(void)rmdir(c->writers[i].cgroup);
  memset(c,0,sizeof(*c));c->fd=c->peerfd=c->parentfd=c->cancel_read=c->cancel_write=-1;
}
static int request_shape(const struct kls_request *r) {
  unsigned nonzero=0;for(unsigned i=0;i<32;i++)nonzero|=r->nonce[i];
  if(r->magic!=KLS_MAGIC||r->version!=KLS_VERSION||r->op<KLS_HELLO||r->op>KLS_PERMIT||!r->ordinal||r->reserved||!nonzero||
     !r->cleanup_ms||r->cleanup_ms>KLS_MAX_CLEANUP_MS||r->work_deadline_ns>UINT64_MAX-r->cleanup_ms*UINT64_C(1000000))return -1;
  if(r->op==KLS_OPEN){if(!r->payload_len||r->payload_len>KLS_MAX_INPUT||r->pid)return -1;}
  else if(r->payload_len||(r->op==KLS_REGISTER_WRITER?(r->pid<2||r->pid>INT_MAX):r->pid!=0))return -1;
  return 0;
}
static int same_attempt(const struct kls_request *a,const struct kls_request *b) {
  return a->work_deadline_ns==b->work_deadline_ns&&a->cleanup_ms==b->cleanup_ms&&memcmp(a->nonce,b->nonce,32)==0;
}
static int capability(struct client *c) {
  char json[2048];int n=snprintf(json,sizeof(json),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"capability\",\"status\":\"%s\",\"installation_id\":\"%s\",\"host_id\":\"%s\",\"boot_id\":\"%s\",\"daemon_epoch\":\"%s\",\"source_sha256\":\"%s\",\"runtime_sha256\":\"%s\",\"native_source_sha256\":\"%s\",\"trusted_runtime_manifest_sha256\":\"%s\",\"trusted_source_manifest_sha256\":\"%s\",\"node_sha256\":\"%s\",\"broker_binary_sha256\":\"%s\",\"client_pid\":%d,\"controller_pid\":%d,\"controller_uid\":%d,\"controller_birth_ticks\":\"%llu\",\"busy\":%s}",
    quarantine?"quarantined":"ready",KLS_INSTALLATION_ID,KLS_HOST_ID,boot_hex,epoch_hex,KLS_NATIVE_SOURCE_SHA,KLS_RUNTIME_MANIFEST_SHA,KLS_NATIVE_SOURCE_SHA,KLS_RUNTIME_MANIFEST_SHA,KLS_TRUSTED_SOURCE_MANIFEST_SHA,KLS_NODE_SHA,binary_hex,c->pid,c->parent,c->uid,(unsigned long long)c->parent_birth,truth(attempt.active));
  if(n<0||(size_t)n>=sizeof(json))return -1;
  /* SCM_RIGHTS shares file-status flags. An ordinary recipient must not be
   * able to clear O_NONBLOCK on the root broker's own cancel writer and then
   * fill the pipe to stall its stop path. Reopen the fixed kernel FD alias to
   * obtain a separate OFD for the public capability, retaining the same FIFO. */
  char alias[96];snprintf(alias,sizeof(alias),"/proc/self/fd/%d",c->cancel_write);
  int public_write=open(alias,O_WRONLY|O_NONBLOCK|O_CLOEXEC);struct stat original,copy;
  if(public_write<0||fstat(c->cancel_write,&original)||fstat(public_write,&copy)||!S_ISFIFO(copy.st_mode)||
     original.st_dev!=copy.st_dev||original.st_ino!=copy.st_ino){if(public_write>=0)close(public_write);return -1;}
  int sent=json_packet(c->fd,json,public_write);close(public_write);return sent;
}
static void deny_client(int slot,const char *reason) {
  char reply[512];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"denied\",\"status\":\"rejected\",\"reason\":\"%s\"}",reason);
  if(clients[slot].fd>=0)(void)json_packet(clients[slot].fd,reply,-1);close_client(slot);
}
static void fence_expired_writers(void) {
  uint64_t now=now_ns();
  for(unsigned ci=0;ci<MAX_CLIENTS;ci++)for(unsigned wi=0;wi<clients[ci].writers_count;wi++){
    const struct writer *w=&clients[ci].writers[wi];if(!w->closed&&w->pidfd>=0&&now>=w->deadline)quarantine=1;
  }
}
static void receive_request(int slot) {
  struct client *c=&clients[slot];struct kls_request request;struct ucred cred;int passed=-1;
  ssize_t bytes=packet_recv(c->fd,&request,sizeof(request),&passed,&cred,1);
  if(bytes<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
  if(bytes!=sizeof(request)||cred.pid!=c->pid||cred.uid!=(uid_t)c->uid||pidfd_dead(c->peerfd)||pidfd_dead(c->parentfd)||request_shape(&request)){
    if(passed>=0)close(passed);deny_client(slot,"invalid_request_or_origin");return;
  }
  /* Client slot order must not admit a new request ahead of an already
   * expired writer that the normal observation loop has not visited yet. */
  fence_expired_writers();
  if(!c->ordinal){
    uint64_t now=now_ns();
    if(passed>=0||request.op!=KLS_HELLO||request.ordinal!=1||request.work_deadline_ns<=now||request.work_deadline_ns-now>KLS_MAX_WORK_MS*UINT64_C(1000000)){
      if(passed>=0)close(passed);deny_client(slot,"invalid_hello");return;
    }
    int pipefd[2];if(pipe2(pipefd,O_CLOEXEC|O_NONBLOCK)){deny_client(slot,"cancel_channel_unavailable");return;}
    c->cancel_read=pipefd[0];c->cancel_write=pipefd[1];c->first=request;c->ordinal=1;
    if(capability(c))close_client(slot);return;
  }
  if(request.op==KLS_HELLO||request.ordinal!=(uint32_t)c->ordinal+1||!same_attempt(&request,&c->first)||
     (request.op==KLS_OPEN?!sealed_input(passed,request.payload_len):passed>=0)){
    if(passed>=0)close(passed);deny_client(slot,"ordinal_identity_or_descriptor");return;
  }
  c->ordinal=(int)request.ordinal;int ok=0;
  switch(request.op){
    case KLS_REGISTER_WRITER:ok=register_writer(c,&request);break;
    case KLS_OPEN:ok=start_attempt(slot,passed);close(passed);passed=-1;break;
    case KLS_PERMIT:{
      if(!attempt.active||attempt.closed||attempt.permitted||attempt.client_slot!=slot||attempt.initfd<0||attempt.quarantined||quarantine||
         now_ns()>=attempt.work_deadline||pidfd_dead(attempt.initfd)||pidfd_dead(attempt.keeperfd)||pidfd_dead(c->cancel_read)){ok=-1;break;}
      uint32_t permit=INTERNAL_PERMIT;ok=packet_send(attempt.channel,&permit,sizeof(permit),-1);if(!ok)attempt.permitted=1;
      char reply[384];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"permitted\",\"status\":\"running\",\"ordinal\":%u}",request.ordinal);if(!ok)ok=json_packet(c->fd,reply,-1);break;
    }
    case KLS_STOP:{unsigned char byte=1;if(write(c->cancel_write,&byte,1)<0&&errno!=EAGAIN)ok=-1;
      if(attempt.active&&!attempt.closed&&attempt.client_slot==slot){uint32_t stop=INTERNAL_STOP;(void)packet_send(attempt.channel,&stop,sizeof(stop),-1);}
      char reply[256];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"stop_requested\",\"status\":\"stopping\",\"ordinal\":%u}",request.ordinal);if(json_packet(c->fd,reply,-1))ok=-1;break;}
    case KLS_OBSERVE:{observe_writers(c);char reply[512];snprintf(reply,sizeof(reply),"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"observation\",\"status\":\"%s\",\"ordinal\":%u,\"writers_open\":%u,\"terminal\":%s,\"quarantined\":%s}",c->terminal?"terminal":c->opened?"running":"ready",request.ordinal,writers_open(c),truth(c->terminal),truth(quarantine));ok=json_packet(c->fd,reply,-1);break;}
    default:ok=-1;
  }
  if(passed>=0)close(passed);if(ok)deny_client(slot,quarantine?"native_quarantined":"operation_failed");
}
static void accept_client(void) {
  int accepted=accept4(serverfd,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);if(accepted<0)return;
  int slot=-1;for(unsigned i=0;i<MAX_CLIENTS;i++)if(clients[i].peerfd<0){slot=(int)i;break;}if(slot<0){close(accepted);return;}
  struct ucred cred;socklen_t size=sizeof(cred);int peer=-1;socklen_t peer_size=sizeof(peer);int one=1;
  if(setsockopt(accepted,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))||getsockopt(accepted,SOL_SOCKET,SO_PEERCRED,&cred,&size)||size!=sizeof(cred)||cred.uid!=KLS_CALLER_UID||cred.pid<2||
     getsockopt(accepted,SOL_SOCKET,SO_PEERPIDFD,&peer,&peer_size)||peer_size!=sizeof(peer)||peer<0){if(peer>=0)close(peer);close(accepted);return;}
  pid_t parent,grandparent;uint64_t birth,parent_birth;uid_t uid,parent_uid;int parentfd=-1;
  if(process_identity(cred.pid,&parent,&birth,&uid)||uid!=KLS_CALLER_UID||parent<2||(parentfd=pidfd_open_exact(parent))<0||
     process_identity(parent,&grandparent,&parent_birth,&parent_uid)||parent_uid!=KLS_CALLER_UID||pidfd_dead(peer)||pidfd_dead(parentfd)){
    if(parentfd>=0)close(parentfd);close(peer);close(accepted);return;
  }
  struct client *c=&clients[slot];memset(c,0,sizeof(*c));c->fd=accepted;c->peerfd=peer;c->parentfd=parentfd;c->cancel_read=c->cancel_write=-1;c->pid=cred.pid;c->parent=parent;c->uid=(int)cred.uid;c->parent_birth=parent_birth;c->accepted_ns=now_ns();
}
static int unresolved_writers(void) {
  int duplicate=dup(rootfd);if(duplicate<0)return -1;DIR *dir=fdopendir(duplicate);if(!dir){close(duplicate);return -1;}
  int found=0;struct dirent *entry;errno=0;while((entry=readdir(dir)))if(!strncmp(entry->d_name,"writer-",7)){found=1;break;}if(!found&&errno)found=-1;closedir(dir);return found;
}
static int notify_ready(void) {
  const char *name=getenv("NOTIFY_SOCKET");if(!name||!name[0]||strlen(name)>=sizeof(((struct sockaddr_un *)0)->sun_path)||(name[0]!='/'&&name[0]!='@'))return -1;
  struct sockaddr_un address={.sun_family=AF_UNIX};size_t bytes=strlen(name);memcpy(address.sun_path,name,bytes+1);if(name[0]=='@')address.sun_path[0]=0;
  int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
  socklen_t length=(socklen_t)(offsetof(struct sockaddr_un,sun_path)+bytes+(name[0]=='@'?0:1));
  int ok=sendto(fd,"READY=1",7,MSG_NOSIGNAL,(struct sockaddr *)&address,length)==7;close(fd);return ok?0:-1;
}
static int serve(void) {
  kv_linux_uid_configuration config;const char *reason=NULL;
  if(getuid()!=0||geteuid()!=0||getppid()!=1||fixed_configuration(&config)||(rootfd=protected_open(KLS_ROOT,1))<0||validate_runtime()||read_boot()||
     getrandom(epoch,sizeof(epoch),0)!=(ssize_t)sizeof(epoch)||discover_cgroup()||prctl(PR_SET_CHILD_SUBREAPER,1))return 160;
  hex(epoch,sizeof(epoch),epoch_hex);int binary=protected_open(KLS_ROOT "/broker",0);if(binary<0||digest_fd(binary,UINT64_C(16)*1024*1024,binary_hex))return 161;close(binary);
  daemonfd=pidfd_open_exact(getpid());history=kv_linux_uid_open(&config,&reason);kv_linux_uid_snapshot snapshot;
  if(daemonfd<0||!history||kv_linux_uid_read(history,&snapshot))return 162;
  /* A prior unresolved custody record is a fence, never an age-based lease.
   * Losing native custody does not authorize same-boot admission on restart. */
  quarantine=snapshot.pending_cleanup||unresolved_writers()!=0;
  for(unsigned i=0;i<MAX_CLIENTS;i++)clients[i].fd=clients[i].peerfd=clients[i].parentfd=clients[i].cancel_read=clients[i].cancel_write=-1;
  serverfd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(serverfd<0)return 163;
  int one=1;if(setsockopt(serverfd,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one)))return 164;
  struct sockaddr_un address={.sun_family=AF_UNIX};if(strlen(KLS_ROOT "/control.sock")>=sizeof(address.sun_path))return 165;memcpy(address.sun_path,KLS_ROOT "/control.sock",sizeof(KLS_ROOT "/control.sock"));
  struct stat old;if(lstat(address.sun_path,&old)==0){if(!S_ISSOCK(old.st_mode)||old.st_uid!=0||unlink(address.sun_path))return 166;}else if(errno!=ENOENT)return 166;
  if(bind(serverfd,(struct sockaddr *)&address,sizeof(address))||chmod(address.sun_path,0666)||listen(serverfd,MAX_CLIENTS))return 167;
  if(notify_ready())return 187;
  while(!cancelled){
    struct pollfd fds[1+MAX_CLIENTS];fds[0]=(struct pollfd){serverfd,POLLIN,0};for(unsigned i=0;i<MAX_CLIENTS;i++)fds[1+i]=(struct pollfd){clients[i].fd,POLLIN,0};
    int ready=poll(fds,1+MAX_CLIENTS,10);if(ready<0&&errno!=EINTR)break;
    if(fds[0].revents&POLLIN)accept_client();
    for(unsigned i=0;i<MAX_CLIENTS;i++)if(clients[i].peerfd>=0){
      if(clients[i].fd>=0&&fds[1+i].revents&POLLIN)receive_request((int)i);
      if(clients[i].fd>=0&&((fds[1+i].revents&(POLLHUP|POLLERR|POLLNVAL))||pidfd_dead(clients[i].peerfd)||pidfd_dead(clients[i].parentfd)||(!clients[i].ordinal&&now_ns()-clients[i].accepted_ns>UINT64_C(5000000000))))close_client((int)i);
      observe_writers(&clients[i]);release_client((int)i);
    }
    observe_attempt();
  }
  for(unsigned i=0;i<MAX_CLIENTS;i++)if(clients[i].peerfd>=0)close_client((int)i);
  /* Independent keepers/guardians retain the original deadline after this
   * native broker exits. The systemd unit additionally owns every cgroup. */
  return 0;
}

struct client_output { unsigned char *bytes;size_t used,sent,capacity; };
static int append_output(struct client_output *out,uint32_t type,const void *body,size_t bytes) {
  if(bytes>UINT32_MAX||out->used-out->sent+sizeof(struct kls_output_header)+bytes>(size_t)KLS_MAX_RESULT+UINT32_C(1048576))return -1;
  if(out->sent){memmove(out->bytes,out->bytes+out->sent,out->used-out->sent);out->used-=out->sent;out->sent=0;}
  size_t need=out->used+sizeof(struct kls_output_header)+bytes;if(need>out->capacity){size_t cap=need+65536;unsigned char *next=realloc(out->bytes,cap);if(!next)return -1;out->bytes=next;out->capacity=cap;}
  struct kls_output_header header={KLS_OUTPUT_MAGIC,KLS_VERSION,type,(uint32_t)bytes};memcpy(out->bytes+out->used,&header,sizeof(header));out->used+=sizeof(header);if(bytes)memcpy(out->bytes+out->used,body,bytes);out->used+=bytes;return 0;
}
static int append_result(struct client_output *out,int fd) {
  struct stat s;int required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL,actual=fcntl(fd,F_GET_SEALS);
  if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_nlink||s.st_size<0||(uint64_t)s.st_size>KLS_MAX_RESULT||actual<0||(actual&required)!=required)return -1;
  size_t bytes=(size_t)s.st_size;unsigned char *body=malloc(bytes?bytes:1);if(!body)return -1;size_t at=0;
  while(at<bytes){ssize_t n=pread(fd,body+at,bytes-at,(off_t)at);if(n<0&&errno==EINTR)continue;if(n<=0){free(body);return -1;}at+=(size_t)n;}
  int result=append_output(out,KLS_AUTHORITY_JSON,body,bytes);free(body);return result;
}
static uint64_t control_deadline(const char *body) {
  const char *at=strstr(body,"\"cleanup_deadline_ns\":\"");if(!at)return 0;at+=strlen("\"cleanup_deadline_ns\":\"");char *end;errno=0;unsigned long long value=strtoull(at,&end,10);return errno||end==at||*end!='\"'?0:(uint64_t)value;
}
static int native_client(void) {
  if(getuid()!=KLS_CALLER_UID||geteuid()!=KLS_CALLER_UID)return 170;
  pid_t parent=getppid(),grandparent;uint64_t parent_birth;uid_t parent_uid;int parentfd=pidfd_open_exact(parent);
  if(parent<2||parentfd<0||process_identity(parent,&grandparent,&parent_birth,&parent_uid)||parent_uid!=KLS_CALLER_UID||prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent||pidfd_dead(parentfd))return 171;
  int connection=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(connection<0)return 172;
  struct sockaddr_un address={.sun_family=AF_UNIX};if(strlen(KLS_ROOT "/control.sock")>=sizeof(address.sun_path))return 173;memcpy(address.sun_path,KLS_ROOT "/control.sock",sizeof(KLS_ROOT "/control.sock"));
  struct stat socket_info;if(lstat(address.sun_path,&socket_info)||!S_ISSOCK(socket_info.st_mode)||socket_info.st_uid!=0||connect(connection,(struct sockaddr *)&address,sizeof(address)))return 174;
  int peer=-1,one=1;struct ucred credentials;socklen_t size=sizeof(credentials),peer_size=sizeof(peer);
  if(setsockopt(connection,SOL_SOCKET,SO_PASSCRED,&one,sizeof(one))||getsockopt(connection,SOL_SOCKET,SO_PEERCRED,&credentials,&size)||size!=sizeof(credentials)||credentials.uid!=0||
     getsockopt(connection,SOL_SOCKET,SO_PEERPIDFD,&peer,&peer_size)||peer_size!=sizeof(peer)||peer<0||nonblock(connection)||nonblock(STDIN_FILENO)||nonblock(STDOUT_FILENO))return 175;
  /* The ordinary client may parse framing, never root-side project JSON. The
   * source descriptor is filled and sealed here before a privileged receive. */
  struct kls_request first={0},request={0};size_t header_bytes=0,payload_bytes=0;int input=-1,cancel_write=-1,hello_sent=0,capability_seen=0,terminal=0,opened=0,stdin_eof=0,pending=0;uint32_t ordinal=0;
  uint64_t end=now_ns()+UINT64_C(5000000000);struct client_output output={0};int result=176;
  while(now_ns()<end&&!pidfd_dead(parentfd)&&!pidfd_dead(peer)&&!cancelled){
    struct pollfd fds[]={{connection,POLLIN,0},{STDIN_FILENO,(!stdin_eof&&!pending)?POLLIN:0,0},{STDOUT_FILENO,output.sent<output.used?POLLOUT:0,0},{parentfd,POLLIN,0},{peer,POLLIN,0}};
    int ready=poll(fds,5,10);if(ready<0&&errno==EINTR)continue;if(ready<0)break;
    if(fds[0].revents&POLLIN){
      char body[8192];int passed=-1;struct ucred sender;ssize_t bytes=packet_recv(connection,body,sizeof(body)-1,&passed,&sender,1);
      if(bytes<=0||sender.pid!=credentials.pid||sender.uid!=0||pidfd_dead(peer)){if(passed>=0)close(passed);break;}body[bytes]=0;
      if(memchr(body,0,(size_t)bytes)||strncmp(body,"{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\"",strlen("{\"schema_version\":\"knowledge-linux-native-service.v1\",\"event\":\""))){if(passed>=0)close(passed);break;}
      int is_cap=strstr(body,"\"event\":\"capability\"")!=NULL,is_terminal=strstr(body,"\"event\":\"terminal\"")!=NULL;
      if(is_cap){struct stat s;int flags=passed>=0?fcntl(passed,F_GETFL):-1;if(capability_seen||passed<0||fstat(passed,&s)||!S_ISFIFO(s.st_mode)||flags<0||(flags&O_ACCMODE)!=O_WRONLY){if(passed>=0)close(passed);break;}cancel_write=passed;passed=-1;capability_seen=1;}
      else if(is_terminal){if(!capability_seen||terminal||passed<0){if(passed>=0)close(passed);break;}uint64_t next=control_deadline(body);if(!next||next>end){close(passed);break;}end=next;terminal=1;}
      else if(passed>=0){close(passed);break;}
      if(strstr(body,"\"event\":\"cleanup_started\"")){uint64_t next=control_deadline(body);if(!next||next>end)break;end=next;}
      if(append_output(&output,KLS_CONTROL_JSON,body,(size_t)bytes)||(is_terminal&&append_result(&output,passed))){if(passed>=0)close(passed);break;}
      if(passed>=0)close(passed);
    }
    if(fds[2].revents&POLLOUT){ssize_t n=write(STDOUT_FILENO,output.bytes+output.sent,output.used-output.sent);if(n>0)output.sent+=(size_t)n;else if(n<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;if(output.sent==output.used)output.sent=output.used=0;}
    if(fds[2].revents&(POLLHUP|POLLERR|POLLNVAL))break;
    if(fds[1].revents&(POLLIN|POLLHUP)){
      if(header_bytes<sizeof(request)){
        ssize_t n=read(STDIN_FILENO,(unsigned char *)&request+header_bytes,sizeof(request)-header_bytes);
        if(n>0)header_bytes+=(size_t)n;
        else if(!n)stdin_eof=1;
        else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;
        if(header_bytes==sizeof(request)){
          if(request_shape(&request)||request.ordinal!=ordinal+1||(!hello_sent?(request.op!=KLS_HELLO||request.ordinal!=1):request.op==KLS_HELLO||!same_attempt(&request,&first)))break;
          if(!hello_sent){uint64_t now=now_ns();if(request.work_deadline_ns<=now||request.work_deadline_ns-now>KLS_MAX_WORK_MS*UINT64_C(1000000))break;first=request;end=first.work_deadline_ns+first.cleanup_ms*UINT64_C(1000000);}
          if(request.op==KLS_OPEN){input=(int)syscall(SYS_memfd_create,"knowledge-native-source",MFD_CLOEXEC|MFD_ALLOW_SEALING|MFD_NOEXEC_SEAL);if(input<0)break;payload_bytes=0;}
          else pending=1;
        }
      } else if(request.op==KLS_OPEN&&payload_bytes<request.payload_len){
        unsigned char body[65536];size_t count=request.payload_len-payload_bytes;if(count>sizeof(body))count=sizeof(body);ssize_t n=read(STDIN_FILENO,body,count);
        if(n>0){if(write_all(input,body,(size_t)n))break;payload_bytes+=(size_t)n;}
        else if(!n)stdin_eof=1;else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;
        if(payload_bytes==request.payload_len){if(fcntl(input,F_ADD_SEALS,F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE))break;pending=1;}
      }
    }
    if(pending){
      if(request.op==KLS_STOP){if(cancel_write<0){if(!capability_seen)continue;break;}unsigned char byte=1;if(write(cancel_write,&byte,1)<0&&errno!=EAGAIN)break;}
      if(packet_send(connection,&request,sizeof(request),request.op==KLS_OPEN?input:-1)==0){if(input>=0){close(input);input=-1;}ordinal=request.ordinal;if(request.op==KLS_HELLO)hello_sent=1;if(request.op==KLS_OPEN)opened=1;memset(&request,0,sizeof(request));header_bytes=payload_bytes=0;pending=0;}
      else if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR)break;
    }
    if(stdin_eof){
      if(header_bytes||payload_bytes)break;
      if(terminal&&!output.used){result=0;break;}
      if(!opened&&!output.used){result=0;break;}
      if(opened&&!terminal&&cancel_write>=0){unsigned char byte=1;{ssize_t ignored=write(cancel_write,&byte,1);(void)ignored;}}
    }
    if(fds[0].revents&(POLLHUP|POLLERR|POLLNVAL)){if(!output.used&&terminal)result=0;break;}
  }
  if(cancel_write>=0){unsigned char byte=1;if(!terminal){ssize_t ignored=write(cancel_write,&byte,1);(void)ignored;}close(cancel_write);}if(input>=0)close(input);close(connection);close(parentfd);close(peer);free(output.bytes);return result;
}
int main(int argc,char **argv) {
  signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);umask(0077);
  if(argc!=2)return 179;
  if(!strcmp(argv[1],"--client"))return native_client();
  if(getuid()!=0||geteuid()!=0)return 180;
  if(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)!=1)return 186;
  if(!strcmp(argv[1],"--serve"))return serve();
  if(!strcmp(argv[1],"--initialize-history")){
    kv_linux_uid_configuration config;const char *reason=NULL;int fd=protected_open(KLS_ROOT,1);
    if(fd<0||fixed_configuration(&config)||validate_runtime())return 181;close(fd);
    if(kv_linux_uid_initialize(&config,&reason)){if(reason)fprintf(stderr,"native history initialization: %s\n",reason);return 182;}return 0;
  }
  return 183;
}
