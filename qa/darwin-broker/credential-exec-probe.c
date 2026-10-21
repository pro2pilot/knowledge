/* Audit-only Darwin privileged-exec qualification. Own children/fixtures only.
 * clang -std=c11 -O2 -Wall -Wextra credential-exec-probe.c -lsandbox -o probe
 * Root-prepared fixture args; never install setuid helpers globally.
 */
#define _DARWIN_C_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <sandbox.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/clonefile.h>
#include <copyfile.h>

static void facts(const char *label) {
 struct proc_bsdinfo b;memset(&b,0,sizeof(b));
 int n=proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&b,sizeof(b));
 printf("{\"kind\":\"credentials\",\"label\":\"%s\",\"pid\":%d,\"ruid\":%u,\"euid\":%u,\"rgid\":%u,\"egid\":%u,\"bsd_bytes\":%d,\"saved_uid\":%u,\"saved_gid\":%u}\n",label,getpid(),getuid(),geteuid(),getgid(),getegid(),n,b.pbi_svuid,b.pbi_svgid);
 fflush(stdout);
}
static int leaf(const char *original) {
 uid_t uid=(uid_t)strtoul(original,NULL,10);facts("after_exec_before_migration");
 errno=0;int r=setreuid(uid,(uid_t)-1),e=errno;
 printf("{\"kind\":\"migration\",\"rc\":%d,\"errno\":%d,\"ruid_after\":%u,\"euid_after\":%u}\n",r,e,getuid(),geteuid());
 fflush(stdout);return 0;
}
static int apply(const char *profile) {
 char *error=NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 int r=sandbox_init(profile,0,&error);
#pragma clang diagnostic pop
 if(error)sandbox_free_error(error);
 return r;
}
static int own_fixture(const char *p,uid_t owner,mode_t bit) {
 struct stat s;return !lstat(p,&s)&&S_ISREG(s.st_mode)&&s.st_uid==owner&&!(s.st_mode&0022)&&(s.st_mode&bit);
}
static int one(const char *image,const char *copy,const char *profile,uid_t original,uid_t private_uid,int sandboxed,int import_method) {
 pid_t p=fork();if(p<0)return 1;
 if(!p){
  alarm(8);gid_t group=(gid_t)private_uid;
  if(setgroups(1,&group)||setgid(group)||setuid(private_uid))_exit(120);
  if(sandboxed&&apply(profile))_exit(121);
  facts("private_before_exec");
  typedef int(*setthread_fn)(uid_t,gid_t);void *sym=dlsym(RTLD_DEFAULT,"pthread_setugid_np");setthread_fn fn=NULL;memcpy(&fn,&sym,sizeof(fn));
  errno=0;int tr=fn?fn(original,(gid_t)original):-2,te=errno;
  printf("{\"kind\":\"thread_override_attempt\",\"symbol\":%s,\"rc\":%d,\"errno\":%d}\n",fn?"true":"false",tr,te);fflush(stdout);
  const char *target=image;char linked[PATH_MAX];
  if(import_method){
   if(snprintf(linked,sizeof(linked),"%s/import-%d",copy,getpid())>=(int)sizeof(linked))_exit(122);
   errno=0;int lr=-1;
   if(import_method==1)lr=link(image,linked);
   if(import_method==2)lr=symlink(image,linked);
   if(import_method==3)lr=clonefile(image,linked,0);
   if(import_method==4)lr=copyfile(image,linked,NULL,COPYFILE_ALL|COPYFILE_CLONE);
   if(import_method==5){int fd=open(image,O_RDONLY);lr=fd<0?-1:0;if(fd>=0)snprintf(linked,sizeof(linked),"/dev/fd/%d",fd);}
   int le=errno;struct stat imported;memset(&imported,0,sizeof(imported));int sr=stat(linked,&imported);
   printf("{\"kind\":\"image_import\",\"method\":%d,\"rc\":%d,\"errno\":%d,\"stat_rc\":%d,\"owner\":%u,\"group\":%u,\"mode\":%u}\n",import_method,lr,le,sr,imported.st_uid,imported.st_gid,(unsigned)(imported.st_mode&07777));fflush(stdout);
   if(lr)_exit(0);target=linked;
  }
  char original_text[32];snprintf(original_text,sizeof(original_text),"%u",original);
  execl(target,target,"--credential-leaf",original_text,(char*)NULL);
  int e=errno;printf("{\"kind\":\"exec_rejected\",\"errno\":%d}\n",e);fflush(stdout);_exit(0);
 }
 int s=0;while(waitpid(p,&s,0)<0&&errno==EINTR){}
 printf("{\"kind\":\"case_exit\",\"sandboxed\":%s,\"import_method\":%d,\"wait_status\":%d}\n",sandboxed?"true":"false",import_method,s);fflush(stdout);
 return !WIFEXITED(s)||WEXITSTATUS(s)!=0;
}
int main(int argc,char **argv) {
 setvbuf(stdout,NULL,_IONBF,0);alarm(90);
 if(argc==3&&!strcmp(argv[1],"--credential-leaf"))return leaf(argv[2]);
 if(argc!=8||geteuid()!=0){fprintf(stderr,"usage(root): probe ROOT_SUID ORIGINAL_SUID ROOT_SGID OWN_COPY_DIR ORIGINAL_UID PRIVATE_UID PROFILE_STRING\n");return 2;}
 uid_t original=(uid_t)strtoul(argv[5],NULL,10),private_uid=(uid_t)strtoul(argv[6],NULL,10);
 if(original<500||private_uid<1000000000||private_uid>2000000000||original==private_uid)return 3;
 if(getpwuid(private_uid)!=NULL)return 3;
 struct stat d;if(lstat(argv[4],&d)||!S_ISDIR(d.st_mode)||d.st_uid!=private_uid||(d.st_mode&0077))return 4;
 if(!own_fixture(argv[1],0,S_ISUID)||!own_fixture(argv[2],original,S_ISUID)||!own_fixture(argv[3],0,S_ISGID))return 5;
 pid_t ids[4];int n=proc_listpids(PROC_RUID_ONLY,private_uid,ids,sizeof(ids));
 if(n!=0){fprintf(stderr,"private UID already has kernel members or enumeration failed\n");return 6;}
 int errors=0;
 for(int fixture=0;fixture<=3;fixture++)for(int sandboxed=0;sandboxed<=1;sandboxed++)for(int method=0;method<=5;method++){
  printf("{\"kind\":\"case_begin\",\"fixture\":%d,\"sandboxed\":%s,\"import_method\":%d}\n",fixture,sandboxed?"true":"false",method);
  errors+=one(argv[fixture],argv[4],argv[7],original,private_uid,sandboxed,method);
 }
 printf("{\"kind\":\"summary\",\"infrastructure_errors\":%d,\"product_backend_certified\":false}\n",errors);
 return errors?1:0;
}
