/* Test-only exact birth/version signal helper. No PID-only fallback. */
#if !defined(__APPLE__)
#error "Darwin required"
#endif
#include <bsm/audit.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct Unique { uint8_t uuid[16];uint64_t unique,parent;int32_t version;uint32_t r;uint64_t r2,r3; };
struct Identity { struct proc_bsdinfo bsd;struct Unique unique; };
_Static_assert(sizeof(struct Unique)==56,"Darwin combined ABI");
int main(int argc,char **argv) {
  if(argc!=8||getuid()!=0||geteuid()!=0)return 64;
  unsigned long long values[6];
  for(unsigned i=0;i<6;i++){char *end=NULL;errno=0;values[i]=strtoull(argv[i+1],&end,10);
    if(errno||!argv[i+1][0]||!end||*end)return 64;}
  if(values[0]<2||values[0]>2147483647||!values[1]||values[3]>999999||values[4]>1900000000ull
      ||(values[5]!=SIGKILL&&values[5]!=SIGTERM&&values[5]!=SIGSTOP&&values[5]!=SIGCONT))return 64;
  struct Identity v={0};char image[PROC_PIDPATHINFO_MAXSIZE]={0};
  if(proc_pidinfo((pid_t)values[0],18,0,&v,sizeof(v))!=(int)sizeof(v)||v.bsd.pbi_pid!=values[0]
      ||v.unique.unique!=values[1]||v.bsd.pbi_start_tvsec!=values[2]||v.bsd.pbi_start_tvusec!=values[3]
      ||v.bsd.pbi_ruid!=values[4]||v.unique.version<=0||proc_pidpath((pid_t)values[0],image,sizeof(image))<=0
      ||strcmp(image,argv[7]))return 77;
  typedef int (*Signal)(const audit_token_t *,int);Signal fn=(Signal)dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");
  if(!fn)return 78;audit_token_t token={{0}};token.val[5]=v.bsd.pbi_pid;token.val[7]=(uint32_t)v.unique.version;
  int result=fn(&token,(int)values[5]);
  printf("{\"exact_birth_checked\":true,\"signal\":%llu,\"native_result\":%d}\n",values[5],result);
  return result==0?0:1;
}
