/* Narrow native Seatbelt feasibility matrix. No files, signals, descendants,
 * global config, UID accounts, or daemon mutations. Each profile gets one
 * owned child, and only that child's credentials are modified. */
#if !defined(__APPLE__)
#error native Darwin required
#endif
#define _DARWIN_C_SOURCE 1
#include <sys/types.h>
#include <sys/wait.h>
#include <sandbox.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct profile_case {const char *name,*text;};
static const struct profile_case cases[]={
  {"current_profile","(version 1)(allow default)(deny system-audit)(deny mach-lookup)"},
  {"deny_default_allow_file","(version 1)(deny default)(allow file*)"},
  {"deny_process_family","(version 1)(allow default)(deny process*)"},
  {"deny_default_allow_file_fork_exec","(version 1)(deny default)(allow file*)(allow process-fork)(allow process-exec)"},
  {"deny_process_info_setcontrol","(version 1)(allow default)(deny process-info-setcontrol)"}
};
int main(void) {
  setvbuf(stdout,NULL,_IONBF,0);alarm(60);
  const char *v=getenv("SUDO_UID");char *end=NULL;
  unsigned long original=v?strtoul(v,&end,10):0;
  if(geteuid()!=0||!v||!end||*end||original==0||original>=1000000000ul) {
    printf("{\"probe\":\"credential_policy_matrix\",\"available\":false,\"reason\":\"requires_root_and_valid_SUDO_UID\"}\n");return 2;
  }
  for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
    pid_t child=fork();if(child<0)return 3;
    if(!child) {
      alarm(8);
      uid_t private_uid=(uid_t)(1000000000u+arc4random_uniform(900000000u));
      if(setgroups(0,NULL)||setgid(private_uid)||setreuid(private_uid,(uid_t)original))_exit(10);
      char *error=NULL;errno=0;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      int sr=sandbox_init(cases[i].text,0,&error);
#pragma clang diagnostic pop
      int se=errno;
      if(error){fprintf(stderr,"profile %s: %s\n",cases[i].name,error);sandbox_free_error(error);}
      if(sr) {
        printf("{\"profile\":\"%s\",\"applied\":false,\"errno\":%d}\n",cases[i].name,se);_exit(0);
      }
      uid_t before=getuid();errno=0;
      int rc=setreuid((uid_t)original,(uid_t)-1),re=errno;
      printf("{\"profile\":\"%s\",\"applied\":true,\"before_ruid\":%u,\"original_euid\":%lu,\"setreuid_rc\":%d,\"errno\":%d,\"after_ruid\":%u,\"escape_observed\":%s}\n",cases[i].name,before,original,rc,re,getuid(),rc==0&&getuid()==(uid_t)original?"true":"false");
      _exit(0);
    }
    int status=0;while(waitpid(child,&status,0)<0){if(errno!=EINTR)return 4;}
    printf("{\"probe\":\"profile_child_exit\",\"profile\":\"%s\",\"wait_status\":%d}\n",cases[i].name,status);
  }
  printf("{\"probe\":\"credential_policy_matrix_summary\",\"product_backend_certified\":false,\"note\":\"deny-default allowing migration refutes these SBPL policies as an immutable RUID mechanism\"}\n");
  return 0;
}
